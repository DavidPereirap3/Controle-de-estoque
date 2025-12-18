// server.js
const express = require('express');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const fs = require('fs-extra');
const crypto = require('crypto');
const path = require('path');
const { RateLimiterMemory } = require('rate-limiter-flexible');

const SAVE_KEY = process.env.SAVE_KEY || ''; // obrigatório
if(!SAVE_KEY || SAVE_KEY.length < 32) {
  console.error('Defina SAVE_KEY com pelo menos 32 caracteres (env variable).');
  process.exit(1);
}

const app = express();
app.use(helmet());
app.use(bodyParser.json({limit: '10mb'})); // ajustar limite conforme necessário

// rate limiter simples (por IP) — reduz spam; aceita algumas requisições por minuto
const rateLimiter = new RateLimiterMemory({ points: 10, duration: 60 }); // 10 req/min

app.post('/submit', async (req, res) => {
  try {
    // Aplica limiter (usa IP indireto, mas não logamos)
    const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
    try { await rateLimiter.consume(ip); } catch(e) { return res.status(429).send('Muitas requisições'); }

    const { category, description, attachmentBase64, timestamp } = req.body || {};
    if(!description) return res.status(400).send('Descrição é obrigatória');

    const payload = { category, description, attachmentBase64: attachmentBase64 || null, timestamp: timestamp || new Date().toISOString() };

    // Criptografa payload com AES-256-GCM
    const key = crypto.createHash('sha256').update(SAVE_KEY).digest();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const data = Buffer.from(JSON.stringify(payload), 'utf8');
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();

    const out = Buffer.concat([iv, tag, encrypted]).toString('base64');

    await fs.ensureDir(path.join(__dirname, 'reports'));
    const filename = path.join(__dirname, 'reports', `${Date.now()}-${crypto.randomBytes(6).toString('hex')}.txt`);
    await fs.writeFile(filename, out, { encoding:'utf8', flag:'wx' });

    return res.status(200).send('ok');
  } catch (err) {
    console.error('submit error'); // não imprime dados do usuário
    return res.status(500).send('erro interno');
  }
});

// rota para download dos arquivos (opcional) — só local/admin
// NÃO habilite isto em produção sem autenticação
app.use(express.static('public')); // caso queira servir a página estática aqui

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log(`Servidor rodando na porta ${PORT}`));
