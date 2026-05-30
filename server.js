// ==================== server.js ====================
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

// dotenv nur in Entwicklung
if (process.env.NODE_ENV !== 'production') {
  try { require('dotenv').config(); } catch (e) { /* ignore */ }
}

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- SQLite DB ----------
const db = new Database('backup_codes.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    code TEXT NOT NULL,
    used INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    used_at TEXT
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    token TEXT NOT NULL,
    expires_at TEXT
  )
`);

// ---------- Middleware ----------
app.use(express.json());

// ---------- Static Files ----------
const staticDir = path.join(__dirname, 'public');
app.use(express.static(staticDir));

// ---------- HILFSFUNKTIONEN ----------
function generateBackupCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const segments = [];
  for (let s = 0; s < 3; s++) {
    let segment = '';
    for (let i = 0; i < 4; i++) {
      segment += chars[crypto.randomInt(chars.length)];
    }
    segments.push(segment);
  }
  return segments.join('-');
}

function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function generateResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ==================== API ROUTES ====================

app.get('/api/health', (req, res) => res.json({ ok: true }));

// --- FORGOT PASSWORD ---
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'E-Mail erforderlich' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user) {
    return res.json({ message: 'Falls ein Konto existiert, wurden Codes per E-Mail gesendet.' });
  }

  // Alte nicht verwendete Codes löschen
  db.prepare('DELETE FROM backup_codes WHERE user_id = ? AND used = 0').run(user.id);

  // 3 neue Backup-Codes generieren
  const codes = [];
  for (let i = 0; i < 3; i++) {
    const code = generateBackupCode();
    db.prepare('INSERT INTO backup_codes (user_id, code) VALUES (?, ?)')
      .run(user.id, hashCode(code));
    codes.push(code);
  }

  // DEV MODE: Codes in Console loggen
  if (process.env.NODE_ENV !== 'production') {
    console.log('\n📧 === BACKUP CODES (DEV MODE) ===');
    console.log('An:', email);
    codes.forEach(c => console.log('  Code:', c));
    console.log('===================================\n');
  } else {
    await sendBackupCodesEmail(email, codes);
  }

  return res.json({ message: 'Falls ein Konto existiert, wurden Codes per E-Mail gesendet.' });
});

// --- BACKUP-CODE VERIFIZIEREN ---
app.post('/api/auth/verify-backup-code', (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ error: 'E-Mail und Code erforderlich' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) {
    return res.status(404).json({ error: 'User nicht gefunden' });
  }

  const validCode = db.prepare(`
    SELECT * FROM backup_codes 
    WHERE user_id = ? AND code = ? AND used = 0
  `).get(user.id, hashCode(code));

  if (!validCode) {
    return res.status(401).json({ error: 'Ungültiger oder bereits verwendeter Code' });
  }

  // Code als verwendet markieren
  db.prepare('UPDATE backup_codes SET used = 1, used_at = CURRENT_TIMESTAMP WHERE id = ?')
    .run(validCode.id);

  const resetToken = generateResetToken();

  db.prepare('INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, datetime("now", "+1 hour"))')
    .run(user.id, hashToken(resetToken));

  return res.json({ success: true, resetToken: resetToken });
});

// --- PASSWORT ZURÜCKSETZEN ---
app.post('/api/auth/reset-password', (req, res) => {
  const { resetToken, newPassword } = req.body;

  const validToken = db.prepare(`
    SELECT * FROM reset_tokens 
    WHERE token = ? AND expires_at > datetime('now')
  `).get(hashToken(resetToken));

  if (!validToken) {
    return res.status(401).json({ error: 'Token ungültig oder abgelaufen' });
  }

  // Passwort updaten (hier einfach als Hash - echtes PW hashing später!)
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
    .run(hashToken(newPassword), validToken.user_id);

  db.prepare('DELETE FROM reset_tokens WHERE token = ?').run(hashToken(resetToken));

  return res.json({ message: 'Passwort erfolgreich geändert!' });
});

// ==================== STATIC & FALLBACK ====================

app.get('/', (req, res) => {
  res.sendFile(path.join(staticDir, 'index.html'), err => {
    if (err) {
      res.status(500).send('Server error');
    }
  });
});

app.get('*', (req, res) => res.sendFile(path.join(staticDir, 'index.html')));

// ==================== E-MAIL FUNKTION ====================

async function sendBackupCodesEmail(email, codes) {
  try {
    const nodemailer = require('nodemailer');
    
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT || 587,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    await transporter.sendMail({
      from: `"Dein Service" <${process.env.SMTP_FROM || 'noreply@example.com'}>`,
      to: email,
      subject: 'Deine Backup-Codes',
      html: `
        <h2>Deine Backup-Codes</h2>
        <p>Bewahre diese Codes sicher auf!</p>
        <ul>
          ${codes.map(code => `<li style="font-family: monospace; font-size: 18px;"><b>${code}</b></li>`).join('')}
        </ul>
        <p>Jeder Code kann nur einmal verwendet werden.</p>
      `
    });
  } catch (error) {
    console.error('E-Mail Fehler:', error);
  }
}

// ==================== SERVER START ====================

app.listen(PORT, () => {
  console.log(`Server läuft auf Port ${PORT}`);
});
