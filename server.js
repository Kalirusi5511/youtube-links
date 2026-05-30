// ==================== server.js ====================
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

// dotenv nur in Entwicklung
if (process.env.NODE_ENV !== 'production') {
  try { require('dotenv').config(); } catch (e) { /* ignore */ }
}

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Middleware ----------
app.use(express.json());

// ---------- SQL.js Import (async!) ----------
let db;

async function initDatabase() {
  const initSqlJs = require('sql.js');
  
  const SQL = await initSqlJs({
    locateFile: file => `https://sql.js.org/dist/${file}`
  });

  // Datenbank laden oder neue erstellen
  const dbFile = 'database.db';
  
  if (fs.existsSync(dbFile)) {
    const buffer = fs.readFileSync(dbFile);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  // Tabellen erstellen
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS backup_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      code TEXT NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      used_at TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS reset_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL,
      expires_at TEXT
    )
  `);

  // Admin User erstellen (falls nicht vorhanden)
  const existingAdmin = db.exec("SELECT * FROM users WHERE email = 'admin@example.com'");
  if (existingAdmin.length === 0) {
    const hashedPassword = crypto.createHash('sha256').update('admin123').digest('hex');
    db.run("INSERT INTO users (email, password_hash) VALUES (?, ?)", ['admin@example.com', hashedPassword]);
    console.log('✅ Admin User erstellt: admin@example.com / admin123');
  }

  saveDatabase();
  console.log('✅ Datenbank initialisiert');
}

// Datenbank speichern
function saveDatabase() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync('database.db', buffer);
}

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

// ---------- STATIC FILES ----------
const staticDir = path.join(__dirname, 'public');
app.use(express.static(staticDir));

// ==================== API ROUTES ====================

// --- HEALTH CHECK ---
app.get('/api/health', (req, res) => res.json({ ok: true, database: !!db }));

// --- LOGIN ---
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'E-Mail und Passwort erforderlich' });
  }

  const hashedPassword = hashToken(password);
  const result = db.exec("SELECT * FROM users WHERE email = ? AND password_hash = ?", [email, hashedPassword]);
  
  if (result.length === 0 || result[0].values.length === 0) {
    return res.status(401).json({ error: 'Ungültige Anmeldedaten' });
  }

  const user = result[0].values[0];
  
  req.session.userId = user[0];
  req.session.email = user[1];
  
  return res.json({ success: true, email: user[1] });
});

// --- REGISTER ---
app.post('/api/auth/register', (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'E-Mail und Passwort erforderlich' });
  }

  const existing = db.exec("SELECT * FROM users WHERE email = ?", [email]);
  if (existing.length > 0 && existing[0].values.length > 0) {
    return res.status(400).json({ error: 'E-Mail bereits registriert' });
  }

  const hashedPassword = hashToken(password);
  db.run("INSERT INTO users (email, password_hash) VALUES (?, ?)", [email, hashedPassword]);
  saveDatabase();

  return res.json({ success: true, message: 'Account erstellt!' });
});

// --- FORGOT PASSWORD (Backup-Codes generieren) ---
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'E-Mail erforderlich' });
  }

  const result = db.exec("SELECT id FROM users WHERE email = ?", [email]);
  
  if (result.length === 0 || result[0].values.length === 0) {
    return res.json({ message: 'Falls ein Konto existiert, wurden Codes per E-Mail gesendet.' });
  }

  const userId = result[0].values[0][0];

  // Alte nicht verwendete Codes löschen
  db.run("DELETE FROM backup_codes WHERE user_id = ? AND used = 0", [userId]);

  // 3 neue Backup-Codes generieren
  const codes = [];
  for (let i = 0; i < 3; i++) {
    const code = generateBackupCode();
    db.run("INSERT INTO backup_codes (user_id, code) VALUES (?, ?)", [userId, hashCode(code)]);
    codes.push(code);
  }
  saveDatabase();

  // DEV MODE: Codes in Console loggen
  console.log('\n📧 === BACKUP CODES (DEV MODE) ===');
  console.log('An:', email);
  codes.forEach(c => console.log('  Code:', c));
  console.log('===================================\n');

  return res.json({ message: 'Falls ein Konto existiert, wurden Codes per E-Mail gesendet.' });
});

// --- BACKUP-CODE VERIFIZIEREN ---
app.post('/api/auth/verify-backup-code', (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ error: 'E-Mail und Code erforderlich' });
  }

  const userResult = db.exec("SELECT id FROM users WHERE email = ?", [email]);
  if (userResult.length === 0 || userResult[0].values.length === 0) {
    return res.status(404).json({ error: 'User nicht gefunden' });
  }

  const userId = userResult[0].values[0][0];
  const hashedCode = hashCode(code);

  const validCodeResult = db.exec(
    "SELECT * FROM backup_codes WHERE user_id = ? AND code = ? AND used = 0",
    [userId, hashedCode]
  );

  if (validCodeResult.length === 0 || validCodeResult[0].values.length === 0) {
    return res.status(401).json({ error: 'Ungültiger oder bereits verwendeter Code' });
  }

  const codeId = validCodeResult[0].values[0][0];

  // Code als verwendet markieren
  const now = new Date().toISOString();
  db.run("UPDATE backup_codes SET used = 1, used_at = ? WHERE id = ?", [now, codeId]);

  const resetToken = generateResetToken();

  // Reset-Token speichern (1 Stunde gültig)
  const expiresAt = new Date(Date.now() + 3600000).toISOString();
  db.run("INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)", [userId, hashToken(resetToken), expiresAt]);
  saveDatabase();

  return res.json({ success: true, resetToken: resetToken });
});

// --- PASSWORT ZURÜCKSETZEN ---
app.post('/api/auth/reset-password', (req, res) => {
  const { resetToken, newPassword } = req.body;

  const tokenResult = db.exec(
    "SELECT user_id FROM reset_tokens WHERE token = ? AND expires_at > ?",
    [hashToken(resetToken), new Date().toISOString()]
  );

  if (tokenResult.length === 0 || tokenResult[0].values.length === 0) {
    return res.status(401).json({ error: 'Token ungültig oder abgelaufen' });
  }

  const userId = tokenResult[0].values[0][0];
  const hashedPassword = hashToken(newPassword);

  db.run("UPDATE users SET password_hash = ? WHERE id = ?", [hashedPassword, userId]);
  db.run("DELETE FROM reset_tokens WHERE token = ?", [hashToken(resetToken)]);
  saveDatabase();

  return res.json({ message: 'Passwort erfolgreich geändert!' });
});

// --- LOGOUT ---
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  return res.json({ success: true });
});

// --- SESSION CHECK ---
app.get('/api/auth/session', (req, res) => {
  if (req.session.userId) {
    return res.json({ loggedIn: true, email: req.session.email });
  }
  return res.json({ loggedIn: false });
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

// ==================== SERVER START ====================

async function start() {
  await initDatabase();
  
  // Session middleware (nach DB init)
  const session = require('express-session');
  app.use(session({
    secret: process.env.SESSION_SECRET || 'super-geheimes-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 Stunden
  }));

  app.listen(PORT, () => {
    console.log(`Server läuft auf Port ${PORT}`);
    console.log(`DB Datei: database.db`);
  });
}

start();
