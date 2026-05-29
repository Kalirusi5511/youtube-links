// server.js
require('dotenv').config(); // nur lokal / bei Bedarf
const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_HASH = process.env.ADMIN_HASH;         // bcrypt hash z.B. $2b$10$...
const SESSION_SECRET = process.env.SESSION_SECRET; // langes zufälliges Secret
const IN_PROD = process.env.NODE_ENV === 'production';

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Einfaches Rate Limit für /login (Schutz vor Brute Force)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 Minuten
  max: 6,                   // max 6 Versuche pro IP pro window
  message: 'Zu viele Login‑Versuche. Bitte später erneut versuchen.'
});
app.use('/login', loginLimiter);

// Session (für Produktion bitte persistenten Store verwenden)
app.use(session({
  name: 'sid',
  secret: SESSION_SECRET || 'dev-secret-please-change',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: IN_PROD,        // nur über HTTPS
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 2 // 2 Stunden
  }
}));

// Statische Dateien (index.html in /public)
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

// Login-Endpoint
app.post('/login', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).send('❌ Kein Passwort eingegeben');

  if (!ADMIN_HASH) {
    console.error('ADMIN_HASH fehlt in den ENV variablen');
    return res.status(500).send('Serverkonfiguration fehlerhaft');
  }

  try {
    const match = await bcrypt.compare(password, ADMIN_HASH);
    if (match) {
      req.session.admin = true;
      return res.redirect('/');
    } else {
      return res.status(401).send('❌ Falsches Passwort');
    }
  } catch (err) {
    console.error(err);
    return res.status(500).send('Serverfehler');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Admin-Status prüfen
app.get('/isAdmin', (req, res) => {
  res.json({ isAdmin: !!req.session.admin });
});

// Für SPAs: alle unbekannten GETs auf index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(publicPath, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Server läuft auf Port ${PORT}`);
});
