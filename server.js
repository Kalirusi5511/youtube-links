// server.js (vollständig)
try {
  if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
  }
} catch (e) {
  // ignore
}

const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_HASH = process.env.ADMIN_HASH;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-please-change';
const IN_PROD = process.env.NODE_ENV === 'production';

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 6,
  message: 'Zu viele Login‑Versuche. Bitte später erneut versuchen.'
});
app.use('/login', loginLimiter);

app.use(session({
  name: 'sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: IN_PROD,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 2
  }
}));

const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

app.post('/login', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).send('❌ Kein Passwort eingegeben');
  if (!ADMIN_HASH) {
    console.error('ADMIN_HASH fehlt in ENV');
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

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.get('/isAdmin', (req, res) => {
  res.json({ isAdmin: !!req.session.admin });
});

// Für SPA: alle nicht gefundenen GETs auf index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(publicPath, 'index.html'));
});

app.listen(PORT, () => console.log(`🚀 Server läuft auf Port ${PORT}`));
