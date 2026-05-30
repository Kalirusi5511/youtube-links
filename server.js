const express = require('express');
const path = require('path');

// dotenv nur in Entwicklung laden (verhindert Crash, falls nicht installiert in Prod)
if (process.env.NODE_ENV !== 'production') {
  try { require('dotenv').config(); } catch (e) { /* ignore if missing */ }
}

const app = express();
const PORT = process.env.PORT || 3000;

// Falls deine index.html im Projekt‑Root liegt, benutze __dirname
// Wenn sie in "build" oder "public" liegt, passe staticDir an (z.B. path.join(__dirname,'build'))
const staticDir = path.join(__dirname);
app.use(express.static(staticDir));

// Beispiel-API-Route (optional)
app.get('/api/health', (req, res) => res.json({ ok: true }));

// Root-Route explizit liefern (sicherer als nur express.static)
app.get('/', (req, res) => {
  res.sendFile(path.join(staticDir, 'index.html'), err => {
    if (err) {
      console.error('Fehler beim Senden von index.html:', err);
      res.status(500).send('Server error');
    }
  });
});

// Fallback für alle anderen nicht-API Anfragen (optional für SPAs)
// app.get('*', (req, res) => res.sendFile(path.join(staticDir, 'index.html')));

app.listen(PORT, () => console.log(`Server läuft auf Port ${PORT}`));
