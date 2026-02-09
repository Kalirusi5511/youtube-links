const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// === Passwort-Hash (aus hash.js generiert) ===
const ADMIN_HASH = "$2b$10$E9v2YxZ..."; // Hier den generierten Hash eintragen

// === Middleware ===
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: "geheimesessionkey",
    resave: false,
    saveUninitialized: true
}));

// Statisches Frontend
app.use(express.static(path.join(__dirname, "public")));

// === Login Endpoint ===
app.post("/login", async (req, res) => {
    const { password } = req.body;
    if (!password) return res.send("❌ Kein Passwort eingegeben");

    const match = await bcrypt.compare(password, ADMIN_HASH);
    if (match) {
        req.session.admin = true;
        res.redirect("/"); // zurück zur Frontend-Seite
    } else {
        res.send("❌ Falsches Passwort");
    }
});

// === Logout ===
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/");
    });
});

// === Admin-Status prüfen ===
app.get("/isAdmin", (req, res) => {
    res.json({ isAdmin: !!req.session.admin });
});

app.listen(PORT, () => {
    console.log(`🚀 Server läuft auf Port ${PORT}`);
});
