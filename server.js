const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: "supersecret",
    resave: false,
    saveUninitialized: false
}));

// 👇 Passwort hier ändern
const ADMIN_PASSWORD_HASH = bcrypt.hashSync("5402", 10);

app.get("/", (req, res) => {
    if (req.session.loggedIn) {
        res.send("<h1>Admin Bereich</h1><a href='/logout'>Logout</a>");
    } else {
        res.send(`
            <form method="POST" action="/login">
                <input type="password" name="password" placeholder="Passwort" />
                <button type="submit">Login</button>
            </form>
        `);
    }
});

app.post("/login", async (req, res) => {
    const { password } = req.body;
    const match = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
    if (match) {
        req.session.loggedIn = true;
        res.redirect("/");
    } else {
        res.send("❌ Falsches Passwort");
    }
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/");
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server läuft auf Port " + PORT));
