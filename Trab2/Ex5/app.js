const express = require('express');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 8080;

// Configurar EJS + pasta de views
app.set('view engine', 'ejs');
app.set('views', './views');

// Middleware básico
app.use(express.static('public'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());


app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});


app.get('/', (req, res) => {
    const user = req.cookies["session-id"]
        ? { name: "Utilizador", role: "free" } // provisório, depois ligamos ao sessionStore
        : null;

    res.render('home', { user });
});
