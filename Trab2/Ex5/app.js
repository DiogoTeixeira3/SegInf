
require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');

const authRoutes = require('./routes/authRoutes');
const sessionStore = require('./stores/sessionStore');
const githubRoutes = require('./routes/githubRoutes');

// Criar app Express
const app = express();

// PORT
const PORT = process.env.PORT;

// Middlewares globais
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Configurar views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Servir ficheiros estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Rotas
app.use('/auth', authRoutes);

app.use('/github', githubRoutes);

app.get('/', (req, res) => {
    const sid = req.cookies["session-id"];
    const user = sessionStore.get(sid);

    res.render('home', { user });
});
// Levantar servidor
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
