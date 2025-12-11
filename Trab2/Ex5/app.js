require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');

const authRoutes = require('./routes/authRoutes');
const sessionStore = require('./stores/sessionStore');
const githubRoutes = require('./routes/githubRoutes');
const taskRoutes = require('./routes/taskRoutes');
const setupCasbin = require("./casbin/casbin");


// Criar app Express
const app = express();

// PORT
const PORT = process.env.PORT;

// Middlewares globais
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(require("./middleware/tempSession"));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/auth', authRoutes);
app.use('/github', githubRoutes);
app.use('/tasks', taskRoutes);


// Configurar views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

(async () => {
    app.locals.enforcer = await setupCasbin();
})();
app.get('/', (req, res) => {
    const sid = req.cookies["session-id"];
    const user = sessionStore.get(sid);

    res.render('home', { user });
});


// Levantar servidor
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
