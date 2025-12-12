const githubAuthService = require("../services/githubAuthService");
const sessionStore = require("../stores/sessionStore");

exports.login = (req, res) => {
    res.redirect(githubAuthService.getAuthUrl());
};


exports.callback = async (req, res) => {
    const code = req.query.code;
    if (!code) return res.status(400).send("Code em falta");

    const token = await githubAuthService.exchangeCodeForToken(code);

    const sid = req.cookies["session-id"];
    if (!sid) return res.status(401).send("Sessão inexistente");

    const session = sessionStore.get(sid);
    if (!session) return res.status(401).send("Sessão inválida");

    // 🔑 guardar token GitHub na sessão EXISTENTE
    session.githubAccessToken = token;

    res.redirect("/github");
};

