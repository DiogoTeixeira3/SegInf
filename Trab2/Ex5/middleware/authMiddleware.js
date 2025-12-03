const sessionStore = require('../stores/sessionStore');

module.exports = function authMiddleware(req, res, next) {
    // 1. Ler o cookie enviado pelobrowser
    const sid = req.cookies["session-id"];

    // 2. Procurar sessão em memória
    const user = sessionStore.get(sid);

    // 3. Se NÃO existir user, redirecionar para login
    if (!user) {
        return res.redirect('/auth/login');
    }

    // 4. Guardar user no pedido (fica acessível nos controllers)
    req.user = user;

    // 5. Continuar o pipeline para o endpoint seguinte
    next();
};
