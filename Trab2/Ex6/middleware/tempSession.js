const sessionStore = require('../stores/sessionStore');

module.exports = (req, res, next) => {
    const sid = req.cookies["session-id"];

    // se não existir user, não criamos sessão temporária
    const user = sessionStore.get(sid);
    if (!user) {
        req.tempSession = {};
        return next();
    }

    // chave única para os dados temporários deste utilizador
    const key = `temp-${sid}`;

    // carregar
    req.tempSession = sessionStore.get(key) || {};

    // função para guardar
    req.saveTempSession = () => {
        sessionStore.set(key, req.tempSession);
    };

    next();
};
