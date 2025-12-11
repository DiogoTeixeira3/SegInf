const sessionStore = require('../stores/sessionStore');

exports.requireAuth = (req, res, next) => {
    const sid = req.cookies["session-id"];
    const user = sessionStore.get(sid);

    if (!user) {
        return res.redirect('/auth/login');
    }

    req.user = user;
    next();
};
