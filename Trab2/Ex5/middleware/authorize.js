module.exports = function authorize(obj, act) {
    return async (req, res, next) => {

        const enforcer = req.app.locals.enforcer;

        if (!req.user) {
            return res.status(401).send("Não autenticado");
        }

        const role = req.user.role;   // free | regular | premium

        const allowed = await enforcer.enforce(role, obj, act);

        if (!allowed) {
            return res.status(403).send("Acesso proibido (RBAC)");
        }

        next();
    };
};
