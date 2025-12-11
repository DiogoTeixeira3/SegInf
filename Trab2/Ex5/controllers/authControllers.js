const sessionStore = require('../stores/sessionStore');
const { exchangeCodeForTokens, decodeIdToken } = require('../services/googleAuthServices');

const axios = require('axios');

function randomId() {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
}
const PORT = process.env.PORT;

exports.login = (req, res) => {

    const redirectURL =
        'https://accounts.google.com/o/oauth2/v2/auth?' +
        'client_id=' + process.env.CLIENT_ID + '&' +
        'response_type=code&' +
        'scope=openid%20email%20profile%20https://www.googleapis.com/auth/tasks&' +
        'redirect_uri=http://localhost:' + PORT + '/auth/callback&' +
        'state=xyz123';

    res.redirect(302, redirectURL);
};

exports.callback = async (req, res) => {
    const code = req.query.code;
    if (!code) return res.status(400).send("missing code");

    try {
        const tokens = await exchangeCodeForTokens(code);
        // Ir buscar name + picture ao endpoint userinfo
        const userInfo = await axios.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            {
                headers: {
                    Authorization: `Bearer ${tokens.access_token}`
                }
            }
        );

        const sid = randomId();

        sessionStore.set(sid, {
            email: userInfo.data.email,
            name: userInfo.data.name,
            picture: userInfo.data.picture,
            googleAccessToken: tokens.access_token,
            role: "free"   // papel inicial
        });

        res.cookie("session-id", sid, {
            httpOnly: true,
            maxAge: 1000 * 60 * 30 // 30 min
        });

        res.redirect('/');

    } catch (err) {
        console.error(err);
        res.status(500).send("Erro no callback Google");
    }
};

exports.logout = (req, res) => {
    const sid = req.cookies["session-id"];

    if (sid) {
        // remover sessão do store
        sessionStore.delete(sid);
    }

    // apagar cookie
    res.clearCookie("session-id");

    // voltar para home
    res.redirect('/');
};
