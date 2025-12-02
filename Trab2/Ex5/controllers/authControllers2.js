//TODO: relying-party-demo.js -> Equivalente do Stor



const { exchangeCodeForTokens, decodeIdToken } = require('../services/googleAuthService');
const sessionStore = require('../stores/sessionStore');

function cryptoRandom() {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

const PORT = 8080;

exports.login = (req, res) => {

    const redirectURL =
        'https://accounts.google.com/o/oauth2/v2/auth?' +
        'client_id=' + process.env.CLIENT_ID + '&' +
        'response_type=code&' +
        'scope=openid%20email%20profile&' +
        'redirect_uri=http://localhost:' + PORT + '/auth/callback&' +
        'state=xyz';

    res.redirect(302, redirectURL);
};

exports.callback = async (req, res) => {
    const code = req.query.code;
    if (!code) return res.status(400).send("Erro: sem authorization code");

    try {
        const tokens = await exchangeCodeForTokens(code);
        const payload = decodeIdToken(tokens.id_token);

        const sessionId = cryptoRandom();
        sessionStore.set(sessionId, {
            email: payload.email,
            name: payload.name,
            picture: payload.picture,
            googleAccessToken: tokens.access_token,
            role: "free"
        });

        res.cookie("session-id", sessionId, {
            httpOnly: true,
            maxAge: 1000 * 60 * 30
        });

        res.redirect('/');

    } catch (err) {
        console.error(err);
        res.status(500).send("Erro no callback Google");
    }
};
