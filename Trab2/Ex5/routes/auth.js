// routes/auth.js

const express = require('express');
const FormData = require('form-data');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const sessionStore = require('../stores/sessionStore'); // vamos criar já a seguir

require('dotenv').config(); // para usar CLIENT_ID e CLIENT_SECRET do .env

const router = express.Router();

const PORT = 8080;
const CALLBACK = 'callback';

// 1) Rota de Login → redireciona para Google
router.get('/login', (req, res) => {

    const redirectURL =
        'https://accounts.google.com/o/oauth2/v2/auth?' +
        'client_id=' + process.env.CLIENT_ID + '&' +
        'response_type=code&' +
        'scope=openid%20email%20profile&' +
        'redirect_uri=http://localhost:' + PORT + '/auth/' + CALLBACK + '&' +
        'state=random_state_123';

    res.redirect(302, redirectURL);
});


// 2) Rota /callback → recebe ?code=...
router.get('/' + CALLBACK, async (req, res) => {

    const code = req.query.code;

    if (!code) {
        return res.status(400).send("Erro: sem authorization code");
    }

    // Preparar pedido POST para trocar code → tokens
    const form = new FormData();
    form.append('code', code);
    form.append('client_id', process.env.CLIENT_ID);
    form.append('client_secret', process.env.CLIENT_SECRET);
    form.append('redirect_uri', 'http://localhost:' + PORT + '/auth/' + CALLBACK);
    form.append('grant_type', 'authorization_code');

    try {
        // Token endpoint Google
        const tokenResponse = await axios.post(
            'https://www.googleapis.com/oauth2/v3/token',
            form,
            { headers: form.getHeaders() }
        );

        const tokens = tokenResponse.data;

        // Decodificar ID Token (jwt)
        const payload = jwt.decode(tokens.id_token);

        // Criar sessão para este utilizador
        const sessionId = cryptoRandom();
        sessionStore.set(sessionId, {
            email: payload.email,
            name: payload.name,
            picture: payload.picture,
            googleAccessToken: tokens.access_token,
            role: "free" // default — depois mudamos com RBAC
        });

        // Enviar cookie
        res.cookie("session-id", sessionId, {
            httpOnly: true,
            maxAge: 1000 * 60 * 30, // 30 min
        });

        // Redirecionar para home
        res.redirect('/');

    } catch (err) {
        console.error(err);
        res.status(500).send("Erro ao autenticar com Google");
    }
});

// gerar ID random simples (tu podes melhorar isto)
function cryptoRandom() {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

module.exports = router;
