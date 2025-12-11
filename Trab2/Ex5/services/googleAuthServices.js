// services/googleAuthService.js

const axios = require('axios');
const FormData = require('form-data');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT;

// Função que troca o authorization code pelos tokens
exports.exchangeCodeForTokens = async function (code) {

    const form = new FormData();
    form.append('code', code);
    form.append('client_id', process.env.CLIENT_ID);
    form.append('client_secret', process.env.CLIENT_SECRET);
    form.append('redirect_uri', `http://localhost:${PORT}/auth/callback`);
    form.append('grant_type', 'authorization_code');

    const response = await axios.post(
        'https://www.googleapis.com/oauth2/v3/token',
        form,
        { headers: form.getHeaders() }
    );

    return response.data;
};

// Função que decodifica o id_token (JWT)
exports.decodeIdToken = function (id_token) {
    return jwt.decode(id_token);
};
