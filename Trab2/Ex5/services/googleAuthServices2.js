const axios = require('axios');
const FormData = require('form-data');
const jwt = require('jsonwebtoken');

const PORT = 8080;

exports.exchangeCodeForTokens = async (code) => {
    const form = new FormData();
    form.append('code', code);
    form.append('client_id', process.env.CLIENT_ID);
    form.append('client_secret', process.env.CLIENT_SECRET);
    form.append('redirect_uri', 'http://localhost:' + PORT + '/auth/callback');
    form.append('grant_type', 'authorization_code');

    const tokenResponse = await axios.post(
        'https://www.googleapis.com/oauth2/v3/token',
        form,
        { headers: form.getHeaders() }
    );

    return tokenResponse.data;
};

exports.decodeIdToken = (id_token) => {
    return jwt.decode(id_token);
};
