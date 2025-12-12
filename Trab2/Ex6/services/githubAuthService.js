const axios = require("axios");

exports.getAuthUrl = () => {
    return (
        "https://github.com/login/oauth/authorize" +
        `?client_id=${process.env.GITHUB_CLIENT_ID}` +
        "&scope=repo"
    );
};

exports.exchangeCodeForToken = async (code) => {
    const res = await axios.post(
        "https://github.com/login/oauth/access_token",
        {
            client_id: process.env.GITHUB_CLIENT_ID,
            client_secret: process.env.GITHUB_CLIENT_SECRET,
            code,
        },
        { headers: { Accept: "application/json" } }
    );

    return res.data.access_token;
};
