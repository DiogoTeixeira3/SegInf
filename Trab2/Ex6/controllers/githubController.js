const axios = require('axios');
const sessionStore = require("../stores/sessionStore");


const GITHUB_USER = "MiguelMPinto"; // <-- usa o teu username real

exports.listRepos = async (req, res) => {
    const user = req.user;   // 👈 FALTAVA ISTO

    const sid = req.cookies["session-id"];
    const session = sessionStore.get(sid);

    const token = session?.githubAccessToken;

    // ainda não ligou GitHub
    if (!token) {
        return res.render("github", {
            user: user,
            repos: [],
            hasGithub: false
        });
    }

    try {
        const response = await axios.get(
            "https://api.github.com/user/repos",
            {
                headers: {
                    Authorization: `Bearer ${token}`,
                    Accept: "application/vnd.github+json"
                }
            }
        );

        const repos = response.data;

        res.render("github", {
            user,
            repos,
            hasGithub: true
        });

    } catch (err) {
        console.error("GitHub error:", err?.response?.data || err);
        res.status(500).send("Erro ao obter repositórios do GitHub");
    }
};

exports.getMilestones = async (req, res) => {
    const user = req.user;
    const repo = req.params.repo;

    try {
        const response = await axios.get(
            `https://api.github.com/repos/${repo}/milestones`
        );

        const milestones = response.data;

        res.render('milestones', { user, repo, milestones });

    } catch (err) {
        console.error("Erro ao obter milestones:", err);
        res.status(500).send("Erro ao obter milestones do GitHub");
    }
};

exports.searchRepos = async (req, res) => {
    const query = req.query.q;

    const sid = req.cookies["session-id"];
    const session = sessionStore.get(sid);
    const token = session?.githubAccessToken;

    if (!query) {
        return res.render("github", {
            user: req.user,
            repos: [],
            hasGithub: !!token
        });
    }

    try {
        const response = await axios.get(
            `https://api.github.com/search/repositories?q=${encodeURIComponent(query)}`,
            token
                ? { headers: { Authorization: `Bearer ${token}` } }
                : {}
        );

        const repos = response.data.items || [];

        res.render("github", {
            user: req.user,
            repos,
            hasGithub: !!token
        });

    } catch (err) {
        console.error("Erro ao pesquisar repositórios:", err?.response?.data || err);
        res.status(500).send("Erro ao pesquisar repositórios");
    }
};

