const axios = require('axios');

const GITHUB_USER = "MiguelMPinto"; // <-- usa o teu username real

exports.listRepos = async (req, res) => {
    const user = req.user;

    try {
        // API pública do GitHub
        const response = await axios.get(
            `https://api.github.com/users/${GITHUB_USER}/repos`
        );

        const repos = response.data.map(repo => ({
            name: repo.name,
            private: repo.private
        }));

        res.render('github', { user, repos });

    } catch (err) {
        console.error("GitHub error:", err);
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

    if (!query) {
        return res.render("github", { user: req.user, repos: [] });
    }

    try {
        const response = await axios.get(
            `https://api.github.com/search/repositories?q=${encodeURIComponent(query)}`
        );

        const repos = response.data.items || [];

        res.render("github", {
            user: req.user,
            repos
        });

    } catch (err) {
        console.error("Erro ao pesquisar repositórios:", err?.response?.data || err);
        res.status(500).send("Erro ao pesquisar repositórios");
    }
};

