const axios = require("axios");
const sessionStore = require('../stores/sessionStore');


/* ------------------------------------------------------------
   1) Página SELECT-LIST (escolher ou criar lista)
   ------------------------------------------------------------ */
exports.renderSelectList = async (req, res) => {
    console.log("TEMP SESSION BEFORE:", req.tempSession);
    console.log("BODY FROM MILESTONE:", req.body);

    const sid = req.cookies["session-id"];
    const user = sessionStore.get(sid);

    // 1) Dados vindos do POST da página milestones
    const { repo, title, due } = req.body;

    // 2) Guardar na sessão temporária
    req.tempSession.repo = repo;
    req.tempSession.title = title;
    req.tempSession.due = due;
    req.saveTempSession();

    console.log("TEMP SESSION AFTER:", req.tempSession);

    // 3) Buscar listas do Google Tasks
    const response = await axios.get(
        "https://tasks.googleapis.com/tasks/v1/users/@me/lists",
        {
            headers: {
                Authorization: `Bearer ${user.googleAccessToken}`,
                "Content-Type": "application/json"
            }
        }
    );

    const lists = response.data.items || [];

    // 4) Renderizar página select-list
    res.render("selectList", {
        user,
        repo,
        title,
        due,
        lists
    });
};


/* ------------------------------------------------------------
   2) Página NEW LIST (form para criar lista nova)
   ------------------------------------------------------------ */
exports.renderCreateList = (req, res) => {
    const { repo, title, due } = req.query;

    res.render("newList", {
        user: req.user,
        repo,
        title,
        due
    });
};

/* ------------------------------------------------------------
   3) Criar lista nova no Google Tasks
   ------------------------------------------------------------ */
exports.createTaskList = async (req, res) => {
    const { repo, title, due, listName } = req.body;

    // guardar na sessão
    req.session.repo = repo;
    req.session.title = title;
    req.session.due = due;

    const response = await axios.post(
        "https://tasks.googleapis.com/tasks/v1/users/@me/lists",
        { title: listName },
        {
            headers: {
                Authorization: `Bearer ${req.user.googleAccessToken}`,
                "Content-Type": "application/json"
            }
        }
    );

    const newList = response.data;

    req.session.selectedList = newList.id;

    req.tempSession.repo = repo;
    req.tempSession.title = title;
    req.tempSession.due = due;
    req.tempSession.selected = newList.id;
    req.saveTempSession();

    res.redirect("/tasks/select-list");

};


/* ------------------------------------------------------------
   4) Handler da página select-list:
      - usar lista existente
      - ou criar lista nova
   ------------------------------------------------------------ */
exports.handleSelectList = async (req, res) => {
    // Dados guardados anteriormente

    const { repo, title, due } = req.tempSession;

    // Dados enviados pelo formulário
    const { existingListId, newListName, action } = req.body;

    // 1) Usar lista existente
    if (action === "use-existing") {
        req.tempSession.listId = existingListId;
        req.saveTempSession();
        return res.redirect("/tasks/create");
    }

    console.log("BODY:", req.body);

    // 2) Criar lista nova
    if (action === "create-new") {

        const response = await axios.post(
            "https://tasks.googleapis.com/tasks/v1/users/@me/lists",
            { title: newListName },
            {
                headers: {
                    Authorization: `Bearer ${req.user.googleAccessToken}`,
                    "Content-Type": "application/json"
                }
            }
        );

        const newListId = response.data.id;

        // Guardar a lista nova na sessão temporária
        req.tempSession.listId = newListId;
        req.saveTempSession();

        return res.redirect("/tasks/create");
    }

    res.status(400).send("Ação inválida");
};

/* ------------------------------------------------------------
   5) Criar Task (regular e premium)
   ------------------------------------------------------------ */
exports.createTask = async (req, res) => {
    const user = req.user;

    const repo = req.tempSession.repo;
    const title = req.tempSession.title;
    const due = req.tempSession.due;
    const listId = req.tempSession.listId || "@default";
    const parsedDue = due ? new Date(due).toISOString() : null;

    try {
        const response = await axios.post(
            `https://tasks.googleapis.com/tasks/v1/lists/${listId}/tasks`,
            {
                title,
                notes: `Gerado automaticamente a partir da milestone do repo ${repo}`,
                ...(parsedDue ? { due: parsedDue } : {})
            },
            {
                headers: {
                    Authorization: `Bearer ${user.googleAccessToken}`,
                    "Content-Type": "application/json"
                }
            }
        );

        res.render("taskSuccess", {
            user,
            task: response.data
        });

    } catch (err) {
        console.error("Erro Google Tasks:", err?.response?.data || err);
        res.status(500).send("Erro ao criar tarefa no Google Tasks");
    }
};
