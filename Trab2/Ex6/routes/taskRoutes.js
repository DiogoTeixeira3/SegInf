const express = require('express');
const router = express.Router();

const { requireAuth } = require('../middleware/authMiddleware');
const taskController = require('../controllers/taskController');
const authorize = require("../middleware/authorize");


// ---- PREMIUM: Página criar nova lista ----
router.get(
    '/lists/new',
    requireAuth,
    authorize("lists", "create"),
    taskController.renderCreateList
);

// ---- PREMIUM: Criar nova lista ----
router.post(
    '/lists/create',
    requireAuth,
    authorize("lists", "create"),
    taskController.createTaskList
);

// ---- PREMIUM: Continuar após selecionar/criar lista ----
router.post(
    '/select-list',
    requireAuth,
    authorize("lists", "select"),
    taskController.renderSelectList
);

router.post(
    '/select-list/action',
    requireAuth,
    authorize("lists", "select"),
    taskController.handleSelectList
);

// ---- REGULAR + PREMIUM: Criar task ----
router.post(
    '/create',
    requireAuth,
    authorize("tasks", "create"),
    taskController.createTask
);

// (Esta rota GET provavelmente nem devia existir, mas se existir:)
router.get(
    '/create',
    requireAuth,
    authorize("tasks", "create"),
    taskController.createTask
);

module.exports = router;
