const express = require('express');
const router = express.Router();

const { requireAuth } = require('../middleware/authMiddleware');
const taskController = require('../controllers/taskController');


// ---- PREMIUM: Página criar nova lista ----
router.get('/lists/new', requireAuth, taskController.renderCreateList);

// ---- PREMIUM: Criar nova lista ----
router.post('/lists/create', requireAuth, taskController.createTaskList);

// ---- PREMIUM: Continuar após selecionar/criar lista ----
router.post('/select-list', requireAuth, taskController.renderSelectList);
router.post('/select-list/action', requireAuth, taskController.handleSelectList);


// ---- REGULAR + PREMIUM: Criar task ----
router.post('/create', requireAuth, taskController.createTask);
router.get('/create', requireAuth, taskController.createTask);

module.exports = router;
