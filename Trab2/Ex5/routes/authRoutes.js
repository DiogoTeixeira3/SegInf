//TODO: http_server.js -> Equivalente stor


const express = require('express');
const { login, callback, logout } = require('../controllers/authControllers');

const router = express.Router();

router.get('/login', login);
router.get('/callback', callback);
router.get('/logout', logout);

module.exports = router;
