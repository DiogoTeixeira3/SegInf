const express = require("express");
const router = express.Router();
const githubAuthController = require("../controllers/githubAuthController");

router.get("/login", githubAuthController.login);
router.get("/callback", githubAuthController.callback);

module.exports = router;
