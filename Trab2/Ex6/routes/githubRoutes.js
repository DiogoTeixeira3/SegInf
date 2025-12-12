const express = require('express');
const router = express.Router();

const { requireAuth } = require('../middleware/authMiddleware');
const githubController = require('../controllers/githubController');
const authorize = require("../middleware/authorize");


// Ver repositórios (free, regular, premium podem ver)
router.get(
    '/',
    requireAuth,
    authorize("milestones", "read"),
    githubController.listRepos
);

router.get(
    '/search',
    requireAuth,
    authorize("milestones", "read"),
    githubController.searchRepos
);


// Ver milestones (free, regular, premium podem ver)
router.get(
    '/:repo/milestones',
    requireAuth,
    authorize("milestones", "read"),
    githubController.getMilestones
);

module.exports = router;
