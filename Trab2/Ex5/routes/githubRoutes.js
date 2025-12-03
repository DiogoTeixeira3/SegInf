const express = require('express');
const router = express.Router();

const { requireAuth } = require('../middleware/authMiddleware');
const githubController = require('../controllers/githubController');

router.get('/', requireAuth, githubController.listRepos);
router.get('/:repo/milestones', requireAuth, githubController.getMilestones);


module.exports = router;
