const express = require('express');
const authMiddleware = require('../middleware/auth');
const User = require('../models/User');
const router = express.Router();

router.get('/', authMiddleware, async (req, res) => {
  try {
    const users = await User.find().select('username points achievements').sort('-points').limit(10).lean();
    res.json(users);
  } catch (error) {
    console.error('Leaderboard error:', error);
    res.status(500).json({ error: 'Failed to fetch leaderboard: ' + error.message });
  }
});

module.exports = router;