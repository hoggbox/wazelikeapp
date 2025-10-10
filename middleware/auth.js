const jwt = require('jsonwebtoken');
const User = require('../models/User');

module.exports = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      console.error('No token provided in auth middleware');
      return res.status(401).json({ error: 'No token provided' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    if (!decoded.id) {
      console.error('Invalid token payload: missing id');
      return res.status(401).json({ error: 'Invalid token payload' });
    }
    const user = await User.findById(decoded.id);
    if (!user) {
      console.error('User not found for id:', decoded.id);
      return res.status(401).json({ error: 'User not found' });
    }
    if (user.isBanned) {
      console.error('Banned user attempted access:', decoded.id);
      return res.status(401).json({ error: 'User is banned' });
    }
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error.message, error.stack);
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Authentication failed', details: error.message });
  }
};