const jwt = require('jsonwebtoken');
const User = require('../models/User');

module.exports = async (req, res, next) => {
  try {
    let token = req.header('Authorization');
    console.log('Received Authorization header:', token); // Log for debugging
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    token = token.replace('Bearer ', '').trim(); // Trim extra spaces
    if (!token || typeof token !== 'string' || !token.includes('.')) {
      console.error('Invalid token format:', token);
      return res.status(401).json({ error: 'Invalid token format' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error.message, 'Token:', token);
    res.status(401).json({ error: 'Authentication failed: ' + error.message });
  }
};