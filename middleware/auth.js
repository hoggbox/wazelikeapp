// middleware/auth.js (Corrected: Using require() for CommonJS compatibility)
const jwt = require('jsonwebtoken');
const User = require('../models/User');

module.exports = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      console.error('No token provided in auth middleware', {
        userAgent: req.get('User-Agent'),
        ip: req.ip,
        path: req.path
      });
      return res.status(401).json({ error: 'No token provided' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret'); // Remove fallback in prod
    if (!decoded.id) {
      console.error('Invalid token payload: missing id', {
        userAgent: req.get('User-Agent'),
        ip: req.ip,
        path: req.path
      });
      return res.status(401).json({ error: 'Invalid token payload' });
    }
    const user = await User.findById(decoded.id);
    if (!user) {
      console.error('User not found for id:', decoded.id, {
        userAgent: req.get('User-Agent'),
        ip: req.ip,
        path: req.path
      });
      return res.status(401).json({ error: 'User not found' });
    }
    if (user.isBanned) {
      console.error('Banned user attempted access:', decoded.id, {
        userAgent: req.get('User-Agent'),
        ip: req.ip,
        path: req.path
      });
      return res.status(401).json({ error: 'User is banned' });
    }
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    console.error('Auth middleware error:', {
      message: error.message,
      stack: error.stack,
      userAgent: req.get('User-Agent'),
      ip: req.ip,
      path: req.path
    });
    const status = error.name === 'TokenExpiredError' ? 401 : (error.name === 'JsonWebTokenError' ? 401 : 500);
    res.status(status).json({ 
      error: 'Authentication failed', 
      details: status === 401 ? 'Token invalid or expired' : error.message 
    });
  }
};