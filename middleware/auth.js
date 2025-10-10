const jwt = require('jsonwebtoken');
const User = require('../models/User');

module.exports = async (req, res, next) => {
  try {
    let token = req.get('Authorization'); // Use req.get for consistency
    console.log('Received Authorization header:', token ? `Bearer [${token.length} chars]` : 'None'); // Redacted logging for security
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    token = token.replace('Bearer ', '').trim(); // Trim extra spaces
    if (!token || typeof token !== 'string' || !token.includes('.')) {
      console.error('Invalid token format:', token ? `[${token.length} chars]` : 'null');
      return res.status(401).json({ error: 'Invalid token format' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).lean(); // .lean() for faster query (plain JS object)
    if (!user) {
      console.error('User not found for token');
      return res.status(401).json({ error: 'User not found' });
    }
    // Check for ban (from updated User model)
    if (user.isBanned) {
      console.error('Banned user attempted access:', user._id);
      return res.status(403).json({ error: 'Account banned' });
    }
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error.message, { 
      name: error.name, 
      stack: error.stack,
      tokenLength: token ? token.length : 'undefined' // Fix scope: log length only
    });
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Token expired', 
        message: 'Please refresh your token or log in again' 
      });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token signature' });
    }
    res.status(401).json({ error: 'Authentication failed: ' + error.message });
  }
};