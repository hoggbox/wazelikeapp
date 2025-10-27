// middleware/auth.js
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose'); // Added mongoose import to fix ReferenceError
const User = require('../models/User');

module.exports = async (req, res, next) => {
  try {
    // Extract token from Authorization header or Socket.IO handshake
    let token;
    if (req.header) {
      token = req.header('Authorization')?.replace('Bearer ', '').trim();
    } else if (req.handshake && req.handshake.auth && req.handshake.auth.token) {
      token = req.handshake.auth.token.trim();
    }

    if (!token || token === 'undefined' || !token.includes('.')) {
      console.error('No valid token provided', {
        userAgent: req.get ? req.get('User-Agent') : req.handshake?.headers['user-agent'],
        ip: req.ip || req.handshake?.address,
        path: req.path || req.handshake?.url,
        source: req.header ? 'HTTP' : 'Socket.IO'
      });
      if (res) {
        return res.status(401).json({ error: 'No token provided', details: 'Authentication required' });
      }
      throw new Error('No token provided');
    }

    // Verify JWT
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret'); // Replace fallback in prod
    if (!decoded.id || !mongoose.Types.ObjectId.isValid(decoded.id)) {
      console.error('Invalid token payload: missing or invalid id', {
        decoded,
        userAgent: req.get ? req.get('User-Agent') : req.handshake?.headers['user-agent'],
        ip: req.ip || req.handshake?.address,
        path: req.path || req.handshake?.url
      });
      if (res) {
        return res.status(401).json({ error: 'Invalid token payload', details: 'Token missing user ID' });
      }
      throw new Error('Invalid token payload');
    }

    // Check MongoDB connection before querying
    if (mongoose.connection.readyState !== 1) {
      console.error('MongoDB not connected:', {
        readyState: mongoose.connection.readyState,
        path: req.path || req.handshake?.url
      });
      if (res) {
        return res.status(503).json({ error: 'Database unavailable', details: 'MongoDB connection not established' });
      }
      throw new Error('Database unavailable');
    }

    // Fetch user with necessary fields
    const user = await User.findById(decoded.id).select(
      '_id username email isAdmin isBanned ipBanned familyMembers offlineRegions totalAlerts activeAlerts points lastLocation lastActive'
    );
    if (!user) {
      console.error('User not found for id:', decoded.id, {
        userAgent: req.get ? req.get('User-Agent') : req.handshake?.headers['user-agent'],
        ip: req.ip || req.handshake?.address,
        path: req.path || req.handshake?.url
      });
      if (res) {
        return res.status(401).json({ error: 'User not found', details: 'Account does not exist' });
      }
      throw new Error('User not found');
    }

    // Check for bans
    if (user.isBanned) {
      console.error('Banned user attempted access:', decoded.id, {
        userAgent: req.get ? req.get('User-Agent') : req.handshake?.headers['user-agent'],
        ip: req.ip || req.handshake?.address,
        path: req.path || req.handshake?.url
      });
      if (res) {
        return res.status(401).json({ error: 'User is banned', details: 'Account access restricted' });
      }
      throw new Error('User is banned');
    }

    // Check for IP ban
    if (user.ipBanned && user.ipBanned === (req.ip || req.handshake?.address)) {
      console.error('IP banned user attempted access:', decoded.id, {
        ip: req.ip || req.handshake?.address,
        path: req.path || req.handshake?.url
      });
      if (res) {
        return res.status(401).json({ error: 'User is IP banned', details: 'Access restricted from this IP' });
      }
      throw new Error('User is IP banned');
    }

    // Attach user and token to request
    req.user = user;
    req.token = token;
    console.log('User authenticated:', {
      userId: user._id,
      username: user.username,
      isAdmin: user.isAdmin,
      path: req.path || req.handshake?.url,
      source: req.header ? 'HTTP' : 'Socket.IO'
    });
    next();
  } catch (error) {
    console.error('Auth middleware error:', {
      message: error.message,
      name: error.name,
      stack: error.stack,
      userAgent: req.get ? req.get('User-Agent') : req.handshake?.headers['user-agent'],
      ip: req.ip || req.handshake?.address,
      path: req.path || req.handshake?.url
    });
    if (res) {
      const status = error.name === 'TokenExpiredError' ? 401 : (error.name === 'JsonWebTokenError' ? 401 : 500);
      res.status(status).json({ 
        error: 'Authentication failed', 
        details: status === 401 ? 'Token invalid or expired' : error.message 
      });
    } else {
      // For Socket.IO, emit error to client
      req.io?.to(req.handshake?.auth?.userId).emit('authError', {
        error: 'Authentication failed',
        details: error.name === 'TokenExpiredError' ? 'Token expired' : error.message
      });
    }
  }
};