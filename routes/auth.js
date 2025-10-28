const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const User = require('../models/User');
const router = express.Router();

// Register
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, firstName, lastName, birthdate, sex, location } = req.body;
    console.log('Register attempt:', { username, email });

    // Validate input
    if (!username || !email || !password) {
      console.error('Missing required fields:', { username, email, password });
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }
    if (!/^\S+@\S+\.\S+$/.test(email)) {
      console.error('Invalid email format:', email);
      return res.status(400).json({ error: 'Invalid email format' });
    }
    if (password.length < 6) {
      console.error('Password too short:', { length: password.length });
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      console.error('MongoDB not connected:', { readyState: mongoose.connection.readyState });
      return res.status(503).json({ error: 'Database unavailable' });
    }

    // Check for existing user
    const existingUser = await User.findOne({ $or: [{ email: email.toLowerCase() }, { username: username.trim() }] });
    if (existingUser) {
      console.error('Duplicate user:', { email, username, existing: existingUser.email });
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    // Create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username: username.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      firstName: firstName?.trim(),
      lastName: lastName?.trim(),
      birthdate: birthdate ? new Date(birthdate) : undefined,
      sex: sex && ['Male', 'Female', 'Other'].includes(sex) ? sex : undefined,
      location: location?.trim(),
      joinDate: new Date(),
      isAdmin: email.toLowerCase() === 'imhoggbox@gmail.com',
      familyMembers: [],
      offlineRegions: [],
      subscriptions: [],
      totalAlerts: 0,
      activeAlerts: 0,
      points: 0,
      achievements: [],
      subscriptionStatus: 'trial',
      trialEndsAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });

    await user.save();
    console.log('User registered:', { userId: user._id, username, email });

    // Generate token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '15m' });
    res.status(201).json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin,
        totalAlerts: user.totalAlerts,
        activeAlerts: user.activeAlerts,
        points: user.points,
        joinDate: user.joinDate,
        familyMembers: user.familyMembers,
        offlineRegions: user.offlineRegions,
        firstName: user.firstName,
        lastName: user.lastName,
        birthdate: user.birthdate,
        sex: user.sex,
        location: user.location,
        achievements: user.achievements
      }
    });
  } catch (error) {
    console.error('Registration error:', {
      message: error.message,
      stack: error.stack,
      body: req.body
    });
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    res.status(500).json({ error: 'Registration failed', details: error.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('Login attempt:', { email });

    // Validate input
    if (!email || !password) {
      console.error('Missing login credentials:', { email, password });
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Check MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      console.error('MongoDB not connected:', { readyState: mongoose.connection.readyState });
      return res.status(503).json({ error: 'Database unavailable' });
    }

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() }).select(
      '_id username email password isAdmin isBanned totalAlerts activeAlerts points joinDate familyMembers offlineRegions firstName lastName birthdate sex location achievements'
    );
    if (!user || user.isBanned) {
      console.error('Login failed:', { email, reason: !user ? 'User not found' : 'User banned' });
      return res.status(401).json({ error: 'Invalid credentials or user banned' });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.error('Login failed: Password mismatch for', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '15m' });
    console.log('Login successful:', { userId: user._id, username: user.username });
    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin,
        totalAlerts: user.totalAlerts,
        activeAlerts: user.activeAlerts,
        points: user.points,
        joinDate: user.joinDate,
        familyMembers: user.familyMembers,
        offlineRegions: user.offlineRegions,
        firstName: user.firstName,
        lastName: user.lastName,
        birthdate: user.birthdate,
        sex: user.sex,
        location: user.location,
        achievements: user.achievements
      }
    });
  } catch (error) {
    console.error('Login error:', {
      message: error.message,
      stack: error.stack,
      email: req.body.email
    });
    res.status(500).json({ error: 'Login failed', details: error.message });
  }
});

// Token Refresh
router.post('/refresh', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1]?.trim();
    if (!token || token === 'undefined' || !token.includes('.')) {
      console.error('No valid token provided for refresh');
      return res.status(401).json({ error: 'No token provided', details: 'Authentication required' });
    }

    // Check MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      console.error('MongoDB not connected:', { readyState: mongoose.connection.readyState });
      return res.status(503).json({ error: 'Database unavailable' });
    }

    // Verify token (ignoring expiration for refresh)
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret', { ignoreExpiration: true });
    if (!decoded.id || !mongoose.Types.ObjectId.isValid(decoded.id)) {
      console.error('Invalid token payload for refresh:', decoded);
      return res.status(401).json({ error: 'Invalid token payload', details: 'Token missing user ID' });
    }

    // Find user
    const user = await User.findById(decoded.id).select(
      '_id username email isAdmin isBanned totalAlerts activeAlerts points joinDate familyMembers offlineRegions firstName lastName birthdate sex location achievements'
    );
    if (!user || user.isBanned) {
      console.error('Refresh failed:', { id: decoded.id, reason: !user ? 'User not found' : 'User banned' });
      return res.status(401).json({ error: 'Invalid or banned user', details: 'Authentication required' });
    }

    // Generate new token
    const newToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '15m' });
    console.log('Token refreshed for user:', { userId: user._id, username: user.username });
    res.json({
      token: newToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin,
        totalAlerts: user.totalAlerts,
        activeAlerts: user.activeAlerts,
        points: user.points,
        joinDate: user.joinDate,
        familyMembers: user.familyMembers,
        offlineRegions: user.offlineRegions,
        firstName: user.firstName,
        lastName: user.lastName,
        birthdate: user.birthdate,
        sex: user.sex,
        location: user.location,
        achievements: user.achievements
      }
    });
  } catch (error) {
    console.error('Token refresh error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(error.name === 'JsonWebTokenError' ? 401 : 500).json({
      error: 'Token refresh failed',
      details: error.name === 'JsonWebTokenError' ? 'Invalid token' : error.message
    });
  }
});

// Get Profile
router.get('/profile/:id', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1]?.trim();
    if (!token || token === 'undefined' || !token.includes('.')) {
      console.error('No valid token provided for profile fetch:', { id: req.params.id });
      return res.status(401).json({ error: 'No token provided', details: 'Authentication required' });
    }

    // Check MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      console.error('MongoDB not connected:', { readyState: mongoose.connection.readyState });
      return res.status(503).json({ error: 'Database unavailable' });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    if (!decoded.id || !mongoose.Types.ObjectId.isValid(decoded.id)) {
      console.error('Invalid token payload for profile fetch:', decoded);
      return res.status(401).json({ error: 'Invalid token payload', details: 'Token missing user ID' });
    }

    // Check authorization
    const currentUser = await User.findById(decoded.id).select('isAdmin');
    if (!currentUser) {
      console.error('Current user not found:', decoded.id);
      return res.status(401).json({ error: 'User not found', details: 'Authentication required' });
    }
    if (decoded.id !== req.params.id && !currentUser.isAdmin) {
      console.error('Unauthorized profile access:', { requesterId: decoded.id, targetId: req.params.id });
      return res.status(403).json({ error: 'Unauthorized', details: 'Cannot access other user profiles' });
    }

    // Fetch target user
    const targetUser = await User.findById(req.params.id).select(
      'username email firstName lastName birthdate sex location joinDate totalAlerts activeAlerts points achievements isAdmin familyMembers offlineRegions'
    );
    if (!targetUser) {
      console.error('Target user not found:', req.params.id);
      return res.status(404).json({ error: 'User not found' });
    }

    console.log('Profile fetched:', { userId: targetUser._id, username: targetUser.username });
    res.json({
      id: targetUser._id,
      username: targetUser.username,
      email: targetUser.email,
      firstName: targetUser.firstName,
      lastName: targetUser.lastName,
      birthdate: targetUser.birthdate,
      sex: targetUser.sex,
      location: targetUser.location,
      joinDate: targetUser.joinDate,
      totalAlerts: targetUser.totalAlerts || 0,
      activeAlerts: targetUser.activeAlerts || 0,
      points: targetUser.points || 0,
      achievements: targetUser.achievements || [],
      isAdmin: targetUser.isAdmin,
      familyMembers: targetUser.familyMembers || [],
      offlineRegions: targetUser.offlineRegions || []
    });
  } catch (error) {
    console.error('Profile fetch error:', {
      message: error.message,
      stack: error.stack,
      targetId: req.params.id
    });
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({
      error: 'Failed to fetch profile',
      details: error.name === 'TokenExpiredError' ? 'Token expired' : error.message
    });
  }
});

// Update Profile
router.put('/profile', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1]?.trim();
    if (!token || token === 'undefined' || !token.includes('.')) {
      console.error('No valid token provided for profile update');
      return res.status(401).json({ error: 'No token provided', details: 'Authentication required' });
    }

    // Check MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      console.error('MongoDB not connected:', { readyState: mongoose.connection.readyState });
      return res.status(503).json({ error: 'Database unavailable' });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    if (!decoded.id || !mongoose.Types.ObjectId.isValid(decoded.id)) {
      console.error('Invalid token payload for profile update:', decoded);
      return res.status(401).json({ error: 'Invalid token payload', details: 'Token missing user ID' });
    }

    // Validate updates
    const updates = {};
    if (req.body.username) updates.username = req.body.username.trim();
    if (req.body.email) {
      if (!/^\S+@\S+\.\S+$/.test(req.body.email)) {
        console.error('Invalid email format for update:', req.body.email);
        return res.status(400).json({ error: 'Invalid email format' });
      }
      updates.email = req.body.email.toLowerCase().trim();
    }
    if (req.body.password) {
      if (req.body.password.length < 6) {
        console.error('Password too short for update:', { length: req.body.password.length });
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
      }
      updates.password = await bcrypt.hash(req.body.password, 10);
    }
    if (req.body.firstName) updates.firstName = req.body.firstName.trim();
    if (req.body.lastName) updates.lastName = req.body.lastName.trim();
    if (req.body.birthdate) updates.birthdate = new Date(req.body.birthdate);
    if (req.body.sex && ['Male', 'Female', 'Other'].includes(req.body.sex)) updates.sex = req.body.sex;
    if (req.body.location) updates.location = req.body.location.trim();

    // Check for duplicate username or email
    if (updates.username || updates.email) {
      const existingUser = await User.findOne({
        $or: [
          updates.username ? { username: updates.username } : {},
          updates.email ? { email: updates.email } : {}
        ],
        _id: { $ne: decoded.id }
      });
      if (existingUser) {
        console.error('Duplicate username or email for update:', { username: updates.username, email: updates.email });
        return res.status(400).json({ error: 'Username or email already exists' });
      }
    }

    // Update user
    const user = await User.findByIdAndUpdate(decoded.id, updates, {
      new: true,
      runValidators: true
    }).select(
      'username email firstName lastName birthdate sex location joinDate totalAlerts activeAlerts points achievements isAdmin familyMembers offlineRegions'
    );
    if (!user) {
      console.error('User not found for update:', decoded.id);
      return res.status(404).json({ error: 'User not found' });
    }

    console.log('Profile updated:', { userId: user._id, username: user.username });
    res.json({
      id: user._id,
      username: user.username,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      birthdate: user.birthdate,
      sex: user.sex,
      location: user.location,
      joinDate: user.joinDate,
      totalAlerts: user.totalAlerts || 0,
      activeAlerts: user.activeAlerts || 0,
      points: user.points || 0,
      achievements: user.achievements || [],
      isAdmin: user.isAdmin,
      familyMembers: user.familyMembers || [],
      offlineRegions: user.offlineRegions || []
    });
  } catch (error) {
    console.error('Profile update error:', {
      message: error.message,
      stack: error.stack,
      userId: decoded?.id
    });
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({
      error: 'Failed to update profile',
      details: error.name === 'TokenExpiredError' ? 'Token expired' : error.message
    });
  }
});

// Subscribe to Push Notifications
router.post('/subscribe', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1]?.trim();
    if (!token || token === 'undefined' || !token.includes('.')) {
      console.error('No valid token provided for subscription');
      return res.status(401).json({ error: 'No token provided', details: 'Authentication required' });
    }

    // Check MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      console.error('MongoDB not connected:', { readyState: mongoose.connection.readyState });
      return res.status(503).json({ error: 'Database unavailable' });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    if (!decoded.id || !mongoose.Types.ObjectId.isValid(decoded.id)) {
      console.error('Invalid token payload for subscription:', decoded);
      return res.status(401).json({ error: 'Invalid token payload', details: 'Token missing user ID' });
    }

    // Validate subscription
    const subscription = req.body;
    if (!subscription || !subscription.endpoint || !subscription.keys) {
      console.error('Invalid subscription data:', subscription);
      return res.status(400).json({ error: 'Invalid subscription data' });
    }

    // Find user
    const user = await User.findById(decoded.id);
    if (!user) {
      console.error('User not found for subscription:', decoded.id);
      return res.status(404).json({ error: 'User not found' });
    }
    if (user.isBanned) {
      console.error('Banned user attempted subscription:', decoded.id);
      return res.status(401).json({ error: 'User is banned', details: 'Cannot subscribe to notifications' });
    }

    // Add subscription if not already present
    if (!user.subscriptions) user.subscriptions = [];
    const existingSub = user.subscriptions.find(sub => sub.endpoint === subscription.endpoint);
    if (!existingSub) {
      user.subscriptions.push(subscription);
      await user.save();
      console.log('Subscribed to notifications:', { userId: user._id, endpoint: subscription.endpoint });
    } else {
      console.log('Subscription already exists:', { userId: user._id, endpoint: subscription.endpoint });
    }

    res.json({ message: 'Subscribed to notifications' });
  } catch (error) {
    console.error('Subscription error:', {
      message: error.message,
      stack: error.stack,
      userId: decoded?.id
    });
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({
      error: 'Failed to subscribe',
      details: error.name === 'TokenExpiredError' ? 'Token expired' : error.message
    });
  }
});

// Unsubscribe from Push Notifications
router.post('/unsubscribe', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1]?.trim();
    if (!token || token === 'undefined' || !token.includes('.')) {
      console.error('No valid token provided for unsubscription');
      return res.status(401).json({ error: 'No token provided', details: 'Authentication required' });
    }

    // Check MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      console.error('MongoDB not connected:', { readyState: mongoose.connection.readyState });
      return res.status(503).json({ error: 'Database unavailable' });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    if (!decoded.id || !mongoose.Types.ObjectId.isValid(decoded.id)) {
      console.error('Invalid token payload for unsubscription:', decoded);
      return res.status(401).json({ error: 'Invalid token payload', details: 'Token missing user ID' });
    }

    // Validate subscription
    const subscription = req.body;
    if (!subscription || !subscription.endpoint) {
      console.error('Invalid subscription data for unsubscription:', subscription);
      return res.status(400).json({ error: 'Invalid subscription data' });
    }

    // Find user
    const user = await User.findById(decoded.id);
    if (!user) {
      console.error('User not found for unsubscription:', decoded.id);
      return res.status(404).json({ error: 'User not found' });
    }
    if (user.isBanned) {
      console.error('Banned user attempted unsubscription:', decoded.id);
      return res.status(401).json({ error: 'User is banned', details: 'Cannot unsubscribe from notifications' });
    }

    // Remove subscription
    if (user.subscriptions) {
      user.subscriptions = user.subscriptions.filter(sub => sub.endpoint !== subscription.endpoint);
      await user.save();
      console.log('Unsubscribed from notifications:', { userId: user._id, endpoint: subscription.endpoint });
    } else {
      console.log('No subscriptions to remove:', { userId: user._id });
    }

    res.json({ message: 'Unsubscribed from notifications' });
  } catch (error) {
    console.error('Unsubscription error:', {
      message: error.message,
      stack: error.stack,
      userId: decoded?.id
    });
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({
      error: 'Failed to unsubscribe',
      details: error.name === 'TokenExpiredError' ? 'Token expired' : error.message
    });
  }
});

module.exports = router;