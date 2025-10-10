const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const router = express.Router();

router.post('/register', async (req, res) => {
  try {
    const { username, email, password, firstName, lastName, birthdate, sex, location } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      email,
      password: hashedPassword,
      firstName,
      lastName,
      birthdate: birthdate ? new Date(birthdate) : undefined,
      sex,
      location,
      lastLocation: null,
      joinDate: new Date(),
      isAdmin: email === 'imhoggbox@gmail.com'
    });
    await user.save();
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '15m' });
    res.status(201).json({ token, user: { id: user._id, username, email, isAdmin: user.isAdmin } });
  } catch (error) {
    console.error('Registration error:', error);
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    res.status(500).json({ error: 'Registration failed', details: error.message });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || user.isBanned) {
      console.error('Login failed:', { email, reason: !user ? 'User not found' : 'User banned' });
      return res.status(401).json({ error: 'Invalid credentials or user banned' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.error('Login failed: Password mismatch for', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '15m' });
    res.json({ token, user: { id: user._id, username: user.username, email: user.email, isAdmin: user.isAdmin } });
  } catch (error) {
    console.error('Login error:', error.message, error.stack);
    res.status(500).json({ error: 'Login failed', details: error.message });
  }
});

router.post('/refresh', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret', { ignoreExpiration: true });
    const user = await User.findById(decoded.id);
    if (!user || user.isBanned) {
      console.error('Refresh failed:', { id: decoded.id, reason: !user ? 'User not found' : 'User banned' });
      return res.status(401).json({ error: 'Invalid or banned user' });
    }
    const newToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '15m' });
    res.json({ token: newToken });
  } catch (error) {
    console.error('Token refresh error:', error.message, error.stack);
    res.status(401).json({ error: 'Token refresh failed', details: error.message });
  }
});

router.get('/profile/:id', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    const targetUser = await User.findById(req.params.id).select(
      'username email firstName lastName birthdate sex location joinDate totalAlerts activeAlerts points achievements isAdmin'
    );
    if (!targetUser) return res.status(404).json({ error: 'User not found' });
    const currentUser = await User.findById(decoded.id).select('isAdmin');
    if (decoded.id !== req.params.id && !currentUser.isAdmin) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    res.json(targetUser);
  } catch (error) {
    console.error('Profile fetch error:', error.message, error.stack);
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to fetch profile', details: error.message });
  }
});

router.put('/profile', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    const updates = {};
    if (req.body.username) updates.username = req.body.username;
    if (req.body.email) updates.email = req.body.email;
    if (req.body.password) updates.password = await bcrypt.hash(req.body.password, 10);
    if (req.body.firstName) updates.firstName = req.body.firstName;
    if (req.body.lastName) updates.lastName = req.body.lastName;
    if (req.body.birthdate) updates.birthdate = new Date(req.body.birthdate);
    if (req.body.sex) updates.sex = req.body.sex;
    if (req.body.location) updates.location = req.body.location;
    const user = await User.findByIdAndUpdate(decoded.id, updates, { new: true });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (error) {
    console.error('Profile update error:', error.message, error.stack);
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to update profile', details: error.message });
  }
});

router.post('/subscribe', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret', { ignoreExpiration: true });
    const user = await User.findByIdAndUpdate(
      decoded.id,
      { pushSubscription: req.body },
      { new: true }
    );
    if (!user) {
      console.error('User not found for subscription:', decoded.id);
      return res.status(404).json({ error: 'User not found' });
    }
    if (user.isBanned) {
      console.error('Banned user attempted subscription:', decoded.id);
      return res.status(401).json({ error: 'User is banned' });
    }
    console.log('Subscribed to notifications for user:', decoded.id);
    res.json({ message: 'Subscribed to notifications' });
  } catch (error) {
    console.error('Subscription error:', error.message, error.stack);
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to subscribe', details: error.message });
  }
});

router.post('/unsubscribe', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret', { ignoreExpiration: true });
    const user = await User.findByIdAndUpdate(
      decoded.id,
      { pushSubscription: null },
      { new: true }
    );
    if (!user) {
      console.error('User not found for unsubscription:', decoded.id);
      return res.status(404).json({ error: 'User not found' });
    }
    if (user.isBanned) {
      console.error('Banned user attempted unsubscription:', decoded.id);
      return res.status(401).json({ error: 'User is banned' });
    }
    console.log('Unsubscribed from notifications for user:', decoded.id);
    res.json({ message: 'Unsubscribed from notifications' });
  } catch (error) {
    console.error('Unsubscription error:', error.message, error.stack);
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to unsubscribe', details: error.message });
  }
});

module.exports = router;