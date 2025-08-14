const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'X7k9pLm2nQv8jRx4yZw5tUv3iOy6pAq1';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'Y8m2qZn3pKw9jSx5zAx6uTv4iPy7rBq2';

// Register
router.post('/register', async (req, res) => {
  const { name, username, email, password, age, dob, location } = req.body;
  console.log('Register request:', { name, username, email, password: '[provided]', age, dob, location });
  try {
    let user = await User.findOne({ $or: [{ username }, { email }] });
    if (user) {
      console.log('User already exists:', { username, email });
      return res.status(400).json({ msg: 'User already exists' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    user = new User({ name, username, email, password: hashedPassword, age, dob, location });
    await user.save();
    console.log('User registered:', { username: user.username, email: user.email, id: user._id });
    const token = jwt.sign({ _id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ _id: user._id, username: user.username }, REFRESH_SECRET, { expiresIn: '7d' });
    res.json({ token, refreshToken, username: user.username, userId: user._id });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('Login request received:', { username, password: '[provided]' });
  try {
    const user = await User.findOne({ $or: [{ username }, { email: username }] });
    if (!user) {
      console.log('User not found:', username);
      return res.status(400).json({ msg: 'Invalid credentials' });
    }
    console.log('Found user:', { username: user.username, email: user.email, id: user._id });
    const isMatch = await bcrypt.compare(password, user.password);
    console.log('Password comparison:', { input: '[provided]', storedHash: user.password, isMatch });
    if (!isMatch) {
      console.log('Password mismatch for user:', user.username);
      return res.status(400).json({ msg: 'Invalid credentials' });
    }
    console.log('Login successful for user:', user.username);
    const token = jwt.sign({ _id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ _id: user._id, username: user.username }, REFRESH_SECRET, { expiresIn: '7d' });
    res.json({ token, refreshToken, username: user.username, userId: user._id });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Refresh Token
router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  console.log('Refresh token request:', { refreshToken: refreshToken ? '[provided]' : 'none' });
  if (!refreshToken) {
    console.log('No refresh token provided');
    return res.status(401).json({ msg: 'No refresh token provided' });
  }
  try {
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    console.log('Refresh token decoded:', { userId: decoded._id, username: decoded.username });
    const user = await User.findById(decoded._id);
    if (!user) {
      console.log('User not found for refresh token:', decoded._id);
      return res.status(403).json({ msg: 'Invalid refresh token' });
    }
    const token = jwt.sign({ _id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    console.log('New access token generated for user:', user.username);
    res.json({ token });
  } catch (err) {
    console.error('Refresh token error:', err.message);
    res.status(403).json({ msg: 'Invalid refresh token' });
  }
});

// Get User Profile
router.get('/user/:username', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) {
      console.log('User not found:', req.params.username);
      return res.status(404).json({ msg: 'User not found' });
    }
    console.log('Fetched user profile:', { username: user.username, id: user._id });
    res.json({
      _id: user._id,
      name: user.name,
      username: user.username,
      email: user.email,
      age: user.age,
      dob: user.dob,
      location: user.location,
      lastUsernameChange: user.lastUsernameChange
    });
  } catch (err) {
    console.error('Fetch user error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Update Profile
router.post('/update', authenticateToken, async (req, res) => {
  const { name, username, email, age, dob, location } = req.body;
  console.log('Update profile request:', { name, username, email, age, dob, location });
  try {
    let user = await User.findById(req.user._id);
    if (!user) {
      console.log('User not found for update:', req.user._id);
      return res.status(404).json({ msg: 'User not found' });
    }
    if (username !== user.username) {
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        console.log('Username already taken:', username);
        return res.status(400).json({ msg: 'Username already taken' });
      }
      if (user.lastUsernameChange) {
        const threeMonthsAgo = new Date();
        threeMonthsAgo.setMonth(threeMonthsAgo.getMonth() - 3);
        if (new Date(user.lastUsernameChange) > threeMonthsAgo) {
          console.log('Username change limit exceeded for:', user.username);
          return res.status(400).json({ msg: 'Username can only be changed once every 3 months' });
        }
      }
      user.lastUsernameChange = new Date();
    }
    user.name = name || user.name;
    user.username = username || user.username;
    user.email = email || user.email;
    user.age = age || user.age;
    user.dob = dob || user.dob;
    user.location = location || user.location;
    await user.save();
    console.log('Profile updated:', { username: user.username, id: user._id });
    res.json({
      _id: user._id,
      name: user.name,
      username: user.username,
      email: user.email,
      age: user.age,
      dob: user.dob,
      location: user.location,
      lastUsernameChange: user.lastUsernameChange
    });
  } catch (err) {
    console.error('Update profile error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Check Username Availability
router.post('/check-availability', async (req, res) => {
  const { username } = req.body;
  console.log('Checking username availability:', username);
  try {
    const user = await User.findOne({ username });
    if (user) {
      console.log('Username taken:', username);
      return res.json({ available: false });
    }
    console.log('Username available:', username);
    res.json({ available: true });
  } catch (err) {
    console.error('Check availability error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  console.log('Authenticating token:', token ? '[provided]' : 'none');
  if (!token) {
    console.log('No token provided in request');
    return res.status(401).json({ msg: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('Token authenticated:', { userId: decoded._id, username: decoded.username });
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Token verification failed:', err.message);
    res.status(403).json({ msg: 'Invalid token' });
  }
}

module.exports = router;