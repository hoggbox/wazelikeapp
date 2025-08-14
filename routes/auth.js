const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ msg: 'No token provided' });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('Token verification error:', err.message);
      return res.status(403).json({ msg: 'Invalid token' });
    }
    req.user = decoded;
    console.log('Authenticated user:', req.user.username);
    next();
  });
};

// Check Username and Email Availability
router.post('/check-availability', async (req, res) => {
  const { username, email } = req.body;
  try {
    console.log('Availability check:', { username, email });
    const trimmedUsername = username?.trim().toLowerCase();
    const trimmedEmail = email?.trim().toLowerCase();
    const errors = {};

    if (!trimmedUsername && !trimmedEmail) {
      console.log('No username or email provided');
      return res.status(400).json({ msg: 'Username or email required' });
    }

    if (trimmedUsername) {
      const userByUsername = await User.findOne({ username: trimmedUsername });
      if (userByUsername) errors.username = 'Username already taken';
    }
    if (trimmedEmail) {
      const userByEmail = await User.findOne({ email: trimmedEmail });
      if (userByEmail) errors.email = 'Email already in use';
    }

    if (Object.keys(errors).length > 0) {
      console.log('Availability check failed:', errors);
      return res.status(400).json({ msg: 'Validation failed', errors });
    }
    console.log('Availability check passed');
    res.json({ available: true });
  } catch (err) {
    console.error('Availability check error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Register User
router.post('/register', async (req, res) => {
  const { username, password, email, name, age, dob, location } = req.body;
  try {
    console.log('Register request:', { username, email, passwordLength: password?.length, name, age, dob, location });
    console.log('Raw password received:', password); // Temporary debug log
    const trimmedUsername = username?.trim().toLowerCase();
    const trimmedEmail = email?.trim().toLowerCase();
    const trimmedPassword = password?.trim();
    if (!trimmedUsername || !trimmedPassword || !trimmedEmail) {
      console.log('Missing required fields');
      return res.status(400).json({ msg: 'Username, password, and email are required' });
    }
    if (!/^[a-z0-9_]{3,20}$/.test(trimmedUsername)) {
      console.log('Invalid username format:', trimmedUsername);
      return res.status(400).json({ msg: 'Username must be 3-20 characters, letters, numbers, or underscores' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      console.log('Invalid email format:', trimmedEmail);
      return res.status(400).json({ msg: 'Invalid email format' });
    }
    if (trimmedPassword.length < 8) {
      console.log('Password too short:', trimmedPassword.length);
      return res.status(400).json({ msg: 'Password must be at least 8 characters' });
    }

    const existingUser = await User.findOne({ $or: [{ username: trimmedUsername }, { email: trimmedEmail }] });
    if (existingUser) {
      console.log('User already exists:', { username: existingUser.username, email: existingUser.email });
      return res.status(400).json({
        msg: 'User already exists',
        errors: {
          username: existingUser.username === trimmedUsername ? 'Username already taken' : undefined,
          email: existingUser.email === trimmedEmail ? 'Email already in use' : undefined
        }
      });
    }

    console.log('Hashing password:', trimmedPassword);
    const hashedPassword = await bcrypt.hash(trimmedPassword, 10);
    console.log('Hashed password:', hashedPassword);
    const user = new User({
      username: trimmedUsername,
      password: hashedPassword,
      email: trimmedEmail,
      name: name?.trim() || '',
      age: parseInt(age) || 0,
      dob: dob ? new Date(dob) : null,
      location: location?.trim() || ''
    });
    await user.save();
    console.log('User registered:', trimmedUsername, 'email:', trimmedEmail, 'ID:', user._id);

    const token = jwt.sign({ username: trimmedUsername }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ username: trimmedUsername }, process.env.REFRESH_SECRET || process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, refreshToken, username: user.username, userId: user._id });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Login User
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('Login request:', { username, passwordLength: password?.length });
  console.log('Raw password received:', password); // Temporary debug log
  try {
    if (!username || !password) {
      console.log('Missing username or password');
      return res.status(400).json({ msg: 'Username or email and password are required' });
    }
    const trimmedUsername = username.trim().toLowerCase();
    const trimmedPassword = password.trim();
    console.log('Querying user with:', { $or: [{ username: trimmedUsername }, { email: trimmedUsername }] });
    const user = await User.findOne({ $or: [{ username: trimmedUsername }, { email: trimmedUsername }] });
    if (!user) {
      console.log('User not found:', trimmedUsername);
      return res.status(400).json({ msg: 'Invalid credentials' });
    }
    console.log('Found user:', user.username, 'email:', user.email, 'ID:', user._id);
    console.log('Comparing password:', { input: trimmedPassword, storedHash: user.password });
    const isMatch = await bcrypt.compare(trimmedPassword, user.password);
    if (!isMatch) {
      console.log('Password mismatch for user:', user.username, 'Input length:', trimmedPassword.length);
      return res.status(400).json({ msg: 'Invalid credentials' });
    }
    console.log('Login successful for user:', user.username);
    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ username: user.username }, process.env.REFRESH_SECRET || process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, refreshToken, username: user.username, userId: user._id });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Reset Password
router.post('/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;
  try {
    console.log('Password reset request for email:', email);
    console.log('Raw new password received:', newPassword); // Temporary debug log
    if (!email || !newPassword) {
      console.log('Missing email or new password');
      return res.status(400).json({ msg: 'Email and new password are required' });
    }
    if (newPassword.length < 8) {
      console.log('New password too short:', newPassword.length);
      return res.status(400).json({ msg: 'New password must be at least 8 characters' });
    }
    const trimmedEmail = email.trim().toLowerCase();
    const trimmedNewPassword = newPassword.trim();
    const user = await User.findOne({ email: trimmedEmail });
    if (!user) {
      console.log('User not found for email:', trimmedEmail);
      return res.status(400).json({ msg: 'User not found' });
    }
    console.log('Hashing new password:', trimmedNewPassword);
    const hashedPassword = await bcrypt.hash(trimmedNewPassword, 10);
    console.log('Hashed new password:', hashedPassword);
    user.password = hashedPassword;
    await user.save();
    console.log('Password reset successful for user:', user.username);
    res.json({ msg: 'Password reset successful' });
  } catch (err) {
    console.error('Password reset error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Refresh Token
router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    console.log('No refresh token provided');
    return res.status(400).json({ msg: 'No refresh token provided' });
  }
  jwt.verify(refreshToken, process.env.REFRESH_SECRET || process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Refresh token verification error:', err.message);
      return res.status(403).json({ msg: 'Invalid refresh token' });
    }
    const newAccessToken = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token: newAccessToken });
  });
});

// Get User Profile
router.get('/user/:username', authenticateToken, async (req, res) => {
  try {
    if (req.params.username !== req.user.username) {
      console.log('Forbidden access:', req.params.username, 'by:', req.user.username);
      return res.status(403).json({ msg: 'Forbidden' });
    }
    const user = await User.findOne({ username: req.params.username }).select('-password');
    if (!user) {
      console.log('User not found:', req.params.username);
      return res.status(404).json({ msg: 'User not found' });
    }
    res.json({
      username: user.username,
      email: user.email,
      name: user.name,
      age: user.age,
      dob: user.dob,
      location: user.location,
      _id: user._id,
      lastUsernameChange: user.lastUsernameChange
    });
  } catch (err) {
    console.error('User fetch error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

module.exports = router;