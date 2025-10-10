const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const authMiddleware = require('../middleware/auth');
const router = express.Router();
const gravatar = require('gravatar');
const multer = require('multer');
const path = require('path');
const webpush = require('web-push');

// Multer for avatar upload with file validation
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'public/uploads/';
    require('fs').mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});

// File filter for images only
const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'), false);
  }
};

const upload = multer({ storage, fileFilter, limits: { fileSize: 5 * 1024 * 1024 } });

// VAPID keys
const vapidEmail = process.env.VAPID_EMAIL || 'your-email@example.com';
webpush.setVapidDetails(
  `mailto:${vapidEmail}`,
  process.env.VAPID_PUBLIC_KEY,
  process.env.VAPID_PRIVATE_KEY
);

// Input sanitization helper
const sanitizeInput = (str) => str ? str.trim().toLowerCase().replace(/[<>\"'&]/g, '') : '';

// Register
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    const cleanUsername = sanitizeInput(username);
    const cleanEmail = sanitizeInput(email);
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    const existingUser = await User.findOne({ 
      $or: [
        { username: { $regex: new RegExp(`^${cleanUsername}$`, 'i') } },
        { email: { $regex: new RegExp(`^${cleanEmail}$`, 'i') } }
      ] 
    });
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    const user = new User({ username: cleanUsername, email: cleanEmail, password });
    await user.save();
    const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.status(201).json({ 
      token, 
      user: { 
        id: user._id, 
        username: user.username, 
        email: user.email,
        avatar: gravatar.url(cleanEmail, { s: '200', r: 'pg', d: 'mm' })
      } 
    });
  } catch (error) {
    console.error('Register error:', error.message, { stack: error.stack });
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    const cleanEmail = sanitizeInput(email);
    const user = await User.findOne({ email: { $regex: new RegExp(`^${cleanEmail}$`, 'i') } });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ 
      token, 
      user: { 
        id: user._id, 
        username: user.username, 
        email: user.email,
        avatar: user.avatar || gravatar.url(cleanEmail, { s: '200', r: 'pg', d: 'mm' })
      } 
    });
  } catch (error) {
    console.error('Login error:', error.message, { stack: error.stack });
    res.status(500).json({ error: 'Failed to login' });
  }
});

// Get profile
router.get('/profile/:id', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    await user.safePopulate(['alerts']);
    user.activeAlerts = user.alerts?.filter(alert => alert.expiry > new Date())?.length || 0;
    user.totalAlerts = user.alerts?.length || 0;
    res.json(user);
  } catch (error) {
    console.error('Profile fetch error:', error.message, { stack: error.stack });
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update avatar
router.post('/upload-avatar', authMiddleware, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded or invalid file type' });
    }
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.avatar = `/uploads/${req.file.filename}`;
    await user.save();
    res.json({ avatar: user.avatar });
  } catch (error) {
    console.error('Avatar upload error:', error.message, { stack: error.stack });
    if (req.file) require('fs').unlinkSync(req.file.path);
    res.status(500).json({ error: 'Failed to upload avatar' });
  }
});

// Subscribe to push
router.post('/subscribe', authMiddleware, async (req, res) => {
  try {
    const { endpoint, keys } = req.body;
    if (!endpoint || !keys || !keys.p256dh || !keys.auth) {
      return res.status(400).json({ error: 'Invalid subscription data' });
    }
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.pushSubscription = req.body;
    await user.save();
    res.status(201).json({ message: 'Subscribed successfully' });
  } catch (error) {
    console.error('Push subscription error:', error.message, { stack: error.stack });
    res.status(500).json({ error: 'Failed to subscribe' });
  }
});

// Refresh token
router.post('/refresh', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
  } catch (error) {
    console.error('Token refresh error:', error.message, { stack: error.stack });
    res.status(500).json({ error: 'Failed to refresh token' });
  }
});

module.exports = router;