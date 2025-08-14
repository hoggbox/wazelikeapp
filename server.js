require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');
const mapRoutes = require('./routes/map');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: [
      'http://127.0.0.1:3000',
      'https://wazelikeapp.onrender.com'
    ],
    methods: ['GET', 'POST'],
    credentials: true
  }
});

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://jhogg39:!Snake1988@cluster0.0uyxp2y.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

// Connect to MongoDB with error handling
const connectWithRetry = () => {
  mongoose.connect(MONGODB_URI, {}).then(() => {
    console.log('MongoDB connected successfully');
  }).catch(err => {
    console.error('MongoDB connection error:', err);
    console.log('Retrying MongoDB connection in 5 seconds...');
    setTimeout(connectWithRetry, 5000);
  });
};
connectWithRetry();

// Middleware
app.use(express.json());
app.use(cors({
  origin: [
    'http://127.0.0.1:3000',
    'https://wazelikeapp.onrender.com'
  ],
  credentials: true
}));

// JWT Middleware for protected routes
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(403).json({ msg: 'Token expired' });
      }
      return res.status(403).json({ msg: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/map', mapRoutes(io));

// Refresh Token Endpoint
app.post('/api/auth/refresh', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ msg: 'No refresh token provided' });

  jwt.verify(refreshToken, process.env.REFRESH_SECRET, (err, user) => {
    if (err) return res.status(403).json({ msg: 'Invalid refresh token', error: err.message });

    const newAccessToken = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token: newAccessToken });
  });
});

// Health check endpoint
app.get('/health', (req, res) => res.json({ status: 'OK' }));

// Serve static files and specific routes
app.use(express.static(path.join(__dirname, 'public')));

// Serve register.html explicitly
app.get('/register.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Fallback for other routes to index.html, excluding API routes
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API route not found' });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Socket.IO Events
io.on('connection', (socket) => {
  console.log('New client connected');
  socket.on('hazard', (data) => io.emit('hazard', data));
  socket.on('detailedAlert', (data) => io.emit('detailedAlert', data));
  socket.on('alert', (data) => io.emit('alert', data));
  socket.on('alertRemoved', (data) => io.emit('alertRemoved', data));
  socket.on('locationUpdate', (data) => io.emit('locationUpdate', data));
  socket.on('disconnect', () => console.log('Client disconnected'));
});

// Error handling for uncaught exceptions
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
});

server.listen(PORT, '0.0.0.0', () => console.log(`Server running on http://0.0.0.0:${PORT}`));