require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const turf = require('@turf/turf');
const winston = require('winston');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const authRoutes = require('./routes/auth');
const friendsRoutes = require('./routes/friends');
const leaderboardRoutes = require('./routes/leaderboard');
const authMiddleware = require('./middleware/auth');
const webpush = require('web-push');
const fs = require('fs');
const path = require('path');

// Create uploads directory if it doesn't exist
fs.mkdirSync(path.join(__dirname, 'public/uploads'), { recursive: true });

const app = express();
const PORT = process.env.PORT || 3000;

// Configure Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Middleware
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? 'https://wazelikeapp.onrender.com'
    : ['http://localhost:3000', 'https://wazelikeapp.onrender.com'],
  methods: ['GET', 'POST', 'DELETE'],
  credentials: true
}));
app.use(express.json());

// MongoDB Alert Schema with GeoJSON and TTL
const alertSchema = new mongoose.Schema({
  type: { 
    type: String, 
    required: true,
    enum: ['Slowdown', 'Crash', 'Construction', 'Police', 'Object on Road', 'Lane Closure', 'Manual Report', 'Low Visibility', 'Traffic Camera']
  },
  location: {
    type: {
      type: String,
      enum: ['Point'],
      required: true
    },
    coordinates: {
      type: [Number], // [longitude, latitude]
      required: true
    }
  },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  timestamp: { type: Date, default: Date.now, expires: parseInt(process.env.ALERT_TTL_SECONDS || 3600) },
  address: { type: String }
});

// Ensure 2dsphere index for geospatial queries
alertSchema.index({ location: '2dsphere' });
const Alert = mongoose.model('Alert', alertSchema);

// Connect to MongoDB Atlas with reconnection logic
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  maxPoolSize: 10,
  retryWrites: true,
  retryReads: true
}).then(() => {
  logger.info('Connected to MongoDB Atlas (pinmap database)');
}).catch(err => {
  logger.error('MongoDB connection error:', err);
  setTimeout(() => mongoose.connect(process.env.MONGODB_URI, mongoose.connectOptions), 5000);
});

mongoose.connection.on('error', err => {
  logger.error('MongoDB error:', err);
});
mongoose.connection.on('disconnected', () => {
  logger.warn('MongoDB disconnected, attempting to reconnect...');
  setTimeout(() => mongoose.connect(process.env.MONGODB_URI, mongoose.connectOptions), 5000);
});

// Serve static files from /public
app.use(express.static('public'));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/friends', friendsRoutes);
app.use('/api/leaderboard', leaderboardRoutes);

// Health check endpoint for Render
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK' });
});

// Basic route for the homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

// Refresh token endpoint
app.post('/api/auth/refresh', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
  } catch (error) {
    logger.error('Token refresh error:', error.message);
    res.status(500).json({ error: 'Failed to refresh token: ' + error.message });
  }
});

// Save alerts
app.post('/api/alerts', authMiddleware, async (req, res) => {
  try {
    const { type, location, timestamp, address } = req.body;
    if (!type || !location || !location.coordinates || !timestamp) {
      logger.warn('Invalid alert data received:', req.body);
      return res.status(400).json({ error: 'Invalid alert data: type, location, and timestamp are required' });
    }
    if (!Array.isArray(location.coordinates) || location.coordinates.length !== 2) {
      logger.warn('Invalid coordinates format:', location);
      return res.status(400).json({ error: 'Invalid coordinates format: must be [longitude, latitude]' });
    }
    const [lng, lat] = location.coordinates;
    if (isNaN(lng) || isNaN(lat) || lng < -180 || lng > 180 || lat < -90 || lat > 90) {
      logger.warn('Invalid coordinates values:', location.coordinates);
      return res.status(400).json({ error: 'Invalid longitude or latitude values' });
    }
    const alert = new Alert({
      type,
      location,
      userId: req.user._id,
      timestamp,
      address
    });
    await alert.save();
    const populatedAlert = await Alert.findById(alert._id).populate('userId', 'username');
    logger.info('Alert saved:', { type, userId: req.user._id, location });
    io.emit('alert', populatedAlert);
    res.status(201).json({ alert: populatedAlert });
  } catch (error) {
    logger.error('Error saving alert:', error.message);
    res.status(500).json({ error: 'Failed to save alert: ' + error.message });
  }
});

// Delete alert
app.delete('/api/alerts/:id', authMiddleware, async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.id);
    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    if (alert.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Unauthorized to delete this alert' });
    }
    await alert.deleteOne();
    logger.info('Alert deleted:', req.params.id);
    io.emit('alertDeleted', req.params.id);
    res.status(200).json({ message: 'Alert deleted' });
  } catch (error) {
    logger.error('Error deleting alert:', error.message);
    res.status(500).json({ error: 'Failed to delete alert: ' + error.message });
  }
});

// Fetch markers near a location
app.get('/api/markers', async (req, res) => {
  try {
    const { lat, lng, maxDistance, type } = req.query;
    if (!lat || !lng || !maxDistance) {
      return res.status(400).json({ error: 'Missing required parameters: lat, lng, maxDistance' });
    }
    const query = {
      location: {
        $near: {
          $geometry: { type: 'Point', coordinates: [parseFloat(lng), parseFloat(lat)] },
          $maxDistance: parseFloat(maxDistance)
        }
      }
    };
    if (type && type !== 'all') {
      query.type = type;
    }
    const markers = await Alert.find(query).populate('userId', 'username');
    logger.info(`Fetched ${markers.length} markers for lat:${lat}, lng:${lng}, maxDistance:${maxDistance}, type:${type || 'all'}`);
    res.json(markers);
  } catch (error) {
    logger.error('Error fetching markers:', error.message);
    res.status(500).json({ error: 'Failed to fetch markers: ' + error.message });
  }
});

// Fetch hazards near a route
app.post('/api/hazards-near-route', authMiddleware, async (req, res) => {
  try {
    const { polyline, maxDistance } = req.body;
    if (!polyline || !Array.isArray(polyline) || !maxDistance) {
      return res.status(400).json({ error: 'Invalid request: polyline and maxDistance required' });
    }
    const lineString = turf.lineString(polyline);
    const buffered = turf.buffer(lineString, maxDistance / 1000, { units: 'kilometers' });
    const hazards = await Alert.find({
      type: { $ne: 'Traffic Camera' },
      location: {
        $geoWithin: {
          $geometry: buffered.geometry
        }
      }
    }).populate('userId', 'username');
    logger.info(`Fetched ${hazards.length} hazards near route, polylineLength:${polyline.length}`);
    res.json(hazards);
  } catch (error) {
    logger.error('Error fetching hazards near route:', error.message);
    res.status(500).json({ error: 'Failed to fetch hazards: ' + error.message });
  }
});

// Socket.IO setup
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production'
      ? 'https://wazelikeapp.onrender.com'
      : ['http://localhost:3000', 'https://wazelikeapp.onrender.com'],
    methods: ['GET', 'POST'],
    credentials: true
  }
});

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error: No token provided'));
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.user = decoded;
    next();
  } catch (error) {
    next(new Error('Authentication error: Invalid token'));
  }
});

io.on('connection', (socket) => {
  logger.info(`User connected via Socket.IO: ${socket.user.id}`);
  socket.on('locationUpdate', async (data) => {
    if (data.location) {
      socket.broadcast.emit('userLocation', {
        userId: socket.user.id,
        location: data.location
      });
    }
  });
  socket.on('disconnect', () => {
    logger.info(`User disconnected: ${socket.user.id}`);
  });
});

server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});