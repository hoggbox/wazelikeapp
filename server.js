require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const turf = require('@turf/turf');
const winston = require('winston');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const authRoutes = require('./routes/auth');
const friendsRoutes = require('./routes/friends');
const leaderboardRoutes = require('./routes/leaderboard');
const authMiddleware = require('./middleware/auth');
const webpush = require('web-push');
const fs = require('fs');
const path = require('path');
const User = require('./models/User');

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
  timestamp: { type: Date, default: Date.now, expires: 3600 },
  address: { type: String }
});

// Ensure 2dsphere index for geospatial queries
alertSchema.index({ location: '2dsphere' });

const Alert = mongoose.model('Alert', alertSchema);

// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  maxPoolSize: 10,
  retryWrites: true,
  retryReads: true
})
  .then(() => logger.info('Connected to MongoDB Atlas (pinmap database)'))
  .catch(err => logger.error('MongoDB connection error:', err));

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
  res.sendFile(__dirname + '/public/index.html');
});

// Refresh token endpoint
app.post('/api/auth/refresh', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
  } catch (error) {
    logger.error('Token refresh error:', error);
    res.status(500).json({ error: 'Failed to refresh token' });
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
    logger.info('Alert saved:', { type, userId: req.user._id, location });
    io.emit('alert', alert); // Broadcast to all connected clients
    res.status(201).json({ alert });
  } catch (error) {
    logger.error('Error saving alert:', error.message);
    res.status(500).json({ error: 'Failed to save alert: ' + error.message });
  }
});

// Delete alerts
app.delete('/api/alerts/:id', authMiddleware, async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.id);
    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    if (alert.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Unauthorized to delete this alert' });
    }
    await Alert.deleteOne({ _id: req.params.id });
    logger.info('Alert deleted:', req.params.id);
    io.emit('alertDeleted', req.params.id);
    res.status(200).json({ message: 'Alert deleted' });
  } catch (error) {
    logger.error('Error deleting alert:', error);
    res.status(500).json({ error: 'Failed to delete alert' });
  }
});

// Fetch nearby markers
app.get('/api/markers', async (req, res) => {
  try {
    const { lat, lng, maxDistance, type } = req.query;
    if (!lat || !lng || !maxDistance) {
      return res.status(400).json({ error: 'Missing required query parameters: lat, lng, maxDistance' });
    }
    const query = {
      location: {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: [parseFloat(lng), parseFloat(lat)]
          },
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
    logger.error('Error fetching markers:', error);
    res.status(500).json({ error: 'Failed to fetch markers' });
  }
});

// Fetch hazards near route
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
    logger.info(`Fetched ${hazards.length} hazards near route:`, { polylineLength: polyline.length });
    res.json(hazards);
  } catch (error) {
    logger.error('Error fetching hazards near route:', error.message);
    res.status(500).json({ error: 'Failed to fetch hazards: ' + error.message });
  }
});

// Create HTTP server and Socket.IO
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
    socket.userId = decoded.id;
    next();
  } catch (error) {
    next(new Error('Authentication error: Invalid token'));
  }
});

io.on('connection', (socket) => {
  logger.info('User connected via Socket.IO:', socket.userId);
  socket.on('locationUpdate', async (data) => {
    try {
      const user = await User.findById(socket.userId);
      if (!user) {
        logger.warn('User not found for location update:', socket.userId);
        return;
      }
      socket.broadcast.emit('locationUpdate', { userId: socket.userId, username: user.username, location: data.location });
    } catch (error) {
      logger.error('Error processing location update:', error);
    }
  });
  socket.on('disconnect', () => {
    logger.info('User disconnected:', socket.userId);
  });
});

// Start server
server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});