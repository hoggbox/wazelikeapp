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
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
  } catch (error) {
    logger.error('Token refresh error:', error);
    res.status(500).json({ error: 'Failed to refresh token' });
  }
});

// Protected API endpoint to save alerts
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
    // Check for existing alerts within MIN_ALERT_DISTANCE (500ft)
    const existingAlerts = await Alert.find({
      location: {
        $near: {
          $geometry: { type: 'Point', coordinates: [lng, lat] },
          $maxDistance: 152.4 // 500ft in meters
        }
      }
    });
    if (existingAlerts.length > 0) {
      return res.status(400).json({ error: 'Alert already exists within 500ft' });
    }
    const alert = new Alert({
      type,
      location: {
        type: 'Point',
        coordinates: [lng, lat]
      },
      userId: req.user.id,
      timestamp: new Date(timestamp),
      address
    });
    await alert.save();
    const user = await User.findById(req.user.id);
    user.points += 10;
    user.contributions.push({ type: 'alert', points: 10 });
    if (user.contributions.length === 1) user.achievements.push('First Alert');
    if (user.contributions.length >= 10) user.achievements.push('Top Contributor');
    await user.save();
    io.emit('alert', alert);
    io.emit('pointsUpdate', { userId: req.user.id, points: user.points });
    if (user.pushSubscription) {
      const payload = JSON.stringify({ title: 'Points Earned', body: `You earned 10 points for posting a ${type} alert! Total: ${user.points}` });
      webpush.sendNotification(user.pushSubscription, payload).catch(err => logger.error('Push notification error:', err));
    }
    logger.info('Alert saved and broadcasted:', alert);
    res.status(201).json({ message: 'Alert saved successfully', alert });
  } catch (error) {
    logger.error('Error saving alert:', error.stack);
    res.status(500).json({ error: `Failed to save alert: ${error.message}` });
  }
});

// API endpoint to retrieve markers within a radius
app.get('/api/markers', async (req, res) => {
  const { lat, lng, maxDistance = 50000, type } = req.query;
  try {
    if (isNaN(parseFloat(lng)) || isNaN(parseFloat(lat))) {
      logger.warn('Invalid latitude or longitude:', { lat, lng });
      return res.status(400).json({ error: 'Invalid latitude or longitude' });
    }
    const query = {
      location: {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: [parseFloat(lng), parseFloat(lat)]
          },
          $maxDistance: parseInt(maxDistance)
        }
      }
    };
    if (type) {
      query.type = type;
    }
    const markers = await Alert.find(query).populate('userId', 'username');
    logger.info(`Fetched ${markers.length} markers for lat:${lat}, lng:${lng}, maxDistance:${maxDistance}, type:${type || 'all'}`);
    res.status(200).json(markers);
  } catch (err) {
    logger.error('Error fetching markers:', err);
    res.status(500).json({ error: err.message });
  }
});

// API endpoint to delete an alert
app.delete('/api/alerts/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const alert = await Alert.findById(id);
    if (!alert) {
      logger.warn(`Alert not found for deletion: ${id}`);
      return res.status(404).json({ error: 'Alert not found' });
    }
    if (alert.userId.toString() !== req.user.id) {
      return res.status(403).json({ error: 'Not authorized to delete this alert' });
    }
    await Alert.findByIdAndDelete(id);
    logger.info('Alert deleted:', id);
    io.emit('alertDeleted', id);
    res.status(200).json({ message: 'Alert deleted successfully' });
  } catch (error) {
    logger.error('Error deleting alert:', error);
    res.status(500).json({ error: 'Failed to delete alert' });
  }
});

// API endpoint to check for hazards near a route polyline
app.post('/api/hazards-near-route', authMiddleware, async (req, res) => {
  const { polyline, maxDistance = 3218.69 } = req.body;
  try {
    // Enhanced polyline validation
    if (!polyline || !Array.isArray(polyline) || polyline.length < 2) {
      logger.warn('Invalid polyline data:', { polyline, length: polyline?.length });
      return res.status(400).json({ error: 'Invalid polyline data: must be an array with at least 2 points' });
    }
    for (const [lng, lat] of polyline) {
      if (isNaN(lng) || isNaN(lat) || lng < -180 || lng > 180 || lat < -90 || lat > 90) {
        logger.warn('Invalid coordinates in polyline:', { lng, lat });
        return res.status(400).json({ error: `Invalid coordinates in polyline: [${lng}, ${lat}]` });
      }
    }
    const routeLineString = turf.lineString(polyline);
    const bufferDistance = maxDistance / 1000;
    let bufferedPolygon = turf.buffer(routeLineString, bufferDistance, { units: 'kilometers' });
    if (bufferedPolygon.geometry.type === 'MultiPolygon') {
      bufferedPolygon = turf.flatten(bufferedPolygon);
      bufferedPolygon = bufferedPolygon.features[0];
    }
    const simplifiedPolygon = turf.simplify(bufferedPolygon, { tolerance: 0.001, highQuality: true });
    if (simplifiedPolygon.geometry.type !== 'Polygon') {
      logger.error('Simplified geometry is not a valid polygon:', { type: simplifiedPolygon.geometry.type });
      return res.status(500).json({ error: 'Failed to generate a valid buffer polygon' });
    }
    logger.info('Searching for hazards intersecting with buffered polygon', { polylinePoints: polyline.length, maxDistance });
    const hazards = await Alert.find({
      location: {
        $geoWithin: {
          $geometry: simplifiedPolygon.geometry
        }
      },
      type: { $ne: 'Traffic Camera' },
      timestamp: { $gte: new Date(Date.now() - 60 * 60 * 1000) }
    }).limit(1).populate('userId', 'username');
    logger.info(`Found ${hazards.length} hazards near route`, { hazardTypes: hazards.map(h => h.type) });
    res.status(200).json(hazards);
  } catch (err) {
    logger.error('Error checking hazards near route:', { error: err.message, stack: err.stack });
    res.status(500).json({ error: err.message });
  }
});

// Placeholder for future server-side route calculation
// app.post('/api/calculate-route', authMiddleware, async (req, res) => {
//   try {
//     const { origin, destination } = req.body;
//     // Implement Google Maps Routes API call here (requires @googlemaps/google-maps-services-js)
//     // Example: Use @googlemaps/google-maps-services-js to call Directions API
//     logger.info('Route calculation requested:', { origin, destination });
//     res.status(501).json({ error: 'Server-side route calculation not implemented' });
//   } catch (error) {
//     logger.error('Error calculating route:', error);
//     res.status(500).json({ error: 'Failed to calculate route' });
//   }
// });

// Create HTTP server and integrate Socket.IO
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

// Socket.IO authentication middleware
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    logger.warn('Socket authentication failed: No token provided');
    return next(new Error('Authentication error: No token provided'));
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.user = decoded;
    next();
  } catch (err) {
    logger.warn('Socket authentication failed: Invalid token', { error: err.message });
    return next(new Error('Authentication error: Invalid token'));
  }
});

// Rate limiting for Socket.IO events
const socketRateLimit = new Map();
const LOCATION_UPDATE_INTERVAL = 1000;
const MAX_UPDATES_PER_MINUTE = 60;

io.on('connection', (socket) => {
  logger.info('User connected:', { userId: socket.user.id });
  socketRateLimit.set(socket.id, { count: 0, resetTime: Date.now() + 60000 });
  Alert.find({ timestamp: { $gte: new Date(Date.now() - 60 * 60 * 1000) } }).populate('userId', 'username')
    .then(alerts => {
      alerts.forEach(alert => socket.emit('alert', alert));
      logger.info('Sent existing alerts to new client:', { userId: socket.user.id, alertCount: alerts.length });
    })
    .catch(err => logger.error('Error fetching alerts for new client:', { error: err.message }));
  socket.on('locationUpdate', (data) => {
    if (!data.location || typeof data.location.lat !== 'number' || typeof data.location.lng !== 'number') {
      logger.warn('Invalid location data from:', { userId: socket.user.id, data });
      return;
    }
    const now = Date.now();
    const rateLimitData = socketRateLimit.get(socket.id);
    if (now > rateLimitData.resetTime) {
      socketRateLimit.set(socket.id, { count: 0, resetTime: now + 60000 });
    }
    if (rateLimitData.count >= MAX_UPDATES_PER_MINUTE) {
      logger.warn('Location update rate limit exceeded for:', { userId: socket.user.id });
      return;
    }
    if (now - rateLimitData.lastUpdate < LOCATION_UPDATE_INTERVAL) {
      return;
    }
    rateLimitData.count++;
    rateLimitData.lastUpdate = now;
    socketRateLimit.set(socket.id, rateLimitData);
    logger.info('Location update from:', { userId: socket.user.id, location: data.location });
    socket.broadcast.emit('locationUpdate', { ...data, userId: socket.user.id });
  });
  socket.on('locationShare', async (data) => {
    const { to, location } = data;
    try {
      const user = await User.findById(socket.user.id).populate('friends', 'username');
      const validFriends = user.friends.filter(f => to.includes(f._id.toString()));
      validFriends.forEach(friend => {
        socket.to(friend._id.toString()).emit('friendLocation', { userId: socket.user.id, location });
      });
      logger.info('Location shared with friends:', { userId: socket.user.id, friends: to });
    } catch (error) {
      logger.error('Error sharing location:', { error: error.message });
    }
  });
  socket.on('friendRequest', async (data) => {
    try {
      const user = await User.findById(socket.user.id);
      socket.to(data.to).emit('friendRequest', { from: user.username, userId: socket.user.id });
      logger.info('Friend request sent:', { from: socket.user.id, to: data.to });
    } catch (error) {
      logger.error('Error broadcasting friend request:', { error: error.message });
    }
  });
  socket.on('friendAccepted', async (data) => {
    try {
      const user = await User.findById(socket.user.id);
      socket.to(data.to).emit('friendAccepted', { from: user.username });
      logger.info('Friend acceptance broadcasted:', { from: socket.user.id, to: data.to });
    } catch (error) {
      logger.error('Error broadcasting friend acceptance:', { error: error.message });
    }
  });
  socket.on('disconnect', () => {
    logger.info('User disconnected:', { userId: socket.user.id });
    socketRateLimit.delete(socket.id);
  });
});

// Start server
server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT} in ${process.env.NODE_ENV} mode with Socket.IO`);
});