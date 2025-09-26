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

// Configure VAPID keys for web-push
webpush.setVapidDetails(
  'mailto:support@wazelikeapp.com',
  process.env.VAPID_PUBLIC_KEY,
  process.env.VAPID_PRIVATE_KEY
);

// Middleware
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? 'https://wazelikeapp.onrender.com'
    : ['http://localhost:3000', 'https://wazelikeapp.onrender.com'],
  methods: ['GET', 'POST', 'DELETE'],
  credentials: true
}));
app.use(express.json());

// Serve fallback favicon to avoid 404s
app.get('/favicon.ico', (req, res) => {
  res.redirect('https://i.postimg.cc/jjN0JrPZ/New-Project-5.png');
  logger.info('Served fallback favicon.ico');
});

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

// Index for geospatial and userId queries
alertSchema.index({ location: '2dsphere', userId: 1 });
const Alert = mongoose.model('Alert', alertSchema);

// MongoDB Push Subscription Schema
const pushSubscriptionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  endpoint: { type: String, required: true },
  keys: {
    p256dh: { type: String, required: true },
    auth: { type: String, required: true }
  },
  lastLocation: {
    type: {
      type: String,
      enum: ['Point'],
      default: 'Point'
    },
    coordinates: {
      type: [Number], // [longitude, latitude]
      default: [0, 0]
    }
  }
});
pushSubscriptionSchema.index({ userId: 1 });
const PushSubscription = mongoose.model('PushSubscription', pushSubscriptionSchema);

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

// Save push subscription
app.post('/api/auth/subscribe', authMiddleware, async (req, res) => {
  try {
    const subscription = req.body;
    if (!subscription || !subscription.endpoint || !subscription.keys || !subscription.keys.p256dh || !subscription.keys.auth) {
      logger.warn('Invalid subscription data:', subscription);
      return res.status(400).json({ error: 'Invalid subscription data' });
    }
    const existingSubscription = await PushSubscription.findOne({ 
      userId: req.user._id, 
      endpoint: subscription.endpoint 
    });
    let subscriptionId;
    if (!existingSubscription) {
      const newSubscription = new PushSubscription({
        userId: req.user._id,
        endpoint: subscription.endpoint,
        keys: subscription.keys,
        lastLocation: { type: 'Point', coordinates: [0, 0] }
      });
      await newSubscription.save();
      subscriptionId = newSubscription._id;
      await User.findByIdAndUpdate(req.user._id, {
        $addToSet: { pushSubscriptions: newSubscription._id }
      });
      logger.info('Push subscription saved:', { userId: req.user._id, endpoint: subscription.endpoint, subscriptionId });
    } else {
      subscriptionId = existingSubscription._id;
      logger.info('Push subscription already exists:', { userId: req.user._id, endpoint: subscription.endpoint, subscriptionId });
    }
    res.status(201).json({ message: 'Subscription saved', subscriptionId });
  } catch (error) {
    logger.error('Error saving push subscription:', error.message);
    res.status(500).json({ error: 'Failed to save subscription: ' + error.message });
  }
});

// Remove push subscription
app.post('/api/auth/unsubscribe', authMiddleware, async (req, res) => {
  try {
    const subscription = req.body;
    if (!subscription || !subscription.endpoint) {
      logger.warn('Invalid subscription data for unsubscribe:', subscription);
      return res.status(400).json({ error: 'Invalid subscription data' });
    }
    const result = await PushSubscription.deleteOne({ 
      userId: req.user._id, 
      endpoint: subscription.endpoint 
    });
    if (result.deletedCount > 0) {
      await User.findByIdAndUpdate(req.user._id, {
        $pull: { pushSubscriptions: { $in: [result._id] } }
      });
      logger.info('Push subscription removed:', { userId: req.user._id, endpoint: subscription.endpoint });
      res.status(200).json({ message: 'Subscription removed' });
    } else {
      logger.warn('No subscription found to remove:', { userId: req.user._id, endpoint: subscription.endpoint });
      res.status(404).json({ error: 'Subscription not found' });
    }
  } catch (error) {
    logger.error('Error removing push subscription:', error.message);
    res.status(500).json({ error: 'Failed to remove subscription: ' + error.message });
  }
});

// Save alerts and send push notifications
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

    // Send push notifications to nearby subscribed users
    const maxDistance = type === 'Traffic Camera' ? 0.5 * 1609.34 : 2 * 1609.34; // 0.5 miles for cameras, 2 miles for hazards
    const users = await User.find({
      pushSubscriptions: { $exists: true, $ne: [] },
      'lastLocation.coordinates': {
        $near: {
          $geometry: { type: 'Point', coordinates: [lng, lat] },
          $maxDistance: maxDistance
        }
      }
    }).populate('pushSubscriptions');
    const notificationPayload = {
      title: `${type} Alert`,
      body: `${type} reported at ${address || `${lat.toFixed(4)}, ${lng.toFixed(4)}`}`,
      alertId: alert._id
    };
    for (const user of users) {
      for (const sub of user.pushSubscriptions) {
        try {
          await webpush.sendNotification(sub, JSON.stringify(notificationPayload));
          logger.info('Push notification sent:', { userId: user._id, endpoint: sub.endpoint, alertId: alert._id });
        } catch (error) {
          logger.error('Failed to send push notification:', { userId: user._id, endpoint: sub.endpoint, error: error.message });
          if (error.statusCode === 410) {
            await PushSubscription.deleteOne({ _id: sub._id });
            await User.findByIdAndUpdate(user._id, {
              $pull: { pushSubscriptions: sub._id }
            });
            logger.info('Removed expired subscription:', { userId: user._id, endpoint: sub.endpoint });
          }
        }
      }
    }

    io.emit('alert', populatedAlert);
    logger.info(`Emitted alert event for: ${alert._id}`);
    res.status(201).json({ alert: populatedAlert });
  } catch (error) {
    logger.error('Error saving alert:', error.message);
    res.status(500).json({ error: 'Failed to save alert: ' + error.message });
  }
});

// Delete alert and send push notifications
app.delete('/api/alerts/:id', authMiddleware, async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.id);
    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    if (alert.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Unauthorized to delete this alert' });
    }
    let retries = 3;
    let success = false;
    while (retries > 0 && !success) {
      try {
        await alert.deleteOne();
        success = true;
      } catch (err) {
        retries--;
        logger.warn(`MongoDB delete attempt failed for alert ${req.params.id}, retries left: ${retries}`, err);
        if (retries === 0) {
          throw new Error(`MongoDB delete failed after retries: ${err.message}`);
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    logger.info('Alert deleted:', req.params.id);

    // Send push notifications for alert deletion
    const maxDistance = alert.type === 'Traffic Camera' ? 0.5 * 1609.34 : 2 * 1609.34;
    const users = await User.find({
      pushSubscriptions: { $exists: true, $ne: [] },
      'lastLocation.coordinates': {
        $near: {
          $geometry: { type: 'Point', coordinates: alert.location.coordinates },
          $maxDistance: maxDistance
        }
      }
    }).populate('pushSubscriptions');
    const notificationPayload = {
      title: 'Alert Removed',
      body: `Alert at ${alert.address || `${alert.location.coordinates[1].toFixed(4)}, ${alert.location.coordinates[0].toFixed(4)}`} has been removed.`,
      alertId: req.params.id
    };
    for (const user of users) {
      for (const sub of user.pushSubscriptions) {
        try {
          await webpush.sendNotification(sub, JSON.stringify(notificationPayload));
          logger.info('Push notification sent for alert deletion:', { userId: user._id, endpoint: sub.endpoint, alertId: req.params.id });
        } catch (error) {
          logger.error('Failed to send push notification for deletion:', { userId: user._id, endpoint: sub.endpoint, error: error.message });
          if (error.statusCode === 410) {
            await PushSubscription.deleteOne({ _id: sub._id });
            await User.findByIdAndUpdate(user._id, {
              $pull: { pushSubscriptions: sub._id }
            });
            logger.info('Removed expired subscription:', { userId: user._id, endpoint: sub.endpoint });
          }
        }
      }
    }

    io.emit('alertDeleted', req.params.id);
    logger.info(`Emitted alertDeleted for: ${req.params.id}`);
    res.status(200).json({ message: 'Alert deleted' });
  } catch (error) {
    logger.error('Error deleting alert:', error.message);
    res.status(500).json({ error: 'Failed to delete alert: ' + error.message });
  }
});

// Update user location for push notifications
app.post('/api/location', authMiddleware, async (req, res) => {
  try {
    const { location } = req.body;
    if (!location || !Array.isArray(location.coordinates) || location.coordinates.length !== 2) {
      logger.warn('Invalid location data:', req.body);
      return res.status(400).json({ error: 'Invalid location data: coordinates must be [longitude, latitude]' });
    }
    const [lng, lat] = location.coordinates;
    if (isNaN(lng) || isNaN(lat) || lng < -180 || lng > 180 || lat < -90 || lat > 90) {
      logger.warn('Invalid coordinates values:', location.coordinates);
      return res.status(400).json({ error: 'Invalid longitude or latitude values' });
    }
    await PushSubscription.updateMany(
      { userId: req.user._id },
      { lastLocation: { type: 'Point', coordinates: [lng, lat] } }
    );
    await User.findByIdAndUpdate(req.user._id, {
      lastLocation: { type: 'Point', coordinates: [lng, lat] }
    });
    logger.info('User location updated for push subscriptions:', { userId: req.user._id, location });
    res.status(200).json({ message: 'Location updated' });
  } catch (error) {
    logger.error('Error updating user location:', error.message);
    res.status(500).json({ error: 'Failed to update location: ' + error.message });
  }
});

// Fetch markers near a location
app.get('/api/markers', async (req, res) => {
  try {
    const { lat, lng, maxDistance, type } = req.query;
    if (!lat || !lng || !maxDistance) {
      return res.status(400).json({ error: 'Missing required parameters: lat, lng, maxDistance' });
    }
    const maxDistNum = parseFloat(maxDistance);
    if (isNaN(maxDistNum) || maxDistNum <= 0) {
      logger.warn('Invalid maxDistance:', maxDistance);
      return res.status(400).json({ error: 'Invalid maxDistance: must be a positive number' });
    }
    const query = {
      location: {
        $near: {
          $geometry: { type: 'Point', coordinates: [parseFloat(lng), parseFloat(lat)] },
          $maxDistance: maxDistNum
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
    const maxDistNum = parseFloat(maxDistance);
    if (isNaN(maxDistNum) || maxDistNum <= 0) {
      logger.warn('Invalid maxDistance:', maxDistance);
      return res.status(400).json({ error: 'Invalid maxDistance: must be a positive number' });
    }
    const lineString = turf.lineString(polyline);
    const buffered = turf.buffer(lineString, maxDistNum / 1000, { units: 'kilometers' });
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
      try {
        await PushSubscription.updateMany(
          { userId: socket.user.id },
          { lastLocation: { type: 'Point', coordinates: [data.location.lng, data.location.lat] } }
        );
        await User.findByIdAndUpdate(socket.user.id, {
          lastLocation: { type: 'Point', coordinates: [data.location.lng, data.location.lat] }
        });
        logger.info('Socket.IO location updated for push subscriptions:', { userId: socket.user.id, location: data.location });
      } catch (error) {
        logger.error('Error updating socket location for push subscriptions:', error.message);
      }
    }
  });
  socket.on('disconnect', () => {
    logger.info(`User disconnected: ${socket.user.id}`);
  });
  socket.on('reconnect_attempt', () => {
    logger.info(`Socket.IO reconnect attempt for user: ${socket.user.id}`);
  });
});

server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});