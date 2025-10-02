require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const turf = require('@turf/turf');
const winston = require('winston');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit'); // Added for rate-limiting
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

// Configure Winston logger with request IDs
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.metadata({ fillExcept: ['message', 'level', 'timestamp'] })
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

// Rate-limiting middleware
const locationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Max 100 requests per window
  message: { error: 'Too many location updates. Please try again later.' }
});
const alertLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // Max 50 alerts per window
  message: { error: 'Too many alerts posted. Please try again later.' }
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

// Serve fallback favicon to avoid 404s
app.get('/favicon.ico', (req, res) => {
  res.redirect('https://i.postimg.cc/jjN0JrPZ/New-Project-5.png');
  logger.info('Served fallback favicon.ico', { ip: req.ip });
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
  logger.info('Connected to MongoDB Atlas (pinmap database)', { uri: process.env.MONGODB_URI });
}).catch(err => {
  logger.error('MongoDB connection error:', { message: err.message, stack: err.stack });
  setTimeout(() => mongoose.connect(process.env.MONGODB_URI, mongoose.connectOptions), 5000);
});

mongoose.connection.on('error', err => {
  logger.error('MongoDB error:', { message: err.message, stack: err.stack });
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
  logger.info('Health check OK', { ip: req.ip });
});

// Basic route for the homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
  logger.info('Served index.html', { ip: req.ip });
});

// Serve admin.html
app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/admin.html'));
  logger.info('Served admin.html', { ip: req.ip });
});

// Refresh token endpoint
app.post('/api/auth/refresh', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      logger.warn('User not found for token refresh', { userId: req.user._id, ip: req.ip });
      return res.status(404).json({ error: 'User not found' });
    }
    const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
    logger.info('Token refreshed', { userId: req.user._id, ip: req.ip });
  } catch (error) {
    logger.error('Token refresh error:', { message: error.message, stack: error.stack, userId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Failed to refresh token: ' + error.message });
  }
});

// Save push subscription
app.post('/api/auth/subscribe', authMiddleware, async (req, res) => {
  try {
    const subscription = req.body;
    if (!subscription || !subscription.endpoint || !subscription.keys || !subscription.keys.p256dh || !subscription.keys.auth) {
      logger.warn('Invalid subscription data:', { subscription, userId: req.user._id, ip: req.ip });
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
      logger.info('Push subscription saved:', { userId: req.user._id, endpoint: subscription.endpoint, subscriptionId, ip: req.ip });
    } else {
      subscriptionId = existingSubscription._id;
      logger.info('Push subscription already exists:', { userId: req.user._id, endpoint: subscription.endpoint, subscriptionId, ip: req.ip });
    }
    res.status(201).json({ message: 'Subscription saved', subscriptionId });
  } catch (error) {
    logger.error('Error saving push subscription:', { message: error.message, stack: error.stack, userId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Failed to save subscription: ' + error.message });
  }
});

// Remove push subscription
app.post('/api/auth/unsubscribe', authMiddleware, async (req, res) => {
  try {
    const subscription = req.body;
    if (!subscription || !subscription.endpoint) {
      logger.warn('Invalid subscription data for unsubscribe:', { subscription, userId: req.user._id, ip: req.ip });
      return res.status(400).json({ error: 'Invalid subscription data' });
    }
    const result = await PushSubscription.deleteOne({ 
      userId: req.user._id, 
      endpoint: subscription.endpoint 
    });
    if (result.deletedCount > 0) {
      await User.findByIdAndUpdate(req.user._id, {
        $pull: { pushSubscriptions: result._id }
      });
      logger.info('Push subscription removed:', { userId: req.user._id, endpoint: subscription.endpoint, ip: req.ip });
      res.status(200).json({ message: 'Subscription removed' });
    } else {
      logger.warn('No subscription found to remove:', { userId: req.user._id, endpoint: subscription.endpoint, ip: req.ip });
      res.status(404).json({ error: 'Subscription not found' });
    }
  } catch (error) {
    logger.error('Error removing push subscription:', { message: error.message, stack: error.stack, userId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Failed to remove subscription: ' + error.message });
  }
});

// Save alerts and send push notifications
app.post('/api/alerts', alertLimiter, authMiddleware, async (req, res) => {
  try {
    const { type, location, timestamp, address } = req.body;
    if (!type || !location || !location.coordinates || !timestamp) {
      logger.warn('Invalid alert data received:', { body: req.body, userId: req.user._id, ip: req.ip });
      return res.status(400).json({ error: 'Invalid alert data: type, location, and timestamp are required' });
    }
    if (!Array.isArray(location.coordinates) || location.coordinates.length !== 2) {
      logger.warn('Invalid coordinates format:', { coordinates: location.coordinates, userId: req.user._id, ip: req.ip });
      return res.status(400).json({ error: 'Invalid coordinates format: must be [longitude, latitude]' });
    }
    const [lng, lat] = location.coordinates;
    if (isNaN(lng) || isNaN(lat) || lng < -180 || lng > 180 || lat < -90 || lat > 90) {
      logger.warn('Invalid coordinates values:', { coordinates: location.coordinates, userId: req.user._id, ip: req.ip });
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
    logger.info('Alert saved:', { type, userId: req.user._id, location, alertId: alert._id, ip: req.ip });

    // Batch send push notifications
    const maxDistance = 15 * 1609.34; // 15 miles in meters
    const users = await User.find({
      pushSubscriptions: { $exists: true, $ne: [] },
      lastLocation: {
        $geoWithin: {
          $centerSphere: [[lng, lat], maxDistance / 6378137] // Earth radius in meters
        }
      }
    }).populate('pushSubscriptions');
    const notificationPayload = {
      title: `${type} Alert`,
      body: `${type} reported at ${address || `${lat.toFixed(4)}, ${lng.toFixed(4)}`}`,
      alertId: alert._id,
      lat: lat,
      lng: lng
    };
    const pushPromises = [];
    for (const user of users) {
      for (const sub of user.pushSubscriptions) {
        pushPromises.push(
          webpush.sendNotification(sub, JSON.stringify(notificationPayload))
            .then(() => {
              logger.info('Push notification sent:', { userId: user._id, endpoint: sub.endpoint, alertId: alert._id, ip: req.ip });
            })
            .catch(error => {
              logger.error('Failed to send push notification:', { userId: user._id, endpoint: sub.endpoint, error: error.message, stack: error.stack, ip: req.ip });
              if (error.statusCode === 410) {
                return PushSubscription.deleteOne({ _id: sub._id }).then(() => {
                  return User.findByIdAndUpdate(user._id, {
                    $pull: { pushSubscriptions: sub._id }
                  });
                }).then(() => {
                  logger.info('Removed expired subscription:', { userId: user._id, endpoint: sub.endpoint, ip: req.ip });
                });
              }
            })
        );
      }
    }
    await Promise.all(pushPromises);

    io.emit('alert', populatedAlert);
    logger.info(`Emitted alert event for: ${alert._id}`, { ip: req.ip });
    res.status(201).json({ alert: populatedAlert });
  } catch (error) {
    logger.error('Error saving alert:', { message: error.message, stack: error.stack, userId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Failed to save alert: ' + error.message });
  }
});

// Delete alert and send push notifications
app.delete('/api/alerts/:id', authMiddleware, async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.id);
    if (!alert) {
      logger.warn('Alert not found for deletion:', { alertId: req.params.id, userId: req.user._id, ip: req.ip });
      return res.status(404).json({ error: 'Alert not found' });
    }
    if (alert.userId.toString() !== req.user._id.toString()) {
      logger.warn('Unauthorized alert deletion attempt:', { alertId: req.params.id, userId: req.user._id, ip: req.ip });
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
        logger.warn(`MongoDB delete attempt failed for alert ${req.params.id}, retries left: ${retries}`, { message: err.message, stack: err.stack, ip: req.ip });
        if (retries === 0) {
          throw new Error(`MongoDB delete failed after retries: ${err.message}`);
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    logger.info('Alert deleted:', { alertId: req.params.id, userId: req.user._id, ip: req.ip });

    // Batch send push notifications for alert deletion
    const maxDistance = 15 * 1609.34; // 15 miles in meters
    const users = await User.find({
      pushSubscriptions: { $exists: true, $ne: [] },
      lastLocation: {
        $geoWithin: {
          $centerSphere: [[alert.location.coordinates[0], alert.location.coordinates[1]], maxDistance / 6378137]
        }
      }
    }).populate('pushSubscriptions');
    const notificationPayload = {
      title: 'Alert Removed',
      body: `Alert at ${alert.address || `${alert.location.coordinates[1].toFixed(4)}, ${alert.location.coordinates[0].toFixed(4)}`} has been removed.`,
      alertId: req.params.id,
      lat: alert.location.coordinates[1],
      lng: alert.location.coordinates[0]
    };
    const pushPromises = [];
    for (const user of users) {
      for (const sub of user.pushSubscriptions) {
        pushPromises.push(
          webpush.sendNotification(sub, JSON.stringify(notificationPayload))
            .then(() => {
              logger.info('Push notification sent for alert deletion:', { userId: user._id, endpoint: sub.endpoint, alertId: req.params.id, ip: req.ip });
            })
            .catch(error => {
              logger.error('Failed to send push notification for deletion:', { userId: user._id, endpoint: sub.endpoint, error: error.message, stack: error.stack, ip: req.ip });
              if (error.statusCode === 410) {
                return PushSubscription.deleteOne({ _id: sub._id }).then(() => {
                  return User.findByIdAndUpdate(user._id, {
                    $pull: { pushSubscriptions: sub._id }
                  });
                }).then(() => {
                  logger.info('Removed expired subscription:', { userId: user._id, endpoint: sub.endpoint, ip: req.ip });
                });
              }
            })
        );
      }
    }
    await Promise.all(pushPromises);

    io.emit('alertDeleted', req.params.id);
    logger.info(`Emitted alertDeleted for: ${req.params.id}`, { ip: req.ip });
    res.status(200).json({ message: 'Alert deleted' });
  } catch (error) {
    logger.error('Error deleting alert:', { message: error.message, stack: error.stack, alertId: req.params.id, userId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Failed to delete alert: ' + error.message });
  }
});

// Update user location for push notifications with retry logic
app.post('/api/location', locationLimiter, authMiddleware, async (req, res) => {
  try {
    const { location } = req.body;
    if (!location || !Array.isArray(location.coordinates) || location.coordinates.length !== 2) {
      logger.warn('Invalid location data:', { body: req.body, userId: req.user._id, ip: req.ip });
      return res.status(400).json({ error: 'Invalid location data: coordinates must be [longitude, latitude]' });
    }
    const [lng, lat] = location.coordinates;
    if (isNaN(lng) || isNaN(lat) || lng < -180 || lng > 180 || lat < -90 || lat > 90) {
      logger.warn('Invalid coordinates values:', { coordinates: location.coordinates, userId: req.user._id, ip: req.ip });
      return res.status(400).json({ error: 'Invalid longitude or latitude values' });
    }
    let retries = 3;
    let success = false;
    while (retries > 0 && !success) {
      try {
        await PushSubscription.updateMany(
          { userId: req.user._id },
          { lastLocation: { type: 'Point', coordinates: [lng, lat] } }
        );
        await User.findByIdAndUpdate(req.user._id, {
          lastLocation: { type: 'Point', coordinates: [lng, lat] }
        });
        success = true;
        logger.info('User location updated for push subscriptions:', { userId: req.user._id, location, ip: req.ip });
      } catch (error) {
        retries--;
        logger.warn(`Location update attempt failed, retries left: ${retries}`, { message: error.message, stack: error.stack, userId: req.user._id, ip: req.ip });
        if (retries === 0) {
          throw new Error(`Location update failed after retries: ${error.message}`);
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    res.status(200).json({ message: 'Location updated' });
  } catch (error) {
    logger.error('Error updating user location:', { message: error.message, stack: error.stack, userId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Failed to update location: ' + error.message });
  }
});

// Fetch markers near a location
app.get('/api/markers', async (req, res) => {
  try {
    const { lat, lng, maxDistance, type } = req.query;
    if (!lat || !lng || !maxDistance) {
      logger.warn('Missing required parameters for /api/markers:', { query: req.query, ip: req.ip });
      return res.status(400).json({ error: 'Missing required parameters: lat, lng, maxDistance' });
    }
    const maxDistNum = parseFloat(maxDistance);
    if (isNaN(maxDistNum) || maxDistNum <= 0) {
      logger.warn('Invalid maxDistance:', { maxDistance, ip: req.ip });
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
    logger.info(`Fetched ${markers.length} markers for lat:${lat}, lng:${lng}, maxDistance:${maxDistance}, type:${type || 'all'}`, { ip: req.ip });
    res.json(markers);
  } catch (error) {
    logger.error('Error fetching markers:', { message: error.message, stack: error.stack, ip: req.ip });
    res.status(500).json({ error: 'Failed to fetch markers: ' + error.message });
  }
});

// Fetch hazards near a route
app.post('/api/hazards-near-route', authMiddleware, async (req, res) => {
  try {
    const { polyline, maxDistance } = req.body;
    if (!polyline || !Array.isArray(polyline) || !maxDistance) {
      logger.warn('Invalid request data for /api/hazards-near-route:', { body: req.body, userId: req.user._id, ip: req.ip });
      return res.status(400).json({ error: 'Invalid request: polyline and maxDistance required' });
    }
    const maxDistNum = parseFloat(maxDistance);
    if (isNaN(maxDistNum) || maxDistNum <= 0) {
      logger.warn('Invalid maxDistance:', { maxDistance, userId: req.user._id, ip: req.ip });
      return res.status(400).json({ error: 'Invalid maxDistance: must be a positive number' });
    }
    // Validate polyline coordinates
    if (!polyline.every(coord => Array.isArray(coord) && coord.length === 2 && !isNaN(coord[0]) && !isNaN(coord[1]))) {
      logger.warn('Invalid polyline coordinates:', { polyline, userId: req.user._id, ip: req.ip });
      return res.status(400).json({ error: 'Invalid polyline: must be array of [lng, lat] coordinates' });
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
    logger.info(`Fetched ${hazards.length} hazards near route, polylineLength:${polyline.length}`, { userId: req.user._id, ip: req.ip });
    res.json(hazards);
  } catch (error) {
    logger.error('Error fetching hazards near route:', { message: error.message, stack: error.stack, userId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Failed to fetch hazards: ' + error.message });
  }
});

// NEW: Users management routes for admin panel
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user.isAdmin) {
      logger.warn('Non-admin access attempt to /api/users', { userId: req.user._id, ip: req.ip });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const { search } = req.query;
    const query = search ? {
      $or: [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
      ],
    } : {};
    const users = await User.find(query).select('-password').limit(50);
    logger.info(`Admin fetched users (search: ${search || 'all'})`, { adminId: req.user._id, count: users.length, ip: req.ip });
    res.json(users);
  } catch (err) {
    logger.error('Error fetching users:', { message: err.message, stack: err.stack, adminId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/users/nearby', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user.isAdmin) {
      logger.warn('Non-admin access attempt to /api/users/nearby', { userId: req.user._id, ip: req.ip });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const { lat, lng, radius = 48280 } = req.query; // Default 30 miles
    const users = await User.find({
      location: {
        $near: {
          $geometry: { type: 'Point', coordinates: [parseFloat(lng), parseFloat(lat)] },
          $maxDistance: parseInt(radius),
        },
      },
      banned: false,
    }).select('-password').limit(50);
    logger.info(`Admin fetched nearby users (lat:${lat}, lng:${lng}, radius:${radius})`, { adminId: req.user._id, count: users.length, ip: req.ip });
    res.json(users);
  } catch (err) {
    logger.error('Error fetching nearby users:', { message: err.message, stack: err.stack, adminId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/users/:id', authMiddleware, async (req, res) => {
  try {
    const adminUser = await User.findById(req.user._id);
    if (!adminUser.isAdmin) {
      logger.warn('Non-admin delete user attempt', { targetId: req.params.id, adminId: req.user._id, ip: req.ip });
      return res.status(403).json({ error: 'Admin access required' });
    }
    await User.findByIdAndDelete(req.params.id);
    logger.info('Admin deleted user', { targetId: req.params.id, adminId: req.user._id, ip: req.ip });
    res.json({ success: true });
  } catch (err) {
    logger.error('Error deleting user:', { message: err.message, stack: err.stack, targetId: req.params.id, adminId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/users/:id/ban', authMiddleware, async (req, res) => {
  try {
    const adminUser = await User.findById(req.user._id);
    if (!adminUser.isAdmin) {
      logger.warn('Non-admin ban user attempt', { targetId: req.params.id, adminId: req.user._id, ip: req.ip });
      return res.status(403).json({ error: 'Admin access required' });
    }
    await User.findByIdAndUpdate(req.params.id, { banned: true });
    logger.info('Admin banned user', { targetId: req.params.id, adminId: req.user._id, ip: req.ip });
    res.json({ success: true });
  } catch (err) {
    logger.error('Error banning user:', { message: err.message, stack: err.stack, targetId: req.params.id, adminId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/users/:id/ipban', authMiddleware, async (req, res) => {
  try {
    const adminUser = await User.findById(req.user._id);
    if (!adminUser.isAdmin) {
      logger.warn('Non-admin IP ban user attempt', { targetId: req.params.id, adminId: req.user._id, ip: req.ip });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const user = await User.findById(req.params.id);
    if (!user.ipBanned) user.ipBanned = [];
    user.ipBanned.push(req.ip); // Note: req.ip may need proxy config for accuracy
    await user.save();
    logger.info('Admin IP banned user', { targetId: req.params.id, adminId: req.user._id, ip: req.ip });
    res.json({ success: true });
  } catch (err) {
    logger.error('Error IP banning user:', { message: err.message, stack: err.stack, targetId: req.params.id, adminId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/users/:id/promote', authMiddleware, async (req, res) => {
  try {
    const adminUser = await User.findById(req.user._id);
    if (!adminUser.isAdmin) {
      logger.warn('Non-admin promote user attempt', { targetId: req.params.id, adminId: req.user._id, ip: req.ip });
      return res.status(403).json({ error: 'Admin access required' });
    }
    await User.findByIdAndUpdate(req.params.id, { isAdmin: true });
    logger.info('Admin promoted user', { targetId: req.params.id, adminId: req.user._id, ip: req.ip });
    res.json({ success: true });
  } catch (err) {
    logger.error('Error promoting user:', { message: err.message, stack: err.stack, targetId: req.params.id, adminId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/users/:id/demote', authMiddleware, async (req, res) => {
  try {
    const adminUser = await User.findById(req.user._id);
    if (!adminUser.isAdmin) {
      logger.warn('Non-admin demote user attempt', { targetId: req.params.id, adminId: req.user._id, ip: req.ip });
      return res.status(403).json({ error: 'Admin access required' });
    }
    await User.findByIdAndUpdate(req.params.id, { isAdmin: false });
    logger.info('Admin demoted user', { targetId: req.params.id, adminId: req.user._id, ip: req.ip });
    res.json({ success: true });
  } catch (err) {
    logger.error('Error demoting user:', { message: err.message, stack: err.stack, targetId: req.params.id, adminId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/users/:id/location', authMiddleware, async (req, res) => {
  try {
    const adminUser = await User.findById(req.user._id);
    if (!adminUser.isAdmin) {
      logger.warn('Non-admin location access attempt', { targetId: req.params.id, adminId: req.user._id, ip: req.ip });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const user = await User.findById(req.params.id).select('location');
    res.json(user || { location: null });
    logger.info('Admin viewed user location', { targetId: req.params.id, adminId: req.user._id, ip: req.ip });
  } catch (err) {
    logger.error('Error fetching user location:', { message: err.message, stack: err.stack, targetId: req.params.id, adminId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/alerts/user/:id', authMiddleware, async (req, res) => {
  try {
    const adminUser = await User.findById(req.user._id);
    if (!adminUser.isAdmin) {
      logger.warn('Non-admin alerts access attempt', { targetId: req.params.id, adminId: req.user._id, ip: req.ip });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const { since } = req.query;
    const query = { userId: req.params.id };
    if (since) query.timestamp = { $gte: new Date(since) };
    const alerts = await Alert.find(query).populate('userId', 'username').sort({ timestamp: -1 });
    logger.info('Admin fetched user alerts', { targetId: req.params.id, adminId: req.user._id, count: alerts.length, ip: req.ip });
    res.json(alerts);
  } catch (err) {
    logger.error('Error fetching user alerts:', { message: err.message, stack: err.stack, targetId: req.params.id, adminId: req.user._id, ip: req.ip });
    res.status(500).json({ error: 'Server error' });
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
    logger.warn('Socket authentication failed: No token provided', { ip: socket.handshake.address });
    return next(new Error('Authentication error: No token provided'));
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.user = decoded;
    next();
  } catch (error) {
    logger.error('Socket authentication failed: Invalid token', { message: error.message, stack: error.stack, ip: socket.handshake.address });
    next(new Error('Authentication error: Invalid token'));
  }
});

io.on('connection', (socket) => {
  logger.info(`User connected via Socket.IO: ${socket.user.id}`, { ip: socket.handshake.address });
  socket.on('locationUpdate', async (data) => {
    if (data.location && Array.isArray(data.location) && data.location.length === 2) {
      logger.warn('Invalid location data in socket locationUpdate:', { location: data.location, userId: socket.user.id, ip: socket.handshake.address });
      return;
    }
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
      logger.info('Socket.IO location updated for push subscriptions:', { userId: socket.user.id, location: data.location, ip: socket.handshake.address });
    } catch (error) {
      logger.error('Error updating socket location for push subscriptions:', { message: error.message, stack: error.stack, userId: socket.user.id, ip: socket.handshake.address });
    }
  });
  // NEW: Handle admin tracking (optional, since broadcast works)
  socket.on('trackUser', (targetId) => {
    // For now, no-op as broadcast sends to all; could join room for targeted emits
    logger.info('Admin tracking user', { adminId: socket.user.id, targetId, ip: socket.handshake.address });
  });
  socket.on('stopTracking', (targetId) => {
    logger.info('Admin stopped tracking user', { adminId: socket.user.id, targetId, ip: socket.handshake.address });
  });
  socket.on('disconnect', () => {
    logger.info(`User disconnected: ${socket.user.id}`, { ip: socket.handshake.address });
  });
  socket.on('reconnect_attempt', () => {
    logger.info(`Socket.IO reconnect attempt for user: ${socket.user.id}`, { ip: socket.handshake.address });
  });
});

server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});