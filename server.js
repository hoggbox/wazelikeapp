require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const helmet = require('helmet'); // Added for security headers
const webpush = require('web-push');
const rateLimit = require('express-rate-limit');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const User = require('./models/User');
const authRoutes = require('./routes/auth');
const authMiddleware = require('./middleware/auth');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    methods: ['GET', 'POST', 'DELETE'],
    credentials: true
  }
});

// Enable trust proxy for hosting platforms like Render
app.set('trust proxy', 1);

// Middleware
app.use(helmet()); // Added security headers
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
  req.io = io;
  next();
});

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Serve index.html for root route
app.get('/', (req, res) => {
  console.log('Serving index.html for root route');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// MongoDB Connection with Retry
async function connectDB() {
  let retries = 5;
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    throw new Error('MONGODB_URI environment variable is required');
  }
  while (retries > 0) {
    try {
      console.log('Attempting MongoDB connection with URI:', uri.replace(/:\/\/[^@]+@/, '://<redacted>@'));
      await mongoose.connect(uri, {
        dbName: 'pinmap', // Explicitly specify the database name
        serverSelectionTimeoutMS: 5000,
        connectTimeoutMS: 10000,
        socketTimeoutMS: 45000
      });
      console.log('MongoDB connected to Atlas database: pinmap');
      
      // Ensure indexes are created
      const existingIndexes = await User.collection.indexes();
      const indexNames = existingIndexes.map(index => index.name);
      
      if (!indexNames.includes('alerts.location_2dsphere')) {
        await User.collection.createIndex({ 'alerts.location': '2dsphere' });
        console.log('Created 2dsphere index on alerts.location');
      }
      if (!indexNames.includes('lastLocation_2dsphere')) {
        await User.collection.createIndex({ lastLocation: '2dsphere' }, { sparse: true, background: true });
        console.log('Created 2dsphere index on lastLocation');
      }
      if (!indexNames.includes('alerts.expiry_1')) {
        await User.collection.createIndex({ 'alerts.expiry': 1 }, { expireAfterSeconds: 3600 });
        console.log('Created TTL index on alerts.expiry');
      }
      if (!indexNames.includes('email_1')) {
        await User.collection.createIndex({ email: 1 });
        console.log('Created index on email');
      }
      return;
    } catch (error) {
      console.error('MongoDB connection error:', {
        message: error.message,
        stack: error.stack,
        retriesLeft: retries - 1
      });
      retries--;
      if (retries === 0) {
        console.error('MongoDB connection failed after retries');
        process.exit(1);
      }
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }
}
connectDB();

// DB Connection Events
mongoose.connection.on('disconnected', () => console.log('MongoDB disconnected'));
mongoose.connection.on('error', (err) => console.error('MongoDB error:', err));
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  console.log('MongoDB connection closed due to app termination');
  process.exit(0);
});

// Test MongoDB Connection
app.get('/api/test-db', async (req, res) => {
  try {
    await mongoose.connection.db.admin().ping();
    console.log('MongoDB ping successful');
    res.json({ message: 'MongoDB connection successful' });
  } catch (error) {
    console.error('MongoDB test error:', error.message, error.stack);
    res.status(500).json({ error: 'MongoDB connection failed' }); // Sanitized
  }
});

// VAPID Keys
const vapidPublicKey = process.env.VAPID_PUBLIC_KEY;
const vapidPrivateKey = process.env.VAPID_PRIVATE_KEY;
if (!vapidPublicKey || !vapidPrivateKey) {
  console.warn('VAPID keys missing; push notifications disabled');
}
webpush.setVapidDetails(
  'mailto:admin@example.com',
  vapidPublicKey,
  vapidPrivateKey
);

// Routes
app.get('/api/vapid-public-key', (req, res) => {
  console.log('Serving VAPID public key');
  res.json({ publicKey: vapidPublicKey });
});

app.use('/api/auth', authRoutes);

// Alert Posting Endpoint
app.post('/api/alerts', authMiddleware, async (req, res) => {
  try {
    const { type, location, address, timestamp } = req.body;
    console.log('Received alert post request:', { type, location, address, timestamp, userId: req.user._id });

    // Validate input
    if (!type || !location || !location.coordinates || location.coordinates.length !== 2) {
      console.error('Invalid alert data:', { type, location });
      return res.status(400).json({ error: 'Invalid alert data' });
    }
    const lng = parseFloat(location.coordinates[0]);
    const lat = parseFloat(location.coordinates[1]);
    if (isNaN(lng) || isNaN(lat) || lng < -180 || lng > 180 || lat < -90 || lat > 90) {
      console.error('Invalid coordinates:', { lng, lat });
      return res.status(400).json({ error: 'Invalid coordinates: longitude must be -180 to 180, latitude -90 to 90' });
    }
    const timestampDate = timestamp ? new Date(timestamp) : new Date();
    if (isNaN(timestampDate.getTime())) {
      console.error('Invalid timestamp:', timestamp);
      return res.status(400).json({ error: 'Invalid timestamp' });
    }

    // Find user
    const user = await User.findById(req.user._id);
    if (!user) {
      console.error('User not found:', req.user._id);
      return res.status(404).json({ error: 'User not found' });
    }

    // Check for duplicate alert (same type, location within ~10m, within 30 seconds)
    const existingIndex = user.alerts.findIndex(a =>
      a.type === type &&
      Math.abs(a.location.coordinates[0] - lng) < 0.0001 &&
      Math.abs(a.location.coordinates[1] - lat) < 0.0001 &&
      a.expiry > new Date() &&
      Math.abs((a.timestamp.getTime() - timestampDate.getTime()) / 1000) < 30
    );
    if (existingIndex !== -1) {
      console.log('Duplicate alert ignored:', { type, lng, lat, userId: user._id });
      const existingAlert = user.alerts[existingIndex];
      const populatedAlert = {
        _id: existingAlert._id,
        type: existingAlert.type,
        location: existingAlert.location,
        address: existingAlert.address,
        timestamp: existingAlert.timestamp,
        votes: existingAlert.votes,
        expiry: existingAlert.expiry,
        userId: { _id: user._id, username: user.username }
      };
      return res.status(409).json({ alert: populatedAlert, message: 'Duplicate alert ignored' });
    }

    // Create new alert
    const alert = {
      _id: new mongoose.Types.ObjectId(),
      type,
      location: {
        type: 'Point',
        coordinates: [lng, lat]
      },
      address: address || 'Unknown',
      timestamp: timestampDate,
      votes: { up: 0, down: 0, upVoters: [], downVoters: [] },
      expiry: new Date(Date.now() + 3600000) // 1 hour expiry
    };

    // Add alert to user and update stats
    user.alerts.push(alert);
    user.totalAlerts = (user.totalAlerts || 0) + 1;
    user.activeAlerts = (user.activeAlerts || 0) + 1;
    user.points = (user.points || 0) + 10;

    console.log('Saving alert to MongoDB:', { alertId: alert._id, type, userId: user._id, alertsCountBefore: user.alerts.length });
    try {
      await user.save();
      console.log('Alert successfully saved:', { alertId: alert._id, alertsCountAfter: user.alerts.length });
    } catch (saveError) {
      console.error('SAVE ERROR DETAILS:', {
        name: saveError.name,
        message: saveError.message,
        errors: saveError.errors,
        stack: saveError.stack
      });
      throw saveError;
    }

    // Prepare response
    const populatedAlert = {
      _id: alert._id,
      type: alert.type,
      location: alert.location,
      address: alert.address,
      timestamp: alert.timestamp,
      votes: alert.votes,
      expiry: alert.expiry,
      userId: { _id: user._id, username: user.username }
    };

    // Emit Socket.IO events
    req.io.emit('alert', populatedAlert);
    if (user.familyMembers?.length > 0) {
      req.io.emit('familyAlert', { alert: populatedAlert, user: { email: user.email, username: user.username } });
    }

    res.status(201).json({ alert: populatedAlert });
  } catch (error) {
    console.error('Error posting alert:', error.message, error.stack);
    const status = error.name === 'TokenExpiredError' ? 401 : 500;
    const details = process.env.NODE_ENV === 'production' ? undefined : error.message;
    res.status(status).json({ error: 'Failed to post alert', details });
  }
});

// Fetch Nearby Alerts (with pagination)
app.get('/api/markers', authMiddleware, async (req, res) => {
  try {
    const { lat, lng, maxDistance = 16093.4, page = 1, limit = 50 } = req.query;
    if (!lat || !lng || isNaN(parseFloat(lat)) || isNaN(parseFloat(lng))) {
      console.error('Invalid query parameters:', { lat, lng });
      return res.status(400).json({ error: 'Invalid latitude or longitude' });
    }
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    if (isNaN(pageNum) || isNaN(limitNum) || pageNum < 1 || limitNum < 1 || limitNum > 100) {
      return res.status(400).json({ error: 'Invalid pagination parameters' });
    }
    const skip = (pageNum - 1) * limitNum;
    console.log('Fetching markers for:', { lat: parseFloat(lat), lng: parseFloat(lng), maxDistance, page: pageNum, limit: limitNum });
    const users = await User.find({
      'alerts.location': {
        $geoWithin: {
          $centerSphere: [[parseFloat(lng), parseFloat(lat)], parseFloat(maxDistance) / 6378137]
        }
      },
      'alerts.expiry': { $gt: new Date() }
    });
    let alerts = users.flatMap(user =>
      user.alerts
        .filter(alert => alert.expiry > new Date())
        .map(alert => ({
          _id: alert._id,
          type: alert.type,
          location: alert.location,
          address: alert.address,
          timestamp: alert.timestamp,
          votes: alert.votes,
          expiry: alert.expiry,
          userId: { _id: user._id, username: user.username }
        }))
    );
    // Paginate
    const total = alerts.length;
    alerts = alerts.slice(skip, skip + limitNum);
    console.log('Returning paginated markers:', alerts.length, `Total: ${total}`);
    res.json({ alerts, pagination: { page: pageNum, limit: limitNum, total, pages: Math.ceil(total / limitNum) } });
  } catch (error) {
    console.error('Error fetching markers:', error.message, error.stack);
    const status = error.name === 'TokenExpiredError' ? 401 : 500;
    const details = process.env.NODE_ENV === 'production' ? undefined : error.message;
    res.status(status).json({ error: 'Failed to fetch markers', details });
  }
});

// Fetch Hazards Near Route (fixed distance to radians)
app.post('/api/hazards-near-route', authMiddleware, async (req, res) => {
  try {
    const { polyline, maxDistance = 50 } = req.body;
    if (!polyline || !Array.isArray(polyline) || polyline.length === 0) {
      console.error('Invalid polyline data:', polyline);
      return res.status(400).json({ error: 'Invalid polyline data' });
    }
    const maxDistRadians = parseFloat(maxDistance) / 6378137; // Fixed: Convert meters to radians
    console.log('Fetching hazards for polyline:', { points: polyline.length, maxDistance, maxDistRadians });
    const lineString = {
      type: 'LineString',
      coordinates: polyline.map(pt => [pt.lng || pt[0], pt.lat || pt[1]]) // Handle both {lng,lat} and [lng,lat]
    };
    const users = await User.find({
      'alerts.location': {
        $geoWithin: {
          $geometry: lineString,
          $maxDistance: maxDistRadians // Fixed radians
        }
      },
      'alerts.expiry': { $gt: new Date() },
      'alerts.type': { $ne: 'Traffic Camera' }
    });
    const hazards = users.flatMap(user =>
      user.alerts
        .filter(alert => alert.expiry > new Date() && alert.type !== 'Traffic Camera')
        .map(alert => ({
          _id: alert._id,
          type: alert.type,
          location: alert.location,
          address: alert.address,
          timestamp: alert.timestamp,
          votes: alert.votes,
          expiry: alert.expiry,
          userId: { _id: user._id, username: user.username }
        }))
    );
    console.log('Returning hazards:', hazards.length);
    res.json(hazards);
  } catch (error) {
    console.error('Error fetching hazards near route:', error.message, error.stack);
    const status = error.name === 'TokenExpiredError' ? 401 : 500;
    const details = process.env.NODE_ENV === 'production' ? undefined : error.message;
    res.status(status).json({ error: 'Failed to fetch hazards', details });
  }
});

// Vote on Alert (added expiry check)
app.post('/api/alerts/:id/vote', authMiddleware, async (req, res) => {
  try {
    const { voteType } = req.body;
    if (!['up', 'down'].includes(voteType)) {
      console.error('Invalid vote type:', voteType);
      return res.status(400).json({ error: 'Invalid vote type' });
    }
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      console.error('Invalid alert ID:', req.params.id);
      return res.status(400).json({ error: 'Invalid alert ID' });
    }
    console.log('Voting on alert:', { alertId: req.params.id, voteType, userId: req.user._id });
    const user = await User.findOne({ 'alerts._id': req.params.id });
    if (!user) {
      console.error('Alert not found:', req.params.id);
      return res.status(404).json({ error: 'Alert not found' });
    }
    const alert = user.alerts.id(req.params.id);
    if (!alert) {
      console.error('Alert not found in user document:', req.params.id);
      return res.status(404).json({ error: 'Alert not found' });
    }
    if (alert.expiry <= new Date()) { // Added expiry check
      console.error('Voting on expired alert:', req.params.id);
      return res.status(410).json({ error: 'Alert expired' });
    }
    if (alert.votes[voteType + 'Voters'].includes(req.user._id)) {
      console.error(`User ${req.user._id} already ${voteType}voted on alert:`, req.params.id);
      return res.status(400).json({ error: `Already ${voteType}voted` });
    }
    alert.votes[voteType + 'Voters'].push(req.user._id);
    alert.votes[voteType] = (alert.votes[voteType] || 0) + 1;
    let deleted = false;
    if (alert.votes.down > alert.votes.up * 2) {
      user.alerts.pull({ _id: req.params.id });
      user.activeAlerts = Math.max(0, (user.activeAlerts || 0) - 1);
      deleted = true;
      req.io.emit('alertDeleted', req.params.id);
      console.log('Alert deleted due to downvotes:', req.params.id);
    } else if (alert.votes.up > alert.votes.down) {
      alert.expiry = new Date(Date.now() + 3600000);
      req.io.emit('extendAlert', req.params.id);
      console.log('Alert extended:', req.params.id);
    }
    await user.save();
    const populatedAlert = {
      _id: alert._id,
      type: alert.type,
      location: alert.location,
      address: alert.address,
      timestamp: alert.timestamp,
      votes: alert.votes,
      expiry: alert.expiry,
      userId: { _id: user._id, username: user.username }
    };
    if (deleted) {
      res.json({ message: 'Alert deleted due to votes', deleted: true });
    } else {
      res.json(populatedAlert);
    }
  } catch (error) {
    console.error('Error voting on alert:', error.message, error.stack);
    const status = error.name === 'TokenExpiredError' ? 401 : 500;
    const details = process.env.NODE_ENV === 'production' ? undefined : error.message;
    res.status(status).json({ error: 'Failed to vote', details });
  }
});

// Delete Alert (added expiry check and logging)
app.delete('/api/alerts/:id', authMiddleware, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      console.error('Invalid alert ID:', req.params.id);
      return res.status(400).json({ error: 'Invalid alert ID' });
    }
    console.log('Deleting alert attempt:', { alertId: req.params.id, userId: req.user._id, isAdmin: req.user.isAdmin });
    let owner = await User.findOne({ 'alerts._id': req.params.id });
    if (!owner) {
      console.error('Alert not found for any user:', req.params.id);
      return res.status(404).json({ error: 'Alert not found' });
    }
    console.log('Alert owner found:', owner._id);
    const alert = owner.alerts.id(req.params.id);
    if (!alert) {
      console.error('Alert not found in owner document:', req.params.id);
      return res.status(404).json({ error: 'Alert not found' });
    }
    if (alert.expiry <= new Date()) { // Added expiry check
      console.error('Deleting expired alert:', req.params.id);
      return res.status(410).json({ error: 'Alert expired' });
    }
    const isOwner = owner._id.toString() === req.user._id.toString();
    const isAuthorized = isOwner || req.user.isAdmin;
    console.log('Delete authorization:', { isOwner, isAdmin: req.user.isAdmin, authorized: isAuthorized });
    if (!isAuthorized) {
      console.error('Unauthorized delete attempt:', { requesterId: req.user._id, ownerId: owner._id, isAdmin: req.user.isAdmin });
      return res.status(403).json({ error: 'Unauthorized' });
    }
    owner.alerts.pull({ _id: req.params.id });
    owner.activeAlerts = Math.max(0, (owner.activeAlerts || 0) - 1);
    await owner.save();
    console.log(`Alert deleted by ${req.user.username} (${req.user._id}) for owner ${owner.username} (${owner._id}):`, { alertId: req.params.id }); // Added logging
    req.io.emit('alertDeleted', req.params.id);
    res.json({ message: 'Alert deleted successfully' });
  } catch (error) {
    console.error('Error deleting alert:', error.message, error.stack);
    const status = error.name === 'TokenExpiredError' ? 401 : 500;
    const details = process.env.NODE_ENV === 'production' ? undefined : error.message;
    res.status(status).json({ error: 'Failed to delete alert', details });
  }
});

// Update User Location
app.post('/api/location', authMiddleware, async (req, res) => {
  try {
    const { location } = req.body;
    if (!location || !location.coordinates || location.coordinates.length !== 2) {
      console.error('Invalid location data:', location);
      return res.status(400).json({ error: 'Invalid location data' });
    }
    const lng = parseFloat(location.coordinates[0]);
    const lat = parseFloat(location.coordinates[1]);
    if (isNaN(lng) || isNaN(lat) || lng < -180 || lng > 180 || lat < -90 || lat > 90) {
      console.error('Invalid location coordinates:', { lng, lat });
      return res.status(400).json({ error: 'Invalid location coordinates: longitude must be -180 to 180, latitude -90 to 90' });
    }
    console.log('Updating location for user:', { userId: req.user._id, location });
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { lastLocation: location, lastActive: new Date() },
      { new: true }
    );
    if (!user) {
      console.error('User not found for location update:', req.user._id);
      return res.status(404).json({ error: 'User not found' });
    }
    req.io.emit('locationUpdate', { userId: req.user._id, location });
    res.json({ message: 'Location updated' });
  } catch (error) {
    console.error('Error updating location:', error.message, error.stack);
    const status = error.name === 'TokenExpiredError' ? 401 : 500;
    const details = process.env.NODE_ENV === 'production' ? undefined : error.message;
    res.status(status).json({ error: 'Failed to update location', details });
  }
});

// Fetch Leaderboard
app.get('/api/leaderboard', authMiddleware, async (req, res) => {
  try {
    const users = await User.find()
      .sort({ points: -1 })
      .limit(10)
      .select('username points achievements');
    console.log('Leaderboard fetched:', users.length);
    res.json(users);
  } catch (error) {
    console.error('Error fetching leaderboard:', error.message, error.stack);
    const status = error.name === 'TokenExpiredError' ? 401 : 500;
    const details = process.env.NODE_ENV === 'production' ? undefined : error.message;
    res.status(status).json({ error: 'Failed to fetch leaderboard', details });
  }
});

// Admin Routes
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      console.error('Non-admin attempted /api/users:', req.user._id);
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const users = await User.find().select('username email joinDate points isAdmin lastLocation lastActive');
    console.log('Users fetched:', users.length);
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error.message, error.stack);
    const status = error.name === 'TokenExpiredError' ? 401 : 500;
    const details = process.env.NODE_ENV === 'production' ? undefined : error.message;
    res.status(status).json({ error: 'Failed to fetch users', details });
  }
});

app.get('/api/users/search', authMiddleware, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      console.error('Non-admin attempted /api/users/search:', req.user._id);
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const { query } = req.query;
    if (!query) {
      console.error('Missing query param for /api/users/search');
      return res.status(400).json({ error: 'Query parameter required' });
    }
    const users = await User.find({
      $or: [
        { username: { $regex: query, $options: 'i' } },
        { email: { $regex: query, $options: 'i' } }
      ]
    }).select('username email joinDate points isAdmin lastLocation lastActive');
    console.log('Users search result:', users.length);
    res.json(users);
  } catch (error) {
    console.error('Error searching users:', error.message, error.stack);
    const status = error.name === 'TokenExpiredError' ? 401 : 500;
    const details = process.env.NODE_ENV === 'production' ? undefined : error.message;
    res.status(status).json({ error: 'Failed to search users', details });
  }
});

app.get('/api/users/:id/activity', authMiddleware, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      console.error('Non-admin attempted /api/users/:id/activity:', req.user._id);
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const user = await User.findById(req.params.id);
    if (!user) {
      console.error('User not found for activity:', req.params.id);
      return res.status(404).json({ error: 'User not found' });
    }
    const activity = user.alerts.map(alert => ({
      type: alert.type,
      description: `Posted ${alert.type} alert at ${alert.address || 'unknown location'}`,
      timestamp: alert.timestamp
    }));
    activity.push({
      type: 'Last Active',
      description: `Last active at ${user.lastLocation ? `Lat: ${user.lastLocation.coordinates[1]}, Lng: ${user.lastLocation.coordinates[0]}` : 'unknown location'}`,
      timestamp: user.lastActive
    });
    console.log('User activity fetched:', activity.length);
    res.json(activity);
  } catch (error) {
    console.error('Error fetching user activity:', error.message, error.stack);
    const status = error.name === 'TokenExpiredError' ? 401 : 500;
    const details = process.env.NODE_ENV === 'production' ? undefined : error.message;
    res.status(status).json({ error: 'Failed to fetch user activity', details });
  }
});

app.post('/api/users/:id/promote', authMiddleware, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      console.error('Non-admin attempted /api/users/:id/promote:', req.user._id);
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const user = await User.findById(req.params.id);
    if (!user) {
      console.error('User not found for promote:', req.params.id);
      return res.status(404).json({ error: 'User not found' });
    }
    user.isAdmin = true;
    await user.save();
    console.log(`${req.user.username} promoted user ${user.username}:`, req.params.id); // Added logging
    res.json({ message: 'User promoted to admin' });
  } catch (error) {
    console.error('Error promoting user:', error.message, error.stack);
    const status = error.name === 'TokenExpiredError' ? 401 : 500;
    const details = process.env.NODE_ENV === 'production' ? undefined : error.message;
    res.status(status).json({ error: 'Failed to promote user', details });
  }
});

app.post('/api/users/:id/demote', authMiddleware, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      console.error('Non-admin attempted /api/users/:id/demote:', req.user._id);
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const user = await User.findById(req.params.id);
    if (!user) {
      console.error('User not found for demote:', req.params.id);
      return res.status(404).json({ error: 'User not found' });
    }
    user.isAdmin = false;
    await user.save();
    console.log(`${req.user.username} demoted user ${user.username}:`, req.params.id); // Added logging
    res.json({ message: 'User demoted from admin' });
  } catch (error) {
    console.error('Error demoting user:', error.message, error.stack);
    const status = error.name === 'TokenExpiredError' ? 401 : 500;
    const details = process.env.NODE_ENV === 'production' ? undefined : error.message;
    res.status(status).json({ error: 'Failed to demote user', details });
  }
});

app.post('/api/users/:id/ban', authMiddleware, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      console.error('Non-admin attempted /api/users/:id/ban:', req.user._id);
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const user = await User.findById(req.params.id);
    if (!user) {
      console.error('User not found for ban:', req.params.id);
      return res.status(404).json({ error: 'User not found' });
    }
    user.isBanned = true;
    await user.save();
    console.log(`${req.user.username} banned user ${user.username}:`, req.params.id); // Added logging
    req.io.emit('userBanned', { userId: req.params.id });
    res.json({ message: 'User banned' });
  } catch (error) {
    console.error('Error banning user:', error.message, error.stack);
    const status = error.name === 'TokenExpiredError' ? 401 : 500;
    const details = process.env.NODE_ENV === 'production' ? undefined : error.message;
    res.status(status).json({ error: 'Failed to ban user', details });
  }
});

app.post('/api/users/:id/ipban', authMiddleware, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      console.error('Non-admin attempted /api/users/:id/ipban:', req.user._id);
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const user = await User.findById(req.params.id);
    if (!user) {
      console.error('User not found for ipban:', req.params.id);
      return res.status(404).json({ error: 'User not found' });
    }
    user.isBanned = true;
    user.ipBanned = req.ip || 'unknown';
    await user.save();
    console.log(`${req.user.username} IP banned user ${user.username} (${req.ip}):`, req.params.id); // Added logging
    req.io.emit('userBanned', { userId: req.params.id });
    res.json({ message: 'User IP banned' });
  } catch (error) {
    console.error('Error IP banning user:', error.message, error.stack);
    const status = error.name === 'TokenExpiredError' ? 401 : 500;
    const details = process.env.NODE_ENV === 'production' ? undefined : error.message;
    res.status(status).json({ error: 'Failed to IP ban user', details });
  }
});

app.delete('/api/users/:id', authMiddleware, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      console.error('Non-admin attempted /api/users/:id:', req.user._id);
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      console.error('User not found for delete:', req.params.id);
      return res.status(404).json({ error: 'User not found' });
    }
    console.log(`${req.user.username} deleted user ${user.username}:`, req.params.id); // Added logging
    req.io.emit('userBanned', { userId: req.params.id });
    res.json({ message: 'User deleted' });
  } catch (error) {
    console.error('Error deleting user:', error.message, error.stack);
    const status = error.name === 'TokenExpiredError' ? 401 : 500;
    const details = process.env.NODE_ENV === 'production' ? undefined : error.message;
    res.status(status).json({ error: 'Failed to delete user', details });
  }
});

function getDistance(point1, point2) {
  const R = 6371e3; // Earth's radius in meters
  const φ1 = point1.lat * Math.PI / 180;
  const φ2 = point2.lat * Math.PI / 180;
  const Δφ = (point2.lat - point1.lat) * Math.PI / 180;
  const Δλ = (point2.lng - point1.lng) * Math.PI / 180;
  const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
            Math.cos(φ1) * Math.cos(φ2) *
            Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// Error Handling Middleware (sanitized)
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message, err.stack);
  const status = err.name === 'TokenExpiredError' ? 401 : 500;
  const details = process.env.NODE_ENV === 'production' ? undefined : err.message;
  res.status(status).json({ error: 'Internal server error', details });
});

// Socket.IO Auth Middleware (added)
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Auth token required'));
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return next(new Error('Invalid token'));
    socket.user = decoded; // Attach user to socket
    next();
  });
});

// Socket.IO Events
io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id, 'User:', socket.user.id);
  socket.on('join', (userId) => {
    if (userId !== socket.user.id) return socket.disconnect(true); // Security
    socket.join(userId);
    console.log(`User ${userId} joined room`);
  });
  socket.on('locationUpdate', async ({ location }) => {
    const user = await User.findById(socket.user.id);
    if (user && !user.isBanned) {
      io.to(socket.user.id).emit('locationUpdate', { userId: socket.user.id, location });
      console.log('Location update emitted:', { userId: socket.user.id, location });
    }
  });
  socket.on('disconnect', () => {
    console.log('Socket disconnected:', socket.id);
  });
});

// Start Server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));