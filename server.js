require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const webpush = require('web-push');
const rateLimit = require('express-rate-limit');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

// Ensure STRIPE_SECRET_KEY is defined
if (!process.env.STRIPE_SECRET_KEY) {
  console.error('❌ Error: STRIPE_SECRET_KEY is not defined in .env file');
  process.exit(1);
}
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

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
  while (retries > 0) {
    try {
      console.log('=== ATTEMPTING MONGODB CONNECTION ===');
      console.log('MongoDB URI exists:', !!process.env.MONGODB_URI);
      console.log('Retry attempts remaining:', retries);
      
      await mongoose.connect(process.env.MONGODB_URI, 
        {
          dbName: 'pinmap',
          serverSelectionTimeoutMS: 5000,
          connectTimeoutMS: 10000,
          socketTimeoutMS: 45000,
          maxPoolSize: 10
        }
      );
      
      console.log('✅ MongoDB connected to Atlas');
      console.log('Database name:', mongoose.connection.db.databaseName);
      console.log('Connection state:', mongoose.connection.readyState);
      
      // Verify collections exist
      const collections = await mongoose.connection.db.listCollections().toArray();
      console.log('Available collections:', collections.map(c => c.name));
      
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
        await User.collection.createIndex({ 'alerts.expiry': 1 }, { expireAfterSeconds: 0 });
        console.log('Created TTL index on alerts.expiry');
      }
      if (!indexNames.includes('email_1')) {
        await User.collection.createIndex({ email: 1 });
        console.log('Created index on email');
      }
      
      console.log('=== MONGODB CONNECTION COMPLETE ===\n');
      return;
    } catch (error) {
      console.error('❌ MongoDB connection error:', error.message, error.stack);
      
      if (error.message.includes('bad auth')) {
        console.error('🔑 Authentication failed - check username/password in MongoDB Atlas');
      } else if (error.message.includes('ENOTFOUND')) {
        console.error('🌐 DNS lookup failed - check cluster URL');
      } else if (error.message.includes('IP') || error.message.includes('not authorized')) {
        console.error('🚫 IP not whitelisted - add 0.0.0.0/0 to MongoDB Atlas Network Access');
      }
      
      retries--;
      if (retries === 0) {
        console.error('💀 MongoDB connection failed after retries');
        process.exit(1);
      }
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }
}
connectDB();

// VAPID Keys
const vapidKeys = {
  publicKey: process.env.VAPID_PUBLIC_KEY,
  privateKey: process.env.VAPID_PRIVATE_KEY
};
webpush.setVapidDetails(
  'mailto:admin@example.com',
  vapidKeys.publicKey,
  vapidKeys.privateKey
);

// Routes
app.get('/api/vapid-public-key', (req, res) => {
  console.log('Serving VAPID public key');
  if (!vapidKeys.publicKey) {
    console.error('VAPID_PUBLIC_KEY is not defined in .env');
    return res.status(500).json({ error: 'VAPID public key not configured' });
  }
  res.json({ publicKey: vapidKeys.publicKey });
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
    if (isNaN(lng) || isNaN(lat)) {
      console.error('Invalid coordinates:', location.coordinates);
      return res.status(400).json({ error: 'Invalid coordinates' });
    }
    const timestampDate = timestamp ? new Date(timestamp) : new Date();
    if (isNaN(timestampDate.getTime())) {
      console.error('Invalid timestamp:', timestamp);
      return res.status(400).json({ error: 'Invalid timestamp' });
    }

    // Check MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      console.error('MongoDB not connected! State:', mongoose.connection.readyState);
      return res.status(503).json({ error: 'Database connection unavailable' });
    }

    // Find user
    const user = await User.findById(req.user._id);
    if (!user) {
      console.error('User not found:', req.user._id);
      return res.status(404).json({ error: 'User not found' });
    }

    // Check for duplicate alert
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
      expiry: new Date(Date.now() + 3600000)
    };

    // Add alert to user and update stats
    user.alerts.push(alert);
    user.totalAlerts = (user.totalAlerts || 0) + 1;
    user.activeAlerts = (user.activeAlerts || 0) + 1;
    user.points = (user.points || 0) + 10;

    console.log('Saving alert to MongoDB:', { alertId: alert._id, type, userId: user._id });
    
    try {
      await user.save();
      console.log('✅ Alert successfully saved:', { alertId: alert._id });
    } catch (saveError) {
      console.error('❌ Save error details:', {
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
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to post alert', details: error.message });
  }
});

// Fetch Nearby Alerts
app.get('/api/markers', authMiddleware, async (req, res) => {
  try {
    const { lat, lng, maxDistance = 16093.4 } = req.query;
    if (!lat || !lng || isNaN(parseFloat(lat)) || isNaN(parseFloat(lng))) {
      console.error('Invalid query parameters:', { lat, lng });
      return res.status(400).json({ error: 'Invalid latitude or longitude' });
    }
    console.log('Fetching markers for:', { lat: parseFloat(lat), lng: parseFloat(lng), maxDistance });
    const users = await User.find({
      'alerts.location': {
        $geoWithin: {
          $centerSphere: [[parseFloat(lng), parseFloat(lat)], parseFloat(maxDistance) / 6378137]
        }
      },
      'alerts.expiry': { $gt: new Date() }
    });
    const alerts = users.flatMap(user =>
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
    console.log('Returning markers:', alerts.length);
    res.json(alerts);
  } catch (error) {
    console.error('Error fetching markers:', error.message, error.stack);
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to fetch markers', details: error.message });
  }
});

// Fetch Hazards Near Route
app.post('/api/hazards-near-route', authMiddleware, async (req, res) => {
  try {
    const { polyline, maxDistance = 50 } = req.body;
    if (!polyline || !Array.isArray(polyline) || polyline.length === 0) {
      console.error('Invalid polyline data:', polyline);
      return res.status(400).json({ error: 'Invalid polyline data' });
    }
    console.log('Fetching hazards for polyline:', { points: polyline.length, maxDistance });
    const lineString = {
      type: 'LineString',
      coordinates: polyline.map(pt => [pt.lng, pt.lat])
    };
    const users = await User.find({
      'alerts.location': {
        $geoWithin: {
          $geometry: lineString,
          $maxDistance: parseFloat(maxDistance)
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
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to fetch hazards', details: error.message });
  }
});

// Vote on Alert
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
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to vote', details: error.message });
  }
});

// Delete Alert
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
    console.log('Alert deleted successfully:', { alertId: req.params.id, ownerId: owner._id, deleterId: req.user._id });
    req.io.emit('alertDeleted', req.params.id);
    res.json({ message: 'Alert deleted successfully' });
  } catch (error) {
    console.error('Error deleting alert:', error.message, error.stack);
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to delete alert', details: error.message });
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
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to update location', details: error.message });
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
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to fetch leaderboard', details: error.message });
  }
});

// Subscription Status Check
app.get('/api/subscription/status', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('subscription_status trial_end isAdmin email');
    const now = new Date();
    const isAdminUser = user.email === 'imhoggbox@gmail.com' || user.isAdmin;
    const trialActive = user.trial_end && now < user.trial_end;
    const isPremium = user.subscription_status || trialActive || isAdminUser;

    // Auto-start trial if none exists and not subscribed/admin
    if (!isPremium && !user.trial_end && !user.subscription_status && !isAdminUser) {
      user.trial_end = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
      await user.save();
      console.log(`Started 7-day trial for user: ${user._id}`);
    }

    res.json({
      premium: isPremium,
      trialEnd: user.trial_end ? user.trial_end.toISOString() : null,
      isAdmin: isAdminUser
    });
  } catch (error) {
    console.error('Subscription status error:', error);
    res.status(500).json({ error: 'Failed to check subscription' });
  }
});

// Create Checkout Session
app.post('/api/subscription/create-checkout-session', authMiddleware, async (req, res) => {
  try {
    if (!process.env.STRIPE_PRICE_ID) {
      console.error('❌ Error: STRIPE_PRICE_ID is not defined in .env file');
      return res.status(500).json({ error: 'Stripe Price ID not configured' });
    }
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price: process.env.STRIPE_PRICE_ID,
        quantity: 1,
      }],
      mode: 'subscription',
      success_url: `${req.headers.origin}/?success=true&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.headers.origin}/?canceled=true`,
      metadata: {
        userId: req.user._id.toString(),
        email: req.user.email
      },
      subscription_data: {
        trial_period_days: 7
      },
      customer_email: req.user.email
    });
    res.json({ url: session.url });
  } catch (error) {
    console.error('Checkout session error:', error);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Stripe Webhook
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    if (!process.env.STRIPE_WEBHOOK_SECRET) {
      console.error('❌ Error: STRIPE_WEBHOOK_SECRET is not defined in .env file');
      return res.status(400).send('Webhook Error: Webhook secret not configured');
    }
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.log(`Webhook signature verification failed: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const userId = session.metadata.userId;
      if (userId) {
        await User.findByIdAndUpdate(userId, {
          subscription_status: true,
          subscription_id: session.subscription,
          trial_end: null
        });
        console.log(`Subscription activated for user: ${userId}`);
      }
    } else if (event.type === 'customer.subscription.deleted') {
      const subscription = event.data.object;
      const user = await User.findOne({ subscription_id: subscription.id });
      if (user) {
        await User.findByIdAndUpdate(user._id, {
          subscription_status: false,
          subscription_id: null
        });
        console.log(`Subscription cancelled for user: ${user._id}`);
      }
    }
    res.json({ received: true });
  } catch (err) {
    console.error('Webhook handler error:', err);
    res.status(400).send(`Webhook Error: ${err.message}`);
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
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to fetch users', details: error.message });
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
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to search users', details: error.message });
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
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to fetch user activity', details: error.message });
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
    console.log('User promoted:', req.params.id);
    res.json({ message: 'User promoted to admin' });
  } catch (error) {
    console.error('Error promoting user:', error.message, error.stack);
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to promote user', details: error.message });
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
    console.log('User demoted:', req.params.id);
    res.json({ message: 'User demoted from admin' });
  } catch (error) {
    console.error('Error demoting user:', error.message, error.stack);
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to demote user', details: error.message });
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
    console.log('User banned:', req.params.id);
    req.io.emit('userBanned', { userId: req.params.id });
    res.json({ message: 'User banned' });
  } catch (error) {
    console.error('Error banning user:', error.message, error.stack);
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to ban user', details: error.message });
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
    console.log('User IP banned:', req.params.id);
    req.io.emit('userBanned', { userId: req.params.id });
    res.json({ message: 'User IP banned' });
  } catch (error) {
    console.error('Error IP banning user:', error.message, error.stack);
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to IP ban user', details: error.message });
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
    console.log('User deleted:', req.params.id);
    req.io.emit('userBanned', { userId: req.params.id });
    res.json({ message: 'User deleted' });
  } catch (error) {
    console.error('Error deleting user:', error.message, error.stack);
    res.status(error.name === 'TokenExpiredError' ? 401 : 500).json({ error: 'Failed to delete user', details: error.message });
  }
});

function getDistance(point1, point2) {
  const R = 6371e3;
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

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message, err.stack);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

// Socket.IO Events
io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id);
  socket.on('join', (userId) => {
    socket.join(userId);
    console.log(`User ${userId} joined room`);
  });
  socket.on('locationUpdate', async ({ location }) => {
    const token = socket.handshake.auth.token;
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id);
      if (user && !user.isBanned) {
        io.to(decoded.id).emit('locationUpdate', { userId: decoded.id, location });
        console.log('Location update emitted:', { userId: decoded.id, location });
      }
    } catch (error) {
      console.error('Error in locationUpdate:', error.message);
    }
  });
  socket.on('disconnect', () => {
    console.log('Socket disconnected:', socket.id);
  });
});

// Start Server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));