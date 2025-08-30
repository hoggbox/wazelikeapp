require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const turf = require('@turf/turf');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Rate limiting for API endpoints
const apiRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit to 100 requests per window
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api', apiRateLimit);

// MongoDB Alert Schema with GeoJSON and TTL
const alertSchema = new mongoose.Schema({
  type: { type: String, required: true },
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
  userId: { type: String },
  timestamp: { type: Date, default: Date.now, expires: 3600 }, // Auto-delete after 1 hour
  address: { type: String },
  votes: { type: Number, default: 0 }
});

// Ensure 2dsphere index for geospatial queries
alertSchema.index({ location: '2dsphere' });

const Alert = mongoose.model('Alert', alertSchema);

// Connect to MongoDB Atlas with reconnection logic
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 15000,
  maxPoolSize: 10,
  retryWrites: true,
  retryReads: true
})
  .then(() => console.log('Connected to MongoDB Atlas (pinmap database)'))
  .catch(err => console.error('MongoDB connection error:', err));

// Handle MongoDB connection events
mongoose.connection.on('error', err => {
  console.error('MongoDB connection error:', err);
});
mongoose.connection.on('disconnected', () => {
  console.warn('MongoDB disconnected, attempting to reconnect...');
  setTimeout(() => {
    mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 15000,
      maxPoolSize: 10,
      retryWrites: true,
      retryReads: true
    }).catch(err => console.error('MongoDB reconnection failed:', err));
  }, 5000);
});

// Serve static files from /public
app.use(express.static('public'));

// Basic route for the homepage
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// API endpoint to save alerts and broadcast via Socket.IO
app.post('/api/alerts', async (req, res) => {
  try {
    const { type, location, timestamp, userId, address } = req.body;
    console.log('Received alert data:', req.body);
    if (!type || !location || !location.coordinates || !timestamp) {
      return res.status(400).json({ error: 'Invalid alert data' });
    }
    if (!Array.isArray(location.coordinates) || location.coordinates.length !== 2) {
      return res.status(400).json({ error: 'Invalid coordinates format' });
    }
    const [lng, lat] = location.coordinates;
    if (isNaN(lng) || isNaN(lat) || lng < -180 || lng > 180 || lat < -90 || lat > 90) {
      return res.status(400).json({ error: 'Invalid longitude or latitude values' });
    }
    const alert = new Alert({
      type,
      location: {
        type: 'Point',
        coordinates: [lng, lat]
      },
      userId,
      timestamp: new Date(timestamp),
      address,
      votes: 0
    });
    await alert.save();
    console.log('Emitting alert to clients:', { id: alert._id, type });
    io.emit('alert', alert);
    res.status(201).json({ message: 'Alert saved successfully', alert });
  } catch (error) {
    console.error('Error saving alert:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to save alert' });
  }
});

// API endpoint to retrieve markers within a radius
app.get('/api/markers', async (req, res) => {
  const { lat, lng, maxDistance = 50000 } = req.query;
  try {
    if (isNaN(parseFloat(lng)) || isNaN(parseFloat(lat))) {
      return res.status(400).json({ error: 'Invalid latitude or longitude' });
    }
    console.log('Fetching markers near:', { lat, lng, maxDistance });
    const markers = await Alert.find({
      location: {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: [parseFloat(lng), parseFloat(lat)]
          },
          $maxDistance: parseInt(maxDistance)
        }
      }
    });
    console.log('Found markers:', markers.length);
    res.status(200).json(markers);
  } catch (error) {
    console.error('Error fetching markers:', error);
    res.status(500).json({ error: error.message });
  }
});

// API endpoint to check for hazards near a route polyline
app.post('/api/hazards-near-route', async (req, res) => {
  const { polyline } = req.body;
  try {
    if (!polyline || !Array.isArray(polyline) || polyline.length < 2) {
      console.error('Invalid polyline data:', polyline);
      return res.status(400).json({ error: 'Invalid polyline data: must be an array with at least 2 points' });
    }
    console.log('Received polyline points:', polyline.length);
    for (const [lng, lat] of polyline) {
      if (isNaN(lng) || isNaN(lat) || lng < -180 || lng > 180 || lat < -90 || lat > 90) {
        console.error('Invalid coordinates in polyline:', [lng, lat]);
        return res.status(400).json({ error: `Invalid coordinates in polyline: [${lng}, ${lat}]` });
      }
    }
    const routeLineString = turf.lineString(polyline);
    const bufferDistance = 3.21869; // 2 miles in kilometers
    console.log('Creating buffer for polyline, distance:', bufferDistance, 'km');
    let bufferedPolygon = turf.buffer(routeLineString, bufferDistance, { units: 'kilometers' });
    if (bufferedPolygon.geometry.type === 'MultiPolygon') {
      console.warn('MultiPolygon detected, flattening to first polygon');
      bufferedPolygon = turf.flatten(bufferedPolygon);
      bufferedPolygon = bufferedPolygon.features[0];
    }
    const simplifiedPolygon = turf.simplify(bufferedPolygon, { tolerance: 0.001, highQuality: true });
    if (simplifiedPolygon.geometry.type !== 'Polygon') {
      console.error('Simplified geometry is not a valid polygon:', simplifiedPolygon.geometry.type);
      return res.status(500).json({ error: 'Failed to generate a valid buffer polygon' });
    }
    console.log('Searching for hazards within buffered polygon');
    const hazards = await Alert.find({
      location: {
        $geoWithin: {
          $geometry: simplifiedPolygon.geometry
        }
      },
      timestamp: { $gte: new Date(Date.now() - 60 * 60 * 1000) }
    }).limit(5);
    console.log('Found hazards:', hazards.length, 'Details:', hazards.map(h => ({ id: h._id, type: h.type, location: h.location.coordinates })));
    res.status(200).json(hazards);
  } catch (error) {
    console.error('Error checking hazards near route:', error);
    res.status(500).json({ error: error.message });
  }
});

// API endpoint for voting on hazards
app.post('/api/alerts/vote', async (req, res) => {
  const { alertId, voteType, userId } = req.body;
  try {
    if (!alertId || !voteType || !userId) {
      console.error('Missing vote parameters:', { alertId, voteType, userId });
      return res.status(400).json({ error: 'Missing alertId, voteType, or userId' });
    }
    if (!['confirm', 'dismiss'].includes(voteType)) {
      console.error('Invalid voteType:', voteType);
      return res.status(400).json({ error: 'Invalid voteType' });
    }
    const alert = await Alert.findById(alertId);
    if (!alert) {
      console.error('Alert not found:', alertId);
      return res.status(404).json({ error: 'Alert not found' });
    }
    alert.votes = voteType === 'confirm' ? alert.votes + 1 : Math.max(0, alert.votes - 1);
    await alert.save();
    console.log(`Vote recorded: ${voteType} for alert ${alertId} by user ${userId}, new votes: ${alert.votes}`);
    io.emit('alert', alert);
    res.status(200).json({ success: true, alert });
  } catch (error) {
    console.error(`Error recording ${voteType} vote for alert ${alertId}:`, error);
    res.status(500).json({ error: 'Failed to record vote' });
  }
});

// Create HTTP server and integrate Socket.IO
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production'
      ? 'https://wazelikeapp.onrender.com'
      : ['http://localhost:3000', 'https://wazelikeapp.onrender.com'],
    methods: ['GET', 'POST']
  }
});

// Rate limiting for Socket.IO events
const rateLimitMap = new Map();
const LOCATION_UPDATE_INTERVAL = 1000;

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);
  Alert.find({ timestamp: { $gte: new Date(Date.now() - 60 * 60 * 1000) } })
    .then(alerts => {
      console.log('Sending', alerts.length, 'recent alerts to client:', socket.id);
      alerts.forEach(alert => socket.emit('alert', alert));
    })
    .catch(err => console.error('Error fetching alerts for new client:', err));
  socket.on('locationUpdate', (data) => {
    if (!data.location || typeof data.location.lat !== 'number' || typeof data.location.lng !== 'number') {
      console.error('Invalid location data from', socket.id, ':', data);
      return;
    }
    const now = Date.now();
    const lastUpdate = rateLimitMap.get(socket.id) || 0;
    if (now - lastUpdate < LOCATION_UPDATE_INTERVAL) {
      return;
    }
    rateLimitMap.set(socket.id, now);
    console.log('Location update from', socket.id, ':', data.location);
    socket.broadcast.emit('locationUpdate', data);
  });
  socket.on('error', (err) => {
    console.error('Socket.IO error for client', socket.id, ':', err);
  });
  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
    rateLimitMap.delete(socket.id);
  });
});

// Start server with port conflict handling
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT} in ${process.env.NODE_ENV} mode with Socket.IO`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Please stop the other process or change PORT.`);
    process.exit(1);
  } else {
    console.error('Server startup error:', err);
    process.exit(1);
  }
});