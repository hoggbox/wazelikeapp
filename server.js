require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const turf = require('@turf/turf');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

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
  address: { type: String } // Optional: Reverse-geocoded address
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
  .then(() => console.log('Connected to MongoDB Atlas (pinmap database)'))
  .catch(err => console.error('MongoDB connection error:', err));

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
    if (!type || !location || !location.coordinates || !timestamp) {
      return res.status(400).json({ error: 'Invalid alert data' });
    }
    // Validate coordinates
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
      address
    });
    await alert.save();
    io.emit('alert', alert); // Broadcast to all clients
    res.status(201).json({ message: 'Alert saved successfully', alert });
  } catch (error) {
    console.error('Error saving alert:', error);
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
    const markers = await Alert.find({
      location: {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: [parseFloat(lng), parseFloat(lat)]
          },
          $maxDistance: parseInt(maxDistance) // Default 50km
        }
      }
    });
    res.status(200).json(markers);
  } catch (err) {
    console.error('Error fetching markers:', err);
    res.status(500).json({ error: err.message });
  }
});

// API endpoint to check for hazards near a route polyline
app.post('/api/hazards-near-route', async (req, res) => {
  const { polyline } = req.body;
  try {
    if (!polyline || !Array.isArray(polyline) || polyline.length < 2) {
      return res.status(400).json({ error: 'Invalid polyline data: must be an array with at least 2 points' });
    }
    // Validate polyline coordinates
    for (const [lng, lat] of polyline) {
      if (isNaN(lng) || isNaN(lat) || lng < -180 || lng > 180 || lat < -90 || lat > 90) {
        return res.status(400).json({ error: `Invalid coordinates in polyline: [${lng}, ${lat}]` });
      }
    }
    // Convert polyline to GeoJSON LineString
    const routeLineString = turf.lineString(polyline);
    
    // Create a buffered polygon (2 miles ≈ 3.21869 km)
    const bufferDistance = 3.21869; // 2 miles in kilometers
    let bufferedPolygon = turf.buffer(routeLineString, bufferDistance, { units: 'kilometers' });

    // Handle MultiPolygon case
    if (bufferedPolygon.geometry.type === 'MultiPolygon') {
      bufferedPolygon = turf.flatten(bufferedPolygon);
      bufferedPolygon = bufferedPolygon.features[0]; // Use the first polygon
    }

    // Simplify to prevent self-intersection
    const simplifiedPolygon = turf.simplify(bufferedPolygon, { tolerance: 0.001, highQuality: true });

    // Validate geometry
    if (simplifiedPolygon.geometry.type !== 'Polygon') {
      console.error('Simplified geometry is not a valid polygon:', simplifiedPolygon.geometry.type);
      return res.status(500).json({ error: 'Failed to generate a valid buffer polygon' });
    }

    console.log('Searching for hazards intersecting with buffered polygon...');

    const hazards = await Alert.find({
      location: {
        $geoWithin: {
          $geometry: simplifiedPolygon.geometry
        }
      },
      timestamp: { $gte: new Date(Date.now() - 60 * 60 * 1000) } // Recent alerts
    }).limit(1); // Closest hazard

    res.status(200).json(hazards);
  } catch (err) {
    console.error('Error checking hazards near route:', err);
    res.status(500).json({ error: err.message });
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
const rateLimit = new Map();
const LOCATION_UPDATE_INTERVAL = 1000; // 1 update per second per user

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // Send recent alerts to new clients (last 1 hour)
  Alert.find({ timestamp: { $gte: new Date(Date.now() - 60 * 60 * 1000) } })
    .then(alerts => {
      alerts.forEach(alert => socket.emit('alert', alert));
    })
    .catch(err => console.error('Error fetching alerts:', err));

  socket.on('locationUpdate', (data) => {
    if (!data.location || typeof data.location.lat !== 'number' || typeof data.location.lng !== 'number') {
      console.error('Invalid location data from', socket.id, ':', data);
      return;
    }

    const now = Date.now();
    const lastUpdate = rateLimit.get(socket.id) || 0;
    if (now - lastUpdate < LOCATION_UPDATE_INTERVAL) {
      return;
    }
    rateLimit.set(socket.id, now);

    console.log('Location update from', socket.id, ':', data.location);
    socket.broadcast.emit('locationUpdate', data);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
    rateLimit.delete(socket.id);
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT} in ${process.env.NODE_ENV} mode with Socket.IO`);
});