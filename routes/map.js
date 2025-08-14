const express = require('express');
const router = express.Router();
const axios = require('axios');
const Alert = require('../models/Alert');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
require('dotenv').config();

module.exports = (io) => {
  const authenticateToken = async (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ msg: 'No token provided' });
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      const user = await User.findOne({ username: req.user.username });
      if (!user) {
        console.error('User not found for token:', 'Username:', req.user.username);
        return res.status(403).json({ msg: 'User not found' });
      }
      req.user._id = user._id;
      req.user.email = user.email;
      console.log('Authenticated user:', req.user.username, 'ID:', req.user._id, 'Email:', req.user.email);
      next();
    } catch (err) {
      console.error('Token verification error:', err.message, 'Token:', token);
      return res.status(403).json({ msg: 'Invalid token', error: err.message });
    }
  };

  router.get('/route', async (req, res) => {
    const { start, end } = req.query;
    if (!start || !end) {
      return res.status(400).json({ error: 'Start and end coordinates required' });
    }

    try {
      const [startLat, startLng] = start.split(',').map(Number);
      const [endLat, endLng] = end.split(',').map(Number);
      const fullUrl = `https://graphhopper.com/api/1/route?point=${startLat},${startLng}&point=${endLat},${endLng}&vehicle=car&instructions=true&key=${process.env.GRAPHHOPPER_API_KEY}`;
      console.log(`Requesting route with URL: ${fullUrl}`);
      const response = await axios.get(fullUrl, {
        headers: { 'User-Agent': 'Waze-like-App/1.0' }
      });
      console.log('GraphHopper response:', response.data);
      res.json(response.data);
    } catch (err) {
      console.error('GraphHopper API error:', err.response ? err.response.data : err.message);
      res.status(500).json({ error: 'Failed to retrieve route: ' + (err.response ? err.response.data.message : err.message) });
    }
  });

  router.post('/alert', authenticateToken, async (req, res) => {
    const { latitude, longitude, type, notes } = req.body;
    if (!req.user || !req.user._id) return res.status(401).json({ msg: 'No authenticated user' });

    try {
      // Check for existing alert with same coordinates, type, and user
      const existingAlert = await Alert.findOne({
        user: req.user._id,
        type,
        'location.coordinates': [longitude, latitude],
        createdAt: { $gte: new Date(Date.now() - 5 * 60 * 1000) } // Within 5 minutes
      });

      if (existingAlert) {
        console.log('Duplicate alert detected:', existingAlert._id);
        return res.status(400).json({ msg: 'Duplicate alert detected', alert: existingAlert });
      }

      const alert = new Alert({
        location: { type: 'Point', coordinates: [longitude, latitude] },
        type,
        user: req.user._id,
        notes
      });

      await alert.save();
      const populatedAlert = await Alert.findById(alert._id).populate('user', 'username email');
      res.status(201).json(populatedAlert);
      io.emit(type === 'Hazard' ? 'hazard' : 'detailedAlert', populatedAlert);
    } catch (err) {
      console.error('Alert save error:', err.message, err.stack);
      res.status(500).json({ msg: 'Failed to save alert', error: err.message });
    }
  });

  router.get('/alerts', authenticateToken, async (req, res) => {
    try {
      if (!req.user || !req.user._id) return res.status(401).json({ msg: 'No authenticated user' });
      const alerts = await Alert.find({ user: req.user._id }).populate('user', 'username email').sort({ createdAt: -1 });
      res.json(alerts);
    } catch (err) {
      console.error('Fetch alerts error:', err.message, err.stack);
      res.status(500).json({ msg: 'Failed to fetch alerts', error: err.message });
    }
  });

  router.get('/alerts/user/:username', authenticateToken, async (req, res) => {
    try {
      if (!req.user || !req.user._id) return res.status(401).json({ msg: 'No authenticated user' });
      if (req.params.username !== req.user.username) return res.status(403).json({ msg: 'Forbidden' });
      const alerts = await Alert.find({ user: req.user._id }).populate('user', 'username email').sort({ createdAt: -1 });
      res.json(alerts);
    } catch (err) {
      console.error('Fetch user alerts error:', err.message, err.stack);
      res.status(500).json({ msg: 'Failed to fetch user alerts', error: err.message });
    }
  });

  router.get('/all-alerts', authenticateToken, async (req, res) => {
    try {
      const alerts = await Alert.find({}).populate('user', 'username email').sort({ createdAt: -1 });
      res.json(alerts);
    } catch (err) {
      console.error('Fetch all alerts error:', err.message, err.stack);
      res.status(500).json({ msg: 'Failed to fetch all alerts', error: err.message });
    }
  });

  router.delete('/alert/:id', authenticateToken, async (req, res) => {
    try {
      if (!req.user || !req.user._id) {
        console.log('No authenticated user in delete request');
        return res.status(401).json({ msg: 'No authenticated user' });
      }
      console.log('Delete request for alert ID:', req.params.id, 'User ID:', req.user._id, 'Email:', req.user.email);
      const alert = await Alert.findById(req.params.id).populate('user', 'username email');
      if (!alert) {
        console.log('Alert not found:', req.params.id);
        return res.status(404).json({ msg: 'Alert not found' });
      }
      if (alert.user._id.toString() !== req.user._id.toString() && req.user.email !== 'imhoggbox@gmail.com') {
        console.log('Unauthorized to delete alert:', alert._id, 'Owner:', alert.user._id, 'Requester:', req.user._id);
        return res.status(403).json({ msg: 'Unauthorized to delete this alert' });
      }
      await Alert.findByIdAndDelete(req.params.id);
      console.log('Alert deleted successfully:', req.params.id);
      res.json({ msg: 'Alert deleted successfully' });
      io.emit('alertRemoved', { _id: req.params.id, user: alert.user });
    } catch (err) {
      console.error('Delete alert error:', err.message, err.stack);
      res.status(500).json({ msg: 'Failed to delete alert', error: err.message });
    }
  });

  return router;
};