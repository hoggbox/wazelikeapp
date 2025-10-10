const mongoose = require('mongoose');

const alertSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    enum: [
      'Slowdown',
      'Crash',
      'Construction',
      'Police',
      'Object on Road',
      'Lane Closure',
      'Manual Report',
      'Low Visibility',
      'Traffic Camera',
      'Manual Traffic Camera'
    ] // Restrict to valid alert types
  },
  location: {
    type: { type: String, enum: ['Point'], required: true },
    coordinates: {
      type: [Number],
      required: true,
      validate: {
        validator: function (coords) {
          return (
            Array.isArray(coords) &&
            coords.length === 2 &&
            coords[0] >= -180 && coords[0] <= 180 && // lng
            coords[1] >= -90 && coords[1] <= 90 // lat
          );
        },
        message: 'Invalid coordinates: must be [lng, lat] with lng [-180, 180] and lat [-90, 90]'
      }
    }
  },
  address: { type: String },
  timestamp: { type: Date, default: Date.now },
  votes: {
    up: { type: Number, default: 0 },
    down: { type: Number, default: 0 },
    upVoters: [{ type: mongoose.Schema.Types.ObjectId }],
    downVoters: [{ type: mongoose.Schema.Types.ObjectId }]
  },
  expiry: { type: Date, default: () => new Date(Date.now() + 3600000) }
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: { type: String, required: false },
  lastName: { type: String, required: false },
  birthdate: { type: Date, required: false },
  sex: { type: String, enum: ['Male', 'Female', 'Other'], required: false },
  location: { type: String, required: false },
  joinDate: { type: Date, default: Date.now },
  alerts: [alertSchema],
  totalAlerts: { type: Number, default: 0 },
  activeAlerts: { type: Number, default: 0 },
  points: { type: Number, default: 0 },
  achievements: [{ type: String }],
  isAdmin: { type: Boolean, default: false },
  isBanned: { type: Boolean, default: false },
  ipBanned: { type: String, required: false },
  lastLocation: {
    type: { type: String, enum: ['Point'], required: false },
    coordinates: {
      type: [Number],
      required: false,
      validate: {
        validator: function (coords) {
          return !coords || (
            Array.isArray(coords) &&
            coords.length === 2 &&
            coords[0] >= -180 && coords[0] <= 180 && // lng
            coords[1] >= -90 && coords[1] <= 90 // lat
          );
        },
        message: 'Invalid lastLocation coordinates: must be [lng, lat] with lng [-180, 180] and lat [-90, 90] or null'
      }
    }
  },
  lastActive: { type: Date, required: false },
  pushSubscription: { type: Object, required: false },
  familyMembers: [{ email: { type: String, required: true } }],
  subscription_status: { type: Boolean, default: false },
  subscription_id: { type: String, default: null }, // Stripe subscription ID
  trial_end: { type: Date, default: null } // End of 7-day trial
});

// Indexes
userSchema.index({ 'alerts.location': '2dsphere' }); // For geospatial queries on alerts
userSchema.index({ lastLocation: '2dsphere' }, { sparse: true }); // Sparse index for lastLocation
userSchema.index({ email: 1 }); // For faster login/register
userSchema.index({ 'alerts.expiry': 1 }, { expireAfterSeconds: 0 }); // TTL index for auto-deleting expired alerts

module.exports = mongoose.model('User', userSchema);