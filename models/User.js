const mongoose = require('mongoose');
const alertSchema = new mongoose.Schema({
  _id: { type: mongoose.Schema.Types.ObjectId, default: () => new mongoose.Types.ObjectId() },
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
    ]
  },
  location: {
    type: { type: String, enum: ['Point'], required: true },
    coordinates: {
      type: [Number], // [lng, lat]
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
  address: { type: String, default: 'Unknown' },
  timestamp: { type: Date, default: Date.now },
  votes: {
    up: { type: Number, default: 0 },
    down: { type: Number, default: 0 },
    upVoters: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    downVoters: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
  },
  expiry: {
    type: Date,
    default: function () {
      return new Date(Date.now() + (this.type === 'Traffic Camera' || this.type === 'Manual Traffic Camera' ? 24 * 3600000 : 3600000));
    }
  }
});
const offlineRegionSchema = new mongoose.Schema({
  bounds: {
    north: { type: Number, required: true, min: -90, max: 90 },
    south: { type: Number, required: true, min: -90, max: 90 },
    east: { type: Number, required: true, min: -180, max: 180 },
    west: { type: Number, required: true, min: -180, max: 180 }
  },
  name: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});
const familyMemberSchema = new mongoose.Schema({
  email: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
});
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\S+@\S+\.\S+$/, 'Invalid email format']
  },
  password: { type: String, required: true },
  firstName: { type: String, trim: true },
  lastName: { type: String, trim: true },
  birthdate: { type: Date },
  sex: { type: String, enum: ['Male', 'Female', 'Other'] },
  location: { type: String, trim: true },
  joinDate: { type: Date, default: Date.now },
  alerts: [alertSchema],
  totalAlerts: { type: Number, default: 0 },
  activeAlerts: { type: Number, default: 0 },
  points: { type: Number, default: 0 },
  achievements: [{ type: String }],
  isAdmin: { type: Boolean, default: false },
  isBanned: { type: Boolean, default: false },
  ipBanned: { type: String, trim: true },
  lastLocation: {
    type: { type: String, enum: ['Point'] },
    coordinates: {
      type: [Number], // [lng, lat]
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
  lastActive: { type: Date },
  subscriptions: [{ type: Object }], // Multiple push subscriptions
  familyMembers: {
    type: [familyMemberSchema],
    validate: {
      validator: function (members) {
        return members.length <= 5 && new Set(members.map(m => m.email)).size === members.length;
      },
      message: 'Maximum 5 unique family members allowed'
    }
  },
  offlineRegions: {
    type: [offlineRegionSchema],
    validate: {
      validator: function (regions) {
        return regions.length <= 10;
      },
      message: 'Maximum 10 offline regions allowed'
    }
  },
  // Add these fields to the User schema
  trialEndsAt: {
    type: Date,
    default: function() {
      return new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days from now
    }
  },
  subscriptionStatus: {
    type: String,
    enum: ['trial', 'active', 'past_due', 'cancelled', 'inactive'],
    default: 'trial'
  },
  stripeCustomerId: String,
  stripeSubscriptionId: String,
  premiumActivatedAt: Date,
  lastReminderSent: Date,
  reminderCount: {
    type: Number,
    default: 0
  }
});
// Indexes
userSchema.index({ email: 1 }, { unique: true }); // Unique index for email
userSchema.index({ 'alerts.location': '2dsphere' }); // Geospatial index for alerts
userSchema.index({ lastLocation: '2dsphere' }, { sparse: true }); // Sparse index for lastLocation
userSchema.index({ 'alerts.expiry': 1 }, { expireAfterSeconds: 0 }); // TTL index for alerts
module.exports = mongoose.model('User', userSchema);