const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const alertSubSchema = new mongoose.Schema({
  _id: { type: mongoose.Schema.Types.ObjectId, auto: true },
  type: { type: String, required: true }, // e.g., 'Crash', 'Police'
  location: {
    type: {
      type: String,
      enum: ['Point'],
      required: true,
      default: 'Point'
    },
    coordinates: {
      type: [Number], // [lng, lat]
      required: true
    }
  },
  address: { type: String, default: 'Unknown' },
  timestamp: { type: Date, required: true, default: Date.now },
  votes: {
    up: { type: Number, default: 0 },
    down: { type: Number, default: 0 },
    upVoters: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    downVoters: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
  },
  expiry: { type: Date, required: true } // TTL handled server-side
}, { _id: false }); // No separate _id for subdocs, but allow manual

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, lowercase: true },
  email: { type: String, required: true, unique: true, trim: true, lowercase: true },
  password: { type: String, required: true, minlength: 6 },
  avatar: { type: String, default: null },
  bio: { type: String, default: '', maxlength: 500 },
  points: { type: Number, default: 0 },
  achievements: [{ type: String }],
  contributions: [{
    type: { type: String, enum: ['alert', 'comment', 'like'] },
    points: Number,
    date: { type: Date, default: Date.now }
  }],
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  pendingRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  pushSubscription: { type: Object, default: null }, // Store directly as object
  familyMembers: [{ email: { type: String, required: true } }], // For sharing
  alerts: [alertSubSchema], // Embedded alerts array
  totalAlerts: { type: Number, default: 0 }, // Computed total
  activeAlerts: { type: Number, default: 0 }, // Computed active (non-expired)
  isAdmin: { type: Boolean, default: false },
  isBanned: { type: Boolean, default: false },
  ipBanned: { type: String, default: null }, // For IP bans
  lastLocation: {
    type: {
      type: String,
      enum: ['Point'],
      default: 'Point'
    },
    coordinates: {
      type: [Number], // [lng, lat]
      sparse: true
    }
  },
  lastActive: { type: Date, default: Date.now },
  joinDate: { type: Date, default: Date.now }, // Alias for createdAt
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Indexes (complement server-side creation)
userSchema.index({ 'alerts.location': '2dsphere' });
userSchema.index({ 'alerts.expiry': 1 }, { expireAfterSeconds: 3600 }); // 1h TTL
userSchema.index({ email: 1 });
userSchema.index({ lastLocation: '2dsphere' }, { sparse: true });
userSchema.index({ isBanned: 1 });
userSchema.index({ createdAt: -1 }); // For leaderboards/join dates

// Pre-save middleware for password hashing
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.updatedAt = Date.now();
  next();
});

// Instance method for password comparison
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Instance method to add alert (with stats update)
userSchema.methods.addAlert = async function(alertData) {
  const alert = new mongoose.Types.Subdocument(alertData, this.schema.path('alerts').schema);
  this.alerts.push(alert);
  this.totalAlerts += 1;
  this.activeAlerts += 1;
  this.points += 10; // Reward points
  await this.save();
  return alert;
};

// Instance method to remove alert (with stats update)
userSchema.methods.removeAlert = async function(alertId) {
  const alertIndex = this.alerts.findIndex(a => a._id.toString() === alertId.toString());
  if (alertIndex !== -1) {
    this.alerts.splice(alertIndex, 1);
    this.activeAlerts = Math.max(0, this.activeAlerts - 1);
    await this.save();
    return true;
  }
  return false;
};

// Virtual for full name (optional enhancement)
userSchema.virtual('fullName').get(function() {
  return `${this.username}`;
});

// Ensure updatedAt on update
userSchema.pre(['updateOne', 'findOneAndUpdate'], function() {
  this.set({ updatedAt: new Date() });
});

// Safe populate method (avoids CVE-2025-23061 nested issues)
userSchema.methods.safePopulate = function(fields = []) {
  return this.populate(fields.map(field => ({ path: field, match: { expiry: { $gt: new Date() } } })));
};

module.exports = mongoose.model('User', userSchema);