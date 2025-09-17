const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  avatar: { type: String, default: null }, // URL to avatar
  bio: { type: String, default: '' },
  points: { type: Number, default: 0 },
  achievements: [{ type: String }], // e.g., ['First Alert', 'Top Contributor']
  contributions: [{
    type: { type: String, enum: ['alert', 'comment', 'like'] },
    points: Number,
    date: { type: Date, default: Date.now }
  }],
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  pendingRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  pushSubscription: { type: Object }, // For push notifications
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);