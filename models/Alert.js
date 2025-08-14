const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const alertSchema = new Schema({
  location: {
    type: { type: String, default: 'Point' },
    coordinates: { type: [Number], required: true }
  },
  type: { type: String, required: true },
  user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now, expires: 10800 }, // Auto-delete after 3 hours
  notes: String
});

alertSchema.index({ location: '2dsphere' }); // For geospatial queries

module.exports = mongoose.model('Alert', alertSchema);