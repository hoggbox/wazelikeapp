const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    console.log('Attempting MongoDB connection to:', process.env.MONGODB_URI);
    await mongoose.connect(process.env.MONGODB_URI, {});
    console.log('MongoDB connected successfully');
  } catch (err) {
    console.error('MongoDB connection failed:', err.message, err.stack);
    process.exit(1);
  }
};

module.exports = connectDB;