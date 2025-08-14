const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String,
  name: String,
  age: Number,
  dob: Date,
  location: String,
  lastUsernameChange: { type: Date, default: null }
});

userSchema.pre('save', async function(next) {
  if (this.isModified('password') && !this.password.startsWith('$2b$')) {
    console.log('Pre-save hook: Hashing password:', this.password);
    this.password = await bcrypt.hash(this.password, 10);
    console.log('Pre-save hook: Hashed password:', this.password);
  }
  next();
});

userSchema.methods.comparePassword = async function(password) {
  console.log('Comparing password:', { input: password, storedHash: this.password });
  return bcrypt.compare(password, this.password);
};

module.exports = mongoose.model('User', userSchema);