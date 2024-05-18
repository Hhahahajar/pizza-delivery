// Update your Mongoose connection code
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    await mongoose.connect('mongodb+srv://sitihajar:hajar1234@cluster0.kjy5ogp.mongodb.net/pizza', {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });
      console.log('MongoDB connected');
    } catch (error) {
      console.error('MongoDB connection error:', error);
      process.exit(1); // Exit process with failure
    }
  };
  
  module.exports = connectDB;