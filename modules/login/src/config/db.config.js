const mongoose = require('mongoose');
require('dotenv').config();

// Optionally, set strictQuery per Mongoose recommendations
mongoose.set('strictQuery', false);

const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGO_URI_T;
    if (!mongoURI) {
      throw new Error('MONGO_URI is not defined in the environment variables.');
    }
    await mongoose.connect(mongoURI);
    console.log("MongoDB Connected...");
  } catch (error) {
    console.error("MongoDB Connection Error:", error);
    process.exit(1);
  }
};

module.exports = connectDB;
