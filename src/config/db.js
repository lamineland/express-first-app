'use strict';

const mongoose = require('mongoose');
const env = require('./env');

/**
 * Connect to MongoDB. Callers are expected to handle the rejected promise
 * (the server entrypoint logs and exits).
 */
const connectDB = async (uri = env.mongoUri) => {
  mongoose.set('strictQuery', true);

  const connection = await mongoose.connect(uri, {
    serverSelectionTimeoutMS: 10000,
  });

  if (!env.isTest) {
    console.log(`[db] connected to ${connection.connection.host}/${connection.connection.name}`);
  }

  return connection;
};

const disconnectDB = async () => {
  await mongoose.connection.close();
};

module.exports = { connectDB, disconnectDB };
