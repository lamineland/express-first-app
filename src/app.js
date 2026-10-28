'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');

const env = require('./config/env');
const { configurePassport, passport } = require('./config/passport');

const {
  helmetMiddleware,
  sanitizeRequest,
  cleanXss,
  corsMiddleware,
} = require('./middleware/security');
const { globalLimiter } = require('./middleware/rateLimiter');
const notFound = require('./middleware/notFound');
const errorHandler = require('./middleware/errorHandler');

const authRoutes = require('./routes/authRoutes');
const taskRoutes = require('./routes/taskRoutes');

/**
 * Build the Express app.
 *
 * Kept separate from server.js so tests can import the app without opening a
 * port or connecting to a database.
 */
const createApp = () => {
  const app = express();

  // Behind a proxy (Render, Heroku, Nginx) so rate limiting sees real client
  // IPs and `secure` cookies work over HTTPS.
  app.set('trust proxy', 1);

  // Do not advertise the framework.
  app.disable('x-powered-by');

  // --- security headers ---------------------------------------------------
  app.use(helmetMiddleware());

  // --- CORS ---------------------------------------------------------------
  app.use(corsMiddleware());

  // --- logging ------------------------------------------------------------
  if (!env.isTest) {
    app.use(morgan(env.isProduction ? 'combined' : 'dev'));
  }

  // --- body parsing -------------------------------------------------------
  // Small limit: this API only accepts JSON documents.
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: true, limit: '10kb' }));

  // --- cookies ------------------------------------------------------------
  app.use(cookieParser());

  // --- sanitization -------------------------------------------------------
  // Order matters: strip Mongo operators first, then escape XSS vectors.
  app.use(sanitizeRequest());
  app.use(cleanXss());

  // --- passport -----------------------------------------------------------
  app.use(passport.initialize());
  configurePassport();

  // --- rate limiting ------------------------------------------------------
  app.use('/api', globalLimiter);

  // --- routes -------------------------------------------------------------
  app.get('/health', (req, res) => {
    res.status(200).json({ status: 'success', message: 'API is healthy' });
  });

  app.use('/api/auth', authRoutes);
  app.use('/api/tasks', taskRoutes);

  // --- 404 + centralized errors -------------------------------------------
  app.use(notFound);
  app.use(errorHandler);

  return app;
};

module.exports = createApp;
