'use strict';

const path = require('path');
const crypto = require('crypto');

require('dotenv').config({ path: path.resolve(__dirname, '../../.env'), quiet: true });

const toBool = (value, fallback = false) => {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
};

const toInt = (value, fallback) => {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
};

const nodeEnv = process.env.NODE_ENV || 'development';
const isProduction = nodeEnv === 'production';
const isTest = nodeEnv === 'test';

/**
 * The JWT secret is the single most sensitive value in the app: anyone who has
 * it can mint valid tokens. Fail fast in production, and fall back to a random
 * per-process secret in development so a missing .env never becomes an
 * insecure default that silently reaches production.
 */
const resolveJwtSecret = () => {
  const secret = process.env.JWT_SECRET;

  if (!secret || secret.includes('replace-me')) {
    if (isProduction) {
      throw new Error(
        'JWT_SECRET is missing or is still the placeholder value. Set a long random JWT_SECRET before starting in production.'
      );
    }

    if (!isTest) {
      console.warn(
        '[config] JWT_SECRET is not set (or is the placeholder). Using a random development secret; all tokens are invalidated on restart.'
      );
    }

    return crypto.randomBytes(48).toString('hex');
  }

  if (isProduction && secret.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters in production.');
  }

  return secret;
};

const corsOrigins = (process.env.CORS_ORIGIN || 'http://localhost:3000')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

const googleClientId = process.env.GOOGLE_CLIENT_ID || '';
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET || '';

const port = toInt(process.env.PORT, 4000);

const env = {
  nodeEnv,
  isProduction,
  isTest,

  port,
  mongoUri: process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/task_manager',

  jwt: {
    secret: resolveJwtSecret(),
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
    issuer: 'task-manager-api',
  },

  cookie: {
    name: process.env.COOKIE_NAME || 'access_token',
    maxAgeMs: toInt(process.env.COOKIE_MAX_AGE_DAYS, 7) * 24 * 60 * 60 * 1000,
    sameSite: process.env.COOKIE_SAME_SITE || 'lax',
    // Cookies are only sent over HTTPS in production.
    secure: isProduction,
  },

  cors: {
    origins: corsOrigins,
  },

  google: {
    clientId: googleClientId,
    clientSecret: googleClientSecret,
    callbackUrl:
      process.env.GOOGLE_CALLBACK_URL ||
      `http://localhost:${port}/api/auth/google/callback`,
    isConfigured: Boolean(googleClientId && googleClientSecret),
  },

  clientUrl: process.env.CLIENT_URL || 'http://localhost:3000',

  rateLimit: {
    authMax: toInt(process.env.AUTH_RATE_LIMIT_MAX, 5),
    authWindowMs: toInt(process.env.AUTH_RATE_LIMIT_WINDOW_MINUTES, 15) * 60 * 1000,
    globalMax: toInt(process.env.GLOBAL_RATE_LIMIT_MAX, 300),
  },

  // Convenience for API clients during development only.
  exposeTokenInResponse: toBool(process.env.EXPOSE_TOKEN_IN_RESPONSE, false),
};

module.exports = env;
