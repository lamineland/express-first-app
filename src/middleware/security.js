'use strict';

const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const cors = require('cors');
const env = require('../config/env');
const AppError = require('../utils/AppError');

/**
 * Helmet sets security-related response headers (CSP, HSTS, no-sniff,
 * frameguard, etc.). Sensible defaults for a JSON API.
 */
const helmetMiddleware = () =>
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        // This API serves JSON only; no scripts, styles or frames should load.
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    // The API is HTTPS-only behind a proxy in production.
    hsts: env.isProduction
      ? { maxAge: 31536000, includeSubDomains: true, preload: true }
      : false,
    crossOriginResourcePolicy: { policy: 'same-site' },
    crossOriginEmbedderPolicy: false,
  });

/**
 * Strip MongoDB operators ($gt, $ne, ...) and dots from user input so that
 * payloads like {"email": {"$gt": ""}} cannot become query operators.
 *
 * Re-assigns the sanitized values because express-mongo-sanitize mutates in
 * place in Express 4, but being explicit keeps req.body/query/params
 * consistent regardless of version.
 */
const sanitizeRequest = () => (req, res, next) => {
  ['body', 'query', 'params'].forEach((key) => {
    if (req[key] && typeof req[key] === 'object') {
      req[key] = mongoSanitize.sanitize(req[key], {
        allowDots: false,
        replaceWith: '_',
      });
    }
  });
  next();
};

/**
 * Escape dangerous HTML/JS from user input to limit stored-XSS payloads.
 * Runs after mongo-sanitize so both concerns are covered.
 */
const cleanXss = () => xss();

/**
 * CORS restricted to an explicit allowlist. `credentials: true` is required
 * so browsers send the HTTP-only auth cookie.
 */
const corsMiddleware = () =>
  cors({
    origin(origin, callback) {
      // Allow same-origin / server-to-server requests that send no Origin.
      if (!origin) return callback(null, true);

      if (env.cors.origins.includes(origin)) return callback(null, true);

      return callback(
        AppError.forbidden(`Origin ${origin} is not allowed to access this API`, {
          code: 'CORS_NOT_ALLOWED',
        })
      );
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400,
  });

module.exports = {
  helmetMiddleware,
  sanitizeRequest,
  cleanXss,
  corsMiddleware,
};
