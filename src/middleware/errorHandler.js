'use strict';

const AppError = require('../utils/AppError');
const env = require('../config/env');

/**
 * Translate known library errors into AppErrors so the client gets a useful
 * message and a correct status code instead of a blanket 500.
 */
const normalizeError = (err) => {
  // Malformed ObjectId (e.g. GET /tasks/not-an-id) -> 400, not 500.
  if (err.name === 'CastError') {
    return AppError.badRequest(`Invalid ${err.path}: ${err.value}`, {
      code: 'INVALID_ID',
    });
  }

  // Mongoose validation failures -> 400 with per-field details.
  if (err.name === 'ValidationError') {
    const details = Object.values(err.errors).map((e) => ({
      field: e.path,
      message: e.message,
    }));
    return AppError.badRequest('Validation failed', { code: 'VALIDATION_ERROR', details });
  }

  // Duplicate unique key (e.g. signing up with an existing email) -> 409.
  if (err.code === 11000) {
    const fields = Object.keys(err.keyValue || {});
    return AppError.conflict(
      fields.length ? `That ${fields.join(', ')} is already in use` : 'That value is already in use',
      { code: 'DUPLICATE_KEY' }
    );
  }

  // JWT failures.
  if (err.name === 'JsonWebTokenError') {
    return AppError.unauthorized('Invalid authentication token', { code: 'INVALID_TOKEN' });
  }
  if (err.name === 'TokenExpiredError') {
    return AppError.unauthorized('Your session has expired, please log in again', {
      code: 'TOKEN_EXPIRED',
    });
  }

  // body-parser errors (invalid JSON, payload too large).
  if (err.type === 'entity.parse.failed') {
    return AppError.badRequest('Malformed JSON in request body', { code: 'INVALID_JSON' });
  }
  if (err.type === 'entity.too.large') {
    return new AppError('Request body too large', 413, { code: 'PAYLOAD_TOO_LARGE' });
  }

  // Unsupported content type.
  if (err.status === 415) {
    return new AppError('Unsupported content type', 415, { code: 'UNSUPPORTED_MEDIA_TYPE' });
  }

  return err;
};

const sendErrorDev = (err, req, res) => {
  res.status(err.statusCode).json({
    status: err.status,
    error: {
      code: err.code || 'ERROR',
      message: err.message,
      ...(err.details ? { details: err.details } : {}),
      stack: err.stack,
    },
    request: { method: req.method, path: req.originalUrl },
  });
};

const sendErrorProd = (err, req, res) => {
  // Only operational errors are safe to expose to the client.
  if (err.isOperational) {
    return res.status(err.statusCode).json({
      status: err.status,
      error: {
        code: err.code || 'ERROR',
        message: err.message,
        ...(err.details ? { details: err.details } : {}),
      },
    });
  }

  // Unknown error: log everything, leak nothing.
  console.error('[fatal] unexpected error:', err);
  return res.status(500).json({
    status: 'error',
    error: { code: 'INTERNAL_ERROR', message: 'Something went wrong' },
  });
};

/**
 * Centralized error-handling middleware. Must be registered last, after all
 * routes. Express identifies it as an error handler by its 4-argument
 * signature, so `next` cannot be omitted.
 */
// eslint-disable-next-line no-unused-vars
const errorHandler = (err, req, res, next) => {
  const normalized = normalizeError(err);

  if (!normalized.statusCode) {
    normalized.statusCode = 500;
    normalized.status = 'error';
  }

  // Mongoose duplicate-key errors arrive with a numeric `code`; treat them as
  // non-operational noise only when they were not already converted.
  if (normalized.statusCode >= 500 && !env.isTest) {
    console.error(`[error] ${req.method} ${req.originalUrl}`, err);
  }

  if (env.isProduction) return sendErrorProd(normalized, req, res);
  return sendErrorDev(normalized, req, res);
};

module.exports = errorHandler;
module.exports.normalizeError = normalizeError;
