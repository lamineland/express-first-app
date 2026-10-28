'use strict';

/**
 * Operational error with an HTTP status code.
 *
 * Anything thrown as an AppError is considered a *known* error: it is safe to
 * expose its message to the client. Anything else is a programming error and
 * is reported as a generic 500 by the error middleware.
 */
class AppError extends Error {
  /**
   * @param {string} message  human-readable, client-safe message
   * @param {number} statusCode HTTP status code
   * @param {object} [options]
   * @param {string} [options.code] machine-readable error code for clients
   * @param {Array}  [options.details] validation details, field errors, etc.
   */
  constructor(message, statusCode, options = {}) {
    super(message);

    this.name = 'AppError';
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;

    if (options.code) this.code = options.code;
    if (options.details) this.details = options.details;

    Error.captureStackTrace(this, this.constructor);
  }

  static badRequest(message = 'Bad request', options) {
    return new AppError(message, 400, options);
  }

  static unauthorized(message = 'Authentication required', options) {
    return new AppError(message, 401, options);
  }

  static forbidden(message = 'You do not have permission to perform this action', options) {
    return new AppError(message, 403, options);
  }

  static notFound(message = 'Resource not found', options) {
    return new AppError(message, 404, options);
  }

  static conflict(message = 'Resource already exists', options) {
    return new AppError(message, 409, options);
  }

  static tooManyRequests(message = 'Too many requests, please try again later', options) {
    return new AppError(message, 429, options);
  }

  static internal(message = 'Something went wrong', options) {
    return new AppError(message, 500, options);
  }
}

module.exports = AppError;
