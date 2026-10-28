'use strict';

const AppError = require('../utils/AppError');

/**
 * Fallback for any request that reached the end of the middleware stack
 * without being handled by a route.
 */
const notFound = (req, res, next) => {
  next(AppError.notFound(`Route ${req.method} ${req.originalUrl} not found`, { code: 'ROUTE_NOT_FOUND' }));
};

module.exports = notFound;
