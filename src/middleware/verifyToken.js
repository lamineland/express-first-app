'use strict';

const AppError = require('../utils/AppError');
const catchAsync = require('../utils/catchAsync');
const { extractToken } = require('../utils/cookie');
const { verifyTokenSignature } = require('../utils/jwt');
const User = require('../models/User');

/**
 * Protects routes: requires a valid JWT (from the HTTP-only cookie or a
 * Bearer header) and attaches the matching user to `req.user`.
 *
 * The user is re-read from the database on every request so that deleted or
 * deactivated accounts lose access immediately instead of waiting for the
 * token to expire.
 */
const verifyToken = catchAsync(async (req, res, next) => {
  const token = extractToken(req);

  if (!token) {
    throw AppError.unauthorized('You are not logged in. Please log in to access this resource.', {
      code: 'NO_TOKEN',
    });
  }

  const payload = verifyTokenSignature(token);

  const user = await User.findById(payload.sub).select('+passwordChangedAt +isActive');

  if (!user) {
    throw AppError.unauthorized('The account for this token no longer exists.', {
      code: 'USER_NOT_FOUND',
    });
  }

  if (!user.isActive) {
    throw AppError.forbidden('This account has been deactivated.', { code: 'ACCOUNT_INACTIVE' });
  }

  // Tokens issued before the last password change are no longer valid.
  if (user.changedPasswordAfter(payload.iat)) {
    throw AppError.unauthorized('Password was changed recently. Please log in again.', {
      code: 'PASSWORD_CHANGED',
    });
  }

  req.user = user;
  req.token = token;

  return next();
});

module.exports = verifyToken;
