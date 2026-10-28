'use strict';

const jwt = require('jsonwebtoken');
const env = require('../config/env');

/**
 * Issue a signed JWT for a user. The payload is intentionally minimal: only
 * the user id and role, never the email or password.
 */
const signToken = (user) =>
  jwt.sign(
    {
      sub: user._id.toString(),
      role: user.role,
    },
    env.jwt.secret,
    {
      expiresIn: env.jwt.expiresIn,
      issuer: env.jwt.issuer,
    }
  );

/**
 * Verify a token and return its payload. Throws JsonWebTokenError or
 * TokenExpiredError, which the error middleware maps to 401.
 */
const verifyTokenSignature = (token) =>
  jwt.verify(token, env.jwt.secret, { issuer: env.jwt.issuer });

module.exports = { signToken, verifyTokenSignature };
