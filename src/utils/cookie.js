'use strict';

const env = require('../config/env');

/**
 * Cookie options for the auth token.
 *
 * httpOnly  -- JavaScript cannot read it, so an XSS bug cannot steal the token.
 * secure    -- HTTPS only in production.
 * sameSite  -- 'lax' blocks the cookie on cross-site subrequests, which is the
 *              main CSRF vector while still allowing normal navigation.
 * path      -- scoped to the whole API so every protected route receives it.
 */
const cookieOptions = () => ({
  httpOnly: true,
  secure: env.cookie.secure,
  sameSite: env.cookie.sameSite,
  maxAge: env.cookie.maxAgeMs,
  path: '/',
});

/**
 * Set the auth token as an HTTP-only cookie.
 */
const setAuthCookie = (res, token) => {
  res.cookie(env.cookie.name, token, cookieOptions());
};

/**
 * Clear the auth cookie. The browser only removes a cookie when the options
 * match those used to set it, so we reuse them minus maxAge.
 */
const clearAuthCookie = (res) => {
  const { maxAge, ...options } = cookieOptions();
  res.clearCookie(env.cookie.name, options);
};

/**
 * Read the token from the request. Accepts the cookie (primary) or an
 * `Authorization: Bearer <token>` header, which is handy for API clients and
 * tests.
 */
const extractToken = (req) => {
  if (req.cookies && req.cookies[env.cookie.name]) {
    return req.cookies[env.cookie.name];
  }

  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    return header.slice('Bearer '.length).trim();
  }

  return null;
};

module.exports = { setAuthCookie, clearAuthCookie, extractToken, cookieOptions };
