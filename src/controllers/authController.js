'use strict';

const passport = require('passport');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const env = require('../config/env');
const User = require('../models/User');
const AppError = require('../utils/AppError');
const catchAsync = require('../utils/catchAsync');
const { signToken } = require('../utils/jwt');
const { setAuthCookie, clearAuthCookie } = require('../utils/cookie');

/**
 * A valid bcrypt hash of a random string, used only to burn equivalent CPU
 * time on the "user not found" path of login.
 */
const DUMMY_PASSWORD_HASH = '$2b$12$4ecToxbEngZKhWlNV2FhTe6UZCTaBAB0.8U0QQufiM6HF9ymV2u6W';

/**
 * Build the JSON body returned after a successful login/signup.
 * The token is only echoed back when explicitly enabled for development,
 * because the HTTP-only cookie is the real credential.
 */
const authResponse = (user, token) => ({
  status: 'success',
  data: {
    user,
    ...(env.exposeTokenInResponse && !env.isProduction ? { token } : {}),
  },
});

/**
 * POST /api/auth/signup
 * Creates an account and logs the user in.
 */
const signup = catchAsync(async (req, res) => {
  const { name, email, password } = req.body;

  // Pre-check for a friendly message. The unique index is still the real
  // guarantee against races, and errorHandler maps its 11000 error too.
  const existing = await User.findOne({ email: email.toLowerCase() });
  if (existing) {
    throw AppError.conflict('An account with that email already exists', {
      code: 'EMAIL_IN_USE',
    });
  }

  const user = await User.create({ name, email, password });
  const token = signToken(user);

  setAuthCookie(res, token);

  res.status(201).json(authResponse(user, token));
});

/**
 * POST /api/auth/login
 *
 * Always returns the same message/status for a wrong email and a wrong
 * password so the endpoint cannot be used to enumerate registered emails.
 */
const login = catchAsync(async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email: email.toLowerCase() }).select('+password +isActive');

  const invalidCredentials = () =>
    AppError.unauthorized('Incorrect email or password', { code: 'INVALID_CREDENTIALS' });

  // Run a comparison against a dummy hash when the user is missing so the
  // response time does not reveal whether the account exists.
  if (!user) {
    await bcrypt.compare(password, DUMMY_PASSWORD_HASH);
    throw invalidCredentials();
  }

  if (!user.isActive) {
    throw AppError.forbidden('This account has been deactivated', { code: 'ACCOUNT_INACTIVE' });
  }

  // Accounts created through Google have no password set.
  if (!user.password) {
    throw AppError.badRequest(
      'This account was created with Google. Please sign in with Google instead.',
      { code: 'USE_GOOGLE_LOGIN' }
    );
  }

  const isMatch = await user.comparePassword(password);
  if (!isMatch) throw invalidCredentials();

  const token = signToken(user);
  setAuthCookie(res, token);

  res.status(200).json(authResponse(user, token));
});

/**
 * POST /api/auth/logout
 * Clears the auth cookie. Requires no valid token, so logging out always
 * succeeds even with an expired session.
 */
const logout = (req, res) => {
  clearAuthCookie(res);
  res.status(200).json({ status: 'success', message: 'Logged out successfully' });
};

/**
 * GET /api/auth/me
 * Returns the currently authenticated user.
 */
const getMe = catchAsync(async (req, res) => {
  res.status(200).json({ status: 'success', data: { user: req.user } });
});

/**
 * Google OAuth
 * ------------
 * The flow is stateless (no express-session), so CSRF protection is built from
 * two cooperating pieces instead of a server-side session:
 *
 *   1. a random nonce is stored in a short-lived, HTTP-only cookie, and
 *   2. the same nonce (plus an optional redirect target) is signed into the
 *      OAuth `state` parameter.
 *
 * On callback the nonce in `state` must match the cookie, and the signature
 * must verify. A forged callback therefore cannot bind an attacker's Google
 * account to a victim's browser session.
 */

const STATE_COOKIE = 'oauth_state';
const STATE_TTL_MS = 10 * 60 * 1000;

const stateCookieOptions = () => ({
  httpOnly: true,
  secure: env.cookie.secure,
  sameSite: 'lax',
  maxAge: STATE_TTL_MS,
  path: '/api/auth/google',
});

const sanitizeRedirect = (candidate) => {
  if (typeof candidate !== 'string' || !candidate) return null;
  // Must be a same-site relative path: no scheme, no protocol-relative //host.
  if (!candidate.startsWith('/') || candidate.startsWith('//')) return null;
  return candidate;
};

const buildState = (nonce, redirect) =>
  jwt.sign(
    { nonce, redirect: redirect || '/' },
    env.jwt.secret,
    { expiresIn: '10m', issuer: env.jwt.issuer }
  );

/**
 * Verify the `state` parameter. Returns the redirect target on success and
 * throws a 400 otherwise.
 */
const verifyState = (state, cookieNonce) => {
  if (!state) {
    throw AppError.badRequest('Missing OAuth state parameter', { code: 'INVALID_OAUTH_STATE' });
  }

  let payload;
  try {
    payload = jwt.verify(state, env.jwt.secret, { issuer: env.jwt.issuer });
  } catch {
    throw AppError.badRequest('Invalid or expired OAuth state parameter', {
      code: 'INVALID_OAUTH_STATE',
    });
  }

  if (!cookieNonce || payload.nonce !== cookieNonce) {
    throw AppError.badRequest('OAuth state does not match this browser session', {
      code: 'INVALID_OAUTH_STATE',
    });
  }

  return sanitizeRedirect(payload.redirect) || '/';
};

/**
 * GET /api/auth/google
 * Redirects the browser to Google's consent screen.
 */
const googleAuth = (req, res, next) => {
  if (!env.google.isConfigured) {
    return next(
      new AppError('Google OAuth is not configured on this server', 503, {
        code: 'GOOGLE_NOT_CONFIGURED',
      })
    );
  }

  const nonce = crypto.randomBytes(24).toString('base64url');
  const redirect = sanitizeRedirect(req.query.redirect);

  res.cookie(STATE_COOKIE, nonce, stateCookieOptions());

  return passport.authenticate('google', {
    session: false,
    scope: ['profile', 'email'],
    state: buildState(nonce, redirect),
  })(req, res, next);
};

/**
 * GET /api/auth/google/callback
 * Google redirects here. Issue our own JWT, store it in the HTTP-only cookie,
 * then bounce the browser back to the frontend.
 */
/**
 * Determine whether a Passport/OAuth failure is a normal user outcome
 * (expired or reused authorization code) rather than a server fault.
 *
 * passport-oauth2 wraps these in an InternalOAuthError whose `oauthError.data`
 * holds Google's JSON error document.
 */
const isOAuthUserError = (err) => {
  if (!err || !err.oauthError) return false;

  let payload = err.oauthError.data;
  if (typeof payload === 'string') {
    try {
      payload = JSON.parse(payload);
    } catch {
      return false;
    }
  }

  const code = payload && payload.error;
  return code === 'invalid_grant' || code === 'invalid_request';
};

const googleCallback = (req, res, next) => {
  let redirectTo;

  try {
    redirectTo = verifyState(req.query.state, req.cookies && req.cookies[STATE_COOKIE]);
  } catch (err) {
    return next(err);
  }

  // The nonce is single-use.
  res.clearCookie(STATE_COOKIE, { path: '/api/auth/google' });

  return passport.authenticate('google', { session: false }, (err, user, info) => {
    if (err) {
      /**
       * An expired/reused authorization code is an ordinary user outcome:
       * send them back to the login page. Genuine misconfiguration (bad client
       * id or secret) still surfaces as a server error rather than looping the
       * user through a login redirect that can never succeed.
       */
      if (isOAuthUserError(err)) {
        return res.redirect(`${env.clientUrl}/login?error=GOOGLE_CODE_REJECTED`);
      }

      // Log the provider detail server-side; do not echo it to the client.
      console.error('[auth] Google token exchange failed:', err.message);

      const wrapped = new AppError('Could not complete Google sign-in. Please try again.', 502, {
        code: 'GOOGLE_OAUTH_ERROR',
      });
      return next(wrapped);
    }

    if (!user) {
      const reason = (info && info.code) || 'GOOGLE_AUTH_FAILED';
      return res.redirect(`${env.clientUrl}/login?error=${encodeURIComponent(reason)}`);
    }

    const token = signToken(user);
    setAuthCookie(res, token);

    // In development, expose the token in the redirect query so a tool like
    // Postman / curl can grab it. Never enabled in production.
    const tokenQuery =
      env.exposeTokenInResponse && !env.isProduction
        ? `?token=${encodeURIComponent(token)}`
        : '';

    const destination = redirectTo === '/' ? env.clientUrl : `${env.clientUrl}${redirectTo}`;
    const separator = destination.includes('?') ? '&' : '?';
    const finalUrl = tokenQuery
      ? `${destination}${separator}${tokenQuery.slice(1)}`
      : destination;

    return res.redirect(finalUrl);
  })(req, res, next);
};

module.exports = {
  signup,
  login,
  logout,
  getMe,
  googleAuth,
  googleCallback,
  // exported for unit testing
  _internal: { sanitizeRedirect, verifyState, isOAuthUserError, buildState },
};
