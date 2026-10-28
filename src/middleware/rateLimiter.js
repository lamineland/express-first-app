'use strict';

const rateLimit = require('express-rate-limit');
const env = require('../config/env');

const message = (text) => ({
  status: 'fail',
  error: { code: 'TOO_MANY_REQUESTS', message: text },
});

/**
 * Build a limiter. Exported as a factory so tests can construct a limiter
 * with `skip` disabled and verify the real throttling behaviour instead of
 * trusting it.
 */
const createLimiter = ({ windowMs, limit, text, skip }) =>
  rateLimit({
    windowMs,
    limit,
    message: message(text),
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    // Tests should not be flaky because of shared counters.
    skip: skip || (() => env.isTest),
  });

const authLimitText = () =>
  `Too many authentication attempts from this IP. Please try again in ${Math.ceil(
    env.rateLimit.authWindowMs / 60000
  )} minutes.`;

/**
 * Strict limiter for credential endpoints. Keyed by IP by default, which
 * throttles brute-force password guessing from a single source.
 */
const authLimiter = createLimiter({
  windowMs: env.rateLimit.authWindowMs,
  limit: env.rateLimit.authMax,
  text: authLimitText(),
});

/**
 * Broad limiter applied to the whole API to blunt scraping and abuse.
 */
const globalLimiter = createLimiter({
  windowMs: 15 * 60 * 1000,
  limit: env.rateLimit.globalMax,
  text: 'Too many requests from this IP. Please try again later.',
});

module.exports = {
  authLimiter,
  globalLimiter,
  createLimiter,
  buildAuthLimiter: (overrides = {}) =>
    createLimiter({
      windowMs: env.rateLimit.authWindowMs,
      limit: env.rateLimit.authMax,
      text: authLimitText(),
      // Explicitly never skip: this builder exists for tests that need the
      // limiter to actually run.
      skip: () => false,
      ...overrides,
    }),
};
