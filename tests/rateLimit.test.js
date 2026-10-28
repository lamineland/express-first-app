'use strict';

const express = require('express');
const request = require('supertest');
const { buildAuthLimiter } = require('../src/middleware/rateLimiter');
const errorHandler = require('../src/middleware/errorHandler');

/**
 * A tiny app exposing one limited route, so the limiter is exercised for real
 * rather than skipped.
 */
const buildTestApp = (limiter) => {
  const app = express();
  app.use(express.json());
  app.post('/login', limiter, (req, res) => res.status(200).json({ status: 'success' }));
  app.use(errorHandler);
  return app;
};

/**
 * Parse the draft-7 `RateLimit` header, e.g. "limit=5, remaining=4, reset=60".
 */
const parseRateLimitHeader = (header) =>
  Object.fromEntries(
    String(header || '')
      .split(',')
      .map((part) => part.trim().split('='))
      .filter((pair) => pair.length === 2)
      .map(([key, value]) => [key, Number(value)])
  );

describe('Rate limiting', () => {
  it('allows requests up to the limit then returns 429', async () => {
    const app = buildTestApp(buildAuthLimiter({ limit: 3, windowMs: 60000 }));

    for (let i = 0; i < 3; i += 1) {
      const res = await request(app).post('/login').send({});
      expect(res.status).toBe(200);
    }

    const blocked = await request(app).post('/login').send({});
    expect(blocked.status).toBe(429);
    expect(blocked.body.error.code).toBe('TOO_MANY_REQUESTS');
  });

  it('advertises the policy and limit via standard headers', async () => {
    const app = buildTestApp(buildAuthLimiter({ limit: 5, windowMs: 60000 }));

    const res = await request(app).post('/login').send({});

    expect(res.headers['ratelimit-policy']).toBeDefined();
    const parsed = parseRateLimitHeader(res.headers.ratelimit);
    expect(parsed.limit).toBe(5);
    expect(parsed.remaining).toBe(4);
  });

  it('decrements the remaining quota as requests are consumed', async () => {
    const app = buildTestApp(buildAuthLimiter({ limit: 5, windowMs: 60000 }));

    const first = parseRateLimitHeader((await request(app).post('/login').send({})).headers.ratelimit);
    const second = parseRateLimitHeader((await request(app).post('/login').send({})).headers.ratelimit);

    expect(second.remaining).toBe(first.remaining - 1);
  });

  it('reports remaining as 0 once blocked', async () => {
    const app = buildTestApp(buildAuthLimiter({ limit: 2, windowMs: 60000 }));

    await request(app).post('/login').send({});
    await request(app).post('/login').send({});
    const blocked = await request(app).post('/login').send({});

    expect(blocked.status).toBe(429);
    expect(parseRateLimitHeader(blocked.headers.ratelimit).remaining).toBe(0);
  });
});
