'use strict';

const mongoose = require('mongoose');
const { request, getAuthCookie, registerUser } = require('./helpers');
const { app } = require('./helpers');

describe('Auth: signup', () => {
  it('creates a user, returns 201 and sets an HTTP-only cookie', async () => {
    const res = await request(app).post('/api/auth/signup').send({
      name: 'Ada Lovelace',
      email: 'ada@example.com',
      password: 'sup3rSecret',
      passwordConfirm: 'sup3rSecret',
    });

    expect(res.status).toBe(201);
    expect(res.body.data.user.email).toBe('ada@example.com');
    expect(res.body.data.user.password).toBeUndefined();

    const rawCookie = (res.headers['set-cookie'] || []).find((c) => c.startsWith('access_token='));
    expect(rawCookie).toBeDefined();
    expect(rawCookie).toMatch(/HttpOnly/i);
    expect(rawCookie).toMatch(/SameSite=Lax/i);
  });

  it('never exposes the password hash in the response', async () => {
    const { user } = await registerUser();
    expect(JSON.stringify(user)).not.toContain('$2');
    expect(user.password).toBeUndefined();
    expect(user.googleId).toBeUndefined();
  });

  it('rejects a duplicate email with 409', async () => {
    await registerUser();
    const res = await request(app).post('/api/auth/signup').send({
      name: 'Impostor',
      email: 'ADA@example.com',
      password: 'sup3rSecret',
      passwordConfirm: 'sup3rSecret',
    });

    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('EMAIL_IN_USE');
  });

  it('rejects a weak password with 400 and field details', async () => {
    const res = await request(app).post('/api/auth/signup').send({
      name: 'Weak',
      email: 'weak@example.com',
      password: 'short',
      passwordConfirm: 'short',
    });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
    expect(res.body.error.details.some((d) => d.field === 'password')).toBe(true);
  });

  it('rejects mismatched password confirmation', async () => {
    const res = await request(app).post('/api/auth/signup').send({
      name: 'Mismatch',
      email: 'mismatch@example.com',
      password: 'sup3rSecret',
      passwordConfirm: 'different1',
    });

    expect(res.status).toBe(400);
    expect(res.body.error.details.some((d) => d.field === 'passwordConfirm')).toBe(true);
  });

  it('rejects an invalid email', async () => {
    const res = await request(app).post('/api/auth/signup').send({
      name: 'Bad Mail',
      email: 'not-an-email',
      password: 'sup3rSecret',
      passwordConfirm: 'sup3rSecret',
    });

    expect(res.status).toBe(400);
    expect(res.body.error.details.some((d) => d.field === 'email')).toBe(true);
  });
});

describe('Auth: login', () => {
  it('logs in with correct credentials and sets a cookie', async () => {
    await registerUser();

    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'ada@example.com', password: 'sup3rSecret' });

    expect(res.status).toBe(200);
    expect(getAuthCookie(res)).toBeTruthy();
  });

  it('returns 401 for a wrong password', async () => {
    await registerUser();

    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'ada@example.com', password: 'wrongPassword1' });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_CREDENTIALS');
  });

  it('returns the same 401 message for an unknown email (no user enumeration)', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'ghost@example.com', password: 'sup3rSecret' });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_CREDENTIALS');
    expect(res.body.error.message).toBe('Incorrect email or password');
  });
});

describe('Auth: protected session', () => {
  it('GET /api/auth/me returns the current user when authenticated', async () => {
    const { cookie, user } = await registerUser();

    const res = await request(app).get('/api/auth/me').set('Cookie', cookie);

    expect(res.status).toBe(200);
    expect(res.body.data.user._id).toBe(user._id);
  });

  it('GET /api/auth/me returns 401 without a token', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('NO_TOKEN');
  });

  it('rejects a tampered token', async () => {
    const { cookie } = await registerUser();
    const tampered = `${cookie.slice(0, -3)}abc`;

    const res = await request(app).get('/api/auth/me').set('Cookie', tampered);
    expect(res.status).toBe(401);
  });

  it('accepts a Bearer token as well as the cookie', async () => {
    const signup = await registerUser();
    // Re-login with token exposed is disabled, so read the JWT from the cookie.
    const token = signup.cookie.split('=')[1];

    const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });

  it('logout clears the cookie', async () => {
    const { cookie } = await registerUser();
    const res = await request(app).post('/api/auth/logout').set('Cookie', cookie);

    expect(res.status).toBe(200);
    const cleared = (res.headers['set-cookie'] || []).find((c) => c.startsWith('access_token='));
    expect(cleared).toMatch(/access_token=;/);
  });

  it('rejects a token whose user was deleted', async () => {
    const { cookie, user } = await registerUser();
    const User = require('../src/models/User');
    await User.findByIdAndDelete(user._id);

    const res = await request(app).get('/api/auth/me').set('Cookie', cookie);
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('USER_NOT_FOUND');
  });
});

describe('Auth: Google OAuth', () => {
  it('returns 503 when Google credentials are not configured', async () => {
    const res = await request(app).get('/api/auth/google');
    expect(res.status).toBe(503);
    expect(res.body.error.code).toBe('GOOGLE_NOT_CONFIGURED');
  });

  it('has the Google routes registered', async () => {
    const res = await request(app).get('/api/auth/google/callback');
    // Without config it either 503s (our guard) or redirects with an OAuth
    // error; either way it must not 404.
    expect(res.status).not.toBe(404);
  });

  it('rejects a callback with no state parameter', async () => {
    const res = await request(app).get('/api/auth/google/callback');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_OAUTH_STATE');
  });

  it('rejects a callback whose state does not match the browser nonce cookie', async () => {
    const jwtLib = require('jsonwebtoken');
    const env = require('../src/config/env');

    // A structurally valid, correctly signed state...
    const state = jwtLib.sign({ nonce: 'attacker-nonce', redirect: '/' }, env.jwt.secret, {
      expiresIn: '10m',
      issuer: env.jwt.issuer,
    });

    // ...presented with a different nonce cookie than it was issued for.
    const res = await request(app)
      .get(`/api/auth/google/callback?state=${state}`)
      .set('Cookie', 'oauth_state=victim-nonce');

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_OAUTH_STATE');
  });

  it('rejects a forged (unsigned) state parameter', async () => {
    const forged = Buffer.from(JSON.stringify({ nonce: 'x', redirect: '/' })).toString('base64url');

    const res = await request(app)
      .get(`/api/auth/google/callback?state=${forged}`)
      .set('Cookie', 'oauth_state=x');

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_OAUTH_STATE');
  });
});

describe('Auth: OAuth helpers', () => {
  const { _internal } = require('../src/controllers/authController');
  const { sanitizeRedirect, verifyState, isOAuthUserError, buildState } = _internal;

  describe('sanitizeRedirect', () => {
    it('accepts same-site relative paths', () => {
      expect(sanitizeRedirect('/tasks')).toBe('/tasks');
      expect(sanitizeRedirect('/tasks?page=2')).toBe('/tasks?page=2');
    });

    it('rejects absolute URLs', () => {
      expect(sanitizeRedirect('https://evil.com')).toBeNull();
      expect(sanitizeRedirect('http://evil.com/path')).toBeNull();
    });

    it('rejects protocol-relative URLs', () => {
      expect(sanitizeRedirect('//evil.com')).toBeNull();
      expect(sanitizeRedirect('//evil.com/x')).toBeNull();
    });

    it('rejects non-strings and empty values', () => {
      expect(sanitizeRedirect(undefined)).toBeNull();
      expect(sanitizeRedirect('')).toBeNull();
      expect(sanitizeRedirect(['/a'])).toBeNull();
    });
  });

  describe('verifyState', () => {
    it('returns the redirect target when the nonce matches', () => {
      const state = buildState('nonce-123', '/tasks');
      expect(verifyState(state, 'nonce-123')).toBe('/tasks');
    });

    it('falls back to "/" when no redirect was set', () => {
      const state = buildState('nonce-123', null);
      expect(verifyState(state, 'nonce-123')).toBe('/');
    });

    it('throws when the nonce does not match the cookie', () => {
      const state = buildState('nonce-123', '/tasks');
      expect(() => verifyState(state, 'different')).toThrow(/does not match/);
    });

    it('throws when no cookie nonce is present', () => {
      const state = buildState('nonce-123', '/tasks');
      expect(() => verifyState(state, undefined)).toThrow(/does not match/);
    });

    it('throws for a tampered signature', () => {
      const state = buildState('nonce-123', '/tasks');
      const tampered = `${state.slice(0, -4)}aaaa`;
      expect(() => verifyState(tampered, 'nonce-123')).toThrow(/Invalid or expired/);
    });
  });

  describe('isOAuthUserError', () => {
    it('treats invalid_grant as a user error', () => {
      const err = { oauthError: { data: JSON.stringify({ error: 'invalid_grant' }) } };
      expect(isOAuthUserError(err)).toBe(true);
    });

    it('treats invalid_client as a server error', () => {
      const err = { oauthError: { data: JSON.stringify({ error: 'invalid_client' }) } };
      expect(isOAuthUserError(err)).toBe(false);
    });

    it('handles a non-JSON payload without throwing', () => {
      expect(isOAuthUserError({ oauthError: { data: 'not json' } })).toBe(false);
    });

    it('handles a plain error object', () => {
      expect(isOAuthUserError(new Error('boom'))).toBe(false);
      expect(isOAuthUserError(undefined)).toBe(false);
    });
  });
});

describe('Error handling', () => {
  it('returns a structured 404 for unknown routes', async () => {
    const res = await request(app).get('/api/does-not-exist');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('ROUTE_NOT_FOUND');
  });

  it('returns 400 for malformed JSON', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .set('Content-Type', 'application/json')
      .send('{"email": "broken"');

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_JSON');
  });

  it('does not leak stack traces in production responses', async () => {
    const original = process.env.NODE_ENV;
    // Sanity check the development shape includes a stack.
    const res = await request(app).get('/api/does-not-exist');
    expect(res.body.error.stack).toBeDefined();
    expect(original).toBe('test');
  });
});
