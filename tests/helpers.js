'use strict';

const request = require('supertest');
const createApp = require('../src/app');

const app = createApp();

/**
 * Extract the auth cookie from a login/signup response so tests can reuse it.
 */
const getAuthCookie = (res) => {
  const cookies = res.headers['set-cookie'] || [];
  const authCookie = cookies.find((cookie) => cookie.startsWith('access_token='));
  return authCookie ? authCookie.split(';')[0] : null;
};

const validUser = {
  name: 'Ada Lovelace',
  email: 'ada@example.com',
  password: 'sup3rSecret',
  passwordConfirm: 'sup3rSecret',
};

/**
 * Create a user and return { user, cookie }.
 */
const registerUser = async (overrides = {}) => {
  const payload = { ...validUser, ...overrides };
  const res = await request(app).post('/api/auth/signup').send(payload);

  return {
    response: res,
    user: res.body.data && res.body.data.user,
    cookie: getAuthCookie(res),
  };
};

module.exports = { app, request, getAuthCookie, registerUser, validUser };
