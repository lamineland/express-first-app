'use strict';

const express = require('express');
const authController = require('../controllers/authController');
const verifyToken = require('../middleware/verifyToken');
const { authLimiter } = require('../middleware/rateLimiter');
const { signupRules, loginRules, validate } = require('../middleware/validateAuth');

const router = express.Router();

// --- public ---------------------------------------------------------------

// The rate limiter sits in front of the credential endpoints so brute-force
// attempts are throttled before any password comparison happens.
router.post('/signup', authLimiter, signupRules, validate, authController.signup);
router.post('/login', authLimiter, loginRules, validate, authController.login);

router.post('/logout', authController.logout);

// --- Google OAuth ---------------------------------------------------------

router.get('/google', authLimiter, authController.googleAuth);
router.get('/google/callback', authController.googleCallback);

// --- private --------------------------------------------------------------

router.get('/me', verifyToken, authController.getMe);

module.exports = router;
