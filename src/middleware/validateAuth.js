'use strict';

const { body, validationResult } = require('express-validator');
const AppError = require('../utils/AppError');

/**
 * Run after validation chains: collects errors and forwards a single 400 with
 * per-field details.
 */
const validate = (req, res, next) => {
  const result = validationResult(req);
  if (result.isEmpty()) return next();

  const details = result.array().map((error) => ({
    field: error.path,
    message: error.msg,
  }));

  return next(AppError.badRequest('Validation failed', { code: 'VALIDATION_ERROR', details }));
};

const PASSWORD_MIN_LENGTH = 8;

const signupRules = [
  body('name')
    .trim()
    .notEmpty()
    .withMessage('Name is required')
    .isLength({ min: 2, max: 80 })
    .withMessage('Name must be between 2 and 80 characters'),

  body('email')
    .trim()
    .notEmpty()
    .withMessage('Email is required')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail()
    .isLength({ max: 254 })
    .withMessage('Email is too long'),

  body('password')
    .isString()
    .withMessage('Password must be a string')
    // bail() stops at the first failure so a single bad field does not
    // produce a cascade of messages for the client to untangle.
    .bail()
    .isLength({ min: PASSWORD_MIN_LENGTH, max: 128 })
    .withMessage(`Password must be between ${PASSWORD_MIN_LENGTH} and 128 characters`)
    .bail()
    // A little strength checking: at least one letter and one number.
    .matches(/[A-Za-z]/)
    .withMessage('Password must contain at least one letter')
    .bail()
    .matches(/\d/)
    .withMessage('Password must contain at least one number'),

  body('passwordConfirm')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match');
      }
      return true;
    }),
];

const loginRules = [
  body('email')
    .trim()
    .notEmpty()
    .withMessage('Email is required')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),

  body('password').isString().withMessage('Password is required').notEmpty().withMessage('Password is required'),
];

module.exports = { validate, signupRules, loginRules, PASSWORD_MIN_LENGTH };
