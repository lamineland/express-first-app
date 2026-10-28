'use strict';

const { body, param, query } = require('express-validator');
const { validate } = require('./validateAuth');
const { TASK_STATUSES, TASK_PRIORITIES } = require('../models/Task');

const OBJECT_ID = /^[0-9a-fA-F]{24}$/;

const createTaskRules = [
  body('title')
    .trim()
    .notEmpty()
    .withMessage('Title is required')
    .isLength({ max: 200 })
    .withMessage('Title cannot be longer than 200 characters')
    // Reject control characters that would corrupt stored text.
    .matches(/^[^\u0000-\u001F\u007F]*$/)
    .withMessage('Title contains invalid characters'),

  body('description')
    .optional()
    .isString()
    .withMessage('Description must be a string')
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Description cannot be longer than 2000 characters'),

  body('status')
    .optional()
    .isIn(TASK_STATUSES)
    .withMessage(`Status must be one of: ${TASK_STATUSES.join(', ')}`),

  body('priority')
    .optional()
    .isIn(TASK_PRIORITIES)
    .withMessage(`Priority must be one of: ${TASK_PRIORITIES.join(', ')}`),

  body('dueDate')
    .optional({ values: 'null' })
    .isISO8601()
    .withMessage('Due date must be a valid ISO 8601 date'),
];

const updateTaskRules = [
  body('title')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('Title cannot be empty')
    .isLength({ max: 200 })
    .withMessage('Title cannot be longer than 200 characters'),

  body('description')
    .optional()
    .isString()
    .withMessage('Description must be a string')
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Description cannot be longer than 2000 characters'),

  body('status')
    .optional()
    .isIn(TASK_STATUSES)
    .withMessage(`Status must be one of: ${TASK_STATUSES.join(', ')}`),

  body('priority')
    .optional()
    .isIn(TASK_PRIORITIES)
    .withMessage(`Priority must be one of: ${TASK_PRIORITIES.join(', ')}`),

  body('dueDate')
    .optional({ values: 'null' })
    .isISO8601()
    .withMessage('Due date must be a valid ISO 8601 date'),
];

/**
 * Guards the `:id` route param. A malformed id gets a clean 400 instead of a
 * Mongoose CastError surfacing as a 500.
 */
const taskIdRule = [
  param('id').matches(OBJECT_ID).withMessage('Invalid task id'),
];

const listTasksRules = [
  query('status')
    .optional()
    .isIn(TASK_STATUSES)
    .withMessage(`Status must be one of: ${TASK_STATUSES.join(', ')}`),

  query('priority')
    .optional()
    .isIn(TASK_PRIORITIES)
    .withMessage(`Priority must be one of: ${TASK_PRIORITIES.join(', ')}`),

  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer').toInt(),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100')
    .toInt(),

  query('sort')
    .optional()
    .isIn(['createdAt', '-createdAt', 'dueDate', '-dueDate', 'priority', '-priority', 'title', '-title'])
    .withMessage('Invalid sort field'),
];

module.exports = {
  validate,
  createTaskRules,
  updateTaskRules,
  listTasksRules,
  taskIdRule,
};
