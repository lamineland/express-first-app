'use strict';

const Task = require('../models/Task');
const AppError = require('../utils/AppError');
const catchAsync = require('../utils/catchAsync');

/**
 * Only these fields may be written by a client. Anything else in the body
 * (e.g. `owner`, `_id`, `createdAt`) is ignored, which prevents privilege
 * escalation such as re-assigning a task to another user.
 */
const pickTaskFields = (body) => {
  const allowed = ['title', 'description', 'status', 'priority', 'dueDate'];
  return allowed.reduce((acc, field) => {
    if (body[field] !== undefined) acc[field] = body[field];
    return acc;
  }, {});
};

/**
 * Load a task by id, scoped to the current user.
 *
 * Ownership is enforced in the query itself (`owner: req.user._id`) rather
 * than by fetching first and comparing after, so a non-owner can never read
 * another user's task even transiently.
 *
 * A task that exists but belongs to someone else returns 404 rather than 403:
 * telling the caller "this exists but is not yours" would leak the existence
 * of other users' task ids.
 */
const findOwnedTask = async (taskId, userId) => {
  const task = await Task.findOne({ _id: taskId, owner: userId });

  if (!task) {
    throw AppError.notFound('Task not found', { code: 'TASK_NOT_FOUND' });
  }

  return task;
};

/**
 * POST /api/tasks
 */
const createTask = catchAsync(async (req, res) => {
  const task = await Task.create({
    ...pickTaskFields(req.body),
    owner: req.user._id,
  });

  res.status(201).json({ status: 'success', data: { task } });
});

/**
 * GET /api/tasks
 * Returns the current user's tasks. Supports filtering, sorting, pagination.
 */
const getTasks = catchAsync(async (req, res) => {
  const { status, priority, sort = '-createdAt' } = req.query;
  const page = req.query.page || 1;
  const limit = req.query.limit || 20;

  const filter = { owner: req.user._id };
  if (status) filter.status = status;
  if (priority) filter.priority = priority;

  const [tasks, total] = await Promise.all([
    Task.find(filter)
      .sort(sort)
      .skip((page - 1) * limit)
      .limit(limit),
    Task.countDocuments(filter),
  ]);

  res.status(200).json({
    status: 'success',
    results: tasks.length,
    data: { tasks },
    pagination: {
      total,
      page,
      limit,
      pages: Math.ceil(total / limit) || 1,
    },
  });
});

/**
 * GET /api/tasks/:id
 */
const getTask = catchAsync(async (req, res) => {
  const task = await findOwnedTask(req.params.id, req.user._id);
  res.status(200).json({ status: 'success', data: { task } });
});

/**
 * PATCH /api/tasks/:id
 */
const updateTask = catchAsync(async (req, res) => {
  const task = await findOwnedTask(req.params.id, req.user._id);

  Object.assign(task, pickTaskFields(req.body));
  await task.save();

  res.status(200).json({ status: 'success', data: { task } });
});

/**
 * DELETE /api/tasks/:id
 */
const deleteTask = catchAsync(async (req, res) => {
  const task = await findOwnedTask(req.params.id, req.user._id);
  await task.deleteOne();

  res.status(200).json({ status: 'success', message: 'Task deleted', data: { id: task._id } });
});

module.exports = {
  createTask,
  getTasks,
  getTask,
  updateTask,
  deleteTask,
};
