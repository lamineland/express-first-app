'use strict';

const express = require('express');
const taskController = require('../controllers/taskController');
const verifyToken = require('../middleware/verifyToken');
const {
  validate,
  createTaskRules,
  updateTaskRules,
  listTasksRules,
  taskIdRule,
} = require('../middleware/validateTask');

const router = express.Router();

// Every task route requires a valid session.
router.use(verifyToken);

router
  .route('/')
  .get(listTasksRules, validate, taskController.getTasks)
  .post(createTaskRules, validate, taskController.createTask);

router
  .route('/:id')
  .all(taskIdRule, validate)
  .get(taskController.getTask)
  .patch(updateTaskRules, validate, taskController.updateTask)
  .delete(taskController.deleteTask);

module.exports = router;
