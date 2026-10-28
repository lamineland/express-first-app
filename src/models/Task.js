'use strict';

const mongoose = require('mongoose');

const TASK_STATUSES = ['pending', 'in-progress', 'completed'];
const TASK_PRIORITIES = ['low', 'medium', 'high'];

const taskSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, 'Title is required'],
      trim: true,
      minlength: [1, 'Title cannot be empty'],
      maxlength: [200, 'Title cannot be longer than 200 characters'],
    },

    description: {
      type: String,
      trim: true,
      maxlength: [2000, 'Description cannot be longer than 2000 characters'],
      default: '',
    },

    status: {
      type: String,
      enum: { values: TASK_STATUSES, message: `Status must be one of: ${TASK_STATUSES.join(', ')}` },
      default: 'pending',
    },

    priority: {
      type: String,
      enum: { values: TASK_PRIORITIES, message: `Priority must be one of: ${TASK_PRIORITIES.join(', ')}` },
      default: 'medium',
    },

    dueDate: {
      type: Date,
      default: null,
    },

    /**
     * The owner. Every query in the controller filters on this field, which
     * is what enforces per-user isolation.
     */
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform(doc, ret) {
        delete ret.__v;
        return ret;
      },
    },
  }
);

// Covers the common "my newest tasks" query.
taskSchema.index({ owner: 1, createdAt: -1 });

const Task = mongoose.model('Task', taskSchema);

module.exports = Task;
module.exports.TASK_STATUSES = TASK_STATUSES;
module.exports.TASK_PRIORITIES = TASK_PRIORITIES;
