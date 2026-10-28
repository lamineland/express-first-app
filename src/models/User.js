'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const SALT_ROUNDS = 12;

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Name is required'],
      trim: true,
      minlength: [2, 'Name must be at least 2 characters'],
      maxlength: [80, 'Name cannot be longer than 80 characters'],
    },

    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please provide a valid email address'],
    },

    /**
     * Absent for Google-only accounts. `select: false` keeps the hash out of
     * query results unless explicitly requested, so it cannot be accidentally
     * serialized into a response.
     */
    password: {
      type: String,
      minlength: [8, 'Password must be at least 8 characters'],
      select: false,
    },

    googleId: {
      type: String,
      unique: true,
      sparse: true,
    },

    avatar: {
      type: String,
    },

    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user',
    },

    isActive: {
      type: Boolean,
      default: true,
      select: false,
    },

    passwordChangedAt: {
      type: Date,
      select: false,
    },
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform(doc, ret) {
        delete ret.password;
        delete ret.__v;
        delete ret.googleId;
        delete ret.isActive;
        delete ret.passwordChangedAt;
        return ret;
      },
    },
  }
);

// Hash the password whenever it is set or changed. Runs on save() so every
// write path (signup, password change, seed scripts) is covered.
// NOTE: this is an async hook, so Mongoose awaits the returned promise and
// does not pass a `next` callback.
userSchema.pre('save', async function hashPassword() {
  if (!this.isModified('password') || !this.password) return;

  this.password = await bcrypt.hash(this.password, SALT_ROUNDS);

  // Only stamp passwordChangedAt for existing users; on create, `isNew` is
  // true and the token-issuing code already treats the token as current.
  if (!this.isNew) {
    this.passwordChangedAt = new Date(Date.now() - 1000);
  }
});

/**
 * Compare a plaintext candidate against the stored hash.
 * Requires the document to have been loaded with `+password`.
 */
userSchema.methods.comparePassword = async function comparePassword(candidate) {
  if (!this.password) return false;
  return bcrypt.compare(candidate, this.password);
};

/**
 * True when the password (or the account) changed after the token's `iat`
 * claim. Used to invalidate tokens issued before a password reset.
 */
userSchema.methods.changedPasswordAfter = function changedPasswordAfter(jwtIssuedAtSeconds) {
  if (!this.passwordChangedAt) return false;

  const changedAtSeconds = Math.floor(this.passwordChangedAt.getTime() / 1000);
  return changedAtSeconds > jwtIssuedAtSeconds;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
module.exports.SALT_ROUNDS = SALT_ROUNDS;
