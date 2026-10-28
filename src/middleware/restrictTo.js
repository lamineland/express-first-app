'use strict';

const AppError = require('../utils/AppError');

/**
 * Role gate. Use after verifyToken:
 *   router.delete('/:id', verifyToken, restrictTo('admin'), handler)
 */
const restrictTo = (...roles) => (req, res, next) => {
  if (!req.user) {
    return next(AppError.unauthorized('Authentication required', { code: 'NO_TOKEN' }));
  }

  if (!roles.includes(req.user.role)) {
    return next(
      AppError.forbidden('You do not have permission to perform this action', {
        code: 'FORBIDDEN',
      })
    );
  }

  return next();
};

module.exports = restrictTo;
