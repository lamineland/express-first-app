'use strict';

/**
 * Wraps an async route handler so a rejected promise is forwarded to Express'
 * error pipeline via next(err).
 *
 * Express 4 does not await handlers, so an async throw would otherwise become
 * an unhandled rejection and the request would hang until it times out.
 *
 * @param {(req: import('express').Request, res: import('express').Response, next: import('express').NextFunction) => Promise<any>} fn
 * @returns {import('express').RequestHandler}
 */
const catchAsync = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = catchAsync;
