'use strict';

const restrictTo = require('../src/middleware/restrictTo');

/**
 * `restrictTo` is not used by the task routes (every authenticated user manages
 * only their own tasks) but is kept as the role gate for future admin-only
 * endpoints. These tests keep it verified rather than dead.
 */
const run = (middleware, req) =>
  new Promise((resolve) => {
    middleware(req, {}, (err) => resolve(err));
  });

describe('restrictTo middleware', () => {
  it('allows a user whose role is permitted', async () => {
    const err = await run(restrictTo('admin'), { user: { role: 'admin' } });
    expect(err).toBeUndefined();
  });

  it('rejects a user without the role (403)', async () => {
    const err = await run(restrictTo('admin'), { user: { role: 'user' } });
    expect(err).toBeDefined();
    expect(err.statusCode).toBe(403);
    expect(err.code).toBe('FORBIDDEN');
  });

  it('rejects an unauthenticated request (401)', async () => {
    const err = await run(restrictTo('admin'), {});
    expect(err.statusCode).toBe(401);
    expect(err.code).toBe('NO_TOKEN');
  });

  it('supports multiple allowed roles', async () => {
    const err = await run(restrictTo('admin', 'user'), { user: { role: 'user' } });
    expect(err).toBeUndefined();
  });
});
