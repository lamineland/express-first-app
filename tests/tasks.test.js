'use strict';

const { app, request, registerUser } = require('./helpers');

const createTask = (cookie, body = {}) =>
  request(app)
    .post('/api/tasks')
    .set('Cookie', cookie)
    .send({ title: 'Write the report', ...body });

describe('Tasks: authentication required', () => {
  it('rejects every task route without a token', async () => {
    const responses = await Promise.all([
      request(app).get('/api/tasks'),
      request(app).post('/api/tasks').send({ title: 'x' }),
      request(app).get('/api/tasks/507f1f77bcf86cd799439011'),
      request(app).patch('/api/tasks/507f1f77bcf86cd799439011').send({ title: 'x' }),
      request(app).delete('/api/tasks/507f1f77bcf86cd799439011'),
    ]);

    responses.forEach((res) => {
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('NO_TOKEN');
    });
  });
});

describe('Tasks: create', () => {
  it('creates a task owned by the current user', async () => {
    const { cookie, user } = await registerUser();

    const res = await createTask(cookie, { description: 'Q3 numbers', priority: 'high' });

    expect(res.status).toBe(201);
    expect(res.body.data.task.title).toBe('Write the report');
    expect(res.body.data.task.owner).toBe(user._id);
    expect(res.body.data.task.status).toBe('pending');
  });

  it('ignores an owner supplied in the body (no privilege escalation)', async () => {
    const { cookie, user } = await registerUser();
    const other = await registerUser({ email: 'other@example.com', name: 'Other' });

    const res = await createTask(cookie, { owner: other.user._id });

    expect(res.status).toBe(201);
    expect(res.body.data.task.owner).toBe(user._id);
    expect(res.body.data.task.owner).not.toBe(other.user._id);
  });

  it('rejects a missing title with 400', async () => {
    const { cookie } = await registerUser();
    const res = await createTask(cookie, { title: '' });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('rejects an invalid status value', async () => {
    const { cookie } = await registerUser();
    const res = await createTask(cookie, { status: 'not-a-status' });

    expect(res.status).toBe(400);
    expect(res.body.error.details.some((d) => d.field === 'status')).toBe(true);
  });

  it('strips injected Mongo operators from input', async () => {
    const { cookie } = await registerUser();
    const res = await createTask(cookie, { title: { $gt: '' } });

    // The operator is sanitized/rejected -- never stored as a working query.
    expect([201, 400]).toContain(res.status);
    if (res.status === 201) {
      expect(typeof res.body.data.task.title).toBe('string');
    }
  });

  it('escapes HTML in stored input', async () => {
    const { cookie } = await registerUser();
    const res = await createTask(cookie, {
      title: '<script>alert(1)</script>',
      description: '<img src=x onerror=alert(1)>',
    });

    expect(res.status).toBe(201);

    // xss-clean escapes angle brackets, so no executable tags survive.
    const { title, description } = res.body.data.task;
    expect(title).not.toContain('<script>');
    expect(description).not.toContain('<img');
    expect(description).not.toMatch(/<\s*\/?\s*(script|img|iframe)/i);
    // The payload is stored as inert text instead.
    expect(description).toContain('&lt;');
  });
});

describe('Tasks: read own tasks', () => {
  it('returns only the current user\'s tasks', async () => {
    const alice = await registerUser({ email: 'alice@example.com', name: 'Alice' });
    const bob = await registerUser({ email: 'bob@example.com', name: 'Bob' });

    await createTask(alice.cookie, { title: 'Alice task 1' });
    await createTask(alice.cookie, { title: 'Alice task 2' });
    await createTask(bob.cookie, { title: 'Bob task' });

    const res = await request(app).get('/api/tasks').set('Cookie', alice.cookie);

    expect(res.status).toBe(200);
    expect(res.body.results).toBe(2);
    expect(res.body.pagination.total).toBe(2);
    res.body.data.tasks.forEach((task) => {
      expect(task.owner).toBe(alice.user._id);
    });
    expect(res.body.data.tasks.map((t) => t.title)).not.toContain('Bob task');
  });

  it('filters by status', async () => {
    const { cookie } = await registerUser();
    await createTask(cookie, { title: 'Done', status: 'completed' });
    await createTask(cookie, { title: 'Todo' });

    const res = await request(app).get('/api/tasks?status=completed').set('Cookie', cookie);

    expect(res.status).toBe(200);
    expect(res.body.results).toBe(1);
    expect(res.body.data.tasks[0].title).toBe('Done');
  });

  it('paginates results', async () => {
    const { cookie } = await registerUser();
    for (let i = 0; i < 5; i += 1) {
      await createTask(cookie, { title: `Task ${i}` });
    }

    const res = await request(app).get('/api/tasks?page=2&limit=2').set('Cookie', cookie);

    expect(res.status).toBe(200);
    expect(res.body.results).toBe(2);
    expect(res.body.pagination).toMatchObject({ total: 5, page: 2, limit: 2, pages: 3 });
  });

  it('rejects an invalid pagination value', async () => {
    const { cookie } = await registerUser();
    const res = await request(app).get('/api/tasks?limit=999').set('Cookie', cookie);
    expect(res.status).toBe(400);
  });
});

describe('Tasks: access control', () => {
  it('lets the owner read their own task', async () => {
    const { cookie } = await registerUser();
    const created = await createTask(cookie);

    const res = await request(app)
      .get(`/api/tasks/${created.body.data.task._id}`)
      .set('Cookie', cookie);

    expect(res.status).toBe(200);
  });

  it('hides another user\'s task behind a 404 (does not leak existence)', async () => {
    const owner = await registerUser({ email: 'owner@example.com', name: 'Owner' });
    const intruder = await registerUser({ email: 'intruder@example.com', name: 'Intruder' });

    const created = await createTask(owner.cookie, { title: 'Private' });
    const taskId = created.body.data.task._id;

    const res = await request(app).get(`/api/tasks/${taskId}`).set('Cookie', intruder.cookie);

    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('TASK_NOT_FOUND');
  });

  it('prevents a non-owner from updating a task', async () => {
    const owner = await registerUser({ email: 'owner@example.com', name: 'Owner' });
    const intruder = await registerUser({ email: 'intruder@example.com', name: 'Intruder' });

    const created = await createTask(owner.cookie, { title: 'Original' });
    const taskId = created.body.data.task._id;

    const res = await request(app)
      .patch(`/api/tasks/${taskId}`)
      .set('Cookie', intruder.cookie)
      .send({ title: 'Hacked' });

    expect(res.status).toBe(404);

    // Confirm the original is untouched.
    const check = await request(app).get(`/api/tasks/${taskId}`).set('Cookie', owner.cookie);
    expect(check.body.data.task.title).toBe('Original');
  });

  it('prevents a non-owner from deleting a task', async () => {
    const owner = await registerUser({ email: 'owner@example.com', name: 'Owner' });
    const intruder = await registerUser({ email: 'intruder@example.com', name: 'Intruder' });

    const created = await createTask(owner.cookie, { title: 'Keep me' });
    const taskId = created.body.data.task._id;

    const res = await request(app).delete(`/api/tasks/${taskId}`).set('Cookie', intruder.cookie);

    expect(res.status).toBe(404);

    const check = await request(app).get(`/api/tasks/${taskId}`).set('Cookie', owner.cookie);
    expect(check.status).toBe(200);
  });

  it('lets the owner update a task', async () => {
    const { cookie } = await registerUser();
    const created = await createTask(cookie);
    const taskId = created.body.data.task._id;

    const res = await request(app)
      .patch(`/api/tasks/${taskId}`)
      .set('Cookie', cookie)
      .send({ title: 'Updated', status: 'completed' });

    expect(res.status).toBe(200);
    expect(res.body.data.task.title).toBe('Updated');
    expect(res.body.data.task.status).toBe('completed');
  });

  it('lets the owner delete a task, and it stays deleted', async () => {
    const { cookie } = await registerUser();
    const created = await createTask(cookie);
    const taskId = created.body.data.task._id;

    const del = await request(app).delete(`/api/tasks/${taskId}`).set('Cookie', cookie);
    expect(del.status).toBe(200);

    const check = await request(app).get(`/api/tasks/${taskId}`).set('Cookie', cookie);
    expect(check.status).toBe(404);
  });

  it('rejects a malformed task id instead of 500', async () => {
    const { cookie } = await registerUser();
    const res = await request(app).get('/api/tasks/not-an-object-id').set('Cookie', cookie);

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('does not let a query-string operator bypass ownership filtering', async () => {
    // Attempt the classic NoSQL-injection payload on the status filter.
    const alice = await registerUser({ email: 'alice@example.com', name: 'Alice' });
    const bob = await registerUser({ email: 'bob@example.com', name: 'Bob' });

    await createTask(alice.cookie, { title: 'Alice secret' });
    await createTask(bob.cookie, { title: 'Bob secret' });

    const res = await request(app)
      .get('/api/tasks?status[$ne]=pending')
      .set('Cookie', bob.cookie);

    // Either the payload is rejected as an invalid status, or the sanitizer
    // neutralises the operator -- in neither case may Alice's task leak.
    expect([200, 400]).toContain(res.status);
    if (res.status === 200) {
      const titles = res.body.data.tasks.map((t) => t.title);
      expect(titles).not.toContain('Alice secret');
      res.body.data.tasks.forEach((task) => expect(task.owner).toBe(bob.user._id));
    }
  });

  it('ignores an attempt to filter by another user\'s owner id', async () => {
    const alice = await registerUser({ email: 'alice@example.com', name: 'Alice' });
    const bob = await registerUser({ email: 'bob@example.com', name: 'Bob' });

    await createTask(alice.cookie, { title: 'Alice secret' });

    const res = await request(app)
      .get(`/api/tasks?owner=${alice.user._id}`)
      .set('Cookie', bob.cookie);

    expect(res.status).toBe(200);
    expect(res.body.results).toBe(0);
  });
});
