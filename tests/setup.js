'use strict';

const os = require('os');
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');

let mongo;

beforeAll(async () => {
  mongo = await MongoMemoryServer.create();

  await mongoose.connect(mongo.getUri(), {
    dbName: 'task_manager_test',
    /**
     * The MongoDB driver resolves its `os` adapter with a dynamic `import()`,
     * which Jest's CommonJS sandbox never settles. Supplying the adapter
     * explicitly keeps the connection working under test. This is a test-only
     * concern; production uses the driver's default.
     */
    runtimeAdapters: { os },
  });
});

afterEach(async () => {
  // Isolate tests: every test starts with an empty database.
  const collections = await mongoose.connection.db.collections();
  await Promise.all(collections.map((collection) => collection.deleteMany({})));
});

afterAll(async () => {
  await mongoose.connection.dropDatabase();
  await mongoose.disconnect();
  if (mongo) await mongo.stop();
});
