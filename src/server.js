'use strict';

const env = require('./config/env');
const { connectDB, disconnectDB } = require('./config/db');
const createApp = require('./app');

const start = async () => {
  await connectDB();

  const app = createApp();
  const server = app.listen(env.port, () => {
    console.log(`[server] listening on http://localhost:${env.port} (${env.nodeEnv})`);
  });

  const shutdown = async (signal) => {
    console.log(`\n[server] ${signal} received, shutting down gracefully...`);
    server.close(async () => {
      await disconnectDB();
      process.exit(0);
    });

    // Force-exit if connections do not drain in time.
    setTimeout(() => process.exit(1), 10000).unref();
  };

  ['SIGINT', 'SIGTERM'].forEach((signal) => process.on(signal, () => shutdown(signal)));

  process.on('unhandledRejection', (reason) => {
    console.error('[fatal] unhandled rejection:', reason);
    server.close(() => process.exit(1));
  });
};

start().catch((err) => {
  console.error('[fatal] failed to start server:', err.message);
  process.exit(1);
});
