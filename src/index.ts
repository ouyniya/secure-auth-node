import app from './server';
import config from './config/index';
import prisma from './config/database';

/**
 * Immediately Invoked Function Expression (IIFE)
 * Used here to initialize routes and handle errors at startup.
 */
(async () => {
  try {
    // connect database
    await prisma.$connect();
    console.log('Database connected successfully!');

    // Server is running ?
    if (
      process.env.JEST_WORKER_ID === undefined &&
      process.env.NODE_ENV !== 'production'
    ) {
      app.listen(config.PORT, () => {
        console.log(`Server is running on port: ${config.PORT}`);
      });
    }
  } catch (error) {
    console.log(`Failed to start the server`, error);
    await prisma.$disconnect();

    if (config.NODE_ENV === 'production') {
      process.exit(1);
    }
  }
})();

/**
 * Gracefully handles server shutdown.
 * Logs a shutdown message, then exits the process.
 * If an error occurs during shutdown, it will be logged.
 */
const handleServerShutdown = async () => {
  try {
    console.log('Shutting down gracefully...');

    await prisma.$disconnect();
    console.log('Database disconnected');

    console.log('Server SHUTDOWN');
    process.exit(0);
  } catch (error) {
    console.log('Error during server shutdown', error);
    process.exit(1);
  }
};

/**
 * Attach shutdown handler to termination signals
 * - SIGINT: triggered when you press Ctrl+C in the terminal
 * - SIGTERM: triggered when the system or process manager stops the app
 */
process.on('SIGTERM', handleServerShutdown);
process.on('SIGINT', handleServerShutdown);
