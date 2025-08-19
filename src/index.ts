/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */

import app from './server';
import config from './config/index';
import prisma from './config/database';
import { logger } from './lib/winston';

/**
 * Immediately Invoked Function Expression (IIFE)
 * Used here to initialize routes and handle errors at startup.
 */
(async () => {
  try {
    // connect database
    await prisma.$connect();
    logger.info('Database connected successfully!');

    // Server is running ?
    if (
      process.env.JEST_WORKER_ID === undefined &&
      process.env.NODE_ENV !== 'production'
    ) {
      app.listen(config.PORT, () => {
        logger.info(`Server is running on port: ${config.PORT}`);
      });
    }
  } catch (error) {
    logger.error(`Failed to start the server`, error);
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
    logger.info('Shutting down gracefully...');

    await prisma.$disconnect();
    logger.info('Database disconnected');

    logger.info('Server SHUTDOWN');
    process.exit(0);
  } catch (error) {
    logger.error('Error during server shutdown', error);
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
