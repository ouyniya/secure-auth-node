/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */

import winston from 'winston';

/**
 * Custom modules
 */

import config from '../config/index';

const { combine, timestamp, json, errors, align, printf, colorize } =
  winston.format;

// Define the transports array to hold different logging transports
const transports: winston.transport[] = [];

// if the application is not running in production, add a console transport
if (config.NODE_ENV !== 'production') {
  transports.push(
    new winston.transports.Console({
      format: combine(
        colorize({ all: true }), // add color to log levels
        timestamp({ format: 'YYYY-MM-DD hh:mm:ss A' }), // Add timestamp to logs
        align(), // Align log messages
        printf(({ timestamp, level, message, ...meta }) => {
          const metaStr = Object.keys(meta).length
            ? `\n${JSON.stringify(meta)}`
            : '';

          return `${timestamp} [${level.toUpperCase()}]: ${message}${metaStr}`;
        }),
      ),
    }),
  );
}

// create a logger instance using winston
const logger = winston.createLogger({
  level: config.LOG_LEVEL || "info", // Set the default logging to 'info'
  format: combine(timestamp(), errors({ stack: true }), json()), // Use JSON format to log messages
  transports,
  silent: config.NODE_ENV === 'test', // Disable logging in test environment
});

export { logger };
