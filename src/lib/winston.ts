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
import { safeMask, sanitizeStack } from '../utils/v1/markSensitive';

const { combine, timestamp, errors, printf } = winston.format;

/**
 *
 * Useful functions
 */

// Define the transports array to hold different logging transports
const transports: winston.transport[] = [];

// if the application is not running in production, add a console transport
if (config.NODE_ENV !== 'production') {
  const consoleFormat = winston.format.combine(
    winston.format.colorize({ all: true }),
    winston.format.timestamp({ format: 'YYYY-MM-DD hh:mm:ss A' }),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      const metaStr = Object.keys(meta).length
        ? `\n${JSON.stringify(meta, null, 2)}`
        : '';
      return `${timestamp} [${level}]: ${message}${metaStr}`;
    }),
  );

  transports.push(
    new winston.transports.Console({
      format: consoleFormat,
    }),
  );
} else {
  // Production environment format
  const productionFormat = combine(
    // Step 1: Add timestamp and errors
    timestamp(),
    errors({ stack: true }),
    // Step 2: Use a custom printf to format and sanitize the output
    printf(({ timestamp, level, message, ...meta }) => {
      let details: Record<string, any> = {};

      if (meta[Symbol.for('splat')]) {
        const splat = meta[Symbol.for('splat')] as unknown[];

        splat.forEach((m) => {
          if (m instanceof Error) {
            details.name = m.name;
            details.stack = sanitizeStack(m.stack || '');
          } else {
            details = {
              ...details,
              ...safeMask(m),
            };
          }
        });
      }

      details = safeMask(details);

      // mask message ถ้าเป็น object หรือ JSON string
      let msg = safeMask(message);

      return JSON.stringify({
        timestamp,
        level,
        message: typeof msg === 'object' ? JSON.stringify(msg) : msg,
        errorCode: details.name || undefined,
        details: Object.keys(details).length ? details : undefined,
      });
    }),
  );

  transports.push(
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      format: productionFormat,
    }),
  );

  transports.push(
    new winston.transports.File({
      filename: 'logs/warn.log',
      level: 'warn',
      format: productionFormat,
    }),
  );

  transports.push(
    new winston.transports.File({
      filename: 'logs/combined.log',
      level: 'info',
      format: productionFormat,
    }),
  );

  transports.push(
    new winston.transports.Console({
      format: productionFormat,
    }),
  );
}

// create a logger instance using winston
const logger = winston.createLogger({
  level: config.LOG_LEVEL || 'info', // Set the default logging to 'info'
  // format: combine(timestamp(), errors({ stack: true }), json()), // Use JSON format to log messages
  transports,
  silent: config.NODE_ENV === 'test', // Disable logging in test environment
});

export { logger };
