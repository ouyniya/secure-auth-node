/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */

import dotenv from 'dotenv';

dotenv.config(); // Load .env file variables

const config = {
  PORT: process.env.PORT ?? 3000,
  NODE_ENV: process.env.NODE_ENV,
  WHITELIST_ORIGINS: ['https://nysdev.com'],
  LOG_LEVEL: process.env.LOG_LEVEL ?? 'info',
  ROUTE_VERSION: process.env.ROUTE_VERSION,
  JWT_SECRET: process.env.JWT_SECRET,

  // Password Policy
  MIN_LENGTH: process.env.MIN_LENGTH,
  MAX_LIFETIME_DAYS: process.env.MAX_LIFETIME_DAYS,
  MIN_LIFETIME_DAYS: process.env.MIN_LIFETIME_DAYS,
  HISTORY_COUNT: process.env.HISTORY_COUNT,
  SALT_ROUNDS: process.env.SALT_ROUNDS,
};

export default config;
