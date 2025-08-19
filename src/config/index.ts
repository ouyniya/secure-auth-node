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
};

export default config;
