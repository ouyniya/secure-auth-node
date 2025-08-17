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
  PORT: process.env.PORT || 3000,
};

export default config;
