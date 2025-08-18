/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */

import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';

/**
 * Custom modules
 */

import limiter from './lib/express-rate-limits';

/**
 * Types
 */
import type { CorsOptions } from 'cors';

/**
 * Express app initial
 */
const app = express();

// Remove header X-Powered-By
app.disable('x-powered-by');

dotenv.config(); // Load .env file variables

const config = {
  PORT: process.env.PORT ?? 3000,
  NODE_ENV: process.env.NODE_ENV,
  WHITELIST_ORIGINS: ['https://nysdev.com'],
};

// Configure CORS options
const corsOptions: CorsOptions = {
  origin(origin, callback) {
    if (
      config.NODE_ENV === 'development' ||
      !origin ||
      config.WHITELIST_ORIGINS.includes(origin)
    ) {
      callback(null, true);
    } else {
      // Reject requests from non-whitelisted origins
      callback(
        new Error(`CORS Error: ${origin} is not allowed by CORS`),
        false,
      );
      console.log(`CORS Error: ${origin} is not allowed by CORS`);
    }
  },
};

// Apply CORS
app.use(cors(corsOptions));

// Enable JSON request body parsing
app.use(express.json());

// Enable URL-encoded request body parsing with extended mode
// `extended: true` allows rich objects and arrays via querystring library
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

app.use(cookieParser());

// Use Helmet to enhance security by setting various HTTP headers
app.use(helmet());

// Apply rate limiting middleware to prevent excessive requests and enhance security
app.use(limiter);

(async () => {
  try {
    app.get('/', (req, res) => {
      res.json({ message: 'Hello Secure World!' });
    });
  } catch (error) {
    console.log(`Failed to start the server`, error);

    if (config.NODE_ENV === 'production') {
      process.exit(1);
    }
  }
})();

// export app for unit testing
export default app;
