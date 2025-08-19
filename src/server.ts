/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */

import express, { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

/**
 * Custom modules
 */
import config from './config/index';
import {
  authRateLimit,
  generalRateLimit,
} from './middlewares/security-rate-limits';
import { logger } from './lib/winston';

/**
 * Router
 */
import v1Route from './routes/v1';

/**
 * Types
 */
import type { CorsOptions } from 'cors';
import { securityHeaders } from './middlewares/security-headers';
import { sanitizeRequest } from './middlewares/security-sanitization';

/**
 * Express app initial
 */
const app = express();

// Remove header X-Powered-By
app.disable('x-powered-by');

// Trust proxy for proper IP detection
app.set('trust proxy', 1);

// Security middleware
app.use(securityHeaders);
app.use(sanitizeRequest);

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
      logger.warn(`CORS Error: ${origin} is not allowed by CORS`);
    }
  },
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
};

// Apply CORS
app.use(cors(corsOptions));

// Enable JSON request body parsing
app.use(express.json({ limit: '10mb' }));

// Enable URL-encoded request body parsing with extended mode
// `extended: true` allows rich objects and arrays via querystring library
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use(cookieParser());

// Apply rate limiting middleware to prevent excessive requests and enhance security
app.use(`${config.ROUTE_VERSION}/auth`, authRateLimit);
app.use(`${config.ROUTE_VERSION}`, generalRateLimit);

// API routes
app.use(`${config.ROUTE_VERSION}`, v1Route);
app.use(`/api/v1`, v1Route);

// Error handling middleware
app.use((error: any, req: Request, res: Response, next: NextFunction) => {
  logger.error('Unhandled error:', error);

  if (error.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON payload' });
  }

  if (error.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload too large' });
  }

  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler วาง หลังทุก route และ middleware
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// export app for unit testing
export default app;
