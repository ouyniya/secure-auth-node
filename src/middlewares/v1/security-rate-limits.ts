/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */

import { rateLimit } from 'express-rate-limit';

// Rate limiting for general API endpoint
export const generalRateLimit = rateLimit({
  windowMs: 60000, // 1-min time window for request limiting
  limit: 60, // allow a maximum of 60 request per window per IP
  standardHeaders: 'draft-8', // use the latest standard rate-limit headers
  legacyHeaders: false, // disable depreciated X-ratelimit headers
  message: {
    error:
      'You have sent too many requests in a given amount of time. Please try again later.',
  },
  //   keyGenerator: (req) => {
  //     const token = req.headers['x-auth-token'] as string | undefined;
  //     if (token) {
  //       return `user:${token}`; // limit per logged-in user
  //     }
  //     return `ip:${req.ip}`; // fallback for guest
  //   },
});

export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: {
    error: 'Too many authentication attempts, please try again later',
  },
  standardHeaders: 'draft-8',
  legacyHeaders: false,
});


