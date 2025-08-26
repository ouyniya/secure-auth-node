/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */
import { Router } from 'express';
const router = Router();

/**
 * Routes
 */
import authRoutes from './auth';
import { logger } from '../../lib/winston';

/**
 * Root route
 */

router.get('/', (req, res) => {
  logger.info("Hello world", {service: "checkout"})
  
  res.json({
    message: 'API is live',
    status: 'ok',
    version: '1.0.0',
    docs: 'https://github.com/ouyniya/secure-blog-node',
    timestamp: new Date().toISOString(),
  });
});

router.use('/auth', authRoutes);

export default router;
