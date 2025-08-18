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
 * Root route
 */

router.get('/', (req, res) => {
  res.json({
    message: 'API is live',
    status: 'ok',
    version: '1.0.0',
    docs: 'https://github.com/ouyniya/secure-blog-node',
    timestamp: new Date().toISOString(),
  });
});

export default router;
