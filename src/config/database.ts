/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */

import { PrismaClient } from '@prisma/client';
import { logger } from '../lib/winston';

const prisma = new PrismaClient({
  log: [
    { level: 'query', emit: 'event' },
    { level: 'error', emit: 'event' },
    { level: 'info', emit: 'event' },
    { level: 'warn', emit: 'event' },
  ],
});

// Log database queries for audit purposes
prisma.$on('query', (e) => {
  logger.info('Database Query', {
    query: e.query,
    params: e.params,
    duration: e.duration,
    timestamp: e.timestamp,
  });
});

export default prisma;
