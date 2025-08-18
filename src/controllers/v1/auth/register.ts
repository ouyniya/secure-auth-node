/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Custom Modules
 */
import { logger } from '../../../lib/winston';
import config from '../../../config/index';

/**
 * Models
 */

/**
 * Types
 */
import type { Request, Response } from 'express';

const register = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(201).json({ message: 'New user created' });
  } catch (error) {
    res.status(500).json({
      code: 'ServerError',
      message: 'Internal server error',
      error: error,
    });

    logger.error('Error during user registration', error);
  }
};

export default register;
