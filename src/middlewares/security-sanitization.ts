/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */
import { NextFunction, Request, Response } from 'express';

/**
 * Types
 */
interface CustomRequest extends Request {
  clientIp?: string;
}

export const sanitizeRequest = (
  req: CustomRequest,
  res: Response,
  next: NextFunction,
) => {
  // Remove any potentially harmful headers
  delete req.headers['x-forwarded-host'];
  delete req.headers['x-forwarded-server'];

  next();
};
