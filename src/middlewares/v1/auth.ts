/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */
import { Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import prisma from '../../config/database';
import { logger } from '../../lib/winston';
import { AuthenticatedRequest } from '../../types/v1/index';
import config from '../../config/index';

export const authenticateToken = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
) => {
  try {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, config.JWT_SECRET!);

    // Verify session is still active
    const session = await prisma.userSession.findFirst({
      where: {
        sessionToken: token,
        isActive: true,
        expiresAt: { gt: new Date() },
      },
      include: {
        user: true,
        device: true,
      },
    });

    if (!session || !session.user.isActive) {
      return res.status(401).json({ error: 'Invalid or expired session' });
    }

    // Update last activity
    await prisma.userSession.update({
      where: { id: session.id },
      data: {
        lastActivity: new Date(),
      },
    });

    await prisma.user.update({
      where: {
        id: session.userId,
      },
      data: { lastActivity: new Date() },
    });

    req.user = {
      id: session.user.id,
      username: session.user.username,
      isPrivileged: session.user.isPrivileged,
      sessionId: session.id,
    };

    if (session.device) {
      req.device = {
        id: session.device.id,
        deviceId: session.device.deviceId,
      };
    }

    next();
  } catch (error) {
    logger.error('Authentication error:', error);
    return res.status(403).json({ error: 'Invalid token' });
  }
};

export const requirePrivileged = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
) => {
  if (!req.user?.isPrivileged) {
    logger.warn(
      `Unauthorized privileged access attempt by user: ${req.user?.username}`,
    );
    return res.status(403).json({ error: 'Privileged access required' });
  }

  next();
};

export const auditLog = (action: string) => {
  return async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      await prisma.auditLog.create({
        data: {
          userId: req.user?.id!,
          deviceId: req.device?.id,
          action,
          resource: req.path,
          details: {
            method: req.method,
            params: req.params,
            query: req.query,
            timestamp: new Date().toISOString(),
          },
          ipAddress: req.ip!,
          userAgent: req.get('User-Agent') || '',
        },
      });
      next();
    } catch (error) {
      logger.error('Audit logging error:', error);
      next();
    }
  };
};
