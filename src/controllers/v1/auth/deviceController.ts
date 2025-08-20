/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */
import { Response } from 'express';
import prisma from '../../../config/database';
import { logger } from '../../../lib/winston';
import { AuthenticatedRequest } from '../../../types';

export class DeviceController {
  static async registerDevice(req: AuthenticatedRequest, res: Response) {
    try {
      const { deviceName, deviceType, fingerprint } = req.body;

      // Check if device already exists
      const existingDevice = await prisma.device.findUnique({
        where: { deviceId: fingerprint },
      });

      if (existingDevice) {
        return res.status(400).json({ error: 'Device already registered' });
      }

      const device = await prisma.device.create({
        data: {
          deviceId: fingerprint,
          deviceName,
          deviceType,
          fingerprint,
          lastSeen: new Date(),
        },
      });

      logger.info(`Device ${deviceName} registered by ${req.user?.username}`);

      res.status(201).json({
        message: 'Device registered successfully',
        device: {
          id: device.id,
          deviceId: device.deviceId,
          deviceName: device.deviceName,
          deviceType: device.deviceType,
        },
      });
    } catch (error) {
      logger.error('Device registration error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  static async getDevices(req: AuthenticatedRequest, res: Response) {
    try {
      const devices = await prisma.device.findMany({
        where: { isActive: true },
        orderBy: { lastSeen: 'desc' },
      });

      res.json({ devices });
    } catch (error) {
      logger.error('Get devices error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  static async deactivateDevice(req: AuthenticatedRequest, res: Response) {
    try {
      const { deviceId } = req.params;

      const device = await prisma.device.findUnique({
        where: { id: deviceId },
      });

      if (!device) {
        return res.status(404).json({ error: 'Device not found' });
      }

      await prisma.device.update({
        where: { id: deviceId },
        data: { isActive: false },
      });

      // Revoke all sessions for this device
      await prisma.userSession.updateMany({
        where: { deviceId },
        data: { isActive: false },
      });

      logger.info(
        `Device ${device.deviceName} deactivated by ${req.user?.username}`,
      );

      res.json({ message: 'Device deactivated successfully' });
    } catch (error) {
      logger.error('Deactivate device error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
}
