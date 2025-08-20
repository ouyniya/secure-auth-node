/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import prisma from '../../../config/database';
import { logger } from '../../../lib/winston';
import { PasswordPolicy } from '../../../utils/passwordPolicy';
import { AuthenticatedRequest, LoginRequest } from '../../../types/index';
import { MFAService } from '../../../utils/mfa';
import { CryptoUtils } from '../../../utils/crypto';

export class AuthController {
  static async login(req: Request, res: Response) {
    try {
      // TODO: validate input

      const {
        username,
        password,
        totpCode,
        deviceFingerprint,
        rememberDevice,
      } = req.body;
      const ipAddress = req.ip;
      const userAgent = req.get('User-Agent') || '';

      // Find user
      const user = await prisma.user.findUnique({
        where: { username },
        include: { passwordHistory: true },
      });

      // Log Login attempt
      const loginAttempt = {
        userId: user?.id!, // required
        username,
        ipAddress: ipAddress || 'unknown',
        userAgent,
        success: false,
        deviceId: deviceFingerprint,
      };

      if (!user || !user.isActive) {
        await prisma.loginAttempt.create({
          data: {
            ...loginAttempt,
            failureReason: 'User not found or inactive',
          },
        });
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Verify password
      const validPassword = await PasswordPolicy.verifyPassword(
        password,
        user.hashedPassword,
      );
      if (!validPassword) {
        await prisma.loginAttempt.create({
          data: { ...loginAttempt, failureReason: 'Invalid password' },
        });
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Check password expiry
      if (PasswordPolicy.isPasswordExpired(user.passwordChangedAt)) {
        await prisma.loginAttempt.create({
          data: { ...loginAttempt, failureReason: 'Password expired' },
        });
        return res
          .status(403)
          .json({ error: 'Password expired', requirePasswordChange: true });
      }

      // MFA verification for privileged accounts
      if (user.isPrivileged || user.mfaEnabled) {
        if (!totpCode) {
          await prisma.loginAttempt.create({
            data: {
              ...loginAttempt,
              failureReason: 'MFA required',
            },
          });
          return res
            .status(403)
            .json({ error: 'MFA code required', requireMFA: true });
        }

        if (!user.totpSecret) {
          return res.status(403).json({ error: 'MFA not configured' });
        }

        const validMFA = MFAService.verifyToken(user.totpSecret, totpCode);
        if (!validMFA) {
          // Check backup codes
          if (user.backupCodes) {
            const backupResult = MFAService.verifyBackupCode(
              user.backupCodes,
              totpCode,
            );
            if (!backupResult.valid) {
              await prisma.loginAttempt.create({
                data: { ...loginAttempt, failureReason: 'Invalid MFA code' },
              });
              return res.status(401).json({ error: 'Invalid MFA code' });
            }
            // Update remaining backup codes
            await prisma.user.update({
              where: { id: user.id },
              data: { backupCodes: backupResult.remainingCodes },
            });
          } else {
            await prisma.loginAttempt.create({
              data: { ...loginAttempt, failureReason: 'Invalid MFA code' },
            });
            return res.status(401).json({ error: 'Invalid MFA code' });
          }
        }
      }

      // Handle device registration/verification
      let device = await prisma.device.findUnique({
        where: { deviceId: deviceFingerprint },
      });

      if (!device && rememberDevice) {
        device = await prisma.device.create({
          data: {
            deviceId: deviceFingerprint,
            deviceName: `${userAgent.split(' ')[0]} Device`,
            deviceType: 'web',
            fingerprint: deviceFingerprint,
            lastSeen: new Date(),
          },
        });
      } else if (device) {
        await prisma.device.update({
          where: { id: device.id },
          data: { lastSeen: new Date() },
        });
      }

      // Create session tokens
      const sessionToken = jwt.sign(
        {
          userId: user.id,
          username: user.username,
          isPrivileged: user.isPrivileged,
        },
        process.env.JWT_SECRET!,
        { expiresIn: '8h' },
      );

      const refreshToken = CryptoUtils.generateSecureToken(64);
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 8);

      // Create session record
      const session = await prisma.userSession.create({
        data: {
          userId: user.id,
          deviceId: device?.id,
          sessionToken,
          refreshToken,
          ipAddress: ipAddress ?? 'unknown',
          userAgent,
          expiresAt,
        },
      });

      // Update user last activity
      await prisma.user.update({
        where: { id: user.id },
        data: { lastActivity: new Date() },
      });

      // Log successful login
      await prisma.loginAttempt.create({
        data: {
          ...loginAttempt,
          success: true,
          mfaUsed: !!(user.isPrivileged || user.mfaEnabled),
        },
      });

      logger.info(`User ${username} logged in successfully from ${ipAddress}`);

      res.json({
        message: 'Login successful',
        token: sessionToken,
        refreshToken,
        user: {
          id: user.id,
          username: user.username,
          fullName: user.fullName,
          isPrivileged: user.isPrivileged,
          mfaEnabled: user.mfaEnabled,
        },
      });
    } catch (error) {
      logger.error('Login error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  static async logout(req: AuthenticatedRequest, res: Response) {
    try {
      if (req.user?.sessionId) {
        await prisma.userSession.update({
          where: { id: req.user.sessionId },
          data: { isActive: false },
        });

        await prisma.auditLog.create({
          data: {
            userId: req.user.id,
            action: 'LOGOUT',
            ipAddress: req.ip ?? 'unknown',
            userAgent: req.get('User-Agent') || '',
          },
        });

        logger.info(`User ${req.user.username} logged out`);
      }

      res.json({ message: 'Logout successful' });
    } catch (error) {
      logger.error('Logout error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  static async changePassword(req: AuthenticatedRequest, res: Response) {
    try {
      // TODO: validate input

      const { currenPassword, newPassword } = req.body;
      const userId = req.user!.id;

      const user = await prisma.user.findUnique({
        where: {
          id: userId,
        },
      });

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Verify current password
      const validCurrentPassword = await PasswordPolicy.verifyPassword(
        currenPassword,
        user.hashedPassword,
      );
      if (!validCurrentPassword) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }

      // Validate new password complexity
      const complexityErrors = PasswordPolicy.validateComplexity(
        newPassword,
        user.username,
        user.fullName,
      );
      if (complexityErrors.length > 0) {
        return res.status(400).json({ errors: complexityErrors });
      }

      // Check password history
      const isReused = !(await PasswordPolicy.checkPasswordHistory(
        userId,
        newPassword,
      ));
      if (isReused) {
        return res
          .status(400)
          .json({ error: 'Password has been used recently' });
      }

      // Check minimum age (at least 1 day since last change)
      const daysSinceLastChange = Math.floor(
        (new Date().getTime() - user.passwordChangedAt.getTime()) /
          (1000 * 60 * 60 * 24),
      );
      if (daysSinceLastChange < Number(PasswordPolicy.MIN_LIFETIME_DAYS)) {
        return res.status(400).json({ error: 'Password cannot be change yet' });
      }

      // Hash new password and update
      const newPasswordHash = await PasswordPolicy.hashedPassword(newPassword);

      await prisma.user.update({
        where: {
          id: userId,
        },
        data: {
          hashedPassword: newPasswordHash,
          passwordChangedAt: new Date(),
        },
      });

      // Save to password history
      await PasswordPolicy.savePasswordHistory(userId, newPasswordHash);

      logger.info(`User ${user.username} changed password`);

      res.json({ message: 'Password changed successfully' });
    } catch (error) {
      logger.error('Change password error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
}
