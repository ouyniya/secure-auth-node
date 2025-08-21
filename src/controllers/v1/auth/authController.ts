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
import { PasswordPolicy } from '../../../utils/v1/passwordPolicy';
import { AuthenticatedRequest } from '../../../types/v1/index';
import { MFAService } from '../../../utils/v1/mfa';
import { CryptoUtils } from '../../../utils/v1/crypto';

export class AuthController {
  static async login(req: Request, res: Response) {
    try {
      // TODO: validate input

      const {
        username,
        password,
        totpCode,
        rememberDevice,
      } = req.body;
      const ipAddress = req.ip || 'unknown';
      const userAgent = req.get('User-Agent') || '';
      const deviceFingerprint = CryptoUtils.generateDeviceFingerprint(
        userAgent,
        ipAddress,
      );

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

        // Decrypt the secret before verification
        const decryptedSecret = CryptoUtils.decrypt(user.totpSecret);
        const validMFA = MFAService.verifyToken(decryptedSecret, totpCode);

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
      await prisma.userSession.create({
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

      // Audit log
      await prisma.auditLog.create({
        data: {
          userId: user?.id,
          deviceId: device!.id,
          action: 'LOGIN_ATTEMPT',
          resource: req.path,
          details: {
            method: req.method,
            params: req.params,
            query: req.query,
            timestamp: new Date().toISOString(),
          },
          ipAddress: req.ip || 'unknown',
          userAgent: req.get('User-Agent') || '',
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

      const { currentPassword, newPassword } = req.body;
      if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Password is required' });
      }

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
        currentPassword,
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

  static async setupMFA(req: AuthenticatedRequest, res: Response) {
    try {
      const userId = req.user!.id;

      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      if (user.mfaEnabled) {
        return res.status(400).json({ error: 'MFA already enabled' });
      }

      // Generate MFA secret and QR code
      const mfaSetup = MFAService.generateSecret(user.username);
      const qrCode = await MFAService.generateQRCode(mfaSetup.qrCodeUrl);
      const backupCodes = MFAService.generateBackupCodes();

      // Store secret temporarily (not enabled until verified)
      await prisma.user.update({
        where: { id: userId },
        data: {
          totpSecret: mfaSetup.encryptedSecret,
        },
      });

      logger.info(`User ${user.username} initiated MFA setup`);

      res.json({
        secret: mfaSetup.encryptedSecret,
        qrCode,
        backupCodes,
      });
    } catch (error) {
      logger.error('MFA setup error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  static async verifyMFA(req: AuthenticatedRequest, res: Response) {
    try {
      const { totpCode } = req.body;
      const userId = req.user!.id;

      if (!totpCode || totpCode.length !== 6) {
        return res.status(400).json({ error: 'Valid TOPT code required' });
      }

      const user = await prisma.user.findUnique({
        where: {
          id: userId,
        },
      });

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      if (!user.totpSecret) {
        return res.status(400).json({ error: 'MFA setup not initiated' });
      }

      // Decrypt the secret before verification
      const decryptedSecret = CryptoUtils.decrypt(user.totpSecret);

      // Verify secret
      const isValid = MFAService.verifyToken(decryptedSecret, totpCode);
      if (!isValid) {
        return res.status(400).json({ error: 'Invalid TOTP code' });
      }

      // Enable MFA and save backup codes
      const backupCodes = MFAService.generateBackupCodes();

      await prisma.user.update({
        where: { id: userId },
        data: {
          mfaEnabled: true,
          backupCodes: JSON.stringify(backupCodes),
        },
      });

      logger.info(`User ${user.username} enabled MFA`);

      res.json({
        message: 'MFA enabled successfully',
        backupCodes,
      });
    } catch (error) {
      logger.error('MFA verification error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  static async disableMFA(req: AuthenticatedRequest, res: Response) {
    try {
      const { password, totpCode } = req.body;
      const userId = req.user!.id;

      if (!password || !totpCode) {
        return res
          .status(400)
          .json({ error: 'Password and TOTP code required' });
      }

      const user = await prisma.user.findUnique({
        where: {
          id: userId,
        },
      });

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Verify password

      if (user.totpSecret) {
        // Decrypt the secret before verification
        const decryptedSecret = CryptoUtils.decrypt(user.totpSecret);
        const validMFA = MFAService.verifyToken(decryptedSecret, totpCode);

        if (!validMFA) {
          return res.status(400).json({ error: 'Invalid TOTP code' });
        }
      }

      // Disable MFA
      await prisma.user.update({
        where: { id: userId },
        data: {
          mfaEnabled: false,
          totpSecret: null,
          backupCodes: null,
        },
      });

      logger.info(`User ${user.username} disabled MFA`);

      res.json({ message: 'MFA disabled successfully' });
    } catch (error) {
      logger.error('MFA disable error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  static async refreshToken(req: Request, res: Response) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(401).json({ error: 'Refresh token required' });
      }

      const session = await prisma.userSession.findUnique({
        where: { refreshToken },
        include: { user: true },
      });

      if (!session || !session.isActive || session.expiresAt < new Date()) {
        return res.status(401).json({ error: 'Invalid refresh token' });
      }

      // Generate new tokens
      const newSessionToken = jwt.sign(
        {
          userId: session.user.id,
          username: session.user.username,
          isPrivileged: session.user.isPrivileged,
        },
        process.env.JWT_SECRET!,
        { expiresIn: '8h' },
      );

      const newRefreshToken = CryptoUtils.generateSecureToken(64);
      const newExpiresAt = new Date();
      newExpiresAt.setHours(newExpiresAt.getHours() + 8);

      // Update session
      await prisma.userSession.update({
        where: { id: session.id },
        data: {
          sessionToken: newSessionToken,
          refreshToken: newRefreshToken,
          expiresAt: newExpiresAt,
          lastActivity: new Date(),
        },
      });

      res.json({
        token: newSessionToken,
        refreshToken: newRefreshToken,
      });
    } catch (error) {
      logger.error('Token refresh error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  static async pkiAuth(req: Request, res: Response) {
    try {
      const { certificate, deviceFingerprint } = req.body;

      if (!certificate) {
        return res.status(400).json({ error: 'Client certificate required' });
      }

      // Parse and validate certificate
      const certInfo = CryptoUtils.parsePKICertificate(certificate);

      // Check certificate revocation
      const isRevoked = await prisma.certificateRevocation.findUnique({
        where: { serialNumber: certInfo.serialNumber },
      });

      if (isRevoked) {
        return res.status(401).json({ error: 'Certificate revoked' });
      }

      // Find user by certificate DN
      const user = await prisma.user.findFirst({
        where: {
          certificateDN: certInfo.subject,
          isActive: true,
        },
      });

      if (!user) {
        return res
          .status(401)
          .json({ error: 'Certificate not associated with any user' });
      }

      // Handle device if provided
      let device = null;
      if (deviceFingerprint) {
        device = await prisma.device.findUnique({
          where: { deviceId: deviceFingerprint },
        });

        device ??
          (await prisma.device.create({
            data: {
              deviceId: deviceFingerprint,
              deviceName: 'PKI Authenticated Device',
              deviceType: 'certificate',
              fingerprint: deviceFingerprint,
              certificateHash: certInfo.fingerprint,
            },
          }));
      }

      // Create session
      const sessionToken = jwt.sign(
        {
          userId: user.id,
          username: user.username,
          isPrivileged: user.isPrivileged,
          authMethod: 'PKI',
        },
        process.env.JWT_SECRET!,
        { expiresIn: '8h' },
      );

      const refreshToken = CryptoUtils.generateSecureToken(64);
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 8);

      await prisma.userSession.create({
        data: {
          userId: user.id,
          deviceId: device?.id,
          sessionToken,
          refreshToken,
          ipAddress: req.ip || 'unknown',
          userAgent: req.get('User-Agent') || '',
          expiresAt,
        },
      });

      // Log PKI authentication
      await prisma.loginAttempt.create({
        data: {
          userId: user.id,
          username: user.username,
          ipAddress: req.ip || 'unknown',
          userAgent: req.get('User-Agent') || '',
          success: true,
          deviceId: deviceFingerprint,
        },
      });

      logger.info(`User ${user.username} authenticated via PKI certificate`);

      res.json({
        message: 'PKI authentication successful',
        token: sessionToken,
        refreshToken,
        user: {
          id: user.id,
          username: user.username,
          fullName: user.fullName,
          isPrivileged: user.isPrivileged,
        },
      });
    } catch (error) {
      logger.error('PKI authentication error:', error);
      res.status(500).json({ error: 'PKI authentication failed' });
    }
  }
}
