/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */
import bcrypt from 'bcryptjs';
import prisma from '../config/database';
import config from '../config/index';

export class PasswordPolicy {
  static readonly MIN_LENGTH = config.MIN_LENGTH;
  static readonly MAX_LIFETIME_DAYS = config.MAX_LIFETIME_DAYS;
  static readonly MIN_LIFETIME_DAYS = config.MIN_LIFETIME_DAYS;
  static readonly HISTORY_COUNT = config.HISTORY_COUNT;
  static readonly SALT_ROUNDS = config.SALT_ROUNDS;

  static validateComplexity(
    password: string,
    username: string,
    fullName: string,
  ): string[] {
    const errors: string[] = [];

    // Minimum length
    if (password.length < Number(this.MIN_LENGTH)) {
      errors.push(
        `Password must be at least ${this.MIN_LENGTH} characters long`,
      );
    }

    // Cannot contain username or full name
    if (password.toLowerCase().includes(username.toLowerCase())) {
      errors.push('Password cannot contain username');
    }

    if (password.toLowerCase().includes(fullName.toLowerCase())) {
      errors.push('Password cannot contain full name');
    }

    // Character categories
    const categories = {
      uppercase:
        /[A-Z\u00C0-\u00D6\u00D8-\u00DE\u0100-\u017F\u0180-\u024F\u1E00-\u1EFF\u0400-\u04FF]/,
      lowercase:
        /[a-z\u00DF\u00E0-\u00F6\u00F8-\u00FF\u0100-\u017F\u0180-\u024F\u1E00-\u1EFF\u0400-\u04FF]/,
      digits: /\d/,
      symbols: /[~!@#$%^&*_\-+=`|\\(){}[\]:;"'<>,.?/]/,
      unicode: /[\u4E00-\u9FFF\u3040-\u309F\u30A0-\u30FF\uAC00-\uD7AF]/,
    };

    let categoryCount = 0;
    Object.values(categories).forEach((regex) => {
      if (regex.test(password)) categoryCount++;
    });

    if (categoryCount < 3) {
      errors.push(
        'Password must contain characters from at least 3 different categories',
      );
    }

    return errors;
  }

  // Manage password
  static async hashedPassword(password: string): Promise<string> {
    return bcrypt.hash(password, Number(this.SALT_ROUNDS));
  }

  static async verifyPassword(
    password: string,
    hash: string,
  ): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  static async checkPasswordHistory(
    userId: string,
    newPassword: string,
  ): Promise<boolean> {
    const history = await prisma.passwordHistory.findMany({
      where: {
        userId,
      },
      orderBy: { createdAt: 'desc' },
      take: Number(this.HISTORY_COUNT),
    });

    for (const entry of history) {
      if (await bcrypt.compare(newPassword, entry.hashedPassword)) {
        return false;
      }
    }
    return true;
  }

  static async savePasswordHistory(
    userId: string,
    hashedPassword: string,
  ): Promise<void> {
    // Save new password to history
    await prisma.passwordHistory.create({
      data: {
        userId,
        hashedPassword,
      },
    });

    // Clean up old history beyond the limit
    const allHistory = await prisma.passwordHistory.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });

    if (allHistory.length > Number(this.HISTORY_COUNT)) {
      const toDelete = allHistory.slice(Number(this.HISTORY_COUNT));
      await prisma.passwordHistory.deleteMany({
        where: {
          id: {
            in: toDelete.map((h) => h.id),
          },
        },
      });
    }
  }

  static isPasswordExpired(passwordChangedAt: Date): boolean {
    const now = new Date();
    const daysSinceChange =
      Math.floor(now.getTime() - passwordChangedAt.getTime()) /
      (1000 * 60 * 60 * 24);
    return daysSinceChange > Number(this.MAX_LIFETIME_DAYS);
  }
}
