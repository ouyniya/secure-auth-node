/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */
import { z } from 'zod';
import { Request, Response, NextFunction } from 'express';

/**
 * Types
 */
interface ValidationSchemas {
  body?: z.ZodSchema;
  query?: z.ZodSchema;
  params?: z.ZodSchema;
}

/**
 * Validation schema
 */
export const registerSchema = z.object({
  email: z
    .email({ message: 'Invalid email format' })
    .max(100, { message: 'Email must not exceed 100 characters' }),
  username: z
    .string()
    .min(3, { message: 'Username must be at least 3 characters' })
    .max(50, { message: 'Username must be less than 50 characters' })
    .regex(/^[a-z0-9_]+$/, {
      message: 'Username can only contain letters, numbers, and underscores',
    }),
  fullName: z
    .string()
    .min(3, { message: 'Full name must be at least 3 characters' })
    .max(50, { message: 'Full name must be less than 50 characters' })
    .regex(/^[a-z0-9_]+$/, {
      message: 'Full name can only contain letters, numbers, and underscores',
    }),
  password: z
    .string()
    .min(8, { message: 'Password must be at least 8 characters' })
    .max(128, { message: 'Password must not exceed 128 characters' }),
});

export const loginSchema = z.object({
  username: z
    .string()
    .min(3, { message: 'Username must be at least 3 characters' })
    .max(50, { message: 'Username must be less than 50 characters' })
    .regex(/^[a-z0-9_]+$/, {
      message: 'Username can only contain letters, numbers, and underscores',
    }),
  password: z
    .string()
    .min(8, { message: 'Password must be at least 8 characters' })
    .max(128, { message: 'Password must not exceed 128 characters' }),
  totpCode: z
    .string()
    .regex(/^\d+$/, { message: 'TOTP Code must be a positive integer' })
    .transform(Number)
    .optional(),
  rememberDevice: z.coerce.boolean().optional(),
});

export const changePasswordSchema = z.object({
  currentPassword: z
    .string()
    .min(8, { message: 'Password must be at least 8 characters' })
    .max(128, { message: 'Password must not exceed 128 characters' }),
  newPassword: z
    .string()
    .min(8, { message: 'Password must be at least 8 characters' })
    .max(128, { message: 'Password must not exceed 128 characters' }),
});

export const verifyMFASchema = z.object({
  totpCode: z
    .string()
    .regex(/^\d+$/, { message: 'TOTP Code must be a positive integer' })
    .transform(Number),
});

/**
 * Validation Middlewares
 */

export const validateSchema = (schema: ValidationSchemas) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      if (schema.body) {
        schema.body.parse(req.body);
      }

      if (schema.query) {
        schema.query.parse(req.query);
      }

      if (schema.params) {
        schema.params.parse(req.params);
      }

      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: error.issues.map((err) => ({
            field: err.path.join('.'),
            message: err.message,
          })),
        });
      }
      next(error);
    }
  };
};
