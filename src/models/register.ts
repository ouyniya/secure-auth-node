/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */
import { z } from 'zod';

/**
 * Validation schema
 */

const registerSchema = z.object({
  email: z
    .email({ message: 'Invalid email format' })
    .max(100, { message: 'Email must not exceed 100 characters' }),
  username: z
    .string()
    .min(3, { message: 'Username must be at least 3 characters' })
    .max(20, { message: 'Username must be less than 20 characters' })
    .regex(/^[a-z0-9_]+$/, {
      message: 'Username can only contain letters, numbers, and underscores',
    }),
  password: z
    .string()
    .min(8, { message: 'Password must be at least 8 characters' })
    .max(128, 'Password must not exceed 128 characters'),
});

export default registerSchema;
