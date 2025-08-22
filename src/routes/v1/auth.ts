/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */
import { Router } from 'express';

/**
 * Controllers
 */
import { AuthController } from '../../controllers/v1/auth/authController';
import { auditLog, authenticateToken } from '../../middlewares/v1/auth';
import {
  changePasswordSchema,
  loginSchema,
  registerSchema,
  validateSchema,
  verifyMFASchema,
} from '../../middlewares/v1/validation';

/**
 * Middlewares
 */

/**
 * Models
 */

const router = Router();

router.post(
  '/register',
  validateSchema({ body: registerSchema }),
  AuthController.register,
);

router.post(
  '/login',
  validateSchema({ body: loginSchema }),
  AuthController.login,
);

router.post(
  '/logout',
  authenticateToken,
  auditLog('LOGOUT'),
  AuthController.logout,
);

router.post(
  '/change-password',
  authenticateToken,
  validateSchema({ body: changePasswordSchema }),
  auditLog('PASSWORD_CHANGE'),
  AuthController.changePassword,
);

router.post(
  '/setup-mfa',
  authenticateToken,
  auditLog('MFA_SETUP'),
  AuthController.setupMFA,
);

router.post(
  '/verify-mfa',
  authenticateToken,
  validateSchema({ body: verifyMFASchema }),
  auditLog('MFA_VERIFY'),
  AuthController.verifyMFA,
);

router.post(
  '/disable-mfa',
  authenticateToken,
  auditLog('MFA_DISABLE'),
  AuthController.disableMFA,
);

router.post(
  '/refresh-token',
  auditLog('TOKEN_REFRESH'),
  AuthController.refreshToken,
);

router.post('/pki-auth', auditLog('PKI_AUTH'), AuthController.pkiAuth);

export default router;
