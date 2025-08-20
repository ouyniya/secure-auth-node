/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */
import express from 'express';
import { DeviceController } from '../../controllers/v1/auth/deviceController';
import { authenticateToken, requirePrivileged, auditLog } from '../../middlewares/auth';

const router = express.Router();

router.post('/register',
  authenticateToken,
//   DeviceController.registerDeviceValidation,
  auditLog('DEVICE_REGISTER'),
  DeviceController.registerDevice
);

router.get('/',
  authenticateToken,
  requirePrivileged,
  auditLog('DEVICES_VIEW'),
  DeviceController.getDevices
);

router.put('/deactivate/:deviceId',
  authenticateToken,
  requirePrivileged,
  auditLog('DEVICE_DEACTIVATE'),
  DeviceController.deactivateDevice
);

export default router;
      