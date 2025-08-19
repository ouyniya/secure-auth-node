/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    username: string;
    isPrivileged: boolean;
    sessionId: boolean;
  };
  device?: {
    id: string;
    deviceId: string;
  };
}

export interface LoginRequest {
  username: string;
  password: string;
  totpCode?: string;
  deviceFingerprint: string;
  rememberDevice?: boolean;
}

export interface MFASetupResponse {
  secret: string;
  qrCode: string;
  backupCodes: string[];
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: Date;
  validTo: Date;
  fingerprint: string;
}
