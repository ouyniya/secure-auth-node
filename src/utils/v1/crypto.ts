/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */
import crypto from 'crypto';
import forge from 'node-forge';

/**
 * CryptoUtils
 * AES-256-GCM symmetric encryption utility
 *
 * Usage:
 * const encrypted = CryptoUtils.encrypt("my secret");
 * const decrypted = CryptoUtils.decrypt(encrypted);
 */
export class CryptoUtils {
  private static readonly ALGORITHM = 'aes-256-gcm';
  private static readonly ENC_KEY = Buffer.from(process.env.ENC_KEY!, 'hex'); // 32-byte key
  private static readonly IV_LENGTH = 12; // 96-bit IV
  private static readonly TAG_LENGTH = 16; // 128-bit auth tag

  /**
   * Encrypt plain text
   * @param plainText string
   * @returns base64 string containing IV + Tag + Ciphertext
   */
  static encrypt(plainText: string): string {
    const iv = crypto.randomBytes(this.IV_LENGTH);
    const cipher = crypto.createCipheriv(this.ALGORITHM, this.ENC_KEY, iv);

    const encrypted = Buffer.concat([
      cipher.update(plainText, 'utf8'),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    // Combine IV + Tag + Ciphertext for storage/transmission
    return Buffer.concat([iv, tag, encrypted]).toString('base64');
  }

  /**
   * Decrypt base64 string produced by encrypt()
   * @param ciphertextB64 string (base64 IV + Tag + Ciphertext)
   * @returns decrypted plain text
   */
  static decrypt(ciphertextB64: string): string {
    const data = Buffer.from(ciphertextB64, 'base64');

    // Extract IV, Tag, Ciphertext
    const iv = data.subarray(0, this.IV_LENGTH);
    const tag = data.subarray(this.IV_LENGTH, this.IV_LENGTH + this.TAG_LENGTH);
    const encrypted = data.subarray(this.IV_LENGTH + this.TAG_LENGTH);

    const decipher = crypto.createDecipheriv(this.ALGORITHM, this.ENC_KEY, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);
    return decrypted.toString('utf8');
  }

  /**
   * Generate a secure, cryptographically strong token.
   * @param length The desired length of the token in bytes. The final string will be double this length (hexadecimal representation).
   * @returns A cryptographically secure token as a hexadecimal string.
   */
  static generateSecureToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Hash a string using the SHA256 algorithm.
   * @param data The string to hash.
   * @returns The SHA256 hash as a hexadecimal string.
   */
  static hashSHA256(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Generate a unique device fingerprint by hashing key user and device data.
   * @param userAgent The user's browser user agent string.
   * @param ip The user's IP address.
   * @param additionalData Optional string for additional data to include in the hash (e.g., screen resolution, fonts).
   * @returns The SHA256 hash representing the device fingerprint.
   */
  static generateDeviceFingerprint(
    userAgent: string,
    ip: string,
    additionalData?: string,
  ): string {
    const data = `${userAgent}|${ip}|${additionalData || ''}`;
    return this.hashSHA256(data);
  }

  static parsePKICertificate(certPem: string): any {
    try {
      const cert = forge.pki.certificateFromPem(certPem);
      return {
        subject: cert.subject.getField('CN')?.value || '',
        issuer: cert.issuer.getField('CN')?.value || '',
        serialNumber: cert.serialNumber,
        validFrom: cert.validity.notBefore,
        validTo: cert.validity.notAfter,
        fingerprint: forge.md.sha256
          .create()
          .update(
            forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(),
          )
          .digest()
          .toHex(),
      };
    } catch (error) {
      console.log('PKI Certificate Error: ', error);
      throw new Error('Invalid certificate format');
    }
  }

  static verifyCertificateChain(certPem: string, caCertPem: string): boolean {
    try {
      const cert = forge.pki.certificateFromPem(certPem);
      const caCert = forge.pki.certificateFromPem(caCertPem);

      // Verify certificate against CA
      return caCert.verify(cert);
    } catch (error) {
      console.log('PKI Certificate error: ', error);
      return false;
    }
  }
}
