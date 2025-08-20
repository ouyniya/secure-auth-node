/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */
import QRCode from 'qrcode';
import crypto from 'crypto';
import { CryptoUtils } from './crypto';

/**
 * Types
 */

enum HashAlgorithm {
  SHA1 = 'SHA1',
  SHA256 = 'SHA256',
  SHA512 = 'SHA512',
}

/**
 * Variables
 */
const DEFAULT_DIGITS = 6;
const DEFAULT_PERIOD = 30; // seconds
const DEFAULT_ALGO: HashAlgorithm = HashAlgorithm.SHA1; // ใช้ SHA1 เพื่อความเข้ากันได้กับ Google Authenticator

/**
 * Pad a number with leading zeros to reach the desired length เติมเลขศูนย์นำหน้าตัวเลขเพื่อให้มีความยาวตามที่กำหนด
 * @param n The number to pad
 * @param digits The total number of digits desired
 * @returns A string representation of the number with leading zeros if needed
 */
function padStartNum(n: number, digits: number): string {
  const s = String(n);
  return s.length >= digits ? s : '0'.repeat(digits - s.length) + s;
}

/** ---------- Base32 (RFC 4648) ---------- */
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const B32_LOOKUP: Record<string, number> = Object.fromEntries(
  [...B32_ALPHABET].map((c, i) => [c, i]),
);

/**
 * Encode a buffer into a Base32 string according to RFC 4648.
 * @param buf The buffer to encode.
 * @returns A Base32 encoded string.
 */
function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      output += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += B32_ALPHABET[(value << (5 - bits)) & 31];
  }
  // เติม '=' ให้ความยาวเป็นหลายเท่าของ 8
  while (output.length % 8 !== 0) output += '=';
  return output;
}

/**
 * Decode a Base32 string into a buffer.
 * @param str The Base32 string to decode.
 * @returns The decoded buffer.
 * @throws {Error} If the string contains an invalid Base32 character.
 */
function base32Decode(str: string): Buffer {
  const clean = str.toUpperCase().replace(/=+$/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (const ch of clean) {
    const idx = B32_LOOKUP[ch];
    if (idx === undefined) throw new Error('Invalid base32 character');
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** ---------- HOTP / TOTP ---------- */
/**
 * Generate a HMAC-based One-Time Password (HOTP).
 * @param secret The secret key as a Buffer.
 * @param counter The counter value (can be number or bigint).
 * @param digits The number of digits for the OTP.
 * @param algo The hashing algorithm to use (SHA1, SHA256, or SHA512).
 * @returns The HOTP token as a string.
 */
function hotp(
  secret: Buffer,
  counter: number | bigint,
  digits = DEFAULT_DIGITS,
  algo = DEFAULT_ALGO,
): string {
  const buf = Buffer.alloc(8);
  let c = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(c & 0xffn);
    c >>= 8n;
  }

  const hmac = crypto
    .createHmac(algo.toLowerCase(), secret)
    .update(buf)
    .digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return padStartNum(code % 10 ** digits, digits);
}

/**
 * Calculate the time-based counter value for TOTP.
 * @param epochSeconds The current timestamp in seconds since the Unix epoch.
 * @param period The time step period in seconds.
 * @returns The counter value as a BigInt.
 */
function timeCounter(epochSeconds: number, period = DEFAULT_PERIOD): bigint {
  return BigInt(Math.floor(epochSeconds / period));
}

/**
 * Generate a Time-based One-Time Password (TOTP).
 * @param secret The secret key as a Buffer.
 * @param opts An optional object containing period, digits, algo, and timestamp.
 * @returns The TOTP token as a string.
 */
function totp(
  secret: Buffer,
  opts?: {
    period?: number;
    digits?: number;
    algo?: HashAlgorithm;
    timestamp?: number;
  },
): string {
  const period = opts?.period ?? DEFAULT_PERIOD;
  const digits = opts?.digits ?? DEFAULT_DIGITS;
  const algo = opts?.algo ?? DEFAULT_ALGO;
  const ts = opts?.timestamp ?? Math.floor(Date.now() / 1000);
  const ctr = timeCounter(ts, period);
  return hotp(secret, ctr, digits, algo);
}

/**
 * Verify a TOTP token against a Base32 secret.
 * @param base32Secret The Base32 encoded secret.
 * @param token The token to verify.
 * @param opts An optional object containing verification options.
 * @returns True if the token is valid, otherwise false.
 */
function verifyTotp(
  base32Secret: string,
  token: string,
  opts?: {
    window?: number;
    period?: number;
    digits?: number;
    algo?: HashAlgorithm;
    timestamp?: number;
  },
): boolean {
  const secretBuf = base32Decode(base32Secret);
  return verifyHotp(secretBuf, token, opts);
}

/**
 * Verify a HOTP token against a secret buffer, allowing for a time window.
 * @param secret The secret key as a Buffer.
 * @param token The token to verify.
 * @param opts An optional object containing verification options.
 * @returns True if the token is valid, otherwise false.
 */
function verifyHotp(
  secret: Buffer,
  token: string,
  opts?: {
    window?: number;
    period?: number;
    digits?: number;
    algo?: HashAlgorithm;
    timestamp?: number;
  },
): boolean {
  const period = opts?.period ?? DEFAULT_PERIOD;
  const digits = opts?.digits ?? DEFAULT_DIGITS;
  const algo = opts?.algo ?? DEFAULT_ALGO;
  const ts = opts?.timestamp ?? Math.floor(Date.now() / 1000);
  const win = opts?.window ?? 1; // Check previous/next time steps as well.

  const currentCtr = timeCounter(ts, period);
  for (let w = -win; w <= win; w++) {
    const candidate = hotp(secret, currentCtr + BigInt(w), digits, algo);

    console.log(`w=${w} candidate************* ${candidate}`);

    if (candidate === token) return true;
  }
  return false;
}

/** ---------- otpauth URL ---------- */
/**
 * Build the otpauth:// URI for a TOTP secret.
 * @param params The parameters for the URL, including secret, label, and issuer.
 * @returns The formatted otpauth:// URI string.
 */
function buildOtpAuthURL(params: {
  secretBase32: string;
  label: string; // e.g. FinancialApp:username
  issuer: string;
  period?: number;
  digits?: number;
  algo?: HashAlgorithm;
}): string {
  const period = params.period ?? DEFAULT_PERIOD;
  const digits = params.digits ?? DEFAULT_DIGITS;
  const algo = params.algo ?? DEFAULT_ALGO;

  const label = encodeURIComponent(params.label);
  const issuer = encodeURIComponent(params.issuer);
  const secret = encodeURIComponent(params.secretBase32);

  // otpauth://totp/Issuer:Label?secret=...&issuer=Issuer&algorithm=SHA1&digits=6&period=30
  return `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=${algo}&digits=${digits}&period=${period}`;
}

/** ---------- Public API (compatible with your previous class) ---------- */
/**
 * Generate a new MFA secret, encrypt it, and create an associated QR code URL.
 * @param username The user's unique identifier.
 * @param options An optional object containing issuer, secret bytes, algorithm, digits, and period.
 * @returns An object containing the Base32 secret, encrypted secret, and QR code URL.
 */
export class MFAService {
  static generateSecret(
    username: string,
    options?: {
      issuer?: string;
      bytes?: number; // ขนาด secret ในหน่วยไบต์
      algorithm?: HashAlgorithm; // 'SHA1' | 'SHA256' | 'SHA512'
      digits?: number;
      period?: number;
    },
  ): { encryptedSecret: string; qrCodeUrl: string } {
    const issuer = options?.issuer ?? 'Financial Institution';
    const bytes = options?.bytes ?? 20; // 20 bytes (~160 bits) เป็นค่าแนะนำ
    const algo = options?.algorithm ?? DEFAULT_ALGO;
    const digits = options?.digits ?? DEFAULT_DIGITS;
    const period = options?.period ?? DEFAULT_PERIOD;

    const rawSecret = crypto.randomBytes(bytes);
    const base32Secret = base32Encode(rawSecret);
    const label = `${issuer}:${username}`;

    const encryptedSecret = CryptoUtils.encrypt(base32Secret);

    const otpauthUrl = buildOtpAuthURL({
      secretBase32: base32Secret,
      label,
      issuer,
      period,
      digits,
      algo,
    });

    return {
      encryptedSecret, // เก็บใน DB
      qrCodeUrl: otpauthUrl,
    };
  }

  /**
   * Generate a QR code as a data URL from an otpauth:// URI.
   * @param otpauthUrl The otpauth:// URI string.
   * @returns A Promise that resolves to the QR code data URL string.
   */
  static async generateQRCode(otpauthUrl: string): Promise<string> {
    return QRCode.toDataURL(otpauthUrl);
  }

  /**
   * Verify a TOTP token provided by the user.
   * @param secret The Base32 encoded secret stored in the database.
   * @param token The token string to verify.
   * @param options An optional object containing window, algorithm, digits, period, and timestamp.
   * @returns True if the token is valid, otherwise false.
   */
  static verifyToken(
    secret: string,
    token: string,
    options?: {
      window?: number;
      algorithm?: HashAlgorithm;
      digits?: number;
      period?: number;
      timestamp?: number; // สำหรับทดสอบ/ย้อนเวลา
    },
  ): boolean {
    return verifyTotp(secret, token, {
      window: options?.window ?? 2, // Allow 2 time steps tolerance
      algo: options?.algorithm ?? DEFAULT_ALGO,
      digits: options?.digits ?? DEFAULT_DIGITS,
      period: options?.period ?? DEFAULT_PERIOD,
      timestamp: options?.timestamp,
    });
  }

  /**
   * Generate a list of random, human-readable backup codes.
   * @param count The number of backup codes to generate.
   * @returns An array of backup code strings.
   */
  static generateBackupCodes(count: number = 8): string[] {
    const codes: string[] = [];
    for (let i = 0; i < count; i++) {
      const code = crypto.randomBytes(4).toString('hex').toUpperCase();
      codes.push(`${code.slice(0, 4)}-${code.slice(4, 8)}`);
    }
    return codes;
  }

  /**
   * Verify if a provided backup code is valid and remove it from the stored list.
   * @param storedCodes A JSON string of the stored backup codes.
   * @param inputCode The backup code to verify.
   * @returns An object indicating if the code is valid and the remaining codes as a JSON string.
   */
  static verifyBackupCode(
    storedCodes: string,
    inputCode: string,
  ): { valid: boolean; remainingCodes: string } {
    const codes = JSON.parse(storedCodes) as string[];
    const codeIndex = codes.findIndex(
      (code) => code === inputCode.toUpperCase(),
    );

    if (codeIndex === -1) {
      return { valid: false, remainingCodes: storedCodes };
    }
    // Remove used backup code
    codes.splice(codeIndex, 1);
    return { valid: true, remainingCodes: JSON.stringify(codes) };
  }
}
