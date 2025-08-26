/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Variables
 */
const sensitiveKeys = [
  'token',
  'sessionToken',
  'refreshToken',
  'password',
  'hashedPassword',
  'totpSecret',
  'backupCodes',
  'certificateDN',
  'certificateHash',
  'publicKeyHash',
  'hardwareTokenId',
];

// ฟังก์ชัน sanitize stack trace
export function sanitizeStack(stack: string) {
  if (!stack) return '';
  // ลบ path ของเครื่อง local
  return stack.replace(/\/Users\/[^\s]+/g, '/REDACTED_PATH');
}

// ฟังก์ชัน mask sensitive info
export function maskSensitive(value: any): any {
  if (Array.isArray(value)) {
    return value.map(maskSensitive);
  }

  if (typeof value === 'object' && value !== null) {
    const clone: Record<string, any> = {};
    for (const key in value) {
      if (sensitiveKeys.includes(key)) {
        clone[key] = '*****';
      } else {
        clone[key] = maskSensitive(value[key]);
      }
    }
    return clone;
  }

  if (typeof value === 'string') {
    // ถ้า string เป็น JSON ของ object/array → parse แล้ว mask
    try {
      const parsed = JSON.parse(value);
      const masked = maskSensitive(parsed);
      return typeof masked === 'string' ? masked : JSON.stringify(masked);
    } catch {
      return value; // ถ้า parse ไม่ได้ คืนค่าเดิม
    }
  }

  return value; // number, boolean, null
}

export function safeMask(value: any) {
  return maskSensitive(value);
}


// Regex สำหรับ detect JWT
const jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;

// ฟังก์ชัน mask JWT ใน params
export const maskTokens = (params: any) => {
  let parsedParams: any[] = [];

  // ถ้าเป็น string parse เป็น JSON
  if (typeof params === 'string') {
    try {
      parsedParams = JSON.parse(params);
    } catch {
      // parse ไม่ได้ ให้ return string เดิม
      return params;
    }
  } else if (Array.isArray(params)) {
    parsedParams = params;
  } else {
    return params; // type อื่น return ตามเดิม
  }

  return parsedParams.map((p) => {
    if (typeof p === 'string') {
      const isJWT = jwtRegex.test(p);
      const isLongString = p.length > 40; // heuristic สำหรับ token/hash
      const isHex = /^[a-f0-9]{40,}$/i.test(p); // optional: hex string ยาว ๆ

      if (isJWT || isLongString || isHex) return '[MASKED]';
    }
    return p;
  });
};