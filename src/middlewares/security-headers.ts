/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */
import helmet from 'helmet';

// Configure CSP HTTP Header
export const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],

      // React bundle JS
      scriptSrc: ["'self'"],

      // Tailwind CSS (build-in styles only)
      styleSrc: ["'self'", 'https://fonts.googleapis.com'],

      // Google Fonts
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],

      // รูป (ในเว็บตัวเอง + data URI)
      imgSrc: ["'self'", 'data:', 'https:'],

      // API
      connectSrc: ["'self'"],

      // ไม่ใช้ object/embed
      objectSrc: ["'none'"],

      mediaSrc: ["'self'"],

      // เราไม่ embed iframe จากเว็บอื่น
      frameSrc: ["'none'"],

      // ไม่อนุญาตให้คนอื่น embed เว็บเรา กัน clickjacking
      frameAncestors: ["'none'"],

      // Force HTTPS
      upgradeInsecureRequests: [],
    },
  },
  // ป้องกัน side-channel attack (Spectre) บังคับ resource ต้องมาจากที่เดียวกัน
  crossOriginEmbedderPolicy: true,

  // กันโดน hijack ผ่าน window.opener แยก browsing context ออกจากเว็บอื่น
  crossOriginOpenerPolicy: true,

  // อนุญาตให้ resource ของเว็บเราโหลดจาก cross-origin ได้ (ปรับได้ same-origin / same-site)
  crossOriginResourcePolicy: { policy: 'cross-origin' },

  // ปิด DNS Prefetching (ลดการรั่วไหลของ privacy จากการ resolve domain ล่วงหน้า)
  dnsPrefetchControl: true,

  // ป้องกัน clickjacking โดยห้าม embed เว็บเราผ่าน iframe เลย
  frameguard: { action: 'deny' },

  // ซ่อน header "X-Powered-By" ไม่บอก attacker ว่าเราใช้อะไร
  hidePoweredBy: true,

  // บังคับ HTTPS ด้วย Strict-Transport-Security (HSTS)
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },

  // สำหรับ IE: ป้องกันการเปิดไฟล์ดาวน์โหลดใน context ของเว็บเรา
  ieNoOpen: true,

  // ป้องกัน browser เดา MIME type เอง (X-Content-Type-Options: nosniff)
  noSniff: true,

  // บังคับ browser isolate memory ของ origin (เพิ่ม security isolation)
  originAgentCluster: true,

  // ปิด Adobe Flash / PDF cross-domain policy (X-Permitted-Cross-Domain-Policies: none)
  permittedCrossDomainPolicies: false,

  // ไม่ส่งค่า Referrer เลย (เพิ่ม privacy เวลา navigate ไปเว็บอื่น)
  referrerPolicy: { policy: 'no-referrer' },

  // เปิดการป้องกัน XSS (แต่ browser modern ส่วนใหญ่เลิกใช้แล้ว)
  xssFilter: true,
});
