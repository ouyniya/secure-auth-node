# 🛡️ Security Headers Mapping (Helmet.js)

| Header (Helmet Config)             | ค่าที่ตั้งไว้                     | ป้องกันการโจมตี / ความเสี่ยงที่แก้ได้                                  |
|------------------------------------|-----------------------------------|--------------------------------------------------------------------------|
| `Cross-Origin-Embedder-Policy`     | `crossOriginEmbedderPolicy: true` | Side-channel attacks (เช่น Spectre) จากการโหลด resource ข้าม origin |
| `Cross-Origin-Opener-Policy`       | `crossOriginOpenerPolicy: true`   | Clickjacking / Tabnabbing ผ่าน `window.opener`                        |
| `Cross-Origin-Resource-Policy`     | `{ policy: "cross-origin" }`      | Data theft จาก resource ที่โหลดข้าม origin โดยไม่ได้ตั้งใจ            |
| `X-DNS-Prefetch-Control`           | `dnsPrefetchControl: true`        | Privacy leak จาก DNS Prefetching                                       |
| `X-Frame-Options`                  | `frameguard: { action: "deny" }`  | Clickjacking (เว็บถูก embed เป็น `<iframe>`)                          |
| `X-Powered-By`                     | `hidePoweredBy: true`             | Information disclosure (ซ่อนว่า backend ใช้ Express)                  |
| `Strict-Transport-Security` (HSTS) | `hsts: { maxAge: 31536000, ... }` | SSL Stripping / MITM attacks (บังคับ HTTPS)                           |
| `X-Download-Options`               | `ieNoOpen: true`                  | XSS ผ่านไฟล์ดาวน์โหลดใน IE                                            |
| `X-Content-Type-Options`           | `noSniff: true`                   | MIME-sniffing → Drive-by download / RCE                                |
| `Origin-Agent-Cluster`             | `originAgentCluster: true`        | Cross-origin data leak (เพิ่ม memory isolation)                        |
| `X-Permitted-Cross-Domain-Policies`| `permittedCrossDomainPolicies: false` | Flash/PDF cross-domain policy abuse (แม้เทคโนโลยีเก่าแต่กันไว้) |
| `Referrer-Policy`                  | `{ policy: "no-referrer" }`       | Privacy leak (ป้องกันไม่ให้ส่ง Referer ไปเว็บอื่น)                     |
| `X-XSS-Protection`                 | `xssFilter: true`                 | Reflected XSS (บน browser เก่า ๆ ที่ยังรองรับ XSS Auditor)             |
