# My Secure Node.js App

This is a Secure Node.js application built with **TypeScript** and **Express**, packaged with **Docker** for easy development and deployment.

## Features

### 🛡️ Security Compliance
- Multi-factor authentication (MFA) for privileged and non-privileged accounts
- PKI-based authentication with certificate validation (⏳ pending...)
- Hardware token support (⏳ pending...)
- Comprehensive password policy enforcement
- Session management with device tracking
- Complete audit logging
- Rate limiting and DDoS protection
- Replay-resistant authentication mechanisms

---

### 🔐 Authentication Methods

1. **Username/Password + MFA** - Standard authentication with TOTP
2. **PKI Certificate Authentication** - X.509 certificate-based authentication (⏳ pending...)
3. **Hardware Token** - Support for hardware security keys (⏳ pending...)
4. **Backup Codes** - Emergency access codes

---

### 🔑 Password Policy

- Minimum 8 characters
- Character complexity (3 of 5 categories)
- Password history (12 generations)
- Expiration (120 days maximum)
- Account lockout protection

---

### 🚧 Audit & Compliance

- Complete user activity logging
- Login attempt tracking
- Device registration and management
- Session monitoring (⏳ pending...)
- Certificate revocation checking (⏳ pending...)
- Automated compliance reporting (⏳ pending...)

---

## Quick Start

1. **Clone and Setup**
```bash
cd financial-app
git clone <repository> .
nano .env
```
#### Security Configuration

Environment Variables `.env`:

```
PORT=3000
NODE_ENV=production

ROUTE_VERSION='/api/v1'

DATABASE_URL="mysql://finauth:<securedpassword>@mysql:3306/financial_auth"

LOG_LEVEL=info

# Password Policy
MIN_LENGTH=8
MAX_LIFETIME_DAYS=120
MIN_LIFETIME_DAYS=1
HISTORY_COUNT=12
SALT_ROUNDS=12

# node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
JWT_SECRET=your-super-secure-jwt-secret-key-here-minimum-256-bits

ENC_KEY=your-super-secure-secret-key-here-minimum-256-bits

# openssl rand -base64 32
MYSQL_ROOT_PASSWORD=<password>
MYSQL_PASSWORD=<securedpassword>
```

2. **Start Services**
```bash
docker-compose up -d --build
```

3. **Logs**
```bash
docker compose logs -f mysql
docker compose logs -f app
```

---

## API Endpoints

### Authentication
- `POST /api/<version>/auth/login` - User login
- `POST /api/<version>/auth/logout` - User logout  
- `POST /api/<version>/auth/refresh-token` - Token refresh

### Password Management
- `POST /api/<version>/auth/change-password` - Change password
- `POST /api/<version>/auth/setup-mfa` - Setup MFA
- `POST /api/<version>/auth/verify-mfa` - Verify MFA setup
- `POST /api/<version>/auth/disable-mfa` - Disable MFA

### User Management (Privileged) (⏳ pending...)
- `POST /api/<version>/users/create` - Create user
- `GET /api/<version>/users/profile` - Get user profile
- `GET /api/<version>/users/sessions` - List active sessions
- `DELETE /api/<version>/users/sessions/:id` - Revoke session
- `PUT /api/<version>/users/deactivate/:id` - Deactivate user

### Device Management (Privileged) 
- `POST /api/<version>/devices/register` - Register device
- `GET /api/<version>/devices` - List devices
- `PUT /api/<version>/devices/deactivate/:id` - Deactivate device

---

### SSL/TLS (⏳ pending...)
- TLS 1.2+ required
- Strong cipher suites only
- HSTS enabled
- Certificate pinning recommended

### Database Security (⏳ pending...)
- Encrypted connections required
- Separate audit user with read-only access
- Regular backups with encryption
- Query logging enabled

## Monitoring & Alerting

### Key Metrics
- Failed login attempts
- Suspicious user activities  
- Certificate validation failures
- System performance metrics

### Log Files (⏳ pending...)
- `/app/logs/audit.log` - Audit trail
- `/app/logs/security.log` - Security events
- `/app/logs/error.log` - Error logging
- `/app/logs/access.log` - Access logging

---

## Production Deployment (⏳ pending...)

1. **Security Hardening**
   - Replace development certificates with CA-signed certificates
   - Configure proper firewall rules
   - Enable intrusion detection/prevention
   - Set up log monitoring (SIEM)

2. **High Availability**
   - Load balancer configuration
   - Database replication
   - Redis for session storage
   - Health check monitoring

3. **Backup Strategy**
   - Automated database backups
   - Encrypted backup storage
   - Regular restore testing
   - Disaster recovery procedures


## Support

For technical support and security issues:
- Check the audit logs for detailed error information
- Review the security monitoring dashboards
- Contact the security team for policy violations
- Escalate to incident response team for breaches
