# MicroSIEM - Project Specification

## 📋 Project Overview

**Project Name:** MicroSIEM  
**Version:** 1.0.0 (MVP)  
**Type:** Security Information and Event Management System  
**Target:** Linux Systems Hardening, Monitoring & Compliance  
**Status:** In Development

### Purpose
Sistema centralizzato per gestione, hardening, monitoring e compliance di server Linux remoti tramite console web con dashboard real-time.

### Key Features
- ✅ Hardening automatico basato su modelli (base/severo)
- ✅ Monitoring continuo e alerting
- ✅ Compliance checking (NIS2, PCI-DSS, ISO)
- ✅ Dashboard real-time personalizzabili
- ✅ Role-based access control (sysadmin/reporter)
- ✅ Gestione multi-target via SSH

---

## 🏗️ Architecture Overview

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    MICROSIEM CENTRAL SERVER                  │
│                      (cybersheppard)                         │
├─────────────────────────────────────────────────────────────┤
│  Frontend (React+TS)  │  Nginx  │  Backend (Flask+FastAPI)  │
├───────────────────────┴─────────┴───────────────────────────┤
│                    InfluxDB (Time-Series)                    │
│                    PostgreSQL (Metadata)                     │
└────────────────────────────┬────────────────────────────────┘
                             │ SSH (Ed25519)
                             │ SCP (JSON files)
                             ▼
              ┌──────────────────────────────┐
              │   TARGET SYSTEMS (Debian)    │
              ├──────────────────────────────┤
              │  User: microsiem             │
              │  Cron Jobs → JSON output     │
              │  Hardening configs applied   │
              │  Auditd, monitoring tools    │
              └──────────────────────────────┘
```

### Communication Flow

1. **User → Frontend**: HTTPS, JWT authentication
2. **Frontend → Backend**: REST API (JSON)
3. **Backend → Targets**: SSH (Ed25519), SCP for file transfer
4. **Targets → Backend**: JSON files via SCP (every 30s)
5. **Backend → Databases**: Write parsed data
6. **Frontend → Databases**: Query for dashboards

---

## 🛠️ Technology Stack

### Frontend
- **Framework**: React 18+
- **Language**: TypeScript 5+
- **State Management**: TanStack Query (React Query)
- **UI Components**: shadcn/ui or Material-UI
- **Charts**: Recharts or Chart.js
- **Build Tool**: Vite
- **HTTP Client**: Axios

### Backend
- **Frameworks**: 
  - **Flask** (main application, auth, business logic)
  - **FastAPI** (API endpoints, async operations, WebSocket)
- **Language**: Python 3.11+
- **SSH Library**: Paramiko
- **Data Validation**: Pydantic
- **Task Queue**: Celery (optional for async tasks)
- **WSGI Server**: Gunicorn

### Databases
- **InfluxDB 2.x**: Time-series data (metrics, logs)
- **PostgreSQL 15+**: Metadata (users, hosts, models, configs)

### Infrastructure
- **Web Server**: Nginx (reverse proxy, static files)
- **OS**: Debian/Ubuntu (server + targets)
- **Containerization**: Docker + Docker Compose
- **Process Manager**: systemd

### Security
- **Authentication**: JWT (JSON Web Tokens)
- **SSH Keys**: Ed25519 (elliptic curve)
- **Password Hashing**: bcrypt or Argon2
- **Secrets Management**: Environment variables + .env files
- **HTTPS**: Let's Encrypt (production)

### Data Format
- **Exchange Format**: JSON (standard for all data transfers)
- **Configuration**: YAML (optional, for readability)

---

## 📁 Project Structure

```
microsiem/
├── docs/                          # Documentation
│   ├── PROJECT_SPEC.md           # This file
│   ├── ARCHITECTURE.md           # Architecture details
│   ├── API_CONTRACT.md           # API documentation
│   ├── SECURITY.md               # Security guidelines
│   ├── DEPLOYMENT.md             # Deployment guide
│   └── DEVELOPMENT.md            # Development setup
│
├── frontend/                      # React + TypeScript
│   ├── src/
│   │   ├── components/           # React components
│   │   ├── pages/                # Page components
│   │   ├── services/             # API calls
│   │   ├── hooks/                # Custom hooks
│   │   ├── types/                # TypeScript types
│   │   ├── utils/                # Utilities
│   │   └── App.tsx
│   ├── package.json
│   └── tsconfig.json
│
├── backend/                       # Flask + FastAPI
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py               # FastAPI app
│   │   ├── flask_app.py          # Flask app
│   │   ├── models/               # Database models
│   │   ├── schemas/              # Pydantic schemas
│   │   ├── api/                  # API endpoints
│   │   ├── services/             # Business logic
│   │   ├── auth/                 # Authentication
│   │   └── utils/                # Utilities
│   ├── requirements.txt
│   └── config.py
│
├── modules/                       # Core system modules
│   ├── hardening/                # Hardening module
│   │   ├── models/               # Hardening templates
│   │   ├── validators/           # Config validators
│   │   └── applier.py            # Apply hardening
│   │
│   ├── monitoring/               # Monitoring module
│   │   ├── collectors/           # Data collectors
│   │   ├── parsers/              # JSON parsers
│   │   └── scheduler.py          # Cron management
│   │
│   ├── checking/                 # Checking module
│   │   ├── compliance/           # Compliance checks
│   │   ├── security/             # Security checks
│   │   └── scripts/              # Custom scripts
│   │
│   └── alerting/                 # Alerting module
│       ├── email.py
│       ├── webhook.py
│       └── templates/
│
├── target-scripts/                # Scripts deployed on targets
│   ├── monitoring.sh             # Main monitoring script
│   ├── collectors/               # Individual collectors
│   └── setup.sh                  # Initial setup script
│
├── database/                      # Database schemas
│   ├── influxdb/
│   │   └── schema.flux           # InfluxDB schema
│   └── postgresql/
│       ├── migrations/           # Alembic migrations
│       └── schema.sql            # PostgreSQL schema
│
├── docker/                        # Docker configuration
│   ├── Dockerfile.frontend
│   ├── Dockerfile.backend
│   ├── docker-compose.yml
│   └── nginx.conf
│
├── tests/                         # Test suite
│   ├── frontend/
│   ├── backend/
│   └── integration/
│
├── .env.example                   # Environment variables template
├── .gitignore
└── README.md
```

---

## 🎯 Core Modules Specification

### 1. Hardening Module
**Purpose**: Apply security configurations to target systems

**Features**:
- Pre-built templates (base/severo)
- Compliance-based (NIS2, PCI-DSS, ISO)
- Role-based (web, dns, db, gateway)
- Model validation and error detection
- SHA512 integrity checking
- Testing on non-production machines

**Technologies**:
- `sysctl` (kernel parameters)
- `apparmor/selinux` (mandatory access control)
- `iptables/nftables` (firewall)
- `systemd` (service management)
- `sudoers` (privilege management)

### 2. Monitoring Module
**Purpose**: Collect system metrics and security events

**Features**:
- Continuous monitoring (30s intervals)
- Asynchronous data collection
- JSON output standardization
- Automatic cron setup

**Tools**:
- `auditd` (audit daemon)
- `ulogd2` (netfilter logging)
- `netstat/ss` (network connections)
- `lsof` (open files)
- `find` (file system checks)
- `strace` (system calls)

### 3. Checking Module
**Purpose**: Verify system state and compliance

**Data Collected**:
- Hardening status
- Compliance state
- Active connections (SSH, RDP, VNC)
- Connected users and activities
- Privilege escalation vectors
- Service states
- File integrity (SHA256/SHA512 hashes)
- Suspicious activities

**Extensibility**:
- Custom scripts support
- Standardized JSON output
- Database schema mapping

### 4. Alerting Module
**Purpose**: Notify administrators of security events

**Channels**:
- Email (SMTP)
- Slack (webhook)
- Telegram (webhook)
- WhatsApp (webhook)

**Triggers**:
- Unauthorized configuration changes
- Unexpected service starts
- Suspicious user activities
- Failed compliance checks
- File integrity violations
- Anomalous connections

---

## 📦 Hardening Models Structure

### Model Organization

Hardening models are collections of **real configuration files** ready to be deployed on target systems. Each model is stored as a directory containing configuration files with a special naming convention.

**Base Directory**: `modules/hardening/models/`

```
modules/hardening/models/
├── README.md                          # Documentation and conventions
│
├── base/                              # Level "base" (lighter hardening)
│   ├── web_generic/
│   ├── web_nis2/
│   ├── web_pci/
│   ├── database_generic/
│   ├── database_pci/
│   ├── dns_generic/
│   └── gateway_generic/
│
├── severo/                            # Level "severo" (strict hardening)
│   ├── web_generic/
│   ├── web_nis2/
│   ├── web_pci/
│   ├── database_generic/
│   ├── database_pci/
│   ├── dns_generic/
│   └── gateway_generic/
│
└── custom/                            # User-created custom models
    └── [user_created_models]/
```

### File Naming Convention

Configuration files use **dot notation** to represent the target path on the system.

**Format**: `path.components.separated.by.dots`

| Target Path | Model Filename |
|-------------|----------------|
| `/etc/ssh/sshd_config` | `etc.ssh.sshd_config` |
| `/etc/sysctl.d/99-hardening.conf` | `etc.sysctl.d.99-hardening.conf` |
| `/etc/audit/rules.d/audit.rules` | `etc.audit.rules.d.audit.rules` |
| `/etc/iptables/rules.v4` | `etc.iptables.rules.v4` |
| `/etc/sudoers.d/microsiem` | `etc.sudoers.d.microsiem` |
| `/etc/apparmor.d/usr.sbin.nginx` | `etc.apparmor.d.usr.sbin.nginx` |

### Example Model Structure

```
modules/hardening/models/severo/web_nis2/
├── model.json                                    # Metadata (optional)
├── etc.sysctl.d.99-hardening.conf               # Kernel parameters
├── etc.ssh.sshd_config                          # SSH hardening
├── etc.iptables.rules.v4                        # Firewall rules
├── etc.audit.rules.d.audit.rules                # Audit rules
├── etc.apparmor.d.usr.sbin.nginx                # AppArmor profile
├── etc.fail2ban.jail.local                      # Fail2ban config
├── etc.ulogd.conf                               # Netfilter logging
└── etc.sudoers.d.microsiem                      # Sudo permissions
```

### Model Metadata (model.json)

Optional metadata file with model information:

```json
{
  "name": "web_severo_nis2",
  "version": "1.0.0",
  "description": "Strict hardening for web servers with NIS2 compliance",
  "role": "web",
  "compliance": "nis2",
  "level": "severo",
  "author": "MicroSIEM Team",
  "created_at": "2025-10-30",
  "supported_os": ["debian11", "debian12", "ubuntu20.04", "ubuntu22.04"],
  
  "services_to_enable": ["nginx", "auditd", "ulogd2", "fail2ban"],
  "services_to_disable": ["apache2", "telnet", "ftp", "vsftpd"],
  
  "packages_to_install": ["fail2ban", "ulogd2", "apparmor-utils"],
  "packages_to_remove": ["telnetd", "rsh-server", "rsh-client"],
  
  "requires_reboot": false,
  "estimated_apply_time_seconds": 120,
  
  "notes": [
    "This model enforces strict NIS2 compliance",
    "AppArmor profiles are set to enforce mode",
    "All unnecessary services are disabled"
  ]
}
```

### Model Application Process

1. **Selection**: User selects machine role + compliance + level
2. **Listing**: System lists all files in model directory
3. **Backup**: Creates backup of existing files on target
4. **Transfer**: Copies each file to target via SFTP
5. **Deployment**: Moves files from temp to final location (with sudo)
6. **Post-Steps**: Applies metadata instructions (enable/disable services, install packages)
7. **Verification**: Runs validation checks
8. **Logging**: Records all changes in audit log

### Example Configuration Files

**etc.sysctl.d.99-hardening.conf**:
```conf
# Network hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Kernel hardening
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
```

**etc.ssh.sshd_config** (excerpt):
```conf
# SSH Hardening - MicroSIEM
Protocol 2
Port 22
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers microsiem
```

**etc.sudoers.d.microsiem**:
```conf
# MicroSIEM monitoring user permissions
microsiem ALL=(root) NOPASSWD: /usr/bin/systemctl status *
microsiem ALL=(root) NOPASSWD: /usr/sbin/netstat
microsiem ALL=(root) NOPASSWD: /usr/bin/ss
microsiem ALL=(root) NOPASSWD: /usr/bin/lsof
microsiem ALL=(root) NOPASSWD: /usr/bin/find /etc -type f
microsiem ALL=(root) NOPASSWD: /usr/bin/apt list --upgradable
microsiem ALL=(root) NOPASSWD: /usr/sbin/auditctl -l

# Deny everything else
microsiem ALL=(ALL) !ALL

# Log all sudo commands
Defaults:microsiem log_output
```

### Creating Custom Models

Users can create custom models by:

1. Creating a new directory in `modules/hardening/models/custom/`
2. Adding configuration files using dot notation
3. Optionally creating a `model.json` with metadata
4. Testing on non-production machines
5. Applying to production targets

**Example**:
```bash
mkdir -p modules/hardening/models/custom/my_web_server/
cd modules/hardening/models/custom/my_web_server/

# Create configuration files
echo "..." > etc.ssh.sshd_config
echo "..." > etc.sysctl.d.99-hardening.conf
echo "..." > etc.iptables.rules.v4

# Create metadata
cat > model.json <<EOF
{
  "name": "my_web_server",
  "version": "1.0.0",
  "description": "Custom hardening for my web servers",
  "role": "web",
  "level": "custom"
}
EOF
```

### Model Integrity

**SHA512 Hashing**: Each model directory is hashed to detect unauthorized modifications.

```python
def calculate_model_hash(model_dir: Path) -> str:
    """Calculate SHA512 hash of all files in model"""
    hasher = hashlib.sha512()
    
    for file_path in sorted(model_dir.glob('*')):
        if file_path.is_file() and file_path.name != 'model.json':
            with open(file_path, 'rb') as f:
                hasher.update(f.read())
    
    return hasher.hexdigest()
```

**Integrity Check**: Before applying any model, the system verifies its hash against the stored value in the database. If mismatch is detected, an alert is triggered and the application is blocked.

### Model Validation

Before applying to production, models should be validated:

1. **Syntax Check**: Verify configuration file syntax
2. **Compatibility Check**: Ensure OS compatibility
3. **Conflict Check**: Detect conflicting settings
4. **Test Application**: Apply to test machine first
5. **Rollback Test**: Verify rollback capability

### Model Rollback

When hardening is applied, the system creates backups:

```bash
/etc/ssh/sshd_config.backup.20251030_103045
/etc/sysctl.d/99-hardening.conf.backup.20251030_103045
```

Rollback process:
1. Identify backup timestamp
2. Restore all backed-up files
3. Restart affected services
4. Verify system stability
5. Log rollback event

---

## 👥 User Roles & Permissions

### Role: Sysadmin
**Permissions**: Full access

- ✅ All Reporter permissions
- ✅ Add/modify/remove target machines
- ✅ Apply/modify/remove hardening models
- ✅ Launch ARP scans
- ✅ Upload IP lists
- ✅ Configure system settings
- ✅ Manage SSH keys rotation
- ✅ Configure alerting (SMTP, webhooks)
- ✅ Manage users and roles
- ✅ Access audit logs

### Role: Reporter
**Permissions**: Read-only + reporting

- ✅ View all dashboards
- ✅ Create custom dashboards
- ✅ View machine status
- ✅ Generate executive reports
- ✅ Export data
- ❌ Cannot modify configurations
- ❌ Cannot manage machines
- ❌ Cannot manage users

---

## 🔐 Security Requirements

### Authentication
- JWT-based authentication
- Secure password storage (bcrypt/Argon2)
- Session timeout (configurable)
- MFA support (future enhancement)

### SSH Key Management
- Ed25519 keys only
- Automatic key rotation (configurable interval)
- Key pair generation on first setup
- Secure key storage on server

### Target System Security
- Dedicated user: `microsiem`
- Restricted sudoers permissions
- Auditd monitoring of microsiem user
- SSH hardening (sshd_config)
- Alert on unauthorized activities

### Data Security
- HTTPS only (TLS 1.3)
- Encrypted database connections
- Secure secrets management
- Input validation (all inputs)
- SQL injection prevention (parameterized queries)
- XSS prevention (React escaping + CSP)
- CSRF protection (tokens)

### OWASP Top 10 Compliance
- [ ] A01: Broken Access Control → RBAC implementation
- [ ] A02: Cryptographic Failures → TLS, encrypted storage
- [ ] A03: Injection → Input validation, parameterized queries
- [ ] A04: Insecure Design → Threat modeling, secure architecture
- [ ] A05: Security Misconfiguration → Hardened defaults
- [ ] A06: Vulnerable Components → Dependency scanning
- [ ] A07: Authentication Failures → Strong auth, JWT, MFA ready
- [ ] A08: Software/Data Integrity → Hash verification, signed packages
- [ ] A09: Logging Failures → Comprehensive audit logs
- [ ] A10: SSRF → URL validation, network segmentation

---

## 📊 Data Flow Specification

### Target → Server (Every 30s)

1. **Target**: Cron executes monitoring script
2. **Target**: Script collects data asynchronously
3. **Target**: Generates JSON file: `/tmp/microsiem_<timestamp>.json`
4. **Server**: SCP pulls JSON file
5. **Server**: Parses JSON
6. **Server**: Writes to InfluxDB (metrics) + PostgreSQL (events)
7. **Target**: Removes old JSON files (cleanup)

### JSON Output Structure

```json
{
  "timestamp": "2025-10-30T10:30:00Z",
  "hostname": "webserver-01",
  "ip_address": "192.168.1.10",
  "collection_duration_ms": 1250,
  "hardening": {
    "status": "compliant",
    "score": 95,
    "last_applied": "2025-10-29T08:00:00Z",
    "model": "web_severo_nis2",
    "violations": []
  },
  "compliance": {
    "standard": "nis2",
    "status": "compliant",
    "checks_passed": 45,
    "checks_failed": 0,
    "details": []
  },
  "connections": [
    {
      "protocol": "tcp",
      "local_addr": "0.0.0.0",
      "local_port": 22,
      "remote_addr": "192.168.1.100",
      "remote_port": 54321,
      "state": "ESTABLISHED",
      "process": "sshd"
    }
  ],
  "users": [
    {
      "username": "admin",
      "login_time": "2025-10-30T09:00:00Z",
      "terminal": "pts/0",
      "from": "192.168.1.100",
      "activities": [
        {
          "timestamp": "2025-10-30T10:25:00Z",
          "command": "sudo systemctl restart nginx",
          "suspicious": false
        }
      ]
    }
  ],
  "services": {
    "running": ["nginx", "sshd", "auditd", "ulogd2"],
    "stopped": [],
    "unexpected": [],
    "disabled": ["telnet", "ftp", "rlogin"]
  },
  "packages": {
    "total": 456,
    "upgradable": 3,
    "security_updates": 1,
    "vulnerable": [
      {
        "name": "openssl",
        "version": "1.1.1f-1ubuntu2",
        "cve": ["CVE-2024-XXXX"]
      }
    ]
  },
  "file_integrity": [
    {
      "path": "/etc/passwd",
      "hash": "abc123...",
      "changed": false
    },
    {
      "path": "/etc/shadow",
      "hash": "def456...",
      "changed": false
    }
  ],
  "privilege_escalation": {
    "suid_files": [
      "/usr/bin/sudo",
      "/usr/bin/passwd"
    ],
    "writable_by_others": [],
    "suspicious_binaries": []
  },
  "auditd_events": [
    {
      "timestamp": "2025-10-30T10:29:45Z",
      "type": "SYSCALL",
      "user": "microsiem",
      "command": "cat /var/log/auth.log",
      "result": "success"
    }
  ]
}
```

---

## 🚀 Deployment Architecture

### Production Environment

**Server Requirements**:
- OS: Debian 12 or Ubuntu 22.04 LTS
- RAM: 8GB minimum (16GB recommended)
- CPU: 4 cores minimum
- Disk: 100GB SSD (depends on retention)
- Network: Static IP, firewall configured

**Target Requirements**:
- OS: Debian 11/12 or Ubuntu 20.04/22.04 LTS
- User: `microsiem` with sudo privileges
- SSH: Port 22 accessible from server
- Python 3: Installed (for scripts)

### Docker Compose Setup

```yaml
version: '3.8'
services:
  nginx:
    image: nginx:alpine
    ports: ["80:80", "443:443"]
    
  frontend:
    build: ./frontend
    
  backend-flask:
    build: ./backend
    command: gunicorn -w 4 app.flask_app:app
    
  backend-fastapi:
    build: ./backend
    command: uvicorn app.main:app --host 0.0.0.0
    
  influxdb:
    image: influxdb:2.7
    volumes: ["influxdb-data:/var/lib/influxdb2"]
    
  postgresql:
    image: postgres:15-alpine
    volumes: ["postgres-data:/var/lib/postgresql/data"]
```

---

## 📝 Configuration Management

### Environment Variables

```bash
# Application
APP_ENV=production
APP_SECRET_KEY=<random-secret>
APP_DEBUG=false

# JWT
JWT_SECRET_KEY=<jwt-secret>
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24

# Database - InfluxDB
INFLUX_URL=http://influxdb:8086
INFLUX_TOKEN=<influx-token>
INFLUX_ORG=microsiem
INFLUX_BUCKET=metrics

# Database - PostgreSQL
POSTGRES_HOST=postgresql
POSTGRES_PORT=5432
POSTGRES_DB=microsiem
POSTGRES_USER=microsiem
POSTGRES_PASSWORD=<postgres-password>

# SSH
SSH_PRIVATE_KEY_PATH=/app/keys/microsiem_ed25519
SSH_USER=microsiem
SSH_PORT=22
SSH_TIMEOUT=30

# Monitoring
COLLECTION_INTERVAL_SECONDS=30
DATA_RETENTION_DAYS=90

# Alerting
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=alerts@example.com
SMTP_PASSWORD=<smtp-password>
SMTP_FROM=microsiem@example.com

SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx
TELEGRAM_BOT_TOKEN=<token>
TELEGRAM_CHAT_ID=<chat-id>
```

---

## 📋 Development Roadmap

### Phase 1: Foundation (Weeks 1-2)
- [ ] Setup project structure
- [ ] Database schemas (PostgreSQL + InfluxDB)
- [ ] Basic authentication (JWT)
- [ ] User management (CRUD)

### Phase 2: Core Backend (Weeks 3-4)
- [ ] SSH connection manager
- [ ] Hardening module (model storage, validation)
- [ ] Basic monitoring data collection
- [ ] JSON parser and DB writer

### Phase 3: Frontend (Weeks 5-6)
- [ ] Authentication UI
- [ ] Dashboard framework
- [ ] Machine management UI
- [ ] Basic charts/visualizations

### Phase 4: Modules Integration (Weeks 7-8)
- [ ] Hardening application workflow
- [ ] Monitoring cron setup
- [ ] Checking module
- [ ] Alerting system

### Phase 5: Advanced Features (Weeks 9-10)
- [ ] Custom dashboards
- [ ] Compliance checks
- [ ] Privilege escalation detection
- [ ] File integrity monitoring

### Phase 6: Testing & Polish (Weeks 11-12)
- [ ] Integration testing
- [ ] Security audit
- [ ] Documentation completion
- [ ] Deployment automation

---

## 🧪 Testing Strategy

### Unit Tests
- Backend: pytest
- Frontend: Vitest + React Testing Library

### Integration Tests
- API endpoint testing
- Database operations
- SSH connectivity

### Security Tests
- OWASP ZAP scanning
- Dependency vulnerability scanning
- Penetration testing

### Performance Tests
- Load testing (100+ targets)
- Database query optimization
- Real-time data streaming

---

## 📚 Documentation Requirements

### Developer Documentation
- [ ] Setup instructions
- [ ] API documentation (auto-generated)
- [ ] Code style guide
- [ ] Contributing guidelines

### User Documentation
- [ ] Installation guide
- [ ] User manual
- [ ] Dashboard creation tutorial
- [ ] Troubleshooting guide

### Operations Documentation
- [ ] Deployment procedures
- [ ] Backup/restore procedures
- [ ] Monitoring/alerting setup
- [ ] Upgrade procedures

---

## ✅ Definition of Done (MVP)

The MVP is considered complete when:

1. ✅ User can login (JWT authentication)
2. ✅ User can add target machines (manual + ARP scan)
3. ✅ System can connect to targets via SSH
4. ✅ User can apply hardening (base/severo model)
5. ✅ Monitoring collects data every 30s
6. ✅ Data is stored in InfluxDB
7. ✅ User can view at least 3 dashboards:
   - System overview
   - Connection monitoring
   - Compliance status
8. ✅ Alerting works (email + one webhook)
9. ✅ RBAC works (sysadmin vs reporter)
10. ✅ Basic security measures implemented (OWASP)

---

## 📞 Support & Maintenance

### Logging
- Application logs: `/var/log/microsiem/app.log`
- Nginx logs: `/var/log/nginx/`
- Systemd journal: `journalctl -u microsiem`

### Monitoring
- Health check endpoint: `/api/health`
- Metrics endpoint: `/api/metrics`
- Database connection status

### Backup Strategy
- PostgreSQL: Daily automated backups
- InfluxDB: Retention policy + manual backups
- Configuration files: Version controlled

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-10-30  
**Maintained By**: Development Team
