# MicroSIEM - Security Requirements

## 🔐 Security Overview

This document outlines the security requirements, controls, and best practices for the MicroSIEM project, aligned with OWASP Top 10 and NIST cybersecurity framework.

**Security Principles**:
- Defense in Depth
- Least Privilege
- Secure by Default
- Fail Securely
- Complete Mediation

---

## 🛡️ OWASP Top 10 2021 - Mitigation Strategies

### A01:2021 - Broken Access Control

**Risks**:
- Unauthorized access to machines or data
- Privilege escalation (reporter → sysadmin)
- Bypassing role-based restrictions

**Mitigations**:

✅ **Backend**:
```python
# Decorator for permission checking
from functools import wraps
from flask import abort

def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if permission not in user.permissions:
                abort(403, "Insufficient permissions")
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/machines', methods=['POST'])
@require_permission('write')
def add_machine():
    # Only sysadmin can add machines
    pass
```

✅ **Database**:
- Row-level security (RLS) in PostgreSQL
- All queries include user context
- Audit logging for all access attempts

✅ **API**:
- JWT tokens with role and permissions embedded
- Token validation on every request
- Rate limiting per user role

**Testing**:
- [ ] Attempt to access resources with reporter token
- [ ] Attempt to modify permissions in JWT
- [ ] Test horizontal privilege escalation
- [ ] Test vertical privilege escalation

---

### A02:2021 - Cryptographic Failures

**Risks**:
- Exposure of sensitive data (passwords, SSH keys)
- Man-in-the-middle attacks
- Weak encryption algorithms

**Mitigations**:

✅ **Data at Rest**:
```python
# Password hashing with bcrypt
import bcrypt

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)  # High work factor
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), hash.encode())
```

✅ **Data in Transit**:
- TLS 1.3 only (disable TLS 1.2 and below)
- Strong cipher suites only
- HSTS header: `Strict-Transport-Security: max-age=31536000; includeSubDomains`

✅ **SSH Keys**:
- Ed25519 keys only (256-bit security)
- Private keys encrypted at rest
- Automatic key rotation (90 days default)

✅ **Database Connections**:
```python
# PostgreSQL with TLS
DATABASE_URL = "postgresql://user:pass@host:5432/db?sslmode=require"

# InfluxDB with TLS
INFLUX_CLIENT = InfluxDBClient(
    url="https://influxdb:8086",
    token=INFLUX_TOKEN,
    org=INFLUX_ORG,
    ssl_ca_cert="/path/to/ca.crt"
)
```

✅ **Secrets Management**:
- Never hardcode secrets in code
- Environment variables only
- Use `.env` file for local development (never committed)
- Production: HashiCorp Vault or similar (future)

**Nginx TLS Configuration**:
```nginx
ssl_protocols TLSv1.3;
ssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256';
ssl_prefer_server_ciphers on;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

**Testing**:
- [ ] Verify TLS 1.3 only with `nmap --script ssl-enum-ciphers`
- [ ] Check for weak ciphers
- [ ] Verify HSTS header
- [ ] Test password hash strength

---

### A03:2021 - Injection

**Risks**:
- SQL Injection
- Command Injection (SSH commands)
- LDAP Injection
- OS Command Injection

**Mitigations**:

✅ **SQL Injection Prevention**:
```python
# ALWAYS use SQLAlchemy ORM or parameterized queries
from sqlalchemy import select

# ✅ SAFE - Using ORM
machines = db.session.execute(
    select(Machine).where(Machine.ip_address == user_input)
).scalars().all()

# ✅ SAFE - Parameterized query
db.session.execute(
    "SELECT * FROM machines WHERE ip = :ip",
    {"ip": user_input}
)

# ❌ NEVER DO THIS
db.session.execute(f"SELECT * FROM machines WHERE ip = '{user_input}'")
```

✅ **Command Injection Prevention**:
```python
import shlex
from paramiko import SSHClient

# ✅ SAFE - Whitelist of allowed commands
ALLOWED_COMMANDS = {
    'netstat': ['/usr/bin/netstat', '-tuln'],
    'ps': ['/bin/ps', 'aux'],
    'systemctl_status': ['/usr/bin/systemctl', 'status']
}

def execute_safe_command(ssh: SSHClient, command_name: str, args: list = None):
    if command_name not in ALLOWED_COMMANDS:
        raise ValueError("Command not allowed")
    
    cmd = ALLOWED_COMMANDS[command_name].copy()
    
    # Validate and sanitize arguments
    if args:
        for arg in args:
            if not re.match(r'^[a-zA-Z0-9_.-]+$', arg):
                raise ValueError("Invalid argument")
            cmd.append(shlex.quote(arg))
    
    stdin, stdout, stderr = ssh.exec_command(' '.join(cmd))
    return stdout.read().decode()

# ❌ NEVER DO THIS
ssh.exec_command(f"cat {user_provided_file}")  # Command injection!
```

✅ **Input Validation**:
```python
from pydantic import BaseModel, validator, IPvAnyAddress
import re

class MachineCreateSchema(BaseModel):
    hostname: str
    ip_address: IPvAnyAddress
    role: str
    
    @validator('hostname')
    def validate_hostname(cls, v):
        # RFC 1123 hostname validation
        if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', v, re.I):
            raise ValueError('Invalid hostname format')
        return v
    
    @validator('role')
    def validate_role(cls, v):
        allowed_roles = ['web', 'database', 'dns', 'gateway']
        if v not in allowed_roles:
            raise ValueError(f'Role must be one of {allowed_roles}')
        return v
```

**Testing**:
- [ ] SQL injection with `' OR '1'='1`
- [ ] Command injection with `; rm -rf /`
- [ ] Test special characters in all inputs
- [ ] Automated injection testing with SQLMap

---

### A04:2021 - Insecure Design

**Risks**:
- Missing security controls by design
- Lack of threat modeling
- Insufficient security requirements

**Mitigations**:

✅ **Threat Modeling**:
```
Assets:
- Target machines (critical)
- User credentials (critical)
- SSH private keys (critical)
- Configuration data (high)
- Monitoring data (medium)

Threats:
- Unauthorized access to targets
- Credential theft
- Man-in-the-middle attacks
- Data exfiltration
- Denial of service

Controls:
- Multi-factor authentication (future)
- SSH key rotation
- Network segmentation
- Audit logging
- Rate limiting
```

✅ **Security by Design Principles**:

1. **Principle of Least Privilege**:
   - microsiem user on targets: minimal sudo permissions
   - Reporter role: read-only access
   - Database users: limited to their schema

2. **Separation of Duties**:
   - Frontend cannot directly access databases
   - Backend validates all requests
   - Monitoring scripts cannot modify system

3. **Fail Securely**:
   ```python
   try:
       result = apply_hardening(machine, model)
   except Exception as e:
       # Log error
       logger.error(f"Hardening failed: {e}")
       # Attempt rollback
       rollback_changes(machine)
       # Notify admin
       send_alert("Hardening failed on {machine.hostname}")
       # Return safe state
       return {"success": False, "error": "Hardening failed"}
   ```

4. **Defense in Depth**:
   - Firewall rules
   - Network segmentation
   - Application-level authorization
   - Database-level permissions
   - Audit logging at every layer

✅ **Rate Limiting**:
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")  # Max 5 login attempts per minute
def login():
    pass
```

**Testing**:
- [ ] Review architecture against STRIDE model
- [ ] Perform security design review
- [ ] Validate all security controls implemented

---

### A05:2021 - Security Misconfiguration

**Risks**:
- Default credentials
- Unnecessary features enabled
- Verbose error messages
- Missing security headers

**Mitigations**:

✅ **Secure Defaults**:
```python
# config.py
class ProductionConfig:
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.getenv('SECRET_KEY')  # Required, no default
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
```

✅ **Security Headers**:
```python
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)
Talisman(app, 
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'"],  # Minimize inline scripts
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", "data:", "https:"],
        'font-src': ["'self'"],
        'connect-src': ["'self'", "wss:"]
    }
)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response
```

✅ **Error Handling**:
```python
# Never expose internal details
@app.errorhandler(Exception)
def handle_error(error):
    # Log full error internally
    logger.error(f"Error: {error}", exc_info=True)
    
    # Return generic error to client
    if app.config['DEBUG']:
        return {"error": str(error)}, 500
    else:
        return {"error": "Internal server error"}, 500
```

✅ **Docker Security**:
```dockerfile
# Use non-root user
FROM python:3.11-slim
RUN useradd -m -u 1000 appuser
USER appuser

# Read-only filesystem where possible
VOLUME ["/app/data"]

# Drop unnecessary capabilities
RUN setcap cap_net_bind_service=+ep /usr/local/bin/python
```

**Testing**:
- [ ] Run automated security scanner (OWASP ZAP)
- [ ] Check for default credentials
- [ ] Verify all security headers present
- [ ] Test error messages don't leak info

---

### A06:2021 - Vulnerable and Outdated Components

**Risks**:
- Using libraries with known vulnerabilities
- Outdated frameworks
- Unpatched dependencies

**Mitigations**:

✅ **Dependency Management**:
```bash
# Python - use specific versions
# requirements.txt
Flask==3.0.0
FastAPI==0.104.1
SQLAlchemy==2.0.23
paramiko==3.3.1

# Pin versions, but stay up to date
pip list --outdated
pip install --upgrade <package>
```

✅ **Automated Vulnerability Scanning**:
```bash
# Python
pip install safety
safety check

# Or use pip-audit
pip install pip-audit
pip-audit

# Docker images
docker scan microsiem:latest

# CI/CD integration
# .github/workflows/security.yml
name: Security Scan
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Snyk
        uses: snyk/actions/python@master
```

✅ **Update Policy**:
- Security patches: Apply immediately
- Minor updates: Review and apply monthly
- Major updates: Review, test, and apply quarterly

**Testing**:
- [ ] Run `safety check` and `npm audit`
- [ ] Review all dependencies for CVEs
- [ ] Test after updates

---

### A07:2021 - Identification and Authentication Failures

**Risks**:
- Weak passwords
- No account lockout
- Session fixation
- Insecure password recovery

**Mitigations**:

✅ **Strong Password Policy**:
```python
import re

def validate_password_strength(password: str) -> tuple[bool, list]:
    errors = []
    
    if len(password) < 12:
        errors.append("Password must be at least 12 characters")
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain uppercase letter")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain lowercase letter")
    if not re.search(r'[0-9]', password):
        errors.append("Password must contain number")
    if not re.search(r'[!@#$%^&*]', password):
        errors.append("Password must contain special character")
    
    # Check against common passwords
    with open('common_passwords.txt') as f:
        if password.lower() in f.read().lower():
            errors.append("Password is too common")
    
    return len(errors) == 0, errors
```

✅ **Account Lockout**:
```python
from datetime import datetime, timedelta
from flask import request

# In-memory store (use Redis in production)
failed_attempts = {}

@app.route('/api/auth/login', methods=['POST'])
def login():
    ip = request.remote_addr
    
    # Check if IP is locked out
    if ip in failed_attempts:
        attempts, lockout_until = failed_attempts[ip]
        if datetime.now() < lockout_until:
            return {"error": "Account temporarily locked"}, 403
        else:
            del failed_attempts[ip]
    
    # Authenticate
    user = authenticate(username, password)
    if not user:
        # Track failed attempt
        if ip not in failed_attempts:
            failed_attempts[ip] = [0, None]
        
        failed_attempts[ip][0] += 1
        
        # Lock after 5 failed attempts
        if failed_attempts[ip][0] >= 5:
            lockout_until = datetime.now() + timedelta(minutes=15)
            failed_attempts[ip][1] = lockout_until
            return {"error": "Too many failed attempts. Account locked for 15 minutes"}, 403
        
        return {"error": "Invalid credentials"}, 401
    
    # Success - clear failed attempts
    if ip in failed_attempts:
        del failed_attempts[ip]
    
    return generate_token(user)
```

✅ **JWT Security**:
```python
import jwt
from datetime import datetime, timedelta

def generate_jwt(user):
    payload = {
        'sub': user.id,
        'username': user.username,
        'role': user.role,
        'permissions': user.permissions,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=24),
        'jti': str(uuid.uuid4())  # Unique token ID for revocation
    }
    
    return jwt.encode(
        payload,
        app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )

def verify_jwt(token):
    try:
        payload = jwt.decode(
            token,
            app.config['JWT_SECRET_KEY'],
            algorithms=['HS256']
        )
        
        # Check if token is revoked (check database or Redis)
        if is_token_revoked(payload['jti']):
            return None
        
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
```

✅ **Multi-Factor Authentication** (Future Enhancement):
```python
import pyotp

def generate_totp_secret():
    return pyotp.random_base32()

def verify_totp(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)
```

**Testing**:
- [ ] Test with weak passwords
- [ ] Test account lockout mechanism
- [ ] Test JWT expiration and revocation
- [ ] Test concurrent sessions

---

### A08:2021 - Software and Data Integrity Failures

**Risks**:
- Unsigned updates
- Insecure CI/CD pipeline
- Tampered hardening models
- Supply chain attacks

**Mitigations**:

✅ **Hardening Model Integrity**:
```python
import hashlib
import json

def calculate_model_hash(config: dict) -> str:
    """Calculate SHA-512 hash of hardening model"""
    config_json = json.dumps(config, sort_keys=True)
    return hashlib.sha512(config_json.encode()).hexdigest()

def verify_model_integrity(model_id: int) -> bool:
    """Verify hardening model hasn't been tampered with"""
    model = db.session.get(HardeningModel, model_id)
    calculated_hash = calculate_model_hash(model.config_json)
    
    if calculated_hash != model.hash_sha512:
        # Log security event
        logger.critical(f"Model {model_id} integrity check FAILED")
        send_alert(f"Hardening model {model.name} has been tampered with!")
        return False
    
    return True

# Run integrity check before applying any model
@app.route('/api/hardening/apply', methods=['POST'])
def apply_hardening():
    model_id = request.json['model_id']
    
    if not verify_model_integrity(model_id):
        return {"error": "Model integrity check failed"}, 400
    
    # Proceed with hardening...
```

✅ **File Integrity Monitoring**:
```python
def calculate_file_hash(filepath: str) -> str:
    """Calculate SHA-256 hash of file"""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

# Monitor critical files on targets
CRITICAL_FILES = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/ssh/sshd_config',
    '/etc/sudoers',
    '/etc/iptables/rules.v4'
]

def check_file_integrity(machine_id: int):
    """Check if critical files have been modified"""
    for filepath in CRITICAL_FILES:
        current_hash = get_remote_file_hash(machine_id, filepath)
        stored_hash = get_stored_hash(machine_id, filepath)
        
        if current_hash != stored_hash:
            logger.warning(f"File {filepath} modified on machine {machine_id}")
            send_alert(f"Critical file {filepath} modified on {machine.hostname}")
```

✅ **CI/CD Security**:
```yaml
# .github/workflows/deploy.yml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run security scan
        run: |
          pip install safety
          safety check
          
      - name: Run SAST
        uses: github/codeql-action/analyze@v2
        
  build:
    needs: security-scan
    runs-on: ubuntu-latest
    steps:
      - name: Build Docker image
        run: docker build -t microsiem:${{ github.sha }} .
        
      - name: Sign image
        run: |
          # Use cosign or similar for image signing
          cosign sign microsiem:${{ github.sha }}
```

**Testing**:
- [ ] Tamper with hardening model, verify detection
- [ ] Modify critical file, verify alert
- [ ] Test update process with invalid signature

---

### A09:2021 - Security Logging and Monitoring Failures

**Risks**:
- Insufficient logging
- Logs not monitored
- No alerting on suspicious activity
- Logs can be tampered with

**Mitigations**:

✅ **Comprehensive Audit Logging**:
```python
from datetime import datetime
from flask import request, g

def log_audit_event(action: str, resource_type: str = None, 
                   resource_id: int = None, details: dict = None):
    """Log all security-relevant events"""
    audit_log = AuditLog(
        user_id=g.current_user.id if hasattr(g, 'current_user') else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        timestamp=datetime.utcnow()
    )
    db.session.add(audit_log)
    db.session.commit()

# Log all important actions
@app.route('/api/machines/<int:id>', methods=['DELETE'])
def delete_machine(id):
    machine = db.session.get(Machine, id)
    
    log_audit_event(
        action='machine_deleted',
        resource_type='machine',
        resource_id=id,
        details={'hostname': machine.hostname, 'ip': machine.ip_address}
    )
    
    db.session.delete(machine)
    db.session.commit()
    
    return {"success": True}
```

✅ **Structured Logging**:
```python
import logging
import json
from datetime import datetime

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        if hasattr(record, 'user_id'):
            log_obj['user_id'] = record.user_id
        if hasattr(record, 'ip_address'):
            log_obj['ip_address'] = record.ip_address
        
        return json.dumps(log_obj)

# Configure logger
logger = logging.getLogger('microsiem')
handler = logging.FileHandler('/var/log/microsiem/app.log')
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)
```

✅ **Security Event Monitoring**:
```python
# Events to monitor
SECURITY_EVENTS = {
    'failed_login': {'threshold': 5, 'window_minutes': 5},
    'unauthorized_access': {'threshold': 3, 'window_minutes': 10},
    'hardening_failed': {'threshold': 1, 'window_minutes': 60},
    'file_integrity_violation': {'threshold': 1, 'window_minutes': 5}
}

def check_security_events():
    """Check for suspicious patterns in logs"""
    for event_type, config in SECURITY_EVENTS.items():
        recent_events = get_recent_events(
            event_type,
            minutes=config['window_minutes']
        )
        
        if len(recent_events) >= config['threshold']:
            send_security_alert(
                f"Multiple {event_type} events detected",
                details=recent_events
            )
```

✅ **Log Protection**:
```python
# Use write-once storage for audit logs
# Logs should be append-only and immutable

# Send logs to centralized logging (future)
import logging.handlers

syslog_handler = logging.handlers.SysLogHandler(
    address=('syslog.example.com', 514)
)
logger.addHandler(syslog_handler)
```

**What to Log**:
- ✅ Authentication attempts (success and failure)
- ✅ Authorization failures
- ✅ Input validation failures
- ✅ Administrative actions (add/delete machines, apply hardening)
- ✅ Configuration changes
- ✅ System errors and exceptions
- ✅ SSH connections to targets
- ✅ File integrity violations
- ✅ Suspicious activities on targets

**What NOT to Log**:
- ❌ Passwords (even hashed)
- ❌ SSH private keys
- ❌ Full JWT tokens
- ❌ Credit card numbers
- ❌ Other sensitive PII

**Testing**:
- [ ] Verify all security events are logged
- [ ] Test log monitoring and alerting
- [ ] Attempt to tamper with logs
- [ ] Verify logs are retained properly

---

### A10:2021 - Server-Side Request Forgery (SSRF)

**Risks**:
- Backend makes requests to internal resources
- Attacker can scan internal network
- Access to metadata endpoints (cloud)

**Mitigations**:

✅ **Validate and Sanitize URLs**:
```python
from urllib.parse import urlparse
import ipaddress

ALLOWED_DOMAINS = ['hooks.slack.com', 'api.telegram.org']
BLOCKED_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16')
]

def is_safe_url(url: str) -> bool:
    """Validate URL is safe to fetch"""
    try:
        parsed = urlparse(url)
        
        # Only HTTPS allowed
        if parsed.scheme != 'https':
            return False
        
        # Check domain whitelist
        if parsed.hostname not in ALLOWED_DOMAINS:
            return False
        
        # Resolve and check IP
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        for blocked_range in BLOCKED_IP_RANGES:
            if ip in blocked_range:
                return False
        
        return True
    except Exception:
        return False

@app.route('/api/alerts/webhook', methods=['POST'])
def configure_webhook():
    webhook_url = request.json['webhook_url']
    
    if not is_safe_url(webhook_url):
        return {"error": "Invalid or unsafe webhook URL"}, 400
    
    # Safe to use webhook_url...
```

✅ **Network Segmentation**:
```yaml
# docker-compose.yml
networks:
  frontend_network:
    driver: bridge
  backend_network:
    driver: bridge
    internal: true  # No external access

services:
  frontend:
    networks:
      - frontend_network
  
  backend:
    networks:
      - frontend_network
      - backend_network
  
  database:
    networks:
      - backend_network  # Only accessible from backend
```

**Testing**:
- [ ] Test with internal IP addresses (127.0.0.1, 192.168.x.x)
- [ ] Test with cloud metadata endpoints
- [ ] Test URL bypass techniques

---

## 🔒 Additional Security Controls

### SSH Hardening (sshd_config)

```bash
# Deployed to all target machines
Protocol 2
Port 22
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
AllowUsers microsiem
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
```

### Firewall Rules (iptables)

```bash
# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from MicroSIEM server only
iptables -A INPUT -p tcp -s 192.168.1.5 --dport 22 -j ACCEPT

# Allow specific service ports (based on role)
# Web server example:
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Rate limiting for SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "iptables-dropped: "
iptables -A INPUT -j DROP
```

### sudoers Configuration

```bash
# /etc/sudoers.d/microsiem
# Minimal permissions for microsiem user

microsiem ALL=(root) NOPASSWD: /usr/bin/systemctl status *
microsiem ALL=(root) NOPASSWD: /usr/sbin/netstat *
microsiem ALL=(root) NOPASSWD: /usr/bin/ss *
microsiem ALL=(root) NOPASSWD: /usr/bin/lsof *
microsiem ALL=(root) NOPASSWD: /usr/bin/find /etc -type f
microsiem ALL=(root) NOPASSWD: /usr/bin/apt list --upgradable
microsiem ALL=(root) NOPASSWD: /usr/sbin/auditctl -l

# Explicitly deny everything else
microsiem ALL=(ALL) !ALL

# Log all microsiem sudo commands
Defaults:microsiem log_output
Defaults:microsiem!/usr/bin/sudoreplay !log_output
```

---

## 📋 Security Checklist

### Development
- [ ] All dependencies pinned to specific versions
- [ ] No secrets in code or version control
- [ ] Input validation on all user inputs
- [ ] Output encoding to prevent XSS
- [ ] Parameterized queries for all database operations
- [ ] Error messages don't leak sensitive info
- [ ] Security headers configured
- [ ] HTTPS enforced
- [ ] CSRF protection enabled
- [ ] Rate limiting implemented

### Deployment
- [ ] TLS 1.3 configured
- [ ] Strong cipher suites only
- [ ] SSH key-based authentication only
- [ ] Firewall rules configured
- [ ] Non-root user for application
- [ ] Secrets in environment variables
- [ ] Audit logging enabled
- [ ] Log retention configured
- [ ] Monitoring and alerting active
- [ ] Backup strategy implemented

### Operations
- [ ] Regular security updates applied
- [ ] Vulnerability scanning (weekly)
- [ ] Log review (daily)
- [ ] Audit trail review (weekly)
- [ ] Access review (monthly)
- [ ] Penetration testing (quarterly)
- [ ] Disaster recovery tested (quarterly)
- [ ] Security training (annually)

---

## 🚨 Incident Response Plan

### Detection
1. Automated alerts from monitoring system
2. Log analysis and anomaly detection
3. User reports
4. Scheduled security scans

### Response Steps
1. **Identify**: What happened? When? What systems affected?
2. **Contain**: Isolate affected systems, revoke compromised credentials
3. **Eradicate**: Remove threat, patch vulnerabilities
4. **Recover**: Restore systems from backups, verify integrity
5. **Lessons Learned**: Document incident, update procedures

### Contact Information
- Security Team: security@example.com
- On-Call Admin: +1-XXX-XXX-XXXX
- Incident Response Lead: [Name]

---

## 📚 References

- OWASP Top 10: https://owasp.org/Top10/
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- CIS Controls: https://www.cisecurity.org/controls
- SANS Security Resources: https://www.sans.org/

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-10-30  
**Maintained By**: Security Team
