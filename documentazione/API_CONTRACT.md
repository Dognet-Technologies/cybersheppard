# MicroSIEM - API Contract

## 📡 API Specification

**Base URLs**:
- Flask: `http://cybersheppard:5000`
- FastAPI: `http://cybersheppard:8000`
- Production: `https://microsiem.yourdomain.com/api`

**API Version**: v1  
**Authentication**: JWT Bearer Token  
**Content-Type**: application/json  
**Date Format**: ISO 8601 (RFC 3339)

---

## 🔐 Authentication Endpoints

### POST /auth/login
Authenticate user and receive JWT token.

**Request**:
```json
{
  "username": "admin",
  "password": "SecurePassword123!"
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 86400,
    "user": {
      "id": 1,
      "username": "admin",
      "email": "admin@example.com",
      "role": "sysadmin",
      "permissions": ["read", "write", "delete", "manage_users"]
    }
  }
}
```

**Errors**:
- 401: Invalid credentials
- 403: Account disabled
- 429: Too many login attempts

---

### POST /auth/logout
Invalidate current JWT token.

**Headers**:
```
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

---

### POST /auth/refresh
Refresh JWT token before expiration.

**Headers**:
```
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 86400
  }
}
```

---

### GET /auth/me
Get current user information.

**Headers**:
```
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "sysadmin",
    "permissions": ["read", "write", "delete", "manage_users"],
    "created_at": "2025-01-15T10:00:00Z",
    "last_login": "2025-10-30T08:30:00Z"
  }
}
```

---

## 🖥️ Machine Management Endpoints

### GET /api/machines
List all machines.

**Query Parameters**:
- `page` (int, default: 1)
- `per_page` (int, default: 20, max: 100)
- `status` (string, optional): filter by status
- `role` (string, optional): filter by role
- `compliance` (string, optional): filter by compliance standard

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "machines": [
      {
        "id": 1,
        "hostname": "webserver-01",
        "ip_address": "192.168.1.10",
        "role": "web",
        "compliance_standard": "nis2",
        "ssh_port": 22,
        "status": "active",
        "last_seen": "2025-10-30T10:29:45Z",
        "hardening_applied": true,
        "hardening_model": "web_severo_nis2",
        "hardening_score": 95,
        "created_at": "2025-10-20T12:00:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "per_page": 20,
      "total": 45,
      "pages": 3
    }
  }
}
```

**Required Permission**: read (sysadmin, reporter)

---

### GET /api/machines/{id}
Get detailed information about a specific machine.

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "id": 1,
    "hostname": "webserver-01",
    "ip_address": "192.168.1.10",
    "role": "web",
    "compliance_standard": "nis2",
    "ssh_port": 22,
    "status": "active",
    "last_seen": "2025-10-30T10:29:45Z",
    "hardening": {
      "applied": true,
      "model_id": 5,
      "model_name": "web_severo_nis2",
      "applied_at": "2025-10-29T08:00:00Z",
      "applied_by": "admin",
      "score": 95,
      "last_check": "2025-10-30T10:25:00Z"
    },
    "compliance": {
      "status": "compliant",
      "checks_passed": 45,
      "checks_failed": 0,
      "last_check": "2025-10-30T10:25:00Z"
    },
    "monitoring": {
      "enabled": true,
      "interval_seconds": 30,
      "last_collection": "2025-10-30T10:29:45Z",
      "collection_errors": 0
    },
    "ssh_key": {
      "key_type": "ed25519",
      "created_at": "2025-10-20T12:00:00Z",
      "expires_at": "2026-01-20T12:00:00Z"
    }
  }
}
```

**Errors**:
- 404: Machine not found

---

### POST /api/machines
Add a new machine.

**Request**:
```json
{
  "hostname": "dbserver-01",
  "ip_address": "192.168.1.20",
  "role": "database",
  "compliance_standard": "pci",
  "ssh_port": 22,
  "ssh_username": "microsiem",
  "ssh_password": "TempPassword123!" // Used only for initial setup
}
```

**Response** (201 Created):
```json
{
  "success": true,
  "data": {
    "id": 2,
    "hostname": "dbserver-01",
    "ip_address": "192.168.1.20",
    "status": "pending",
    "setup_required": true,
    "suggested_models": [
      {
        "id": 10,
        "name": "database_base_pci",
        "level": "base",
        "description": "Basic hardening for database servers with PCI compliance"
      },
      {
        "id": 11,
        "name": "database_severo_pci",
        "level": "severo",
        "description": "Strict hardening for database servers with PCI compliance"
      }
    ]
  },
  "message": "Machine added. Please review suggested hardening models."
}
```

**Required Permission**: write (sysadmin only)

**Errors**:
- 400: Invalid input data
- 409: Machine with this IP already exists

---

### PUT /api/machines/{id}
Update machine information.

**Request**:
```json
{
  "hostname": "webserver-01-prod",
  "role": "web",
  "compliance_standard": "nis2"
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "id": 1,
    "hostname": "webserver-01-prod",
    "updated_at": "2025-10-30T10:35:00Z"
  },
  "message": "Machine updated successfully"
}
```

**Required Permission**: write (sysadmin only)

---

### DELETE /api/machines/{id}
Remove a machine from monitoring.

**Query Parameters**:
- `cleanup` (boolean, default: true): Remove monitoring scripts from target

**Response** (200 OK):
```json
{
  "success": true,
  "message": "Machine removed successfully"
}
```

**Required Permission**: delete (sysadmin only)

---

### POST /api/machines/scan
Perform ARP scan to discover machines on the network.

**Request**:
```json
{
  "network": "192.168.1.0/24",
  "timeout_seconds": 10
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "discovered": [
      {
        "ip_address": "192.168.1.15",
        "mac_address": "00:11:22:33:44:55",
        "hostname": "unknown-15",
        "already_managed": false
      },
      {
        "ip_address": "192.168.1.10",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "hostname": "webserver-01",
        "already_managed": true
      }
    ],
    "total_discovered": 2,
    "new_machines": 1
  }
}
```

**Required Permission**: write (sysadmin only)

---

### POST /api/machines/import
Import machines from file (TXT with IP addresses, one per line).

**Request** (multipart/form-data):
```
file: <text file>
role: "web" (optional)
compliance_standard: "nis2" (optional)
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "imported": 5,
    "failed": 1,
    "details": [
      {
        "ip": "192.168.1.25",
        "status": "success",
        "machine_id": 3
      },
      {
        "ip": "192.168.1.invalid",
        "status": "failed",
        "error": "Invalid IP address"
      }
    ]
  }
}
```

**Required Permission**: write (sysadmin only)

---

## 🛡️ Hardening Endpoints

### GET /api/hardening/models
List available hardening models.

**Query Parameters**:
- `role` (string, optional)
- `compliance` (string, optional)
- `level` (string, optional): base, severo

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "models": [
      {
        "id": 5,
        "name": "web_severo_nis2",
        "description": "Strict hardening for web servers with NIS2 compliance",
        "role": "web",
        "compliance_standard": "nis2",
        "level": "severo",
        "version": 2,
        "hash_sha512": "abc123...",
        "is_active": true,
        "created_by": "admin",
        "created_at": "2025-10-15T14:00:00Z",
        "updated_at": "2025-10-28T09:00:00Z"
      }
    ]
  }
}
```

**Required Permission**: read (sysadmin, reporter)

---

### GET /api/hardening/models/{id}
Get detailed hardening model configuration.

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "id": 5,
    "name": "web_severo_nis2",
    "description": "Strict hardening for web servers with NIS2 compliance",
    "role": "web",
    "compliance_standard": "nis2",
    "level": "severo",
    "version": 2,
    "hash_sha512": "abc123...",
    "config": {
      "sysctl": {
        "net.ipv4.tcp_syncookies": 1,
        "net.ipv4.conf.all.rp_filter": 1,
        "kernel.dmesg_restrict": 1
      },
      "iptables": {
        "default_policy": "DROP",
        "rules": [
          "-A INPUT -i lo -j ACCEPT",
          "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
          "-A INPUT -p tcp --dport 22 -j ACCEPT",
          "-A INPUT -p tcp --dport 80 -j ACCEPT",
          "-A INPUT -p tcp --dport 443 -j ACCEPT"
        ]
      },
      "services": {
        "disable": ["telnet", "ftp", "rsh", "rlogin"],
        "enable": ["auditd", "ulogd2"]
      },
      "sudoers": {
        "microsiem": {
          "commands": [
            "/usr/bin/systemctl status *",
            "/usr/sbin/netstat",
            "/usr/bin/ss"
          ],
          "nopasswd": true
        }
      },
      "files": {
        "/etc/ssh/sshd_config": {
          "PermitRootLogin": "no",
          "PasswordAuthentication": "no",
          "PubkeyAuthentication": "yes",
          "MaxAuthTries": 3
        }
      }
    }
  }
}
```

**Required Permission**: read (sysadmin, reporter)

---

### POST /api/hardening/models
Create a new hardening model.

**Request**:
```json
{
  "name": "custom_web_model",
  "description": "Custom web server hardening",
  "role": "web",
  "compliance_standard": "iso27001",
  "level": "base",
  "config": {
    "sysctl": { /* ... */ },
    "iptables": { /* ... */ },
    "services": { /* ... */ }
  }
}
```

**Response** (201 Created):
```json
{
  "success": true,
  "data": {
    "id": 20,
    "name": "custom_web_model",
    "hash_sha512": "def456...",
    "validation": {
      "passed": true,
      "warnings": [],
      "errors": []
    }
  },
  "message": "Hardening model created successfully"
}
```

**Required Permission**: write (sysadmin only)

---

### POST /api/hardening/apply
Apply hardening model to a machine.

**Request**:
```json
{
  "machine_id": 1,
  "model_id": 5,
  "test_mode": false,
  "create_backup": true
}
```

**Response** (202 Accepted):
```json
{
  "success": true,
  "data": {
    "job_id": "abc-123-def-456",
    "status": "in_progress",
    "estimated_duration_seconds": 120
  },
  "message": "Hardening application started"
}
```

**Required Permission**: write (sysadmin only)

---

### GET /api/hardening/jobs/{job_id}
Check status of hardening application job.

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "job_id": "abc-123-def-456",
    "status": "completed",
    "machine_id": 1,
    "model_id": 5,
    "started_at": "2025-10-30T10:30:00Z",
    "completed_at": "2025-10-30T10:32:15Z",
    "result": {
      "success": true,
      "steps_completed": 15,
      "steps_total": 15,
      "changes_applied": [
        "sysctl parameters updated",
        "iptables rules applied",
        "services disabled: telnet, ftp",
        "SSH configuration hardened"
      ],
      "rollback_available": true,
      "rollback_id": "rollback-789"
    }
  }
}
```

---

### POST /api/hardening/rollback
Rollback hardening changes.

**Request**:
```json
{
  "machine_id": 1,
  "rollback_id": "rollback-789"
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "Hardening changes rolled back successfully"
}
```

**Required Permission**: write (sysadmin only)

---

### POST /api/hardening/validate
Validate a hardening model configuration.

**Request**:
```json
{
  "config": {
    "sysctl": { /* ... */ },
    "iptables": { /* ... */ }
  },
  "test_machine_id": 99
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "validation": {
      "passed": true,
      "errors": [],
      "warnings": [
        "iptables rule may block SSH access from certain IPs"
      ],
      "suggestions": [
        "Consider adding rate limiting for SSH"
      ]
    },
    "test_results": {
      "tested": true,
      "test_machine": "test-vm-01",
      "system_stable": true,
      "ssh_accessible": true
    }
  }
}
```

---

## 📊 Monitoring Endpoints

### GET /api/monitoring/machines/{id}/metrics
Get metrics for a specific machine.

**Query Parameters**:
- `start` (ISO 8601 datetime, required)
- `end` (ISO 8601 datetime, required)
- `aggregation` (string, optional): mean, max, min, default: mean
- `interval` (string, optional): 1m, 5m, 15m, 1h, default: 1m

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "machine_id": 1,
    "hostname": "webserver-01",
    "time_range": {
      "start": "2025-10-30T09:00:00Z",
      "end": "2025-10-30T10:00:00Z"
    },
    "metrics": {
      "hardening_score": [
        {"timestamp": "2025-10-30T09:00:00Z", "value": 95},
        {"timestamp": "2025-10-30T09:30:00Z", "value": 95}
      ],
      "connections": [
        {"timestamp": "2025-10-30T09:00:00Z", "value": 5},
        {"timestamp": "2025-10-30T09:30:00Z", "value": 7}
      ],
      "services_running": [
        {"timestamp": "2025-10-30T09:00:00Z", "value": 8},
        {"timestamp": "2025-10-30T09:30:00Z", "value": 8}
      ]
    }
  }
}
```

**Required Permission**: read (sysadmin, reporter)

---

### GET /api/monitoring/machines/{id}/connections
Get current connections for a machine.

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "machine_id": 1,
    "timestamp": "2025-10-30T10:30:00Z",
    "connections": [
      {
        "protocol": "tcp",
        "local_addr": "0.0.0.0",
        "local_port": 22,
        "remote_addr": "192.168.1.100",
        "remote_port": 54321,
        "state": "ESTABLISHED",
        "process": "sshd",
        "pid": 12345,
        "suspicious": false
      },
      {
        "protocol": "tcp",
        "local_addr": "0.0.0.0",
        "local_port": 3389,
        "remote_addr": "10.0.0.50",
        "remote_port": 45678,
        "state": "ESTABLISHED",
        "process": "xrdp",
        "pid": 23456,
        "suspicious": true,
        "alert_reason": "RDP connection detected (not expected for this server role)"
      }
    ],
    "summary": {
      "total": 2,
      "suspicious": 1,
      "by_protocol": {
        "tcp": 2,
        "udp": 0
      }
    }
  }
}
```

---

### GET /api/monitoring/machines/{id}/users
Get connected users and their activities.

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "machine_id": 1,
    "timestamp": "2025-10-30T10:30:00Z",
    "users": [
      {
        "username": "admin",
        "login_time": "2025-10-30T09:00:00Z",
        "terminal": "pts/0",
        "from": "192.168.1.100",
        "status": "active",
        "recent_activities": [
          {
            "timestamp": "2025-10-30T10:25:00Z",
            "command": "sudo systemctl restart nginx",
            "working_directory": "/home/admin",
            "exit_code": 0,
            "suspicious": false
          }
        ]
      },
      {
        "username": "microsiem",
        "login_time": "2025-10-30T10:29:00Z",
        "terminal": "pts/1",
        "from": "192.168.1.5",
        "status": "active",
        "recent_activities": [
          {
            "timestamp": "2025-10-30T10:29:45Z",
            "command": "/opt/microsiem/monitoring.sh",
            "working_directory": "/tmp",
            "exit_code": 0,
            "suspicious": false
          }
        ]
      }
    ]
  }
}
```

---

### GET /api/monitoring/machines/{id}/services
Get service status.

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "machine_id": 1,
    "timestamp": "2025-10-30T10:30:00Z",
    "services": {
      "running": [
        {
          "name": "nginx",
          "status": "active",
          "expected": true,
          "pid": 1234,
          "memory_mb": 45.2
        },
        {
          "name": "sshd",
          "status": "active",
          "expected": true,
          "pid": 987,
          "memory_mb": 12.1
        }
      ],
      "stopped": [],
      "unexpected": [
        {
          "name": "telnet",
          "status": "active",
          "expected": false,
          "alert_triggered": true,
          "started_at": "2025-10-30T10:15:00Z"
        }
      ]
    },
    "summary": {
      "total_running": 9,
      "expected_running": 8,
      "unexpected_running": 1,
      "alerts": 1
    }
  }
}
```

---

### GET /api/monitoring/machines/{id}/packages
Get installed packages and vulnerability information.

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "machine_id": 1,
    "timestamp": "2025-10-30T10:30:00Z",
    "packages": {
      "total": 456,
      "upgradable": 3,
      "security_updates_available": 1
    },
    "vulnerable_packages": [
      {
        "name": "openssl",
        "installed_version": "1.1.1f-1ubuntu2",
        "fixed_version": "1.1.1f-1ubuntu2.20",
        "severity": "high",
        "cve_ids": ["CVE-2024-XXXX"],
        "description": "Buffer overflow vulnerability"
      }
    ]
  }
}
```

---

## ✅ Compliance Endpoints

### GET /api/compliance/standards
List available compliance standards.

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "standards": [
      {
        "id": "nis2",
        "name": "NIS2 Directive",
        "description": "EU Network and Information Security Directive",
        "checks_count": 45
      },
      {
        "id": "pci",
        "name": "PCI-DSS",
        "description": "Payment Card Industry Data Security Standard",
        "checks_count": 52
      },
      {
        "id": "iso27001",
        "name": "ISO 27001",
        "description": "Information Security Management",
        "checks_count": 38
      }
    ]
  }
}
```

---

### GET /api/compliance/machines/{id}/status
Get compliance status for a machine.

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "machine_id": 1,
    "compliance_standard": "nis2",
    "status": "compliant",
    "score": 100,
    "last_check": "2025-10-30T10:25:00Z",
    "checks": {
      "passed": 45,
      "failed": 0,
      "warnings": 0
    },
    "details": [
      {
        "check_id": "nis2_001",
        "check_name": "SSH Root Login Disabled",
        "status": "pass",
        "category": "access_control"
      },
      {
        "check_id": "nis2_002",
        "check_name": "Firewall Active",
        "status": "pass",
        "category": "network_security"
      }
    ]
  }
}
```

---

## 🔔 Alert Endpoints

### GET /api/alerts/configs
List alert configurations.

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "configs": [
      {
        "id": 1,
        "name": "Security Team Email",
        "type": "email",
        "is_active": true,
        "config": {
          "recipients": ["security@example.com", "admin@example.com"]
        },
        "triggers": {
          "suspicious_connections": true,
          "unexpected_services": true,
          "compliance_failures": true
        }
      },
      {
        "id": 2,
        "name": "Slack Security Channel",
        "type": "slack",
        "is_active": true,
        "config": {
          "webhook_url": "https://hooks.slack.com/services/xxx"
        },
        "triggers": {
          "critical_alerts": true
        }
      }
    ]
  }
}
```

---

### POST /api/alerts/configs
Create new alert configuration.

**Request**:
```json
{
  "name": "Security Team Email",
  "type": "email",
  "config": {
    "recipients": ["security@example.com"]
  },
  "triggers": {
    "suspicious_connections": true,
    "unexpected_services": true,
    "compliance_failures": true,
    "hardening_changes": false
  }
}
```

**Response** (201 Created):
```json
{
  "success": true,
  "data": {
    "id": 3,
    "name": "Security Team Email",
    "is_active": true
  },
  "message": "Alert configuration created successfully"
}
```

---

### POST /api/alerts/test
Send test alert.

**Request**:
```json
{
  "config_id": 1
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "sent": true,
    "timestamp": "2025-10-30T10:35:00Z",
    "delivery_status": "delivered"
  },
  "message": "Test alert sent successfully"
}
```

---

## 👥 User Management Endpoints

### GET /api/users
List all users.

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "role": "sysadmin",
        "is_active": true,
        "created_at": "2025-01-15T10:00:00Z",
        "last_login": "2025-10-30T08:30:00Z"
      }
    ]
  }
}
```

**Required Permission**: manage_users (sysadmin only)

---

### POST /api/users
Create new user.

**Request**:
```json
{
  "username": "reporter01",
  "email": "reporter@example.com",
  "password": "SecurePassword123!",
  "role": "reporter"
}
```

**Response** (201 Created):
```json
{
  "success": true,
  "data": {
    "id": 2,
    "username": "reporter01",
    "email": "reporter@example.com",
    "role": "reporter"
  },
  "message": "User created successfully"
}
```

**Required Permission**: manage_users (sysadmin only)

---

### PUT /api/users/{id}
Update user information.

**Request**:
```json
{
  "email": "newemail@example.com",
  "role": "sysadmin"
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "User updated successfully"
}
```

**Required Permission**: manage_users (sysadmin only)

---

### DELETE /api/users/{id}
Deactivate user.

**Response** (200 OK):
```json
{
  "success": true,
  "message": "User deactivated successfully"
}
```

**Required Permission**: manage_users (sysadmin only)

---

## ⚙️ System Configuration Endpoints

### GET /api/config/monitoring
Get monitoring configuration.

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "collection_interval_seconds": 30,
    "data_retention_days": 90,
    "max_concurrent_collections": 10,
    "timeout_seconds": 30
  }
}
```

---

### PUT /api/config/monitoring
Update monitoring configuration.

**Request**:
```json
{
  "collection_interval_seconds": 60,
  "data_retention_days": 180
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "Monitoring configuration updated"
}
```

**Required Permission**: write (sysadmin only)

---

### GET /api/config/ssh
Get SSH configuration.

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "key_type": "ed25519",
    "rotation_days": 90,
    "next_rotation": "2026-01-28T12:00:00Z",
    "port": 22,
    "timeout_seconds": 30
  }
}
```

---

### POST /api/config/ssh/rotate-keys
Trigger SSH key rotation for all machines.

**Response** (202 Accepted):
```json
{
  "success": true,
  "data": {
    "job_id": "rotate-keys-123",
    "machines_count": 45,
    "estimated_duration_minutes": 15
  },
  "message": "Key rotation started"
}
```

---

## 📈 Dashboard Endpoints

### GET /api/dashboards
List user's dashboards.

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "dashboards": [
      {
        "id": 1,
        "name": "Security Overview",
        "description": "Main security dashboard",
        "widgets": 6,
        "is_public": false,
        "created_by": "admin",
        "created_at": "2025-10-20T10:00:00Z"
      }
    ]
  }
}
```

---

### POST /api/dashboards
Create custom dashboard.

**Request**:
```json
{
  "name": "My Custom Dashboard",
  "description": "Custom monitoring view",
  "layout": {
    "widgets": [
      {
        "type": "chart",
        "title": "Connections Over Time",
        "query": "SELECT count FROM connections WHERE time > now() - 1h",
        "chart_type": "line",
        "position": {"x": 0, "y": 0, "w": 6, "h": 4}
      }
    ]
  }
}
```

**Response** (201 Created):
```json
{
  "success": true,
  "data": {
    "id": 5,
    "name": "My Custom Dashboard",
    "url": "/dashboards/5"
  }
}
```

---

## 🌐 WebSocket Events

### Connection
```javascript
const ws = new WebSocket('wss://microsiem.yourdomain.com/ws');
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'subscribe',
    topic: 'machine_metrics',
    machine_id: 1
  }));
};
```

### Events Received

**Machine Metrics Update**:
```json
{
  "type": "metrics_update",
  "machine_id": 1,
  "timestamp": "2025-10-30T10:30:00Z",
  "data": {
    "hardening_score": 95,
    "connections": 7,
    "users": 2
  }
}
```

**Alert Triggered**:
```json
{
  "type": "alert",
  "severity": "high",
  "machine_id": 1,
  "hostname": "webserver-01",
  "alert_type": "unexpected_service",
  "message": "Service 'telnet' started unexpectedly",
  "timestamp": "2025-10-30T10:30:15Z"
}
```

**Hardening Job Status**:
```json
{
  "type": "hardening_status",
  "job_id": "abc-123",
  "status": "completed",
  "machine_id": 1,
  "timestamp": "2025-10-30T10:32:15Z"
}
```

---

## 📋 Common Response Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | OK | Request successful |
| 201 | Created | Resource created successfully |
| 202 | Accepted | Request accepted, processing asynchronously |
| 400 | Bad Request | Invalid input data |
| 401 | Unauthorized | Missing or invalid JWT token |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 422 | Unprocessable Entity | Validation error |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | Server overloaded or maintenance |

---

## 🔒 Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": {
      "ip_address": ["Invalid IP address format"]
    }
  },
  "timestamp": "2025-10-30T10:30:00Z",
  "request_id": "req-abc-123"
}
```

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-10-30  
**Maintained By**: Development Team
