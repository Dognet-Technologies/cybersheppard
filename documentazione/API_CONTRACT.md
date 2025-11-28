# MicroSIEM (CyberSheppard) - API Contract

## 📋 Indice

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Common Response Formats](#common-response-formats)
4. [Error Handling](#error-handling)
5. [Authentication Endpoints](#authentication-endpoints)
6. [Target Management Endpoints](#target-management-endpoints)
7. [Hardening Endpoints](#hardening-endpoints)
8. [Monitoring Endpoints](#monitoring-endpoints)
9. [Compliance Endpoints](#compliance-endpoints)
10. [Integration Endpoints](#integration-endpoints)
11. [Alert & Notification Endpoints](#alert--notification-endpoints)
12. [User Management Endpoints](#user-management-endpoints)
13. [System Configuration Endpoints](#system-configuration-endpoints)
14. [WebSocket API](#websocket-api)

---

## Overview

**Base URL**: `https://microsiem.example.com/api/v1`  
**Protocol**: HTTPS only  
**Content-Type**: `application/json`  
**Date Format**: ISO 8601 (RFC 3339)  
**API Version**: v1  

### Technology Stack

- **Backend**: Rust + Axum
- **Authentication**: JWT (HS256)
- **Session Management**: JWT + Refresh Tokens
- **Security**: CSRF tokens, rate limiting, OWASP compliance
- **Hardening Engine**: Python Flask (localhost:5001)

---

## Authentication

### JWT Token Structure

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user_id_123",
    "username": "admin",
    "role": "admin",
    "iat": 1732791234,
    "exp": 1732793034
  }
}
```

**Token Expiration**: 30 minutes  
**Refresh Token Expiration**: 7 days  

### Authentication Flow

```
1. POST /api/v1/auth/login
   ↓
   Response: { access_token, refresh_token, csrf_token }
   ↓
2. Use access_token in Authorization header
   Authorization: Bearer <access_token>
   ↓
3. Include CSRF token in X-CSRF-Token header (for mutations)
   X-CSRF-Token: <csrf_token>
   ↓
4. When access_token expires (30 min):
   POST /api/v1/auth/refresh
   Body: { refresh_token }
   ↓
   Response: { access_token }
```

---

## Common Response Formats

### Success Response

```json
{
  "success": true,
  "data": {
    // Payload varies by endpoint
  },
  "message": "Operation completed successfully",
  "timestamp": "2025-11-28T10:30:45Z"
}
```

### Error Response

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
  "timestamp": "2025-11-28T10:30:45Z",
  "request_id": "req_abc123def456"
}
```

### Paginated Response

```json
{
  "success": true,
  "data": {
    "items": [...],
    "pagination": {
      "page": 1,
      "per_page": 20,
      "total": 145,
      "total_pages": 8,
      "has_next": true,
      "has_prev": false
    }
  }
}
```

---

## Error Handling

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | OK | Request successful |
| 201 | Created | Resource created successfully |
| 202 | Accepted | Request accepted, processing asynchronously |
| 204 | No Content | Request successful, no content to return |
| 400 | Bad Request | Invalid input data |
| 401 | Unauthorized | Missing or invalid authentication |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 422 | Unprocessable Entity | Validation error |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | Service temporarily unavailable |

### Error Codes

```rust
pub enum ErrorCode {
    // Authentication errors (1xxx)
    InvalidCredentials,        // 1001
    TokenExpired,              // 1002
    TokenInvalid,              // 1003
    CSRFTokenMismatch,         // 1004
    AccountLocked,             // 1005
    
    // Authorization errors (2xxx)
    InsufficientPermissions,   // 2001
    RoleNotAllowed,            // 2002
    
    // Validation errors (3xxx)
    ValidationError,           // 3001
    InvalidIPAddress,          // 3002
    InvalidHostname,           // 3003
    
    // Resource errors (4xxx)
    ResourceNotFound,          // 4001
    ResourceAlreadyExists,     // 4002
    ResourceInUse,             // 4003
    
    // Operation errors (5xxx)
    OperationFailed,           // 5001
    SSHConnectionFailed,       // 5002
    HardeningFailed,           // 5003
    
    // Rate limiting (6xxx)
    RateLimitExceeded,         // 6001
    
    // Internal errors (9xxx)
    InternalServerError,       // 9001
    DatabaseError,             // 9002
}
```

---

## Authentication Endpoints

### POST /api/v1/auth/login

Authenticate user and receive tokens.

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
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "rt_abc123def456...",
    "csrf_token": "csrf_xyz789...",
    "expires_in": 1800,
    "token_type": "Bearer",
    "user": {
      "id": 1,
      "username": "admin",
      "email": "admin@example.com",
      "role": "admin",
      "created_at": "2025-01-15T10:00:00Z",
      "last_login_at": "2025-11-28T10:30:00Z"
    }
  }
}
```

**Errors**:
- 401: Invalid credentials
- 403: Account locked (too many failed attempts)
- 429: Too many login attempts

**Rate Limit**: 5 requests per minute per IP

---

### POST /api/v1/auth/refresh

Refresh access token using refresh token.

**Request**:
```json
{
  "refresh_token": "rt_abc123def456..."
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 1800
  }
}
```

**Errors**:
- 401: Invalid or expired refresh token

**Rate Limit**: 10 requests per hour per user

---

### POST /api/v1/auth/logout

Logout and invalidate tokens.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response** (204 No Content)

---

### GET /api/v1/auth/me

Get current user information.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "permissions": [
      "targets:read",
      "targets:write",
      "targets:delete",
      "hardening:apply",
      "users:manage"
    ],
    "created_at": "2025-01-15T10:00:00Z",
    "last_login_at": "2025-11-28T10:30:00Z",
    "failed_login_attempts": 0
  }
}
```

---

### POST /api/v1/auth/password/change

Change user password.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "current_password": "OldPassword123!",
  "new_password": "NewSecurePassword456!",
  "confirm_password": "NewSecurePassword456!"
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "Password changed successfully"
}
```

**Errors**:
- 400: Passwords don't match
- 401: Current password incorrect
- 422: New password doesn't meet requirements

---

## Target Management Endpoints

### GET /api/v1/targets

List all targets with filtering and pagination.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `page` (int, default: 1)
- `per_page` (int, default: 20, max: 100)
- `status` (string): filter by status (active, inactive, error)
- `role` (string): filter by role (web, database, dns, gateway)
- `compliance` (string): filter by compliance standard
- `group_id` (int): filter by group
- `search` (string): search in hostname or IP
- `sort` (string, default: created_at): sort field
- `order` (string, default: desc): asc or desc

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": 1,
        "hostname": "webserver-01",
        "ip_address": "192.168.1.10",
        "ssh_port": 22,
        "ssh_username": "microcyber",
        "role": "web",
        "environment": "production",
        "group": {
          "id": 1,
          "name": "Web Servers"
        },
        "tags": ["production", "nginx", "https"],
        "compliance_standard": "nis2",
        "status": "active",
        "last_seen": "2025-11-28T10:29:45Z",
        "hardening": {
          "applied": true,
          "model_id": 5,
          "model_name": "web_severo_nis2",
          "applied_at": "2025-11-27T08:00:00Z",
          "score": 95
        },
        "monitoring": {
          "enabled": true,
          "interval_seconds": 30,
          "last_collection": "2025-11-28T10:29:45Z",
          "errors_count": 0
        },
        "integrations": {
          "sentinel_asset_id": 42,
          "firedog_target_id": 15
        },
        "created_at": "2025-11-20T12:00:00Z",
        "updated_at": "2025-11-28T10:29:45Z"
      }
    ],
    "pagination": {
      "page": 1,
      "per_page": 20,
      "total": 45,
      "total_pages": 3,
      "has_next": true,
      "has_prev": false
    }
  }
}
```

**Required Permission**: `targets:read`

---

### GET /api/v1/targets/{id}

Get detailed information about a specific target.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "id": 1,
    "hostname": "webserver-01",
    "ip_address": "192.168.1.10",
    "ssh_port": 22,
    "ssh_username": "microcyber",
    "role": "web",
    "environment": "production",
    "group": {
      "id": 1,
      "name": "Web Servers",
      "description": "Production web servers"
    },
    "tags": ["production", "nginx", "https"],
    "compliance_standard": "nis2",
    "status": "active",
    "last_seen": "2025-11-28T10:29:45Z",
    "network_interfaces": [
      {
        "interface_name": "eth0",
        "ip_address": "192.168.1.10",
        "mac_address": "00:11:22:33:44:55",
        "netmask": "255.255.255.0",
        "is_primary": true
      }
    ],
    "hardening": {
      "applied": true,
      "model_id": 5,
      "model_name": "web_severo_nis2",
      "model_version": "1.2.0",
      "applied_at": "2025-11-27T08:00:00Z",
      "applied_by": "admin",
      "score": 95,
      "last_check": "2025-11-28T10:25:00Z",
      "checks": {
        "total": 50,
        "passed": 48,
        "failed": 2
      }
    },
    "compliance": {
      "status": "compliant",
      "checks_passed": 45,
      "checks_failed": 0,
      "checks_warning": 0,
      "score": 100,
      "last_check": "2025-11-28T10:25:00Z"
    },
    "monitoring": {
      "enabled": true,
      "interval_seconds": 30,
      "last_collection": "2025-11-28T10:29:45Z",
      "collection_errors": 0,
      "data_retention_days": 90
    },
    "ssh_key": {
      "id": 3,
      "name": "production-key",
      "key_type": "ed25519",
      "fingerprint": "SHA256:abc123def456...",
      "created_at": "2025-11-20T12:00:00Z",
      "last_used_at": "2025-11-28T10:29:45Z",
      "rotation_days": 90,
      "expires_at": "2026-02-18T12:00:00Z"
    },
    "integrations": {
      "sentinel_core": {
        "asset_id": 42,
        "last_sync": "2025-11-28T10:00:00Z",
        "vulnerabilities_count": 3
      },
      "firedog": {
        "target_id": 15,
        "last_sync": "2025-11-28T10:00:00Z",
        "threats_count": 1
      }
    },
    "created_at": "2025-11-20T12:00:00Z",
    "updated_at": "2025-11-28T10:29:45Z"
  }
}
```

**Errors**:
- 404: Target not found

**Required Permission**: `targets:read`

---

### POST /api/v1/targets

Add a new target.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "hostname": "dbserver-01",
  "ip_address": "192.168.1.20",
  "ssh_port": 22,
  "ssh_username": "microcyber",
  "ssh_key_id": 3,
  "role": "database",
  "environment": "production",
  "group_id": 2,
  "tags": ["production", "postgresql", "primary"],
  "compliance_standard": "pci",
  "monitoring_enabled": true,
  "monitoring_interval_seconds": 30
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
    "ssh_connection_test": {
      "success": true,
      "os_detected": "Debian GNU/Linux 12 (bookworm)",
      "message": "SSH connection successful"
    },
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
    ],
    "next_steps": [
      "Review and select a hardening model",
      "Apply hardening configuration",
      "Enable monitoring"
    ]
  },
  "message": "Target added successfully. Please review suggested hardening models."
}
```

**Errors**:
- 400: Invalid input data
- 409: Target with this IP already exists
- 422: SSH connection test failed

**Required Permission**: `targets:write`

**Rate Limit**: 10 requests per hour per user

---

### PUT /api/v1/targets/{id}

Update target information.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "hostname": "webserver-01-prod",
  "role": "web",
  "environment": "production",
  "tags": ["production", "nginx", "https", "load-balanced"],
  "compliance_standard": "nis2",
  "monitoring_interval_seconds": 60
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "id": 1,
    "hostname": "webserver-01-prod",
    "updated_at": "2025-11-28T10:35:00Z"
  },
  "message": "Target updated successfully"
}
```

**Required Permission**: `targets:write`

---

### DELETE /api/v1/targets/{id}

Remove a target from monitoring.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Query Parameters**:
- `cleanup` (boolean, default: true): Remove monitoring scripts from target

**Response** (200 OK):
```json
{
  "success": true,
  "message": "Target removed successfully",
  "cleanup_performed": true
}
```

**Required Permission**: `targets:delete`

---

### POST /api/v1/targets/check-connection

Test SSH connection to a target.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "ip_address": "192.168.1.25",
  "ssh_port": 22,
  "ssh_username": "microcyber",
  "ssh_key_id": 3
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "connection_status": "success",
    "hostname": "dbserver-02",
    "os": "Debian GNU/Linux 12 (bookworm)",
    "kernel": "6.1.0-13-amd64",
    "uptime_seconds": 1234567,
    "response_time_ms": 45
  }
}
```

**Errors**:
- 422: Connection failed

---

### GET /api/v1/targets/groups

List target groups.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "groups": [
      {
        "id": 1,
        "name": "Web Servers",
        "description": "Production web servers",
        "targets_count": 15,
        "default_ssh_key_id": 3,
        "default_monitoring_interval": 30,
        "created_at": "2025-11-01T10:00:00Z"
      }
    ]
  }
}
```

---

## Hardening Endpoints

### GET /api/v1/hardening/models

List available hardening models.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `role` (string): filter by role
- `compliance` (string): filter by compliance
- `level` (string): filter by level (base, severo)
- `search` (string): search in name or description

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "models": [
      {
        "id": 5,
        "name": "web_severo_nis2",
        "version": "1.2.0",
        "description": "Strict hardening for web servers with NIS2 compliance",
        "role": "web",
        "compliance_standard": "nis2",
        "level": "severo",
        "author": "MicroSIEM Team",
        "model_path": "/hardening_models/severo/web_nis2",
        "files_count": 8,
        "hash_sha512": "abc123def456...",
        "supported_os": ["debian11", "debian12", "ubuntu20.04", "ubuntu22.04"],
        "services_to_enable": ["nginx", "auditd", "ulogd2"],
        "services_to_disable": ["apache2", "telnet", "ftp"],
        "packages_to_install": ["fail2ban", "ulogd2"],
        "packages_to_remove": ["telnetd"],
        "requires_reboot": false,
        "estimated_apply_time_seconds": 120,
        "is_active": true,
        "created_at": "2025-10-15T14:00:00Z",
        "updated_at": "2025-11-20T09:00:00Z"
      }
    ]
  }
}
```

**Required Permission**: `hardening:read`

---

### GET /api/v1/hardening/models/{id}

Get detailed hardening model configuration.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "id": 5,
    "name": "web_severo_nis2",
    "version": "1.2.0",
    "description": "Strict hardening for web servers with NIS2 compliance",
    "role": "web",
    "compliance_standard": "nis2",
    "level": "severo",
    "hash_sha512": "abc123def456...",
    "files": [
      {
        "file_name": "etc.ssh.sshd_config",
        "target_path": "/etc/ssh/sshd_config",
        "hash_sha256": "def456ghi789...",
        "file_mode": "644",
        "file_owner": "root",
        "file_group": "root"
      },
      {
        "file_name": "etc.sysctl.d.99-hardening.conf",
        "target_path": "/etc/sysctl.d/99-hardening.conf",
        "hash_sha256": "ghi789jkl012...",
        "file_mode": "644",
        "file_owner": "root",
        "file_group": "root"
      }
    ],
    "validation_results": {
      "syntax_valid": true,
      "ssh_safe": true,
      "conflicts": [],
      "warnings": [
        "IP forwarding will be disabled"
      ]
    },
    "metadata": {
      "supported_os": ["debian11", "debian12", "ubuntu20.04", "ubuntu22.04"],
      "services_to_enable": ["nginx", "auditd"],
      "services_to_disable": ["apache2", "telnet"],
      "packages_to_install": ["fail2ban"],
      "packages_to_remove": ["telnetd"],
      "requires_reboot": false,
      "pre_checks": [
        "disk_space > 1GB",
        "ssh_accessible"
      ],
      "post_checks": [
        "ssh_daemon_active",
        "enabled_services_running"
      ],
      "notes": [
        "This model enforces strict NIS2 compliance",
        "All unnecessary services are disabled"
      ],
      "warnings": [
        "⚠️ Review firewall rules before applying",
        "⚠️ Test on non-production system first"
      ]
    }
  }
}
```

**Required Permission**: `hardening:read`

---

### POST /api/v1/hardening/validate

Validate a hardening model configuration.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "model_id": 5
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
        "IP forwarding will be disabled",
        "Some firewall rules may need customization"
      ],
      "suggestions": [
        "Review firewall rules and uncomment needed services",
        "Replace example IP addresses with your networks"
      ]
    },
    "integrity_check": {
      "passed": true,
      "expected_hash": "abc123def456...",
      "calculated_hash": "abc123def456...",
      "message": "Model integrity verified"
    }
  }
}
```

**Required Permission**: `hardening:read`

---

### POST /api/v1/hardening/apply

Apply hardening model to a target.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "target_id": 1,
  "model_id": 5,
  "create_backup": true,
  "dry_run": false
}
```

**Response** (202 Accepted):
```json
{
  "success": true,
  "data": {
    "application_id": "app_abc123",
    "status": "pending",
    "target_id": 1,
    "model_id": 5,
    "estimated_duration_seconds": 120,
    "steps_total": 15,
    "created_at": "2025-11-28T10:30:00Z"
  },
  "message": "Hardening application started. Monitor progress at /api/v1/hardening/applications/app_abc123"
}
```

**Errors**:
- 400: Invalid model or target
- 403: Insufficient permissions
- 422: Validation failed

**Required Permission**: `hardening:apply`

**Rate Limit**: 5 requests per hour per user

---

### GET /api/v1/hardening/applications/{id}

Get status of hardening application.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "application_id": "app_abc123",
    "target_id": 1,
    "target_hostname": "webserver-01",
    "model_id": 5,
    "model_name": "web_severo_nis2",
    "status": "completed",
    "steps_total": 15,
    "steps_completed": 15,
    "steps_failed": 0,
    "started_at": "2025-11-28T10:30:00Z",
    "completed_at": "2025-11-28T10:32:15Z",
    "duration_seconds": 135,
    "result": {
      "success": true,
      "changes_applied": [
        "SSH configuration hardened",
        "Kernel parameters updated",
        "Firewall rules applied",
        "Audit rules configured",
        "Services disabled: telnet, ftp"
      ],
      "backup_created": true,
      "backup_path": "/opt/microsiem/backups/192.168.1.10_1732791000",
      "rollback_available": true
    },
    "log": "Full application log here...",
    "applied_by": "admin"
  }
}
```

**Status values**: `pending`, `in_progress`, `completed`, `failed`, `rolled_back`

---

### POST /api/v1/hardening/rollback

Rollback hardening changes.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "application_id": "app_abc123"
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "rollback_id": "rollback_xyz789",
    "files_restored": 8,
    "services_restarted": ["sshd", "networking"],
    "completed_at": "2025-11-28T10:35:00Z"
  },
  "message": "Hardening changes rolled back successfully"
}
```

**Required Permission**: `hardening:apply`

---

## Monitoring Endpoints

### GET /api/v1/monitoring/targets/{id}/metrics

Get time-series metrics for a target.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `start` (ISO 8601 datetime, required)
- `end` (ISO 8601 datetime, required)
- `metrics` (comma-separated): cpu,memory,disk,connections
- `aggregation` (string, default: mean): mean, max, min, sum
- `interval` (string, default: 1m): 1m, 5m, 15m, 1h

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "target_id": 1,
    "hostname": "webserver-01",
    "time_range": {
      "start": "2025-11-28T09:00:00Z",
      "end": "2025-11-28T10:00:00Z"
    },
    "metrics": {
      "cpu_usage": [
        {"timestamp": "2025-11-28T09:00:00Z", "value": 15.5},
        {"timestamp": "2025-11-28T09:05:00Z", "value": 18.2}
      ],
      "memory_usage": [
        {"timestamp": "2025-11-28T09:00:00Z", "value": 45.8},
        {"timestamp": "2025-11-28T09:05:00Z", "value": 46.1}
      ],
      "connections": [
        {"timestamp": "2025-11-28T09:00:00Z", "value": 25},
        {"timestamp": "2025-11-28T09:05:00Z", "value": 28}
      ]
    }
  }
}
```

**Required Permission**: `monitoring:read`

---

### GET /api/v1/monitoring/targets/{id}/connections

Get current network connections for a target.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "target_id": 1,
    "hostname": "webserver-01",
    "timestamp": "2025-11-28T10:30:00Z",
    "connections": [
      {
        "protocol": "tcp",
        "local_addr": "192.168.1.10",
        "local_port": 22,
        "remote_addr": "192.168.1.100",
        "remote_port": 54321,
        "state": "ESTABLISHED",
        "process": "sshd",
        "pid": 12345,
        "is_suspicious": false
      },
      {
        "protocol": "tcp",
        "local_addr": "192.168.1.10",
        "local_port": 3389,
        "remote_addr": "10.0.0.50",
        "remote_port": 45678,
        "state": "ESTABLISHED",
        "process": "xrdp",
        "pid": 23456,
        "is_suspicious": true,
        "alert_reason": "RDP connection detected (not expected for this server role)"
      }
    ],
    "summary": {
      "total": 25,
      "suspicious": 1,
      "by_protocol": {
        "tcp": 23,
        "udp": 2
      },
      "by_state": {
        "ESTABLISHED": 20,
        "TIME_WAIT": 5
      }
    }
  }
}
```

---

### GET /api/v1/monitoring/targets/{id}/users

Get logged-in users and their activities.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "target_id": 1,
    "timestamp": "2025-11-28T10:30:00Z",
    "users": [
      {
        "username": "admin",
        "terminal": "pts/0",
        "login_time": "2025-11-28T09:00:00Z",
        "remote_ip": "192.168.1.100",
        "is_active": true,
        "recent_commands": [
          {
            "timestamp": "2025-11-28T10:25:00Z",
            "command": "sudo systemctl restart nginx",
            "working_directory": "/home/admin",
            "exit_code": 0,
            "is_suspicious": false
          }
        ],
        "suspicious_commands_count": 0
      }
    ],
    "summary": {
      "total_users": 2,
      "active_users": 2,
      "suspicious_activity": false
    }
  }
}
```

---

### GET /api/v1/monitoring/targets/{id}/services

Get services status.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "target_id": 1,
    "timestamp": "2025-11-28T10:30:00Z",
    "services": {
      "running": [
        {
          "name": "nginx",
          "status": "active",
          "is_expected": true,
          "pid": 1234,
          "memory_mb": 45.2,
          "cpu_percent": 2.5
        }
      ],
      "stopped": [],
      "unexpected": [
        {
          "name": "telnet",
          "status": "active",
          "is_expected": false,
          "alert_triggered": true,
          "started_at": "2025-11-28T10:15:00Z"
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

### GET /api/v1/monitoring/targets/{id}/auditd

Get auditd events.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `start` (ISO 8601 datetime)
- `end` (ISO 8601 datetime)
- `event_type` (string): filter by event type
- `suspicious_only` (boolean): show only suspicious events

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "target_id": 1,
    "events": [
      {
        "event_type": "SYSCALL",
        "timestamp": "2025-11-28T10:29:45Z",
        "username": "microcyber",
        "command": "/usr/bin/systemctl status nginx",
        "key": "rootcmd",
        "result": "success",
        "is_suspicious": false,
        "severity": "info"
      }
    ],
    "summary": {
      "total_events": 150,
      "suspicious_events": 2,
      "by_severity": {
        "critical": 0,
        "high": 0,
        "warning": 2,
        "info": 148
      }
    }
  }
}
```

---

## Compliance Endpoints

### GET /api/v1/compliance/standards

List available compliance standards.

**Headers**:
```
Authorization: Bearer <access_token>
```

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
        "version": "2.0",
        "checks_count": 45,
        "categories": ["access_control", "network_security", "audit_logging"]
      },
      {
        "id": "pci",
        "name": "PCI-DSS",
        "description": "Payment Card Industry Data Security Standard",
        "version": "4.0",
        "checks_count": 52,
        "categories": ["firewall", "encryption", "access_control"]
      }
    ]
  }
}
```

---

### GET /api/v1/compliance/targets/{id}/status

Get compliance status for a target.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `standard` (string, optional): specific standard (nis2, pci, iso27001)

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "target_id": 1,
    "hostname": "webserver-01",
    "compliance_standard": "nis2",
    "status": "compliant",
    "score": 100,
    "last_check": "2025-11-28T10:25:00Z",
    "checks": {
      "total": 45,
      "passed": 45,
      "failed": 0,
      "warning": 0,
      "not_applicable": 0
    },
    "details": [
      {
        "check_id": "nis2_001",
        "check_name": "SSH Root Login Disabled",
        "category": "access_control",
        "status": "pass",
        "severity": "high",
        "description": "Root login via SSH must be disabled",
        "evidence": "PermitRootLogin=no found in /etc/ssh/sshd_config"
      }
    ],
    "recommendations": []
  }
}
```

---

### POST /api/v1/compliance/targets/{id}/check

Trigger compliance check for a target.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "standard": "nis2"
}
```

**Response** (202 Accepted):
```json
{
  "success": true,
  "data": {
    "check_id": "check_abc123",
    "status": "pending",
    "estimated_duration_seconds": 30
  },
  "message": "Compliance check started"
}
```

---

### GET /api/v1/compliance/reports

List compliance reports.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `target_id` (int): filter by target
- `standard` (string): filter by standard
- `report_type` (string): full, executive, delta

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "reports": [
      {
        "id": 15,
        "target_id": 1,
        "target_hostname": "webserver-01",
        "standard": "nis2",
        "report_type": "full",
        "overall_score": 100,
        "total_checks": 45,
        "checks_passed": 45,
        "checks_failed": 0,
        "report_pdf_path": "/reports/nis2_webserver-01_20251128.pdf",
        "created_at": "2025-11-28T10:00:00Z"
      }
    ]
  }
}
```

---

### GET /api/v1/compliance/reports/{id}/download

Download compliance report PDF.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response**: PDF file download

---

## Integration Endpoints

### GET /api/v1/integrations/status

Get status of all integrations.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "sentinel_core": {
      "enabled": true,
      "status": "connected",
      "base_url": "https://sentinel-core.example.com",
      "last_sync": "2025-11-28T10:00:00Z",
      "sync_interval_minutes": 5,
      "assets_synced": 45,
      "vulnerabilities_count": 128
    },
    "firedog": {
      "enabled": true,
      "status": "connected",
      "base_url": "https://firedog.example.com",
      "last_sync": "2025-11-28T10:00:00Z",
      "sync_interval_minutes": 5,
      "targets_synced": 45,
      "threats_count": 12
    }
  }
}
```

**Required Permission**: `integrations:read`

---

### POST /api/v1/integrations/sentinel-core/sync

Trigger manual sync with Sentinel Core.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Response** (202 Accepted):
```json
{
  "success": true,
  "data": {
    "sync_id": "sync_abc123",
    "status": "pending"
  },
  "message": "Sentinel Core synchronization started"
}
```

**Required Permission**: `integrations:write`

---

### POST /api/v1/integrations/firedog/sync

Trigger manual sync with FireDog.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Response** (202 Accepted):
```json
{
  "success": true,
  "data": {
    "sync_id": "sync_def456",
    "status": "pending"
  },
  "message": "FireDog synchronization started"
}
```

**Required Permission**: `integrations:write`

---

### GET /api/v1/integrations/correlations

Get security correlations between vulnerabilities and threats.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `target_id` (int): filter by target
- `risk_level` (string): critical, high, medium, low
- `time_range` (string): 1h, 24h, 7d, 30d

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "correlations": [
      {
        "id": 42,
        "target_id": 1,
        "target_hostname": "webserver-01",
        "vulnerability": {
          "cve_id": "CVE-2024-12345",
          "cvss_score": 9.8,
          "severity": "critical",
          "description": "Remote code execution vulnerability"
        },
        "threat": {
          "source_ip": "203.0.113.42",
          "threat_type": "exploit_attempt",
          "score": 8.5,
          "detected_at": "2025-11-28T09:45:00Z"
        },
        "correlation_confidence": 0.92,
        "risk_level": "critical",
        "recommended_actions": [
          "Apply security patch immediately",
          "Block attacker IP in FireDog",
          "Isolate target from network",
          "Review system logs for compromise indicators"
        ],
        "created_at": "2025-11-28T09:50:00Z"
      }
    ],
    "summary": {
      "total": 5,
      "by_risk_level": {
        "critical": 1,
        "high": 2,
        "medium": 2
      }
    }
  }
}
```

**Required Permission**: `integrations:read`

---

### POST /api/v1/integrations/firedog/block-ip

Block IP address in FireDog firewall.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "ip_address": "203.0.113.42",
  "reason": "High-risk threat detected targeting vulnerable system",
  "duration_hours": 24
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "block_id": "block_xyz789",
    "ip_address": "203.0.113.42",
    "blocked_at": "2025-11-28T10:35:00Z",
    "expires_at": "2025-11-29T10:35:00Z"
  },
  "message": "IP address blocked in FireDog"
}
```

**Required Permission**: `integrations:write`

---

## Alert & Notification Endpoints

### GET /api/v1/notifications/config

Get notification configuration.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "email": {
      "enabled": true,
      "smtp_host": "smtp.example.com",
      "smtp_port": 587,
      "smtp_user": "alerts@example.com",
      "from_address": "microsiem@example.com",
      "recipients": ["security@example.com", "admin@example.com"]
    },
    "slack": {
      "enabled": true,
      "webhook_url": "https://hooks.slack.com/services/xxx"
    },
    "discord": {
      "enabled": false,
      "webhook_url": null
    },
    "alert_triggers": {
      "suspicious_connections": true,
      "unexpected_services": true,
      "compliance_failures": true,
      "hardening_changes": false,
      "high_severity_vulnerabilities": true,
      "critical_threats": true
    },
    "cooldown_minutes": 15
  }
}
```

**Required Permission**: `notifications:read`

---

### PUT /api/v1/notifications/config

Update notification configuration.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "email": {
    "enabled": true,
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "smtp_user": "alerts@example.com",
    "smtp_password": "SecurePassword123!",
    "from_address": "microsiem@example.com",
    "recipients": ["security@example.com"]
  },
  "slack": {
    "enabled": true,
    "webhook_url": "https://hooks.slack.com/services/xxx"
  },
  "alert_triggers": {
    "suspicious_connections": true,
    "unexpected_services": true,
    "compliance_failures": true
  },
  "cooldown_minutes": 15
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "Notification configuration updated successfully"
}
```

**Required Permission**: `notifications:write`

---

### POST /api/v1/notifications/test

Send test notification.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "channel": "email"
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "sent": true,
    "channel": "email",
    "timestamp": "2025-11-28T10:40:00Z",
    "delivery_status": "delivered"
  },
  "message": "Test notification sent successfully"
}
```

**Required Permission**: `notifications:write`

---

### GET /api/v1/alerts

List recent alerts.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `page` (int, default: 1)
- `per_page` (int, default: 20)
- `severity` (string): critical, high, medium, low
- `alert_type` (string): filter by type
- `acknowledged` (boolean): filter by acknowledged status
- `start_date` (ISO 8601): filter from date
- `end_date` (ISO 8601): filter to date

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": 1523,
        "alert_type": "unexpected_service",
        "severity": "high",
        "target_id": 1,
        "target_hostname": "webserver-01",
        "message": "Unexpected service 'telnet' detected running on webserver-01",
        "details": {
          "service_name": "telnet",
          "pid": 23456,
          "started_at": "2025-11-28T10:15:00Z"
        },
        "triggered_at": "2025-11-28T10:15:30Z",
        "acknowledged": false,
        "acknowledged_by": null,
        "acknowledged_at": null,
        "notification_sent": true,
        "notification_channels": ["email", "slack"]
      }
    ],
    "pagination": {
      "page": 1,
      "per_page": 20,
      "total": 42,
      "total_pages": 3
    }
  }
}
```

**Required Permission**: `alerts:read`

---

### POST /api/v1/alerts/{id}/acknowledge

Acknowledge an alert.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "note": "Investigated and resolved. Service was stopped."
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "Alert acknowledged successfully"
}
```

**Required Permission**: `alerts:write`

---

## User Management Endpoints

### GET /api/v1/users

List all users.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `page` (int)
- `per_page` (int)
- `role` (string): filter by role
- `is_active` (boolean): filter by active status

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "role": "admin",
        "is_active": true,
        "created_at": "2025-01-15T10:00:00Z",
        "last_login_at": "2025-11-28T08:30:00Z",
        "failed_login_attempts": 0,
        "account_locked_until": null
      }
    ],
    "pagination": {
      "page": 1,
      "per_page": 20,
      "total": 5,
      "total_pages": 1
    }
  }
}
```

**Required Permission**: `users:read`

---

### POST /api/v1/users

Create new user.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "username": "security_analyst",
  "email": "analyst@example.com",
  "password": "SecurePassword123!",
  "confirm_password": "SecurePassword123!",
  "role": "user"
}
```

**Response** (201 Created):
```json
{
  "success": true,
  "data": {
    "id": 6,
    "username": "security_analyst",
    "email": "analyst@example.com",
    "role": "user",
    "created_at": "2025-11-28T10:45:00Z"
  },
  "message": "User created successfully"
}
```

**Required Permission**: `users:write`

---

### PUT /api/v1/users/{id}

Update user information.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "email": "new.email@example.com",
  "role": "admin"
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "User updated successfully"
}
```

**Required Permission**: `users:write`

---

### DELETE /api/v1/users/{id}

Deactivate user.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "User deactivated successfully"
}
```

**Required Permission**: `users:delete`

---

## System Configuration Endpoints

### GET /api/v1/config/system

Get system configuration.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "monitoring": {
      "collection_interval_seconds": 30,
      "data_retention_days": 90,
      "max_concurrent_collections": 10
    },
    "ssh": {
      "default_port": 22,
      "connection_timeout_seconds": 30,
      "key_rotation_days": 90
    },
    "security": {
      "session_timeout_minutes": 30,
      "max_failed_login_attempts": 5,
      "account_lockout_duration_minutes": 15
    },
    "integrations": {
      "sentinel_core_enabled": true,
      "firedog_enabled": true
    }
  }
}
```

**Required Permission**: `config:read`

---

### PUT /api/v1/config/system

Update system configuration.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "monitoring": {
    "collection_interval_seconds": 60,
    "data_retention_days": 180
  }
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "System configuration updated successfully"
}
```

**Required Permission**: `config:write`

---

### GET /api/v1/config/ssh-keys

List SSH keys.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "keys": [
      {
        "id": 3,
        "name": "production-key",
        "key_type": "ed25519",
        "fingerprint": "SHA256:abc123def456...",
        "scope": "global",
        "is_active": true,
        "created_at": "2025-11-01T10:00:00Z",
        "last_used_at": "2025-11-28T10:29:45Z",
        "rotation_days": 90,
        "expires_at": "2026-01-30T10:00:00Z"
      }
    ]
  }
}
```

---

### POST /api/v1/config/ssh-keys

Create new SSH key.

**Headers**:
```
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
```

**Request**:
```json
{
  "name": "dev-key",
  "key_type": "ed25519",
  "scope": "group",
  "rotation_days": 90
}
```

**Response** (201 Created):
```json
{
  "success": true,
  "data": {
    "id": 4,
    "name": "dev-key",
    "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...",
    "fingerprint": "SHA256:xyz789abc123...",
    "created_at": "2025-11-28T10:50:00Z"
  },
  "message": "SSH key created successfully"
}
```

**Required Permission**: `config:write`

---

## WebSocket API

### Connection

**URL**: `wss://microsiem.example.com/ws`

**Authentication**: Include JWT token in query parameter:
```
wss://microsiem.example.com/ws?token=<access_token>
```

### Subscribe to Topics

```json
{
  "action": "subscribe",
  "topic": "target_metrics",
  "target_id": 1
}
```

**Available Topics**:
- `target_metrics` - Real-time system metrics
- `target_connections` - Connection updates
- `alerts` - New alerts
- `hardening_progress` - Hardening application progress
- `compliance_checks` - Compliance check updates

### Unsubscribe from Topics

```json
{
  "action": "unsubscribe",
  "topic": "target_metrics",
  "target_id": 1
}
```

### Message Format

**Target Metrics Update**:
```json
{
  "type": "target_metrics",
  "target_id": 1,
  "timestamp": "2025-11-28T10:30:00Z",
  "data": {
    "cpu_usage": 15.5,
    "memory_usage": 45.8,
    "disk_usage": 62.3,
    "connections_count": 25
  }
}
```

**Alert Triggered**:
```json
{
  "type": "alert",
  "severity": "high",
  "alert_type": "unexpected_service",
  "target_id": 1,
  "target_hostname": "webserver-01",
  "message": "Unexpected service 'telnet' detected",
  "timestamp": "2025-11-28T10:15:30Z"
}
```

**Hardening Progress**:
```json
{
  "type": "hardening_progress",
  "application_id": "app_abc123",
  "target_id": 1,
  "status": "in_progress",
  "steps_completed": 8,
  "steps_total": 15,
  "current_step": "Configuring firewall rules",
  "timestamp": "2025-11-28T10:31:00Z"
}
```

---

## Rate Limiting

### Limits by Endpoint Category

| Category | Limit |
|----------|-------|
| Authentication | 5 requests/minute per IP |
| Token Refresh | 10 requests/hour per user |
| Target Creation | 10 requests/hour per user |
| Hardening Apply | 5 requests/hour per user |
| Read Operations | 100 requests/minute per user |
| Write Operations | 20 requests/minute per user |

### Rate Limit Headers

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1732791600
```

---

## Pagination

All list endpoints support pagination with consistent parameters:

**Query Parameters**:
- `page` (int, default: 1): Page number
- `per_page` (int, default: 20, max: 100): Items per page
- `sort` (string): Sort field
- `order` (string): `asc` or `desc`

**Response**:
```json
{
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 145,
    "total_pages": 8,
    "has_next": true,
    "has_prev": false
  }
}
```

---

## CORS Configuration

```
Access-Control-Allow-Origin: https://microsiem.example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Authorization, Content-Type, X-CSRF-Token
Access-Control-Max-Age: 86400
```

---

## Security Headers

All responses include security headers:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
```

---

**Versione**: 1.0.0  
**Data**: 2025-11-28  
**Autore**: Development Team
