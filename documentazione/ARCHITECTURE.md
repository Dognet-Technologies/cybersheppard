# MicroSIEM (CyberSheppard) - Architecture Document

## 📋 Indice

1. [Overview](#overview)
2. [High-Level Architecture](#high-level-architecture)
3. [Technology Stack](#technology-stack)
4. [Component Details](#component-details)
5. [Data Flow](#data-flow)
6. [Security Architecture](#security-architecture)
7. [Network Architecture](#network-architecture)
8. [Deployment Architecture](#deployment-architecture)
9. [Performance & Scalability](#performance--scalability)
10. [Monitoring & Observability](#monitoring--observability)

---

## Overview

**MicroSIEM (CyberSheppard)** è un sistema SIEM (Security Information and Event Management) completo progettato per hardening, monitoring e compliance management di sistemi Linux.

### System Characteristics

- **Architecture Style**: Microservices (Rust backend + Python hardening engine)
- **Communication**: REST API + WebSocket (real-time)
- **Data Storage**: PostgreSQL (metadata) + InfluxDB (time-series)
- **Deployment**: LXC container, Docker, o VM
- **Target Platform**: Debian/Ubuntu Linux systems
- **Scalability**: Supports 100+ targets per instance

### Key Features

✅ **Hardening automatico** con modelli pre-configurati (base/severo)  
✅ **Monitoring continuo** ogni 30 secondi con 9 collectors  
✅ **Compliance checking** (NIS2, PCI-DSS, ISO27001)  
✅ **Integration** con Sentinel Core e FireDog  
✅ **Real-time alerting** via Email, Slack, Discord  
✅ **Security correlation** tra vulnerabilità e minacce  
✅ **Role-based access** (admin/user)  
✅ **Audit logging** completo per tutte le operazioni  

---

## High-Level Architecture

### System Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                          EXTERNAL USERS                              │
│                    (Web Browser / Mobile App)                        │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │ HTTPS (443)
                                 │ JWT Auth + CSRF
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│                          NGINX REVERSE PROXY                         │
│                       (SSL/TLS Termination)                          │
│                       Load Balancing (optional)                      │
└─────────┬────────────────────────────────────────────┬───────────────┘
          │                                            │
          │ /                                          │ /api
          │ (Static Files)                             │ (API Calls)
          ▼                                            ▼
┌──────────────────────┐                    ┌─────────────────────────┐
│  FRONTEND            │                    │  BACKEND                │
│  React + TypeScript  │◄───────────────────│  Rust + Axum            │
│  Port: 3000          │    WebSocket       │  Port: 8080             │
│                      │    (Real-time)     │                         │
│  • Dashboard         │                    │  • REST API             │
│  • Target Management │                    │  • WebSocket Server     │
│  • Compliance View   │                    │  • Data Collector       │
│  • Alert Panel       │                    │  • Integration Service  │
│                      │                    │  • Correlation Engine   │
└──────────────────────┘                    └─────────┬───────────────┘
                                                      │
                                                      │ HTTP localhost
                                                      ▼
                                            ┌─────────────────────────┐
                                            │  HARDENING ENGINE       │
                                            │  Python + Flask         │
                                            │  Port: 5001             │
                                            │                         │
                                            │  • Model Loader         │
                                            │  • Validator            │
                                            │  • Applier              │
                                            │  • Backup Manager       │
                                            └─────────┬───────────────┘
                                                      │
                    ┌─────────────────────────────────┼─────────────────┐
                    │                                 │                 │
                    ▼                                 ▼                 ▼
         ┌────────────────────┐          ┌──────────────────┐  ┌──────────────┐
         │   PostgreSQL       │          │   InfluxDB       │  │  SSH Manager │
         │   (Metadata)       │          │   (Time-Series)  │  │              │
         │   Port: 5432       │          │   Port: 8086     │  └──────┬───────┘
         │                    │          │                  │         │
         │  • Users           │          │  • Metrics       │         │ SSH (22)
         │  • Targets         │          │  • Connections   │         │ Ed25519
         │  • Models          │          │  • Auditd Events │         │
         │  • Compliance      │          │  • Correlations  │         ▼
         │  • Audit Logs      │          │                  │  ┌──────────────┐
         └────────────────────┘          └──────────────────┘  │  TARGET      │
                                                                │  SYSTEMS     │
                    ┌───────────────────────────────────────────┤              │
                    │ External Integrations                     │  • Debian    │
                    │                                           │  • Ubuntu    │
                    ▼                                           │              │
         ┌────────────────────┐          ┌──────────────────┐  │  User:       │
         │  SENTINEL CORE     │          │  FIREDOG         │  │  microcyber  │
         │  (Vulnerabilities) │          │  (Firewall)      │  │              │
         │                    │          │                  │  │  Cron: 30s   │
         │  • CVE Database    │          │  • Threats       │  │  monitoring  │
         │  • Asset Sync      │          │  • Statistics    │  │              │
         │  • Scans           │          │  • Block IPs     │  └──────────────┘
         └────────────────────┘          └──────────────────┘
```

---

## Technology Stack

### Backend Layer

```yaml
Core Application:
  Language: Rust 1.75+
  Framework: Axum 0.7+
  Async Runtime: Tokio
  HTTP Client: reqwest
  
Database Clients:
  PostgreSQL: sqlx 0.7+ (async)
  InfluxDB: influxdb2 0.5+
  
Security:
  JWT: jsonwebtoken
  Password Hashing: argon2
  Encryption: ring, aes-gcm
  
Serialization:
  JSON: serde_json
  YAML: serde_yaml
  
Validation:
  validator crate
  
Logging:
  tracing + tracing-subscriber
  
WebSocket:
  axum websocket support
  
SSH Client:
  async-ssh2-tokio (via Rust)
  OR shell out to system SSH
```

### Hardening Engine

```yaml
Language: Python 3.11+
Framework: Flask 3.0+
Libraries:
  SSH: paramiko
  Validation: pydantic
  Encryption: cryptography (Fernet)
  HTTP Client: requests
  
Structure:
  app.py - Flask API server
  models/loader.py - Model loading
  models/validator.py - Configuration validation
  applier/applier.py - Hardening application
  applier/backup.py - Backup management
  applier/rollback.py - Rollback functionality
```

### Frontend Layer

```yaml
Framework: React 18+
Language: TypeScript 5+
Build Tool: Vite 5+
State Management:
  Server State: TanStack Query (React Query)
  Client State: React Context + useState
UI Components:
  Base: shadcn/ui + Radix UI
  Styling: Tailwind CSS
  Icons: Lucide React
Charts:
  Library: Recharts
  Alternative: Chart.js
Forms:
  Validation: React Hook Form + Zod
HTTP:
  Client: Axios
  WebSocket: native WebSocket API
Routing:
  React Router v6
```

### Database Layer

```yaml
Relational Database:
  System: PostgreSQL 15+
  Purpose: Metadata, users, targets, configurations
  Features: JSONB, partitioning, GIN indexes
  
Time-Series Database:
  System: InfluxDB 2.7+
  Purpose: Metrics, logs, correlations
  Features: Retention policies, downsampling, Flux queries
```

### Infrastructure

```yaml
Web Server:
  Nginx 1.24+
  Purpose: Reverse proxy, SSL termination, static files
  
Process Manager:
  systemd
  Purpose: Service management, auto-restart
  
Containerization:
  LXC (primary)
  Docker (alternative)
  VM (alternative)
  
OS:
  Server: Debian 12 / Ubuntu 22.04 LTS
  Targets: Debian 11/12, Ubuntu 20.04/22.04
```

### Target System Components

```yaml
Scripts:
  Language: Bash
  Purpose: Data collection
  Location: /opt/microsiem/
  
Python:
  Version: 3.9+
  Purpose: JSON aggregation
  
Scheduling:
  Cron OR systemd timer
  Interval: 30 seconds
  
User:
  Name: microcyber
  Privileges: Limited sudo (monitoring only)
```

---

## Component Details

### 1. Rust Backend (Main Application)

**Location**: `microsiem/backend/`

```
backend/
├── src/
│   ├── main.rs                    # Entry point
│   ├── config.rs                  # Configuration management
│   ├── error.rs                   # Error handling
│   │
│   ├── api/                       # REST API endpoints
│   │   ├── mod.rs
│   │   ├── auth.rs                # Authentication endpoints
│   │   ├── targets.rs             # Target management
│   │   ├── hardening.rs           # Hardening operations
│   │   ├── monitoring.rs          # Monitoring data
│   │   ├── compliance.rs          # Compliance checks
│   │   ├── integrations.rs        # External integrations
│   │   ├── alerts.rs              # Alert management
│   │   ├── users.rs               # User management
│   │   └── websocket.rs           # WebSocket handler
│   │
│   ├── models/                    # Database models
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   ├── target.rs
│   │   ├── hardening_model.rs
│   │   ├── alert.rs
│   │   └── integration.rs
│   │
│   ├── services/                  # Business logic
│   │   ├── mod.rs
│   │   ├── auth_service.rs        # Authentication & JWT
│   │   ├── target_service.rs      # Target operations
│   │   ├── data_collector.rs      # Data collection from targets
│   │   ├── hardening_client.rs    # Python engine client
│   │   ├── integration_sync.rs    # Sentinel/FireDog sync
│   │   ├── correlation_engine.rs  # Security correlation
│   │   ├── alert_service.rs       # Alert processing
│   │   └── notification_service.rs # Notification dispatch
│   │
│   ├── db/                        # Database connections
│   │   ├── mod.rs
│   │   ├── postgres.rs            # PostgreSQL client
│   │   └── influxdb.rs            # InfluxDB client
│   │
│   ├── integrations/              # External system clients
│   │   ├── mod.rs
│   │   ├── sentinel_core.rs       # Sentinel Core API client
│   │   └── firedog.rs             # FireDog API client
│   │
│   ├── middleware/                # HTTP middleware
│   │   ├── mod.rs
│   │   ├── auth.rs                # JWT validation
│   │   ├── csrf.rs                # CSRF protection
│   │   ├── rate_limit.rs          # Rate limiting
│   │   └── audit_log.rs           # Audit logging
│   │
│   └── utils/                     # Utilities
│       ├── mod.rs
│       ├── validators.rs          # Input validation
│       ├── crypto.rs              # Encryption utilities
│       └── ssh.rs                 # SSH utilities
│
├── Cargo.toml                     # Dependencies
└── .env.example                   # Environment variables template
```

**Key Responsibilities**:
- REST API server (Axum)
- Authentication & authorization (JWT)
- WebSocket server (real-time updates)
- Data collection orchestration
- Integration with Sentinel Core & FireDog
- Security correlation engine
- Alert processing & notification dispatch
- Database operations (PostgreSQL + InfluxDB)

**Port**: 8080 (internal), 443 (external via Nginx)

---

### 2. Python Hardening Engine

**Location**: `microsiem/hardening_engine/`

```
hardening_engine/
├── app.py                         # Flask API server
├── config.py                      # Configuration
├── requirements.txt               # Dependencies
│
├── models/
│   ├── __init__.py
│   ├── loader.py                  # Model loading from filesystem
│   ├── validator.py               # Configuration validation
│   └── schemas.py                 # Pydantic schemas
│
├── applier/
│   ├── __init__.py
│   ├── applier.py                 # Hardening application logic
│   ├── backup.py                  # Backup management
│   ├── rollback.py                # Rollback functionality
│   └── ssh_manager.py             # SSH operations (from FireDog)
│
├── utils/
│   ├── __init__.py
│   ├── validators.py              # Input validators
│   ├── crypto.py                  # Encryption (Fernet)
│   └── logger.py                  # Logging setup
│
└── tests/
    ├── test_loader.py
    ├── test_validator.py
    └── test_applier.py
```

**Key Responsibilities**:
- Load hardening models from filesystem
- Validate model configurations (SSH safety, syntax)
- Apply hardening to targets via SSH
- Create backups before changes
- Rollback on failure or request
- Provide REST API for Rust backend

**Port**: 5001 (localhost only - not exposed externally)

**API Endpoints**:
- GET /health
- GET /models
- GET /models/{name}
- POST /validate
- POST /apply
- POST /rollback
- POST /check_connection

---

### 3. Frontend Application

**Location**: `microsiem/frontend/`

```
frontend/
├── src/
│   ├── main.tsx                   # Entry point
│   ├── App.tsx                    # Root component
│   ├── router.tsx                 # React Router configuration
│   │
│   ├── components/
│   │   ├── layout/
│   │   │   ├── Header.tsx
│   │   │   ├── Sidebar.tsx
│   │   │   └── Layout.tsx
│   │   │
│   │   ├── auth/
│   │   │   ├── LoginForm.tsx
│   │   │   └── ProtectedRoute.tsx
│   │   │
│   │   ├── dashboard/
│   │   │   ├── DashboardGrid.tsx
│   │   │   ├── MetricsCard.tsx
│   │   │   ├── AlertsPanel.tsx
│   │   │   └── ChartWidgets/
│   │   │
│   │   ├── targets/
│   │   │   ├── TargetList.tsx
│   │   │   ├── TargetCard.tsx
│   │   │   ├── TargetDetails.tsx
│   │   │   ├── AddTargetModal.tsx
│   │   │   └── ConnectionStatus.tsx
│   │   │
│   │   ├── hardening/
│   │   │   ├── ModelList.tsx
│   │   │   ├── ModelDetails.tsx
│   │   │   ├── ApplyHardeningModal.tsx
│   │   │   └── ApplicationProgress.tsx
│   │   │
│   │   ├── monitoring/
│   │   │   ├── MetricsCharts.tsx
│   │   │   ├── ConnectionsTable.tsx
│   │   │   ├── ServicesStatus.tsx
│   │   │   └── AuditdEvents.tsx
│   │   │
│   │   ├── compliance/
│   │   │   ├── ComplianceOverview.tsx
│   │   │   ├── ChecksList.tsx
│   │   │   └── ReportGenerator.tsx
│   │   │
│   │   ├── integrations/
│   │   │   ├── IntegrationStatus.tsx
│   │   │   ├── CorrelationsList.tsx
│   │   │   └── SyncControls.tsx
│   │   │
│   │   └── common/
│   │       ├── Button.tsx
│   │       ├── Card.tsx
│   │       ├── Table.tsx
│   │       └── Modal.tsx
│   │
│   ├── pages/
│   │   ├── Dashboard.tsx
│   │   ├── Targets.tsx
│   │   ├── TargetDetails.tsx
│   │   ├── Hardening.tsx
│   │   ├── Monitoring.tsx
│   │   ├── Compliance.tsx
│   │   ├── Integrations.tsx
│   │   ├── Alerts.tsx
│   │   ├── Settings.tsx
│   │   └── Users.tsx
│   │
│   ├── services/
│   │   ├── api.ts                 # Axios instance with interceptors
│   │   ├── auth.service.ts        # Auth operations
│   │   ├── targets.service.ts     # Target API calls
│   │   ├── hardening.service.ts   # Hardening API calls
│   │   ├── monitoring.service.ts  # Monitoring data
│   │   ├── websocket.service.ts   # WebSocket client
│   │   └── storage.service.ts     # LocalStorage wrapper
│   │
│   ├── hooks/
│   │   ├── useAuth.ts             # Auth hook
│   │   ├── useTargets.ts          # Targets data hook
│   │   ├── useRealTime.ts         # WebSocket hook
│   │   └── usePermissions.ts      # Permissions check
│   │
│   ├── types/
│   │   ├── auth.types.ts
│   │   ├── target.types.ts
│   │   ├── hardening.types.ts
│   │   ├── monitoring.types.ts
│   │   └── api.types.ts
│   │
│   ├── utils/
│   │   ├── validators.ts
│   │   ├── formatters.ts
│   │   └── constants.ts
│   │
│   └── styles/
│       └── globals.css
│
├── public/
├── package.json
├── tsconfig.json
├── vite.config.ts
└── tailwind.config.js
```

**Key Responsibilities**:
- User interface for all operations
- Real-time dashboard with WebSocket updates
- Target management interface
- Hardening model selection & application
- Monitoring data visualization
- Compliance status display
- Alert management
- User administration

**Port**: 3000 (development), served via Nginx in production

---

### 4. PostgreSQL Database

**Purpose**: Store relational data and metadata

**Schema**: 20 tables (see DATABASE_SCHEMA.md)

**Key Tables**:
- `users` - User accounts
- `targets` - Managed systems
- `hardening_models` - Hardening configurations
- `hardening_applications` - Application history
- `ssh_keys` - SSH key management
- `notification_config` - Alert settings
- `compliance_checks` - Compliance results
- `audit_logs` - Audit trail (partitioned by month)
- `integration_configs` - External system configs
- `security_correlations` - Vulnerability-threat matches

**Features**:
- JSONB columns for flexible data
- Partitioning for audit_logs (monthly)
- GIN indexes for JSONB search
- Foreign key constraints
- Triggers for updated_at
- Row-level security (future)

**Port**: 5432 (internal only)

**Backup**: Daily pg_dump, 7-day retention

---

### 5. InfluxDB Database

**Purpose**: Store time-series metrics and events

**Schema**: 14 measurements (see DATABASE_SCHEMA.md)

**Key Measurements**:
- `target_system_metrics` - CPU, RAM, disk, network
- `target_connections` - Network connections
- `auditd_events` - Audit daemon events
- `sudolog_events` - Sudo commands
- `file_integrity` - File hashes
- `sentinel_vulnerabilities` - CVE data
- `firedog_threats` - Threat detections
- `security_correlations` - Cross-system correlations

**Buckets**:
- `metrics` - 30 days retention
- `logs` - 90 days retention
- `correlations` - 365 days retention

**Features**:
- Automatic downsampling (5min aggregates)
- Retention policies per bucket
- Flux query language
- Tags for efficient filtering
- Fields for measurements

**Port**: 8086 (internal only)

**Backup**: Daily influx backup, 7-day retention

---

### 6. Target System Components

**Installation Location**: `/opt/microsiem/`

```
/opt/microsiem/
├── monitoring.sh                  # Main orchestrator
├── aggregate_json.py              # JSON aggregation
├── config.json                    # Configuration
│
├── collectors/
│   ├── auditd.sh                 # Audit events
│   ├── sudolog.sh                # Sudo commands
│   ├── connections.sh            # Network connections
│   ├── users.sh                  # User activity
│   ├── services.sh               # Services status
│   ├── packages.sh               # Package info
│   ├── files.sh                  # File integrity
│   ├── system.sh                 # System metrics
│   └── syscalls.sh               # System calls (optional)
│
├── lib/
│   └── common.sh                 # Shared functions
│
├── tmp/
│   └── collectors_output/        # Temporary data
│
└── logs/
    └── monitoring.log            # Monitoring logs
```

**User**: `microcyber`
- Limited sudo permissions (monitoring only)
- SSH key-based authentication (Ed25519)
- Monitored by auditd

**Scheduling**:
- Cron: Every 30 seconds (*/30 * * * *)
- OR systemd timer: OnUnitActiveSec=30s

**Output**: JSON files in `/tmp/microsiem_<timestamp>.json`

---

## Data Flow

### 1. Target Data Collection Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  TARGET SYSTEM                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Cron triggers every 30 seconds                                  │
│     └─> /opt/microsiem/monitoring.sh                                │
│                                                                      │
│  2. monitoring.sh launches collectors in parallel                   │
│     ├─> auditd.sh &                                                 │
│     ├─> sudolog.sh &                                                │
│     ├─> connections.sh &                                            │
│     ├─> users.sh &                                                  │
│     ├─> services.sh &                                               │
│     ├─> packages.sh &                                               │
│     ├─> files.sh &                                                  │
│     └─> system.sh &                                                 │
│                                                                      │
│  3. All collectors write JSON to tmp/collectors_output/             │
│                                                                      │
│  4. wait for all collectors to complete                             │
│                                                                      │
│  5. aggregate_json.py merges all JSON files                         │
│     └─> /tmp/microsiem_1732791000.json                              │
│                                                                      │
│  6. Cleanup old files (keep last 10)                                │
│                                                                      │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           │ Every 30 seconds
                           │ SCP pull initiated by server
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  MICROSIEM SERVER - Data Collector Service (Rust)                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. For each active target:                                         │
│     └─> SSH connection with Ed25519 key                             │
│     └─> Execute: ls -t /tmp/microsiem_*.json | head -1             │
│     └─> Get latest file path                                        │
│                                                                      │
│  2. SCP download JSON file                                          │
│     └─> scp microcyber@target:/tmp/microsiem_*.json /tmp/          │
│                                                                      │
│  3. Parse JSON file                                                 │
│     └─> Validate schema                                             │
│     └─> Extract metrics, events, alerts                             │
│                                                                      │
│  4. Write to InfluxDB (time-series)                                 │
│     ├─> target_system_metrics (CPU, RAM, disk)                      │
│     ├─> target_connections (network connections)                    │
│     ├─> auditd_events (security events)                             │
│     ├─> sudolog_events (sudo commands)                              │
│     ├─> target_services (services status)                           │
│     └─> file_integrity (file hashes)                                │
│                                                                      │
│  5. Write to PostgreSQL (events requiring action)                   │
│     └─> security_events table (suspicious activities)               │
│                                                                      │
│  6. Check alert rules                                               │
│     └─> Evaluate alert conditions                                   │
│     └─> If triggered → Alert Service                                │
│                                                                      │
│  7. Broadcast to WebSocket clients                                  │
│     └─> Real-time dashboard updates                                 │
│                                                                      │
│  8. Cleanup local temp files                                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**Duration**: ~2-5 seconds per target  
**Parallelism**: Up to 10 targets concurrently  
**Error Handling**: Retry once, then mark target as error state  

---

### 2. Hardening Application Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  USER ACTION                                                         │
├─────────────────────────────────────────────────────────────────────┤
│  1. User selects target and hardening model in UI                   │
│  2. User clicks "Apply Hardening"                                   │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           │ POST /api/v1/hardening/apply
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  RUST BACKEND - Hardening Controller                               │
├─────────────────────────────────────────────────────────────────────┤
│  1. Validate JWT token & permissions                                │
│  2. Validate input (target_id, model_id)                            │
│  3. Check target status (must be active)                            │
│  4. Check model exists and is valid                                 │
│  5. Create hardening_applications record (status: pending)          │
│  6. Return 202 Accepted with application_id                         │
│  7. Spawn async task for hardening                                  │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           │ HTTP POST localhost:5001
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PYTHON HARDENING ENGINE - Flask API                               │
├─────────────────────────────────────────────────────────────────────┤
│  POST /apply                                                         │
│  Body: {model_name, target_ip, ssh_key_path, ...}                  │
│                                                                      │
│  1. ModelLoader.load_model(model_name)                              │
│     ├─> Read model.json metadata                                    │
│     ├─> Load all config files (dot notation)                        │
│     └─> Calculate SHA512 hash                                       │
│                                                                      │
│  2. ModelValidator.validate_model(model)                            │
│     ├─> Validate SSH safety (check sshd_config)                     │
│     ├─> Validate iptables (check SSH rule exists)                   │
│     ├─> Validate sysctl syntax                                      │
│     ├─> Validate sudoers syntax                                     │
│     └─> Check for conflicts                                         │
│                                                                      │
│  3. SSHManager.connect(target_ip, ssh_key)                          │
│     └─> Test SSH connection                                         │
│                                                                      │
│  4. Verify OS compatibility                                         │
│     └─> Check /etc/os-release                                       │
│                                                                      │
│  5. Run pre-checks                                                  │
│     └─> Check disk space > 1GB                                      │
│                                                                      │
│  6. BackupManager.create_backup(ssh, model, target_ip)              │
│     ├─> Download existing files from target                         │
│     ├─> Create manifest.json                                        │
│     └─> Create tarball in /opt/microsiem/backups/                   │
│                                                                      │
│  7. Deploy configuration files                                      │
│     For each file in model:                                         │
│       ├─> Upload to /tmp/microsiem_apply/                           │
│       ├─> sudo mv to final location                                 │
│       ├─> sudo chown root:root                                      │
│       └─> sudo chmod 644                                            │
│                                                                      │
│  8. Install/remove packages                                         │
│     ├─> sudo apt-get update                                         │
│     ├─> sudo apt-get install <packages>                             │
│     └─> sudo apt-get remove <packages>                              │
│                                                                      │
│  9. Enable/disable services                                         │
│     ├─> sudo systemctl enable <services>                            │
│     ├─> sudo systemctl start <services>                             │
│     ├─> sudo systemctl stop <services>                              │
│     └─> sudo systemctl disable <services>                           │
│                                                                      │
│  10. Run post-checks                                                │
│      ├─> Verify SSH daemon is active                                │
│      └─> Verify enabled services are running                        │
│                                                                      │
│  11. Return ApplicationResult                                       │
│      └─> success, steps_completed, duration, backup_path            │
│                                                                      │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           │ Return JSON result
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  RUST BACKEND - Update Database                                    │
├─────────────────────────────────────────────────────────────────────┤
│  1. Update hardening_applications record                            │
│     ├─> status: completed (or failed)                               │
│     ├─> steps_completed, steps_failed                               │
│     ├─> result_log, backup_path                                     │
│     └─> completed_at timestamp                                      │
│                                                                      │
│  2. Update target record                                            │
│     ├─> hardening_applied: true                                     │
│     └─> hardening_model_id                                          │
│                                                                      │
│  3. Create audit_log entry                                          │
│     └─> action: hardening_applied                                   │
│                                                                      │
│  4. Broadcast to WebSocket                                          │
│     └─> Send completion notification to UI                          │
│                                                                      │
│  5. Trigger alert (if configured)                                   │
│     └─> Notify admins of hardening change                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**Total Duration**: 90-180 seconds (depends on model complexity)  
**Error Handling**: Automatic rollback on failure  
**Backup**: Always created before changes  
**Audit**: Full audit trail in database  

---

### 3. Integration Sync Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  INTEGRATION SYNC SERVICE (Rust)                                    │
│  Runs every 5 minutes                                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │  SENTINEL CORE SYNC                                      │      │
│  └──────────────────────────────────────────────────────────┘      │
│                                                                      │
│  1. Load all active targets from PostgreSQL                         │
│                                                                      │
│  2. For each target with sentinel_asset_id:                         │
│     └─> GET /api/v1/assets/{id}/vulnerabilities                     │
│     └─> Parse CVE list                                              │
│     └─> Store in PostgreSQL sentinel_vulnerabilities table          │
│     └─> Write to InfluxDB sentinel_vulnerabilities measurement      │
│                                                                      │
│  3. For targets without sentinel_asset_id:                          │
│     └─> Create asset in Sentinel Core                               │
│     └─> POST /api/v1/assets                                         │
│     └─> Store returned asset_id in targets table                    │
│                                                                      │
│  4. Log sync results to integration_sync_logs                       │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │  FIREDOG SYNC                                            │      │
│  └──────────────────────────────────────────────────────────┘      │
│                                                                      │
│  1. GET /api/threats/ (unacknowledged only)                         │
│                                                                      │
│  2. For each threat:                                                │
│     └─> Match destination_ip to MicroSIEM target                    │
│     └─> Store in PostgreSQL firedog_threats table                   │
│     └─> Write to InfluxDB firedog_threats measurement               │
│                                                                      │
│  3. GET /api/targets/{id}/statistics for each target                │
│     └─> Store in InfluxDB firedog_statistics measurement            │
│                                                                      │
│  4. Log sync results                                                │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │  CORRELATION ENGINE                                      │      │
│  └──────────────────────────────────────────────────────────┘      │
│                                                                      │
│  1. Query for targets with BOTH:                                    │
│     ├─> High/critical vulnerabilities (CVSS >= 7.0)                 │
│     └─> Active threats (detected in last 24h, score >= 7.0)         │
│                                                                      │
│  2. For each match:                                                 │
│     ├─> Calculate correlation confidence (0.0-1.0)                  │
│     ├─> Determine risk level (critical/high/medium)                 │
│     ├─> Generate recommended actions                                │
│     ├─> Store in security_correlations table                        │
│     └─> Write to InfluxDB security_correlations measurement         │
│                                                                      │
│  3. Trigger high-priority alerts for critical correlations          │
│                                                                      │
│  4. Optionally auto-block attacker IPs (if configured)              │
│     └─> POST /api/firewall/block to FireDog                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**Frequency**: Every 5 minutes  
**Parallel**: Sentinel Core and FireDog syncs run concurrently  
**Error Handling**: Log errors, continue with next target  
**Rate Limiting**: Respect external API rate limits  

---

### 4. Alert Processing Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  TRIGGER SOURCES                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  • Data Collector (monitoring data)                                 │
│  • Integration Sync (correlations)                                  │
│  • Hardening Application (failures)                                 │
│  • Compliance Checks (failures)                                     │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           │ Call alert_service.trigger_alert()
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  ALERT SERVICE (Rust)                                               │
├─────────────────────────────────────────────────────────────────────┤
│  1. Receive alert trigger                                           │
│     └─> alert_type, severity, target_id, message, details           │
│                                                                      │
│  2. Check cooldown period                                           │
│     └─> Prevent duplicate alerts within 15 minutes                  │
│     └─> Use fingerprint: hash(alert_type + target_id)               │
│                                                                      │
│  3. Check if alert type is enabled in config                        │
│     └─> Query notification_config.alert_triggers                    │
│                                                                      │
│  4. Create alert record in database                                 │
│     └─> INSERT INTO alerts table                                    │
│                                                                      │
│  5. Broadcast to WebSocket clients                                  │
│     └─> Real-time alert notification in UI                          │
│                                                                      │
│  6. Call NotificationService.send_notifications()                   │
│                                                                      │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  NOTIFICATION SERVICE (Rust)                                        │
├─────────────────────────────────────────────────────────────────────┤
│  1. Load notification_config from database                          │
│                                                                      │
│  2. For each enabled channel:                                       │
│                                                                      │
│     ┌───────────────────────────────────────────┐                   │
│     │  EMAIL (if enabled)                       │                   │
│     ├───────────────────────────────────────────┤                   │
│     │  1. Load SMTP config (decrypt password)   │                   │
│     │  2. Format email from template            │                   │
│     │  3. Send via SMTP with TLS                │                   │
│     │  4. Log result to notification_logs        │                   │
│     └───────────────────────────────────────────┘                   │
│                                                                      │
│     ┌───────────────────────────────────────────┐                   │
│     │  SLACK (if enabled)                       │                   │
│     ├───────────────────────────────────────────┤                   │
│     │  1. Format Slack message (blocks format)  │                   │
│     │  2. POST to webhook_url                   │                   │
│     │  3. Log result                             │                   │
│     └───────────────────────────────────────────┘                   │
│                                                                      │
│     ┌───────────────────────────────────────────┐                   │
│     │  DISCORD (if enabled)                     │                   │
│     ├───────────────────────────────────────────┤                   │
│     │  1. Format Discord embed                  │                   │
│     │  2. POST to webhook_url                   │                   │
│     │  3. Log result                             │                   │
│     └───────────────────────────────────────────┘                   │
│                                                                      │
│  3. Update alert record with notification status                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**Alert Types**:
- suspicious_connection
- unexpected_service
- compliance_failure
- hardening_failed
- critical_vulnerability
- high_risk_correlation
- file_integrity_violation

**Cooldown**: 15 minutes (configurable)  
**Deduplication**: Based on fingerprint hash  
**Retry**: 3 attempts for failed notifications  

---

## Security Architecture

### Authentication & Authorization

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHENTICATION FLOW                                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. User submits credentials                                        │
│     └─> POST /api/v1/auth/login                                     │
│     └─> Body: {username, password}                                  │
│                                                                      │
│  2. Backend validates credentials                                   │
│     ├─> Query users table                                           │
│     ├─> Verify password with Argon2                                 │
│     ├─> Check account is active                                     │
│     └─> Check not locked (failed_login_attempts < 5)                │
│                                                                      │
│  3. Generate tokens                                                 │
│     ├─> Access Token (JWT, 30 min expiry)                           │
│     │   └─> Payload: user_id, username, role, permissions, iat, exp │
│     ├─> Refresh Token (random UUID, 7 days)                         │
│     │   └─> Store hash in refresh_tokens table                      │
│     └─> CSRF Token (random, 30 min expiry)                          │
│         └─> Store hash in csrf_tokens table                         │
│                                                                      │
│  4. Update user record                                              │
│     ├─> last_login_at = NOW()                                       │
│     └─> failed_login_attempts = 0                                   │
│                                                                      │
│  5. Return tokens to client                                         │
│     └─> Response: {access_token, refresh_token, csrf_token}         │
│                                                                      │
│  6. Client stores tokens                                            │
│     ├─> access_token: memory (React state)                          │
│     ├─> refresh_token: HttpOnly cookie OR localStorage              │
│     └─> csrf_token: memory                                          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  REQUEST AUTHENTICATION                                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Client sends request with tokens                                │
│     ├─> Authorization: Bearer <access_token>                        │
│     └─> X-CSRF-Token: <csrf_token> (for mutations only)             │
│                                                                      │
│  2. Auth Middleware extracts and validates JWT                      │
│     ├─> Verify signature (HS256 with secret key)                    │
│     ├─> Check expiration (exp claim)                                │
│     ├─> Extract user_id, role, permissions                          │
│     └─> Set in request context                                      │
│                                                                      │
│  3. For mutations (POST/PUT/DELETE):                                │
│     └─> CSRF Middleware validates CSRF token                        │
│         ├─> Check token exists in request                           │
│         ├─> Verify token hash in database                           │
│         ├─> Check not expired                                       │
│         ├─> Mark as used (single-use)                               │
│         └─> Reject if validation fails (403)                        │
│                                                                      │
│  4. Permission check                                                │
│     └─> Verify user has required permission for endpoint            │
│         └─> Reject if insufficient (403)                            │
│                                                                      │
│  5. Rate limit check                                                │
│     └─> Check request count in time window                          │
│         └─> Reject if exceeded (429)                                │
│                                                                      │
│  6. Proceed with request handling                                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  TOKEN REFRESH FLOW                                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Access token expires (after 30 min)                             │
│                                                                      │
│  2. Client detects 401 Unauthorized                                 │
│                                                                      │
│  3. Client sends refresh request                                    │
│     └─> POST /api/v1/auth/refresh                                   │
│     └─> Body: {refresh_token}                                       │
│                                                                      │
│  4. Backend validates refresh token                                 │
│     ├─> Query refresh_tokens table by hash                          │
│     ├─> Check not expired                                           │
│     ├─> Check not revoked                                           │
│     └─> Verify user still exists and active                         │
│                                                                      │
│  5. Generate new access token                                       │
│     └─> Same payload, new iat and exp                               │
│                                                                      │
│  6. Return new access token                                         │
│     └─> Response: {access_token}                                    │
│                                                                      │
│  7. Client stores new access token                                  │
│                                                                      │
│  8. Client retries original request                                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Permission Matrix

| Resource | Action | Admin | User |
|----------|--------|-------|------|
| Targets | Read | ✅ | ✅ |
| Targets | Create | ✅ | ❌ |
| Targets | Update | ✅ | ❌ |
| Targets | Delete | ✅ | ❌ |
| Hardening | Read Models | ✅ | ✅ |
| Hardening | Apply | ✅ | ❌ |
| Hardening | Rollback | ✅ | ❌ |
| Monitoring | Read Data | ✅ | ✅ |
| Compliance | Read Status | ✅ | ✅ |
| Compliance | Trigger Check | ✅ | ❌ |
| Integrations | Read Status | ✅ | ✅ |
| Integrations | Sync/Configure | ✅ | ❌ |
| Alerts | Read | ✅ | ✅ |
| Alerts | Acknowledge | ✅ | ✅ |
| Notifications | Configure | ✅ | ❌ |
| Users | Manage | ✅ | ❌ |
| System Config | Configure | ✅ | ❌ |

---

### Data Encryption

```yaml
At Rest:
  PostgreSQL:
    Passwords: Argon2 (work factor 19)
    SSH Private Keys: Fernet symmetric encryption
    SMTP Password: Fernet encryption
    API Keys: Fernet encryption
    Encryption Key: MICROSIEM_ENCRYPTION_KEY env var
  
  InfluxDB:
    No sensitive data stored
    Metrics are not encrypted
  
  Filesystem:
    SSH private keys: 600 permissions, encrypted
    Backup files: 600 permissions
    Log files: 640 permissions

In Transit:
  External:
    HTTPS: TLS 1.3 only
    Ciphers: Strong ciphers only (ECDHE-RSA-AES256-GCM-SHA384)
    Certificate: Let's Encrypt or custom CA
  
  Internal:
    Backend ↔ PostgreSQL: TLS (sslmode=require)
    Backend ↔ InfluxDB: HTTPS with TLS
    Backend ↔ Python Engine: HTTP localhost (not exposed)
    Backend ↔ External APIs: HTTPS
  
  SSH:
    Protocol: SSH-2 only
    Key Type: Ed25519 (elliptic curve)
    No password authentication
```

---

### Input Validation

```rust
// All inputs validated at multiple layers

// 1. API Layer - Type validation
#[derive(Deserialize, Validate)]
struct CreateTargetRequest {
    #[validate(length(min = 1, max = 100))]
    hostname: String,
    
    #[validate(custom = "validate_ip_address")]
    ip_address: String,
    
    #[validate(range(min = 1, max = 65535))]
    ssh_port: u16,
}

// 2. Service Layer - Business validation
fn validate_ip_address(ip: &str) -> Result<(), ValidationError> {
    match ip.parse::<std::net::IpAddr>() {
        Ok(_) => Ok(()),
        Err(_) => Err(ValidationError::new("invalid_ip")),
    }
}

// 3. Database Layer - Constraints
// - Foreign keys
// - CHECK constraints
// - NOT NULL constraints
```

**Validation Rules**:
- IP Address: Valid IPv4/IPv6, not in reserved ranges
- Hostname: RFC 1123 compliant
- SSH Port: 1-65535
- Model Name: Alphanumeric + underscore, no path traversal
- Email: Valid email format
- Password: Min 12 chars, uppercase, lowercase, number, special char

---

### Security Headers

```yaml
Response Headers:
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  X-XSS-Protection: 1; mode=block
  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: geolocation=(), microphone=(), camera=()
```

---

## Network Architecture

### Port Allocation

```yaml
External (exposed):
  443: HTTPS (Nginx)
  
Internal (localhost only):
  3000: React dev server (development only)
  5001: Python hardening engine
  5432: PostgreSQL
  8080: Rust backend
  8086: InfluxDB

Target Systems:
  22: SSH (Ed25519 only)
```

### Network Diagram

```
Internet
   │
   │ Port 443 (HTTPS)
   │
   ▼
┌──────────────┐
│   Firewall   │
│   (iptables) │
└──────┬───────┘
       │
       │ Only allow 443
       │
       ▼
┌──────────────┐
│    Nginx     │ Listen: 0.0.0.0:443
└──────┬───────┘
       │
       ├─────────────┬─────────────────┬─────────────────┐
       │             │                 │                 │
       │ /           │ /api            │ /ws             │ /metrics
       │             │                 │                 │
       ▼             ▼                 ▼                 ▼
   Static       Rust Backend     WebSocket         Prometheus
   Files        localhost:8080   localhost:8080    (optional)


Internal Network (localhost):

┌──────────────┐
│ Rust Backend │ localhost:8080
└──────┬───────┘
       │
       ├─> PostgreSQL (localhost:5432)
       ├─> InfluxDB (localhost:8086)
       └─> Python Engine (localhost:5001)


Target Network (via SSH):

Rust Backend ─SSH─> Target 1 (192.168.1.10:22)
            └─SSH─> Target 2 (192.168.1.20:22)
            └─SSH─> Target N (192.168.1.x:22)
```

### Firewall Rules (Server)

```bash
# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow HTTPS
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow SSH from management network only
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 22 -j ACCEPT

# Rate limiting for HTTPS
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --update --seconds 1 --hitcount 100 -j DROP

# Drop everything else
iptables -A INPUT -j DROP
```

---

## Deployment Architecture

### Deployment Options

#### Option 1: LXC Container (Recommended)

```yaml
Host OS: Proxmox VE or Debian/Ubuntu
Container OS: Debian 12
Resources:
  CPU: 4 vCores
  RAM: 8 GB
  Disk: 100 GB
  
Advantages:
  - Lightweight (less overhead than VM)
  - Fast startup
  - Easy snapshots and backups
  - Resource efficient
  
Setup:
  pct create 100 local:vztmpl/debian-12-standard_12.0-1_amd64.tar.zst \
    --hostname microsiem \
    --cores 4 \
    --memory 8192 \
    --net0 name=eth0,bridge=vmbr0,ip=dhcp \
    --storage local-lvm \
    --rootfs local-lvm:100
```

#### Option 2: Docker Compose

```yaml
services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
      - ./frontend/dist:/usr/share/nginx/html
  
  backend:
    build: ./backend
    ports:
      - "8080:8080"
    environment:
      DATABASE_URL: postgresql://user:pass@postgres:5432/microsiem
      INFLUXDB_URL: http://influxdb:8086
    depends_on:
      - postgres
      - influxdb
  
  hardening-engine:
    build: ./hardening_engine
    ports:
      - "5001:5001"
    volumes:
      - ./hardening_models:/app/hardening_models
      - ./backups:/opt/microsiem/backups
  
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: microsiem
      POSTGRES_USER: microsiem
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data
  
  influxdb:
    image: influxdb:2.7
    environment:
      DOCKER_INFLUXDB_INIT_MODE: setup
      DOCKER_INFLUXDB_INIT_USERNAME: admin
      DOCKER_INFLUXDB_INIT_PASSWORD: ${INFLUX_PASSWORD}
      DOCKER_INFLUXDB_INIT_ORG: microsiem
      DOCKER_INFLUXDB_INIT_BUCKET: metrics
    volumes:
      - influxdb-data:/var/lib/influxdb2

volumes:
  postgres-data:
  influxdb-data:
```

#### Option 3: VM (KVM/VirtualBox)

```yaml
VM Specs:
  OS: Debian 12
  CPU: 4 cores
  RAM: 8 GB
  Disk: 100 GB
  Network: Bridged
  
Advantages:
  - Complete isolation
  - Full OS control
  - Easier migration
  
Disadvantages:
  - More resource overhead
  - Slower than containers
```

---

### Directory Structure (Production)

```
/opt/microsiem/
├── backend/
│   ├── microsiem-backend         # Rust binary
│   ├── config.toml               # Configuration
│   └── .env                      # Environment variables
│
├── hardening_engine/
│   ├── venv/                     # Python virtualenv
│   ├── app.py
│   ├── models/
│   ├── applier/
│   └── .env
│
├── hardening_models/
│   ├── base/
│   ├── severo/
│   └── custom/
│
├── frontend/
│   └── dist/                     # Built React app
│
├── backups/
│   ├── 192.168.1.10_1732791000/
│   └── 192.168.1.20_1732791100/
│
├── keys/
│   ├── id_ed25519                # SSH private key (encrypted)
│   └── id_ed25519.pub            # SSH public key
│
├── logs/
│   ├── backend.log
│   ├── hardening_engine.log
│   ├── nginx_access.log
│   └── nginx_error.log
│
└── ssl/
    ├── cert.pem
    └── key.pem
```

---

## Performance & Scalability

### Performance Targets

```yaml
Response Times (p95):
  API Endpoints: < 100ms
  Dashboard Load: < 2s
  WebSocket Latency: < 50ms
  
Throughput:
  API Requests: 1000 req/s
  WebSocket Connections: 100 concurrent
  Target Monitoring: 100+ targets
  Data Collection: 30s interval
  
Database Performance:
  PostgreSQL Queries: < 10ms (p95)
  InfluxDB Writes: < 5ms (p95)
  InfluxDB Queries: < 50ms (p95)
```

### Scalability Considerations

**Vertical Scaling**:
- Increase CPU for more concurrent operations
- Increase RAM for larger data sets in memory
- Increase disk for longer data retention

**Horizontal Scaling** (Future):
- Multiple backend instances behind load balancer
- PostgreSQL replication (primary + replica)
- InfluxDB clustering
- Redis for session storage and caching

**Current Limits**:
- Single instance: 100-200 targets
- PostgreSQL: 10M+ rows (with partitioning)
- InfluxDB: TBs of data (with retention policies)

---

## Monitoring & Observability

### Application Metrics

```yaml
Metrics Exposed:
  Endpoint: /metrics (Prometheus format)
  
  Backend Metrics:
    - http_requests_total (counter)
    - http_request_duration_seconds (histogram)
    - active_connections (gauge)
    - database_queries_total (counter)
    - database_query_duration_seconds (histogram)
    - data_collection_duration_seconds (histogram)
    - hardening_applications_total (counter)
    - alerts_triggered_total (counter)
  
  System Metrics:
    - process_cpu_usage
    - process_memory_usage
    - process_open_fds
```

### Logging

```yaml
Log Format: JSON structured logs

Log Levels:
  ERROR: Critical errors requiring immediate attention
  WARN: Warnings that should be reviewed
  INFO: Important events (auth, operations)
  DEBUG: Detailed debugging information (dev only)

Log Destinations:
  stdout: All logs (captured by systemd)
  /opt/microsiem/logs/: Rotating file logs
  Syslog: Optional integration

Log Rotation:
  Size: 100MB per file
  Keep: 7 days
  Compression: gzip
```

### Health Checks

```yaml
Endpoints:
  /health: Basic health check
    Response: {status: "ok", timestamp: "..."}
  
  /health/detailed: Comprehensive health check
    Response:
      status: ok/degraded/error
      components:
        database: ok/error
        influxdb: ok/error
        hardening_engine: ok/error
        integrations: ok/error
```

---

## Summary

### Architecture Highlights

✅ **Microservices** - Rust backend + Python hardening engine  
✅ **Real-time** - WebSocket for live updates  
✅ **Scalable** - Supports 100+ targets per instance  
✅ **Secure** - JWT auth, CSRF, rate limiting, encryption  
✅ **Reliable** - Health checks, error handling, rollback  
✅ **Observable** - Metrics, structured logs, audit trail  
✅ **Extensible** - Plugin system for hardening models  
✅ **Integrated** - Sentinel Core, FireDog APIs  

### Technology Summary

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Backend | Rust + Axum | REST API, WebSocket, business logic |
| Hardening | Python + Flask | Configuration application |
| Frontend | React + TypeScript | User interface |
| Relational DB | PostgreSQL | Metadata, users, configs |
| Time-Series DB | InfluxDB | Metrics, logs, events |
| Web Server | Nginx | Reverse proxy, SSL, static files |
| Target Scripts | Bash | Data collection |
| Integrations | HTTP REST | Sentinel Core, FireDog |

---

**Versione**: 1.0.0  
**Data**: 2025-11-28  
**Autore**: Development Team
