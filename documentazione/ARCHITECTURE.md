# MicroSIEM - Architecture Document

## 📐 System Architecture

### High-Level Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                          EXTERNAL USERS                                │
│                    (Web Browser / Mobile)                              │
└────────────────────────────────┬──────────────────────────────────────┘
                                 │ HTTPS (443)
                                 │ JWT Authentication
                                 ▼
┌───────────────────────────────────────────────────────────────────────┐
│                          NGINX REVERSE PROXY                           │
│                       (SSL/TLS Termination)                            │
└─────────┬────────────────────────────────────────────┬────────────────┘
          │                                             │
          │ /                                           │ /api
          │ (Static Files)                              │ (API Calls)
          ▼                                             ▼
┌──────────────────────┐                    ┌───────────────────────────┐
│  FRONTEND            │                    │  BACKEND                  │
│  React + TypeScript  │◄───────────────────│  Flask + FastAPI          │
│  Port: 3000          │    WebSocket       │  Ports: 5000, 8000        │
│                      │    (Real-time)     │                           │
└──────────────────────┘                    └─────────┬─────────────────┘
                                                      │
                    ┌─────────────────────────────────┼─────────────────┐
                    │                                 │                 │
                    ▼                                 ▼                 ▼
         ┌────────────────────┐          ┌──────────────────┐  ┌──────────────┐
         │   PostgreSQL       │          │   InfluxDB       │  │  SSH Manager │
         │   (Metadata)       │          │   (Time-Series)  │  │  (Paramiko)  │
         │   Port: 5432       │          │   Port: 8086     │  └──────┬───────┘
         └────────────────────┘          └──────────────────┘         │
                                                                       │ SSH (22)
                                                                       │ SCP
                                                                       ▼
                                                    ┌─────────────────────────┐
                                                    │  TARGET SYSTEMS         │
                                                    │  (Debian/Ubuntu)        │
                                                    │  User: microsiem        │
                                                    │  Cron: monitoring.sh    │
                                                    └─────────────────────────┘
```

---

## 🔧 Component Details

### 1. Frontend Layer (React + TypeScript)

#### Technology Stack
```json
{
  "framework": "React 18.2+",
  "language": "TypeScript 5.x",
  "build": "Vite 5.x",
  "state": "TanStack Query (React Query)",
  "routing": "React Router v6",
  "ui": "shadcn/ui + Tailwind CSS",
  "charts": "Recharts",
  "forms": "React Hook Form + Zod",
  "http": "Axios",
  "websocket": "Socket.IO Client"
}
```

#### Main Components
```
frontend/src/
├── components/
│   ├── auth/
│   │   ├── LoginForm.tsx
│   │   └── ProtectedRoute.tsx
│   ├── dashboard/
│   │   ├── DashboardGrid.tsx
│   │   ├── WidgetCard.tsx
│   │   └── ChartComponents/
│   ├── machines/
│   │   ├── MachineList.tsx
│   │   ├── MachineCard.tsx
│   │   ├── AddMachineModal.tsx
│   │   └── MachineDetails.tsx
│   ├── hardening/
│   │   ├── ModelSelector.tsx
│   │   ├── ModelEditor.tsx
│   │   └── ApplyHardeningModal.tsx
│   ├── monitoring/
│   │   ├── LiveConnectionsTable.tsx
│   │   ├── UserActivityLog.tsx
│   │   └── ServiceStatusList.tsx
│   ├── alerts/
│   │   ├── AlertsPanel.tsx
│   │   ├── AlertConfiguration.tsx
│   │   └── TestAlertButton.tsx
│   └── settings/
│       ├── UserManagement.tsx
│       ├── SSHKeyManager.tsx
│       └── SystemConfiguration.tsx
│
├── pages/
│   ├── Dashboard.tsx
│   ├── Machines.tsx
│   ├── Hardening.tsx
│   ├── Monitoring.tsx
│   ├── Compliance.tsx
│   ├── Alerts.tsx
│   └── Settings.tsx
│
├── services/
│   ├── api.ts              # Axios instance with interceptors
│   ├── auth.service.ts     # Login, logout, token refresh
│   ├── machines.service.ts # CRUD for machines
│   ├── hardening.service.ts
│   ├── monitoring.service.ts
│   └── websocket.service.ts
│
├── hooks/
│   ├── useAuth.ts
│   ├── useMachines.ts
│   ├── useRealTimeData.ts
│   └── usePermissions.ts
│
├── types/
│   ├── auth.types.ts
│   ├── machine.types.ts
│   ├── hardening.types.ts
│   ├── monitoring.types.ts
│   └── api.types.ts
│
└── utils/
    ├── dateFormatter.ts
    ├── validators.ts
    └── constants.ts
```

#### State Management Strategy
- **TanStack Query**: Server state (API data, caching, refetching)
- **React Context**: Auth state, user preferences
- **Local State**: Component-specific state (forms, modals)

---

### 2. Backend Layer (Flask + FastAPI)

#### Why Both Flask and FastAPI?

**Flask** (Port 5000):
- Authentication & session management
- Admin operations
- File uploads
- Template rendering (if needed)
- Traditional request-response patterns

**FastAPI** (Port 8000):
- RESTful API endpoints
- WebSocket for real-time updates
- Async operations (SSH, database writes)
- Auto-generated OpenAPI docs
- High-performance data streaming

#### Project Structure
```
backend/
├── app/
│   ├── __init__.py
│   ├── config.py              # Configuration management
│   │
│   ├── flask_app.py           # Flask application
│   ├── main.py                # FastAPI application
│   │
│   ├── models/                # SQLAlchemy models (PostgreSQL)
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── machine.py
│   │   ├── hardening_model.py
│   │   ├── alert_config.py
│   │   └── audit_log.py
│   │
│   ├── schemas/               # Pydantic schemas
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── machine.py
│   │   ├── hardening.py
│   │   ├── monitoring.py
│   │   └── response.py
│   │
│   ├── api/                   # FastAPI routes
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── machines.py
│   │   ├── hardening.py
│   │   ├── monitoring.py
│   │   ├── compliance.py
│   │   ├── alerts.py
│   │   └── websocket.py
│   │
│   ├── services/              # Business logic
│   │   ├── __init__.py
│   │   ├── auth_service.py
│   │   ├── ssh_service.py
│   │   ├── hardening_service.py
│   │   ├── monitoring_service.py
│   │   ├── alert_service.py
│   │   └── compliance_service.py
│   │
│   ├── database/              # Database connection
│   │   ├── __init__.py
│   │   ├── postgres.py        # PostgreSQL connection
│   │   └── influxdb.py        # InfluxDB connection
│   │
│   ├── auth/                  # Authentication & authorization
│   │   ├── __init__.py
│   │   ├── jwt_handler.py
│   │   ├── permissions.py
│   │   └── decorators.py
│   │
│   └── utils/                 # Utilities
│       ├── __init__.py
│       ├── validators.py
│       ├── parsers.py
│       ├── hash_utils.py
│       └── logger.py
│
├── requirements.txt
└── alembic/                   # Database migrations
    ├── versions/
    └── env.py
```

#### Key Services

**SSHService** (`services/ssh_service.py`):
```python
class SSHService:
    def connect(host, port, username, key_path) -> SSHClient
    def execute_command(client, command) -> (stdout, stderr, exit_code)
    def upload_file(client, local_path, remote_path) -> bool
    def download_file(client, remote_path, local_path) -> bool
    def setup_cron(client, interval, script_path) -> bool
    def apply_hardening(client, model_config) -> Result
```

**MonitoringService** (`services/monitoring_service.py`):
```python
class MonitoringService:
    def fetch_data_from_target(machine_id) -> JSONData
    def parse_json(json_file) -> ParsedData
    def write_to_influxdb(parsed_data) -> bool
    def write_to_postgres(events) -> bool
    def get_latest_metrics(machine_id, time_range) -> Metrics
```

**HardeningService** (`services/hardening_service.py`):
```python
class HardeningService:
    def get_model(role, compliance, level) -> HardeningModel
    def validate_model(model) -> ValidationResult
    def apply_model(machine_id, model_id) -> ApplyResult
    def rollback(machine_id, snapshot_id) -> bool
    def test_model(test_machine_id, model_id) -> TestResult
```

---

### 3. Database Layer

#### PostgreSQL Schema

**Tables**:

```sql
-- Users
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('sysadmin', 'reporter')),
    created_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Machines
CREATE TABLE machines (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    ip_address INET NOT NULL,
    role VARCHAR(50), -- web, db, dns, gateway
    compliance_standard VARCHAR(50), -- nis2, pci, iso
    ssh_port INTEGER DEFAULT 22,
    status VARCHAR(20) DEFAULT 'pending', -- pending, active, error, offline
    last_seen TIMESTAMP,
    added_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Hardening Models
CREATE TABLE hardening_models (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    role VARCHAR(50),
    compliance_standard VARCHAR(50),
    level VARCHAR(20) CHECK (level IN ('base', 'severo')),
    config_json JSONB NOT NULL,
    hash_sha512 VARCHAR(128) NOT NULL,
    version INTEGER DEFAULT 1,
    is_active BOOLEAN DEFAULT TRUE,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Applied Hardening
CREATE TABLE applied_hardening (
    id SERIAL PRIMARY KEY,
    machine_id INTEGER REFERENCES machines(id) ON DELETE CASCADE,
    model_id INTEGER REFERENCES hardening_models(id),
    applied_at TIMESTAMP DEFAULT NOW(),
    applied_by INTEGER REFERENCES users(id),
    status VARCHAR(20), -- success, failed, partial
    result_log TEXT,
    rollback_available BOOLEAN DEFAULT FALSE
);

-- Alert Configurations
CREATE TABLE alert_configs (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(20) NOT NULL CHECK (type IN ('email', 'slack', 'telegram', 'whatsapp')),
    config_json JSONB NOT NULL, -- recipient, webhook URL, etc.
    triggers JSONB NOT NULL, -- conditions that trigger alert
    is_active BOOLEAN DEFAULT TRUE,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Audit Logs
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INTEGER,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT NOW()
);

-- SSH Keys
CREATE TABLE ssh_keys (
    id SERIAL PRIMARY KEY,
    machine_id INTEGER REFERENCES machines(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    private_key_path VARCHAR(255) NOT NULL,
    key_type VARCHAR(20) DEFAULT 'ed25519',
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    rotation_days INTEGER DEFAULT 90
);

-- Compliance Checks
CREATE TABLE compliance_checks (
    id SERIAL PRIMARY KEY,
    machine_id INTEGER REFERENCES machines(id) ON DELETE CASCADE,
    standard VARCHAR(50) NOT NULL,
    check_name VARCHAR(100) NOT NULL,
    status VARCHAR(20) CHECK (status IN ('pass', 'fail', 'warning')),
    details TEXT,
    checked_at TIMESTAMP DEFAULT NOW()
);
```

#### InfluxDB Schema

**Buckets**:
- `metrics` (30 days retention)
- `logs` (90 days retention)

**Measurements**:

```flux
// System Metrics
measurement: "system_metrics"
tags: {
    hostname: string,
    ip_address: string,
    role: string
}
fields: {
    cpu_usage: float,
    memory_usage: float,
    disk_usage: float,
    load_average: float
}

// Hardening Status
measurement: "hardening_status"
tags: {
    hostname: string,
    model: string,
    compliance: string
}
fields: {
    score: int,
    is_compliant: boolean
}

// Connections
measurement: "connections"
tags: {
    hostname: string,
    protocol: string,
    state: string
}
fields: {
    count: int,
    suspicious: boolean
}

// User Activity
measurement: "user_activity"
tags: {
    hostname: string,
    username: string,
    activity_type: string
}
fields: {
    command: string,
    suspicious: boolean
}

// Services
measurement: "services"
tags: {
    hostname: string,
    service_name: string,
    state: string
}
fields: {
    expected: boolean,
    alert_triggered: boolean
}

// Vulnerabilities
measurement: "vulnerabilities"
tags: {
    hostname: string,
    package_name: string,
    severity: string
}
fields: {
    cve_id: string,
    fix_available: boolean
}
```

---

### 4. Monitoring & Collection Flow

#### Data Collection Architecture

```
┌─────────────────────────────────────────────────┐
│         TARGET SYSTEM (Debian/Ubuntu)           │
├─────────────────────────────────────────────────┤
│                                                  │
│  Cron Job (every 30s):                          │
│  */0.5 * * * * /opt/microsiem/monitoring.sh     │
│                                                  │
│  monitoring.sh (orchestrator)                   │
│  ├─ collectors/hardening.sh &                   │
│  ├─ collectors/connections.sh &                 │
│  ├─ collectors/users.sh &                       │
│  ├─ collectors/services.sh &                    │
│  ├─ collectors/packages.sh &                    │
│  ├─ collectors/files.sh &                       │
│  └─ collectors/auditd.sh &                      │
│                                                  │
│  wait (all background jobs complete)            │
│                                                  │
│  aggregate_json.py                              │
│  └─> /tmp/microsiem_<timestamp>.json            │
│                                                  │
└──────────────────┬──────────────────────────────┘
                   │
                   │ SCP Pull (server initiates)
                   ▼
┌─────────────────────────────────────────────────┐
│          MICROSIEM SERVER                        │
├─────────────────────────────────────────────────┤
│                                                  │
│  1. SSH/SCP fetch JSON files                    │
│     for machine in machines:                    │
│         scp microsiem@{ip}:/tmp/microsiem_*.json│
│                                                  │
│  2. Parse JSON                                  │
│     parsed_data = json.load(file)               │
│                                                  │
│  3. Write to Databases                          │
│     ├─ InfluxDB: write_points(metrics)          │
│     └─ PostgreSQL: insert_events(events)        │
│                                                  │
│  4. Check Alert Rules                           │
│     if alert_triggered:                         │
│         send_alert(config, data)                │
│                                                  │
│  5. Update WebSocket                            │
│     websocket.broadcast(real_time_data)         │
│                                                  │
│  6. Cleanup                                     │
│     remove_old_files()                          │
│     apply_retention_policy()                    │
│                                                  │
└─────────────────────────────────────────────────┘
```

#### Asynchronous Collection

**Target Script** (`monitoring.sh`):
```bash
#!/bin/bash
# Asynchronous data collection

TIMESTAMP=$(date +%s)
OUTPUT_DIR="/tmp/microsiem_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

# Launch all collectors in parallel
/opt/microsiem/collectors/hardening.sh > "$OUTPUT_DIR/hardening.json" &
/opt/microsiem/collectors/connections.sh > "$OUTPUT_DIR/connections.json" &
/opt/microsiem/collectors/users.sh > "$OUTPUT_DIR/users.json" &
/opt/microsiem/collectors/services.sh > "$OUTPUT_DIR/services.json" &
/opt/microsiem/collectors/packages.sh > "$OUTPUT_DIR/packages.json" &
/opt/microsiem/collectors/files.sh > "$OUTPUT_DIR/files.json" &
/opt/microsiem/collectors/auditd.sh > "$OUTPUT_DIR/auditd.json" &

# Wait for all background jobs
wait

# Aggregate into single JSON
python3 /opt/microsiem/aggregate_json.py "$OUTPUT_DIR" > "/tmp/microsiem_${TIMESTAMP}.json"

# Cleanup intermediate files
rm -rf "$OUTPUT_DIR"

# Keep only last 5 JSON files
ls -t /tmp/microsiem_*.json | tail -n +6 | xargs -r rm
```

---

### 5. Security Architecture

#### Authentication Flow

```
┌──────────┐                                              ┌─────────┐
│  Client  │                                              │ Backend │
└────┬─────┘                                              └────┬────┘
     │                                                          │
     │  POST /api/auth/login                                   │
     │  { username, password }                                 │
     ├─────────────────────────────────────────────────────────>
     │                                                          │
     │                                     Validate credentials │
     │                                     Generate JWT token   │
     │                                                          │
     │  200 OK                                                  │
     │  { token, user, expires_in }                            │
     <─────────────────────────────────────────────────────────┤
     │                                                          │
     │  Store token in memory/localStorage                     │
     │                                                          │
     │  GET /api/machines                                      │
     │  Authorization: Bearer <token>                          │
     ├─────────────────────────────────────────────────────────>
     │                                                          │
     │                                         Verify JWT       │
     │                                         Check permissions│
     │                                                          │
     │  200 OK                                                  │
     │  { machines: [...] }                                    │
     <─────────────────────────────────────────────────────────┤
     │                                                          │
```

#### JWT Token Structure

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user_id",
    "username": "admin",
    "role": "sysadmin",
    "permissions": ["read", "write", "delete", "manage_users"],
    "iat": 1698765432,
    "exp": 1698851832
  },
  "signature": "..."
}
```

#### Authorization Levels

| Endpoint | Sysadmin | Reporter |
|----------|----------|----------|
| GET /api/machines | ✅ | ✅ |
| POST /api/machines | ✅ | ❌ |
| DELETE /api/machines/:id | ✅ | ❌ |
| POST /api/hardening/apply | ✅ | ❌ |
| GET /api/monitoring/data | ✅ | ✅ |
| POST /api/dashboards | ✅ | ✅ |
| POST /api/users | ✅ | ❌ |
| GET /api/reports | ✅ | ✅ |

---

### 6. Real-Time Communication

#### WebSocket Architecture

```
Client                          FastAPI Server
  │                                   │
  │  WS Connect: /ws                  │
  ├──────────────────────────────────>│
  │                                   │
  │  Subscribe: machine_metrics       │
  ├──────────────────────────────────>│
  │                                   │
  │                     Add to subscribers
  │                                   │
  │  ◄────── New Data ──────          │
  │  {                                │
  │    "type": "metrics",             │
  │    "machine": "web-01",           │
  │    "data": {...}                  │
  │  }                                │
  │                                   │
  │  Unsubscribe: machine_metrics     │
  ├──────────────────────────────────>│
  │                                   │
  │  WS Disconnect                    │
  ├──────────────────────────────────>│
```

**Implementation** (`backend/app/api/websocket.py`):
```python
from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict, Set

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, topic: str):
        await websocket.accept()
        if topic not in self.active_connections:
            self.active_connections[topic] = set()
        self.active_connections[topic].add(websocket)
    
    def disconnect(self, websocket: WebSocket, topic: str):
        self.active_connections[topic].discard(websocket)
    
    async def broadcast(self, topic: str, message: dict):
        if topic in self.active_connections:
            for connection in self.active_connections[topic]:
                await connection.send_json(message)
```

---

### 7. Deployment Architecture

#### Container Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Host (cybersheppard)               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐           │
│  │  nginx     │  │  frontend  │  │  backend   │           │
│  │  :80, :443 │  │  :3000     │  │  :5000     │           │
│  └─────┬──────┘  └──────┬─────┘  └──────┬─────┘           │
│        │                │                │                  │
│        └────────────────┴────────────────┘                  │
│                         │                                   │
│  ┌──────────────────────┴──────────────────────┐           │
│  │                                              │           │
│  │  ┌────────────┐              ┌────────────┐ │           │
│  │  │ PostgreSQL │              │  InfluxDB  │ │           │
│  │  │  :5432     │              │   :8086    │ │           │
│  │  └────────────┘              └────────────┘ │           │
│  │                                              │           │
│  │  Docker Network: microsiem_network          │           │
│  └──────────────────────────────────────────────┘           │
│                                                              │
│  Volumes:                                                   │
│  - postgres_data                                            │
│  - influxdb_data                                            │
│  - ssh_keys                                                 │
│  - logs                                                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### Network Flow

```
Internet
   │
   │ :443 (HTTPS)
   ▼
┌─────────────┐
│   Nginx     │
│  (Port 443) │
└──────┬──────┘
       │
       ├─ /          → frontend:3000 (static files)
       ├─ /api       → backend:8000 (FastAPI)
       ├─ /auth      → backend:5000 (Flask)
       └─ /ws        → backend:8000 (WebSocket)
```

---

## 🔄 Data Flow Diagrams

### Hardening Application Flow

```
User Action → Frontend → Backend → Target System

1. User selects machine + hardening model
2. Frontend: POST /api/hardening/apply
3. Backend:
   a. Validate user permissions (sysadmin only)
   b. Fetch hardening model from PostgreSQL
   c. Validate model integrity (SHA512 hash)
   d. SSH connect to target
   e. Create backup/snapshot
   f. Apply configurations:
      - sysctl.conf
      - AppArmor/SELinux profiles
      - iptables rules
      - systemd service configs
      - sudoers file
   g. Verify application (run validation checks)
   h. Log to audit_logs table
   i. Update applied_hardening table
4. Frontend: Receive result, display status
5. Real-time update via WebSocket
```

### Monitoring Data Flow

```
Target System → Server → Databases → Frontend

1. Target: Cron executes monitoring.sh (every 30s)
2. Target: Collectors run in parallel, output JSON
3. Target: Aggregate JSON file created
4. Server: SCP fetch JSON file
5. Server: Parse JSON
6. Server: Write to databases:
   - InfluxDB: Time-series metrics
   - PostgreSQL: Events, alerts
7. Server: Evaluate alert rules
8. Server: If alert triggered → send notification
9. Server: Broadcast via WebSocket to connected clients
10. Frontend: Receive real-time update, update dashboards
```

---

## 🔐 Security Controls

### Input Validation
- All API inputs validated with Pydantic schemas
- SQL injection prevention: SQLAlchemy ORM, parameterized queries
- XSS prevention: React auto-escaping + CSP headers
- Command injection prevention: Parameterized SSH commands

### Network Security
- TLS 1.3 only (no older protocols)
- SSH key-based auth only (no passwords)
- Firewall rules on server (restrict to necessary ports)
- Internal Docker network isolation

### Data Protection
- JWT tokens: Short expiration (24h)
- Passwords: bcrypt with high work factor
- SSH private keys: Encrypted at rest
- Database connections: TLS encrypted
- Secrets: Environment variables (never in code)

### Audit Logging
- All user actions logged to `audit_logs` table
- Failed authentication attempts logged
- Configuration changes logged with full details
- Log retention: 1 year minimum

---

## 📊 Performance Considerations

### Scalability Targets
- Support 100+ target machines
- 30-second data collection interval
- <5 second dashboard load time
- <100ms API response time (p95)

### Optimization Strategies
- Database indexing on frequently queried fields
- InfluxDB downsampling for historical data
- Frontend: React.memo, lazy loading, code splitting
- Backend: Async operations, connection pooling
- Caching: Redis (future enhancement)

### Monitoring
- Prometheus metrics endpoint
- Grafana for infrastructure monitoring
- Health checks for all services
- Alerting on service degradation

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-10-30  
**Maintained By**: Development Team
