# 🛡️ CyberSheppard (MicroSIEM)

**Sistema SIEM completo per hardening automatico e monitoring continuo di sistemi Linux**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![Django](https://img.shields.io/badge/Django-5.0-green.svg)](https://www.djangoproject.com/)
[![React](https://img.shields.io/badge/React-18-blue.svg)](https://reactjs.org/)

---

## 📋 Panoramica

**CyberSheppard** è un micro-SIEM (Security Information and Event Management) che combina:

1. **🔒 Hardening Automatico** - Applica modelli di hardenizzazione pre-configurati (base/severo)
2. **📊 Monitoring Continuo** - Monitora syscall, auditd, sudolog, connessioni, servizi (strumenti nativi Linux)
3. **🔌 Integrazione** - Si integra con Sentinel Core (vulnerability management) e FireDog (firewall management)
4. **⚡ Correlazione Avanzata** - Correla vulnerabilità e minacce per alert critici in tempo reale

---

## 🏗️ Architettura

```
┌────────────────────────────────────────────────────────────┐
│  CYBERSHEPPARD (MicroSIEM)                                 │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  React Frontend ────► Rust Backend (Axum)                  │
│    (Port 5173)        (Port 8080)                          │
│                       │                                     │
│                       ├─► PostgreSQL (metadata)            │
│                       ├─► InfluxDB (time-series)           │
│                       └─► Django Backend (Port 8001)       │
│                           └─► SSH to Targets               │
│                                                             │
│  Integrations:                                             │
│  ├─► Sentinel Core API (vulnerabilities/CVE)              │
│  └─► FireDog API (threats/firewall)                       │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

### Stack Tecnologico

| Componente | Tecnologia | Scopo |
|------------|------------|-------|
| **Frontend** | React 18 + TypeScript + Vite | Dashboard, UI |
| **Backend API** | Rust (Axum) | REST API, autenticazione, correlazioni |
| **Hardening Engine** | Django (Python) | SSH, applicazione modelli, rollback |
| **Database Metadata** | PostgreSQL 16 | Users, targets, hardening models |
| **Database Time-Series** | InfluxDB 2.7 | Metriche, log, eventi sicurezza |
| **Target Scripts** | Bash | Collectors auditd, sudolog, netstat, etc. |

---

## 🚀 Quick Start

### Prerequisiti

- **Docker** >= 24.0
- **Docker Compose** >= 2.20
- **Rust** >= 1.75 (per sviluppo locale)
- **Node.js** >= 20 (per sviluppo frontend)
- **Python** >= 3.11 (per Django backend)

### Setup Completo con Docker

1. **Clone repository**
   ```bash
   git clone https://github.com/Dognet-Technologies/cybersheppard.git
   cd cybersheppard
   ```

2. **Configura environment**
   ```bash
   cp .env.example .env
   # Modifica .env con le tue credenziali
   nano .env
   ```

3. **Avvia tutti i servizi**
   ```bash
   docker-compose up -d
   ```

4. **Verifica stato servizi**
   ```bash
   docker-compose ps
   ```

5. **Accedi al sistema**
   - Frontend: http://localhost:5173
   - Rust API: http://localhost:8080
   - Django API: http://localhost:8001
   - InfluxDB UI: http://localhost:8086

### Setup Sviluppo Locale

#### Rust Backend

```bash
cd backend-rust
cargo build --release
cargo run
```

#### Django Backend

```bash
cd backend-django
python -m venv venv
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver 0.0.0.0:8001
```

#### Frontend

```bash
cd frontend
npm install
npm run dev
```

---

## 📚 Documentazione

- [**Architettura Completa**](documentazione/ARCHITECTURE.md) - Diagrammi e flussi dati
- [**Specifiche Hardening**](documentazione/HARDENING_SPEC.md) - Sistema hardening engine
- [**Modelli Hardening**](documentazione/HARDENING_MODELS.md) - Struttura modelli
- [**Integrazioni**](documentazione/INTEGRATION_SPEC.md) - Sentinel Core & FireDog
- [**Database Schema**](documentazione/DATABASE_SCHEMA.md) - PostgreSQL + InfluxDB
- [**Code Reuse Map**](documentazione/CODE_REUSE_MAP.md) - Codice riutilizzato

---

## 🔒 Modelli di Hardening

CyberSheppard include modelli pre-configurati per diversi tipi di server:

### Livelli di Hardening

- **Base** - Sicurezza bilanciata (compatibilità + sicurezza)
- **Severo** - Massima sicurezza (zero-trust, minimo privilegi)

### Ruoli Server

| Ruolo | Compliance | Esempi |
|-------|-----------|--------|
| `web_generic` | NIS2, PCI-DSS | Nginx, Apache |
| `database_generic` | PCI-DSS | PostgreSQL, MySQL |
| `dns_generic` | NIS2 | BIND, Unbound |
| `gateway_generic` | NIS2 | Router, Firewall |
| `storage_generic` | - | NFS, Samba |
| `generic` | - | Server generico |

### Struttura Modelli

```
hardening-models/
├── base/
│   ├── web_generic/
│   │   ├── etc.ssh.sshd_config
│   │   ├── etc.auditd.audit.rules
│   │   ├── etc.sysctl.conf
│   │   └── model.yaml
│   └── ...
└── severo/
    ├── web_generic/
    │   └── ...
    └── ...
```

---

## 📊 Monitoring

### Collectors Nativi Linux

Ogni target esegue script bash ogni **30 secondi** che raccolgono:

| Collector | Dati Raccolti | Strumenti |
|-----------|---------------|-----------|
| `auditd.sh` | Eventi audit daemon | `ausearch`, `aureport` |
| `sudolog.sh` | Comandi sudo | `/var/log/auth.log` |
| `connections.sh` | Connessioni attive | `netstat`, `ss`, `lsof` |
| `users.sh` | Utenti connessi | `who`, `w`, `last` |
| `services.sh` | Stato servizi | `systemctl`, `pidof` |
| `files.sh` | Integrità file | `sha256sum`, `sha512sum` |
| `syscalls.sh` | System calls | `strace` (opzionale) |
| `packages.sh` | Pacchetti vulnerabili | `dpkg`, `apt` |

Output aggregato in JSON → trasferito via SCP al backend

---

## 🔌 Integrazioni

### Sentinel Core (Vulnerability Management)

- Sincronizzazione vulnerabilità CVE
- Asset management
- Vulnerability scanning
- EPSS scoring

**Endpoint**: `GET /api/v1/vulnerabilities`, `POST /api/v1/scans`

### FireDog (Firewall Management)

- Sincronizzazione minacce
- Statistiche firewall
- Auto-blocking IP
- Threat correlation

**Endpoint**: `GET /api/threats/`, `POST /api/firewall/block/`

---

## 🗄️ Database

### PostgreSQL (Metadata)

- **20 tabelle** - Users, targets, hardening models, compliance, etc.
- **Migrations** - Versionate con SQLx
- **Backup** - Automatico ogni 24h

### InfluxDB (Time-Series)

- **14 measurements** - Metrics, logs, events, correlations
- **Retention**: 30d (metrics), 90d (logs), 365d (correlations)
- **Downsampling** - Aggregazione automatica

---

## 🔐 Sicurezza

- **JWT** - Access token (30 min) + Refresh token (7 giorni)
- **CSRF** - Synchronizer Token Pattern
- **Argon2** - Password hashing
- **Ed25519** - SSH keys (rotazione 90 giorni)
- **Fernet** - Encryption for passwords/keys
- **Rate Limiting** - 100 req/min per IP

---

## 🛠️ API Endpoints

### Autenticazione

```
POST   /api/auth/register          - Registrazione utente
POST   /api/auth/login             - Login (JWT + refresh token)
POST   /api/auth/refresh           - Refresh access token
POST   /api/auth/logout            - Logout (revoke tokens)
GET    /api/auth/csrf              - Get CSRF token
```

### Targets

```
GET    /api/targets                - Lista targets
POST   /api/targets                - Aggiungi target
GET    /api/targets/{id}           - Dettaglio target
PUT    /api/targets/{id}           - Aggiorna target
DELETE /api/targets/{id}           - Elimina target
GET    /api/targets/{id}/status    - Stato monitoring
```

### Hardening

```
GET    /api/hardening/models       - Lista modelli hardening
POST   /api/hardening/apply        - Applica hardening a target
GET    /api/hardening/history      - Storico applicazioni
POST   /api/hardening/rollback     - Rollback hardening
```

### Monitoring

```
GET    /api/monitoring/metrics     - Metriche real-time (InfluxDB)
GET    /api/monitoring/events      - Eventi sicurezza
GET    /api/monitoring/logs        - Log aggregati
WS     /ws/monitoring/{target_id}  - WebSocket streaming
```

### Compliance

```
GET    /api/compliance/checks      - Compliance checks
POST   /api/compliance/report      - Genera report
GET    /api/compliance/standards   - Standard disponibili (NIS2, PCI, ISO27001)
```

---

## 🧪 Testing

```bash
# Backend Rust
cd backend-rust
cargo test

# Backend Django
cd backend-django
pytest

# Frontend
cd frontend
npm test
```

---

## 📦 Deployment Produzione

### Con Docker (consigliato)

```bash
# Build production images
docker-compose -f docker-compose.prod.yml build

# Start services
docker-compose -f docker-compose.prod.yml up -d

# Run migrations
docker-compose exec rust-backend ./migrate.sh
docker-compose exec django-backend python manage.py migrate
```

### Manuale

Vedi [documentazione/DEPLOYMENT.md](documentazione/DEPLOYMENT.md)

---

## 🤝 Contribuire

Contribuzioni benvenute! Vedi [CONTRIBUTING.md](CONTRIBUTING.md) per guidelines.

1. Fork il progetto
2. Crea branch feature (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push al branch (`git push origin feature/AmazingFeature`)
5. Apri Pull Request

---

## 📄 Licenza

Questo progetto è rilasciato sotto licenza **MIT**. Vedi [LICENSE](LICENSE) per dettagli.

---

## 🙏 Credits

Sviluppato da **Dognet Technologies** - 2025

Integra codice riutilizzato da:
- [Sentinel Core](https://github.com/Dognet-Technologies/sentinel-core) - Vulnerability Management
- [FireDog](https://github.com/Dognet-Technologies/firedog) - Firewall Management

---

## 📞 Supporto

- **Issues**: [GitHub Issues](https://github.com/Dognet-Technologies/cybersheppard/issues)
- **Email**: support@dognet.tech
- **Documentazione**: [docs/](documentazione/)

---

**⚡ CyberSheppard - Hardening & Monitoring Made Simple**
