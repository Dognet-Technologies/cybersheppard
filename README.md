# CyberSheppard (MicroSIEM)

**Linux Hardening & Behavioral Compliance Monitoring System**

CyberSheppard is a comprehensive security platform that combines automated Linux hardening with real-time behavioral compliance monitoring.

---

## 🎯 Key Features

- ✅ **Automated Linux Hardening** (SSH, auditd, sysctl)
- ✅ **Real-time Compliance Monitoring** (16+ policies)
- ✅ **Multi-Channel Notifications** (Email, Slack, Discord)
- ✅ **Security Integrations** (Sentinel Core, FireDog)
- ✅ **Modern React Dashboard**
- ✅ **InfluxDB Time-Series Storage**
- ✅ **Automated Violation Tracking**

---

## 🏗️ Architecture

Target Servers → Collector Scripts → Rust API → PostgreSQL + InfluxDB
                                        ↓
                            Compliance Engine (Real-time)
                                        ↓
                            Notifications (Email/Slack/Discord)
                                        ↓
                            React Dashboard

---

## 📁 Project Structure

cybersheppard/
├── backend-rust/          # Rust Axum API
├── backend-django/        # Django hardening engine
├── frontend-react/        # React dashboard
├── database/             # PostgreSQL migrations
├── hardening-models/     # YAML security profiles
├── scripts/              # Deployment scripts & collectors
└── docs/                 # Full documentation

---

## 📚 Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [API Documentation](docs/API_CONTRACT.md)
- [Database Schema](docs/DATABASE_SCHEMA.md)
- [Hardening Guide](docs/HARDENING_SPEC.md)

---

**© 2025 Dognet Technologies**
