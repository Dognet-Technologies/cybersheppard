#!/bin/bash

# CyberSheppard (MicroSIEM) - Complete Project Structure Setup
# Architecture: Rust (Axum) + Django + React TypeScript + PostgreSQL + InfluxDB

set -e

echo "🚀 Creating CyberSheppard (MicroSIEM) project structure..."
echo ""

# ============================================================================
# RUST BACKEND (Axum)
# ============================================================================
echo "📦 Creating Rust backend structure..."
mkdir -p backend-rust/src/{api,middleware,services,models,db,integrations,utils}
mkdir -p backend-rust/src/api/{auth,targets,hardening,monitoring,compliance,settings,integrations}
mkdir -p backend-rust/src/middleware
mkdir -p backend-rust/src/services/{hardening,monitoring,correlation,notification}
mkdir -p backend-rust/src/models
mkdir -p backend-rust/src/db/{postgresql,influxdb}
mkdir -p backend-rust/src/integrations/{sentinel_core,firedog}
mkdir -p backend-rust/migrations

# ============================================================================
# DJANGO BACKEND (Hardening Engine)
# ============================================================================
echo "🐍 Creating Django hardening engine structure..."
mkdir -p backend-django/hardening_engine/{settings,api,ssh,models_loader,applier,validators}
mkdir -p backend-django/hardening_engine/management/commands
mkdir -p backend-django/hardening_engine/migrations
mkdir -p backend-django/notifications
mkdir -p backend-django/integrations

# ============================================================================
# HARDENING MODELS (File-based)
# ============================================================================
echo "🔒 Creating hardening models structure..."
mkdir -p hardening-models/{base,severo}

# Base level models
mkdir -p hardening-models/base/{web_generic,web_nis2,web_pci}
mkdir -p hardening-models/base/{database_generic,database_pci}
mkdir -p hardening-models/base/{dns_generic,gateway_generic,storage_generic,generic}

# Severo level models
mkdir -p hardening-models/severo/{web_generic,web_nis2,web_pci}
mkdir -p hardening-models/severo/{database_generic,database_pci}
mkdir -p hardening-models/severo/{dns_generic,gateway_generic,storage_generic,generic}

# ============================================================================
# TARGET MONITORING SCRIPTS (Bash)
# ============================================================================
echo "📊 Creating monitoring scripts structure..."
mkdir -p target-scripts/collectors
mkdir -p target-scripts/libs
mkdir -p target-scripts/config

# ============================================================================
# FRONTEND (React + TypeScript)
# ============================================================================
echo "🎨 Creating frontend structure..."
mkdir -p frontend/src/{components,pages,services,hooks,types,utils,contexts}
mkdir -p frontend/src/components/{auth,dashboard,targets,hardening,monitoring,compliance,alerts,settings,integrations}
mkdir -p frontend/src/components/common
mkdir -p frontend/src/components/charts
mkdir -p frontend/src/pages
mkdir -p frontend/src/services
mkdir -p frontend/public

# ============================================================================
# DATABASE
# ============================================================================
echo "💾 Creating database structure..."
mkdir -p database/postgresql/migrations
mkdir -p database/influxdb/config

# ============================================================================
# INTEGRATION CLIENTS
# ============================================================================
echo "🔌 Creating integration clients structure..."
mkdir -p integrations/sentinel-core
mkdir -p integrations/firedog

# ============================================================================
# DOCUMENTATION
# ============================================================================
echo "📚 Creating documentation structure..."
mkdir -p docs/{api,architecture,deployment,user-guide}

# ============================================================================
# DOCKER
# ============================================================================
echo "🐳 Creating Docker structure..."
mkdir -p docker/{rust-backend,django-backend,frontend,postgresql,influxdb}

# ============================================================================
# TESTS
# ============================================================================
echo "🧪 Creating tests structure..."
mkdir -p tests/{unit,integration,e2e}
mkdir -p tests/unit/{rust,django,frontend}

# ============================================================================
# CONFIGURATION & DEPLOYMENT
# ============================================================================
echo "⚙️ Creating config and deployment structure..."
mkdir -p config/{development,production}
mkdir -p scripts/{deployment,maintenance,backup}

# ============================================================================
# LOGS & TEMP
# ============================================================================
echo "📝 Creating logs and temp directories..."
mkdir -p logs/{rust-backend,django-backend,hardening,monitoring}
mkdir -p tmp/{uploads,backups,hardening}

# Set secure permissions
echo "🔐 Setting secure permissions (700 for sensitive directories)..."
chmod 700 backend-rust backend-django hardening-models database logs tmp
chmod 755 frontend target-scripts docs

echo ""
echo "✅ Project structure created successfully!"
echo ""
echo "📁 Project layout:"
echo "  backend-rust/       - Rust Axum backend (API, auth, correlation)"
echo "  backend-django/     - Django hardening engine (SSH, models applier)"
echo "  hardening-models/   - File-based hardening models (base/severo)"
echo "  target-scripts/     - Bash monitoring scripts for targets"
echo "  frontend/           - React TypeScript frontend"
echo "  database/           - PostgreSQL & InfluxDB configs"
echo "  integrations/       - Sentinel Core & FireDog clients"
echo "  docker/             - Docker compose & Dockerfiles"
echo "  config/             - Environment-specific configurations"
echo ""
echo "🎯 Next steps:"
echo "  1. Initialize Rust project:  cd backend-rust && cargo init"
echo "  2. Initialize Django project: cd backend-django && django-admin startproject core ."
echo "  3. Initialize React project:  cd frontend && npm create vite@latest . --template react-ts"
echo "  4. Set up databases with docker-compose"
echo ""
