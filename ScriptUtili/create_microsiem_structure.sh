#!/bin/bash

# MicroSIEM - Directory Structure Creation Script
# Creates all project directories as per PROJECT_SPEC.md and ARCHITECTURE.md

set -e

BASE_DIR="microsiem"

echo "Creating MicroSIEM directory structure..."

# Create base directory
mkdir -p "$BASE_DIR"
cd "$BASE_DIR"

# Documentation
mkdir -p docs

# Frontend
mkdir -p frontend/src/{components,pages,services,hooks,types,utils}
mkdir -p frontend/src/components/{auth,dashboard,machines,hardening,monitoring,alerts,settings}
mkdir -p frontend/src/components/dashboard/ChartComponents

# Backend
mkdir -p backend/app/{models,schemas,api,services,database,auth,utils}
mkdir -p backend/alembic/versions

# Modules
mkdir -p modules/hardening/{models,validators}
mkdir -p modules/hardening/models/{base,severo,custom}
mkdir -p modules/hardening/models/service

# Base level hardening models
mkdir -p modules/hardening/models/base/{web_generic,web_nis2,web_pci,database_generic,database_pci,dns_generic,gateway_generic,generic}

# Severo level hardening models
mkdir -p modules/hardening/models/severo/{web_generic,web_nis2,web_pci,database_generic,database_pci,dns_generic,gateway_generic,generic}

# Monitoring module
mkdir -p modules/monitoring/{collectors,parsers}

# Checking module
mkdir -p modules/checking/{compliance,security,scripts}

# Alerting module
mkdir -p modules/alerting/templates

# Target scripts
mkdir -p target-scripts/collectors

# Database
mkdir -p database/influxdb
mkdir -p database/postgresql/migrations

# Docker
mkdir -p docker

# Tests
mkdir -p tests/{frontend,backend,integration}

# Set permissions to 700 for all directories
find . -type d -exec chmod 700 {} \;

echo "✓ Directory structure created successfully"
echo "✓ All directories set to chmod 700"
echo ""
echo "Project root: $(pwd)"

cd ..
