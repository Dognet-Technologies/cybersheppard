#!/bin/bash

# ============================================================================
# CYBERSHEPPARD - PostgreSQL Migrations Script
# ============================================================================

set -e

# Load environment variables
if [ -f "../../.env" ]; then
    export $(cat ../../.env | grep -v '^#' | xargs)
fi

# Default values
POSTGRES_HOST=${POSTGRES_HOST:-localhost}
POSTGRES_PORT=${POSTGRES_PORT:-5432}
POSTGRES_DB=${POSTGRES_DB:-cybersheppard}
POSTGRES_USER=${POSTGRES_USER:-cybersheppard}

echo "🗄️  Applying PostgreSQL migrations..."
echo ""
echo "Host: $POSTGRES_HOST:$POSTGRES_PORT"
echo "Database: $POSTGRES_DB"
echo "User: $POSTGRES_USER"
echo ""

# Check if PostgreSQL is running
if ! pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" > /dev/null 2>&1; then
    echo "❌ PostgreSQL is not running or not accessible"
    echo "   Please start PostgreSQL with: docker-compose up -d postgresql"
    exit 1
fi

# Apply migrations
MIGRATIONS_DIR="./migrations"

if [ ! -d "$MIGRATIONS_DIR" ]; then
    echo "❌ Migrations directory not found: $MIGRATIONS_DIR"
    exit 1
fi

# Get list of migration files
MIGRATION_FILES=$(ls -1 "$MIGRATIONS_DIR"/*.sql 2>/dev/null | sort -V)

if [ -z "$MIGRATION_FILES" ]; then
    echo "⚠️  No migration files found in $MIGRATIONS_DIR"
    exit 0
fi

# Apply each migration
for MIGRATION_FILE in $MIGRATION_FILES; do
    MIGRATION_NAME=$(basename "$MIGRATION_FILE")
    echo "📝 Applying migration: $MIGRATION_NAME"

    PGPASSWORD="$POSTGRES_PASSWORD" psql \
        -h "$POSTGRES_HOST" \
        -p "$POSTGRES_PORT" \
        -U "$POSTGRES_USER" \
        -d "$POSTGRES_DB" \
        -f "$MIGRATION_FILE"

    if [ $? -eq 0 ]; then
        echo "   ✅ Success"
    else
        echo "   ❌ Failed"
        exit 1
    fi
    echo ""
done

echo "✅ All migrations applied successfully!"
echo ""
echo "🔍 Database tables:"
PGPASSWORD="$POSTGRES_PASSWORD" psql \
    -h "$POSTGRES_HOST" \
    -p "$POSTGRES_PORT" \
    -U "$POSTGRES_USER" \
    -d "$POSTGRES_DB" \
    -c "\dt"

echo ""
echo "✨ Done!"
