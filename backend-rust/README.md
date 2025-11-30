# CyberSheppard Rust Backend

## Development Setup

### Prerequisites

1. PostgreSQL database running
2. InfluxDB running
3. Rust toolchain (1.70+)

### Initial Setup

1. Copy `.env.example` to `.env` and configure:
   ```bash
   cp .env.example .env
   ```

2. Start the databases (via Docker Compose from project root):
   ```bash
   cd ..
   docker-compose up -d postgresql influxdb
   ```

3. Apply database migrations:
   ```bash
   cd database/postgresql
   ./apply_migrations.sh
   ```

4. Prepare SQLx for offline compilation (required for first build):
   ```bash
   cd backend-rust
   cargo sqlx prepare
   ```

5. Build and run:
   ```bash
   cargo build
   cargo run
   ```

## Features Implemented

### ✅ Authentication System
- **JWT Tokens**: Access tokens (15 min) + Refresh tokens (7 days)
- **Password Security**: Argon2 password hashing
- **CSRF Protection**: Synchronizer Token Pattern
- **Rate Limiting**: Configurable per-endpoint limits
- **Session Management**: Token revocation and refresh
- **Audit Logging**: All authentication events logged

### API Endpoints

#### Public Routes (No Auth Required)
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login with credentials
- `POST /api/auth/refresh` - Refresh access token
- `GET /health` - Health check

#### Protected Routes (Auth Required)
- `POST /api/auth/logout` - Logout and revoke tokens
- `GET /api/auth/me` - Get current user info
- `/api/targets/*` - Target management
- `/api/hardening/*` - Hardening operations
- `/api/monitoring/*` - Monitoring data
- `/api/compliance/*` - Compliance checks
- `/api/settings/*` - System settings
- `/api/integrations/*` - Integration management
- `GET /ws/logs` - WebSocket log streaming
- `GET /ws/monitoring/:target_id` - WebSocket monitoring stream

## Architecture

### Middleware Stack
1. **Tracing** - Request logging
2. **Compression** - Gzip compression
3. **CORS** - Cross-origin resource sharing
4. **Authentication** - JWT validation (protected routes only)
5. **CSRF** - CSRF token validation (protected routes only)

### Security Features
- Password strength validation (8+ chars, uppercase, lowercase, digit, special)
- Username validation (3-32 chars, alphanumeric + underscore/hyphen)
- Email format validation
- First user automatically gets admin role
- Account status checking (active/disabled)
- Audit trail for all authentication events

## Environment Variables

See `.env.example` for all available configuration options.

Key variables:
- `DATABASE_URL` - PostgreSQL connection string
- `JWT_SECRET` - Secret for access tokens
- `JWT_REFRESH_SECRET` - Secret for refresh tokens
- `RUST_HOST` - Server bind address
- `RUST_PORT` - Server port

## Development Notes

- SQLx uses compile-time query verification
- Run `cargo sqlx prepare` after schema changes
- Use `SQLX_OFFLINE=true` for CI/CD builds (after running prepare)
- All database queries are parameterized to prevent SQL injection
