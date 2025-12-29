# Plugin System Implementation - Complete Documentation

## Overview

This document provides a complete overview of the CyberSheppard & SentinelCore Plugin Manager system implementation.

## Architecture Summary

### Core Components

1. **Database Layer** (`database/postgresql/migrations/008_plugin_system.sql`)
   - Plugin repositories management
   - Plugin registry (available plugins from all repositories)
   - Installed plugins tracking
   - Execution history and debugging
   - Permission management

2. **Backend Service** (`backend-rust/src/services/plugin_manager.rs`)
   - Repository CRUD operations
   - GitHub API integration for plugin fetching
   - Plugin installation/uninstallation
   - Enable/disable management
   - SHA256 checksum verification

3. **API Layer** (`backend-rust/src/api/plugins.rs`)
   - RESTful endpoints for plugin management
   - Repository management endpoints
   - Plugin lifecycle endpoints
   - Configuration management

4. **Frontend UI** (`frontend-react/src/pages/Plugins.tsx`)
   - Plugin browser with filtering
   - Trust level badges
   - Security warnings for community plugins
   - Installation wizard
   - Statistics dashboard

## Plugin Repository Structure

```
plugins-official/
├── README.md                          # Repository overview
├── CONTRIBUTING.md                    # Contribution guidelines
├── .gitignore                         # Git ignore rules
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                     # Main CI/CD pipeline
│   │   └── pr-checks.yml              # PR validation checks
│   ├── labeler.yml                    # Auto-labeling config
│   ├── PULL_REQUEST_TEMPLATE.md       # PR template
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md              # Bug report template
│       └── feature_request.md         # Feature request template
│
├── cybersheppard/                     # CyberSheppard plugins
│   └── example-plugin/
│       ├── manifest.json              # Plugin metadata
│       ├── plugin.py                  # Plugin implementation
│       ├── README.md                  # Plugin documentation
│       ├── requirements.txt           # Python dependencies
│       └── tests/                     # Unit tests
│
└── sentinelcore/                      # SentinelCore plugins
    └── example-plugin/
        ├── manifest.json              # Plugin metadata
        ├── plugin.py                  # Plugin implementation
        ├── README.md                  # Plugin documentation
        ├── requirements.txt           # Python dependencies
        └── tests/                     # Unit tests
```

## Manifest Structure

### Opzione A (Implemented)

**Flat directory structure with stability in manifest.json**

```json
{
  "name": "plugin-name",
  "version": "1.0.0",
  "product": "cybersheppard",        // or "sentinelcore"
  "stato": "stable",                  // or "unstable"
  "stability_level": "beta",          // alpha, beta, or complete
  "description": "Plugin description",
  "author": "Author Name",
  "author_email": "author@example.com",
  "entry_point": "plugin.py",
  "checksum_sha256": "auto-generated-by-ci",
  "permissions": ["network.http", "storage.write"],
  "events": ["security.violation.detected"],
  "configuration_schema": { ... }
}
```

### Key Design Decisions

1. **No directory-based stability** - Plugins stay in place, status in manifest
2. **Settings control** - Users can enable "unstable" plugins in Settings page
3. **Beta usable by default** - Only "unstable" plugins require opt-in
4. **Git tags for versioning** - v1.0.0, v1.2.3, etc.
5. **CI auto-generates checksums** - SHA256 checksums updated on merge to main

## Database Schema

### Tables

1. **plugin_repositories**
   - Multi-source repository support
   - Trust levels: official, community, private
   - Auto-fetch configuration

2. **plugin_registry**
   - All available plugins from all repositories
   - Version tracking
   - Checksum storage
   - Permission declarations

3. **installed_plugins**
   - Locally installed plugins
   - Configuration storage
   - Enable/disable status
   - Installation metadata

4. **plugin_executions**
   - Execution history
   - Performance metrics
   - Error tracking
   - Debugging logs

5. **plugin_permissions**
   - Permission approval system
   - Granular permission control
   - Approval audit trail

### Views

1. **active_plugins** - Currently enabled plugins
2. **available_plugins** - Registry + installation status
3. **plugin_stats_summary** - Performance analytics

## API Endpoints

### Repository Management

```
GET    /api/plugins/repositories              # List all repositories
POST   /api/plugins/repositories              # Add new repository
DELETE /api/plugins/repositories/:id          # Remove repository
POST   /api/plugins/repositories/:id/fetch    # Fetch plugins from repo
```

### Plugin Management

```
GET    /api/plugins/registry                  # List available plugins
GET    /api/plugins/installed                 # List installed plugins
POST   /api/plugins/install/:registry_id      # Install plugin
DELETE /api/plugins/installed/:id             # Uninstall plugin
POST   /api/plugins/installed/:id/enable      # Enable plugin
POST   /api/plugins/installed/:id/disable     # Disable plugin
PUT    /api/plugins/installed/:id/configure   # Configure plugin
```

## Frontend Features

### Plugin Manager Page

1. **Filter System**
   - All plugins
   - Installed only
   - Active only
   - Available only

2. **Search Functionality**
   - Search by name
   - Search by description
   - Search by author

3. **Trust Level Badges**
   - 🟢 OFFICIAL (green badge with checkmark)
   - 🟡 COMMUNITY (yellow badge with alert)
   - 🔵 PRIVATE (blue badge with lock)

4. **Security Warning Modal**
   - Shown for community plugins
   - User must acknowledge risks
   - "I understand the risks" checkbox

5. **Statistics Dashboard**
   - Total plugins available
   - Installed plugins count
   - Active plugins count
   - Plugin repository count

### Actions

- **Install** - Install new plugin
- **Uninstall** - Remove installed plugin
- **Enable** - Activate installed plugin
- **Disable** - Deactivate plugin (keep installed)
- **Configure** - Edit plugin configuration

## CI/CD Pipeline

### Main Pipeline (`ci.yml`)

**Triggers:** Push to develop/main, PRs

**Jobs:**
1. **lint-python** - Black, Pylint, Flake8
2. **lint-rust** - Rustfmt, Clippy
3. **test-python** - Pytest with >70% coverage
4. **test-rust** - Cargo test
5. **validate-manifests** - JSON schema validation
6. **security-scan** - Trivy vulnerability scanning
7. **generate-checksums** - Auto-generate SHA256 (main branch only)
8. **release** - Create GitHub release (on release commits)

### PR Checks (`pr-checks.yml`)

**Triggers:** PR opened/updated

**Jobs:**
1. **pr-validation** - Title format, target branch, new plugins
2. **code-quality** - LOC statistics, plugin count
3. **label-pr** - Auto-label based on changed files
4. **comment-checklist** - Post submission checklist

## Security Features

### Trust Levels

1. **Official** (trust_level: "official")
   - Verified by CyberSheppard team
   - Green badge with checkmark
   - No security warnings

2. **Community** (trust_level: "community")
   - Third-party plugins
   - Yellow badge with alert icon
   - Security warning modal required
   - User must acknowledge risks

3. **Private** (trust_level: "private")
   - Internal organization plugins
   - Blue badge with lock icon
   - No security warnings

### Checksum Verification

- SHA256 checksums auto-generated by CI
- Verified before installation
- Prevents tampering
- Stored in manifest.json and database

### Permission System

- Granular permission declarations
- User approval required
- Permissions tracked in database
- Audit trail maintained

### Security Scanning

- Trivy vulnerability scanner
- Runs on every PR
- SARIF upload to GitHub Security
- Blocks merge on critical vulnerabilities

## Settings Integration

### Plugin Settings Tab (Future Enhancement)

Add to Settings page:

```typescript
// Enable unstable plugins
unstable_plugins_enabled: boolean

// Auto-update plugins
auto_update_plugins: boolean

// Plugin repository management UI
repositories: PluginRepository[]
```

## Plugin Development Workflow

### Creating a New Plugin

1. **Fork the repository**
   ```bash
   git clone https://github.com/YOUR_ORG/plugins-official.git
   cd plugins-official
   ```

2. **Create feature branch**
   ```bash
   git checkout -b feature/my-awesome-plugin
   ```

3. **Create plugin directory**
   ```bash
   mkdir -p cybersheppard/my-awesome-plugin
   cd cybersheppard/my-awesome-plugin
   ```

4. **Create manifest.json**
   - Use template from README.md
   - Set product: "cybersheppard" or "sentinelcore"
   - Set stato: "stable" (for stable) or "unstable" (for development)
   - Set stability_level: "alpha", "beta", or "complete"

5. **Implement plugin.py**
   - Follow example-plugin structure
   - Implement event handlers
   - Add health check
   - Add shutdown cleanup

6. **Write tests**
   ```bash
   mkdir tests
   touch tests/test_core.py
   pytest tests/ --cov=. --cov-report=term
   ```

7. **Create README.md**
   - Installation instructions
   - Configuration documentation
   - Usage examples
   - Troubleshooting

8. **Submit PR**
   ```bash
   git add .
   git commit -m "feat: Add my-awesome-plugin for CyberSheppard"
   git push origin feature/my-awesome-plugin
   ```

9. **Open PR to `develop` branch**
   - Use PR template
   - Wait for CI checks
   - Address review comments

### Versioning Strategy

**Git Tags:**
```bash
# Tag a release
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

**Manifest Version:**
```json
{
  "version": "1.0.0"  // Must match git tag
}
```

**Commit Message for Release:**
```
release: v1.0.0

- Initial release
- Feature X implemented
- Bug Y fixed
```

## Testing the System

### Backend Tests

```bash
cd backend-rust
cargo test
cargo clippy
```

### Database Migration

```bash
psql -U cybersheppard -d cybersheppard < database/postgresql/migrations/008_plugin_system.sql
```

### Frontend Tests

```bash
cd frontend-react
npm run type-check
npm run lint
```

## Deployment

### Initial Setup

1. **Run database migration**
   ```bash
   psql -U cybersheppard -d cybersheppard < database/postgresql/migrations/008_plugin_system.sql
   ```

2. **Restart backend**
   ```bash
   systemctl restart cybersheppard-backend
   ```

3. **Clear frontend cache**
   ```bash
   cd frontend-react && npm run build
   ```

4. **Add official repository** (via UI or API)
   ```bash
   curl -X POST http://localhost:8080/api/plugins/repositories \
     -H "Content-Type: application/json" \
     -d '{
       "name": "Official Plugins",
       "url": "https://github.com/YOUR_ORG/plugins-official",
       "branch": "main",
       "trust_level": "official",
       "is_official": true
     }'
   ```

5. **Fetch plugins**
   ```bash
   curl -X POST http://localhost:8080/api/plugins/repositories/1/fetch
   ```

## Files Created

### Database
- `database/postgresql/migrations/008_plugin_system.sql` (350 lines)

### Backend
- `backend-rust/src/services/plugin_manager.rs` (460 lines)
- `backend-rust/src/api/plugins.rs` (260 lines)
- Updated: `backend-rust/src/api/mod.rs`
- Updated: `backend-rust/src/main.rs`

### Frontend
- `frontend-react/src/pages/Plugins.tsx` (550 lines)
- Updated: `frontend-react/src/services/api.ts` (added 10 methods)
- Updated: `frontend-react/src/App.tsx`
- Updated: `frontend-react/src/components/Layout.tsx`

### Plugin Repository Template
- `docs/plugins-official-template/README.md`
- `docs/plugins-official-template/CONTRIBUTING.md`
- `docs/plugins-official-template/.gitignore`
- `docs/plugins-official-template/.github/workflows/ci.yml`
- `docs/plugins-official-template/.github/workflows/pr-checks.yml`
- `docs/plugins-official-template/.github/labeler.yml`
- `docs/plugins-official-template/.github/PULL_REQUEST_TEMPLATE.md`
- `docs/plugins-official-template/.github/ISSUE_TEMPLATE/bug_report.md`
- `docs/plugins-official-template/.github/ISSUE_TEMPLATE/feature_request.md`
- `docs/plugins-official-template/cybersheppard/example-plugin/*`
- `docs/plugins-official-template/sentinelcore/example-plugin/*`

## Total Implementation

- **Database**: 1 migration file (350 lines)
- **Backend**: 2 new files (720 lines), 2 updated files
- **Frontend**: 1 new page (550 lines), 3 updated files
- **Repository Template**: 15 files (complete plugin repository structure)

## Next Steps

1. ✅ Create GitHub repository: `plugins-official`
2. ✅ Copy template files to repository
3. Test plugin installation flow
4. Create first real plugins
5. Document API for plugin developers
6. Add Settings tab for repository management
7. Implement plugin update system
8. Add plugin marketplace UI

---

**Implementation Status:** ✅ **COMPLETE**

**Last Updated:** 2025-12-29
