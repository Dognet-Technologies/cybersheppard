# Intellidog Integration Guide - MicroSIEM

**Version**: 1.0.0  
**Last Updated**: 2025-12-31  
**Author**: Dognet Technologies  
**Audience**: Developers & System Administrators

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Architecture Integration](#architecture-integration)
4. [Backend Integration](#backend-integration)
5. [Frontend Integration](#frontend-integration)
6. [Database Integration](#database-integration)
7. [Configuration Management](#configuration-management)
8. [Authentication & Authorization](#authentication--authorization)
9. [Deployment Process](#deployment-process)
10. [Testing & Verification](#testing--verification)

---

## Overview

### What is Intellidog?

Intellidog è un **modulo premium opzionale** per MicroSIEM che aggiunge capacità avanzate di threat intelligence:

- Threat Intelligence Aggregation (MISP, OTX, AbuseIPDB)
- Exploit Detection Engine
- Virtual Patching System
- Threat Hunting Platform

### Integration Model

Intellidog si integra con MicroSIEM come **modulo pluggable**:

```
MicroSIEM (Base)
    │
    ├─── Core Services (log collection, alerting, dashboards)
    │
    └─── Intellidog Module (optional, licensed)
         ├─── Backend API (FastAPI)
         ├─── Frontend UI (React components)
         ├─── Database (PostgreSQL schemas)
         └─── Background Workers (Celery)
```

**Key Principle**: Intellidog extends MicroSIEM **without modifying core code**.

---

## Prerequisites

### MicroSIEM Requirements

- **Version**: MicroSIEM 3.0+
- **Database**: PostgreSQL 12+ (shared with MicroSIEM)
- **Message Queue**: Redis 6+ (shared with MicroSIEM)
- **Python**: 3.9+ (same as MicroSIEM)
- **Node.js**: 18+ (for frontend build)

### Additional Requirements for Intellidog

- **InfluxDB**: 2.x (time-series metrics)
- **Disk Space**: +50GB (replicated data + IoC database)
- **Memory**: +4GB RAM (for background workers)
- **Network**: Access to Firedog and Sentinel Core servers

### License Requirement

Intellidog requires a **valid license file** (`LICENSE`) signed by Dognet Technologies GPG key.

---

## Architecture Integration

### Directory Structure

```
/opt/microsiem/                         [MicroSIEM Base]
│
├── backend/                            [Core Backend]
│   ├── app/
│   │   ├── api/                        [API Routes]
│   │   ├── models/                     [SQLAlchemy Models]
│   │   ├── services/                   [Business Logic]
│   │   └── tasks/                      [Celery Tasks]
│   ├── config/
│   └── migrations/                     [Alembic Migrations]
│
├── frontend/                           [Core Frontend]
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   └── services/
│   └── public/
│
├── modules/                            [Extension Modules]
│   │
│   └── intellidog/                     ⭐ NEW - Intellidog Module
│       ├── LICENSE                     [GPG-signed license]
│       ├── README.md
│       ├── requirements.txt
│       │
│       ├── backend/                    [Intellidog Backend]
│       │   ├── feeds/                  [Feed connectors]
│       │   ├── correlation/            [Detection engine]
│       │   ├── virtual_patching/       [Vpatch system]
│       │   ├── hunting/                [Threat hunting]
│       │   ├── api/                    [FastAPI routes]
│       │   ├── models/                 [SQLAlchemy models]
│       │   ├── services/               [Business logic]
│       │   └── tasks/                  [Celery tasks]
│       │
│       ├── frontend/                   [Intellidog Frontend]
│       │   └── src/
│       │       ├── components/
│       │       ├── pages/
│       │       └── services/
│       │
│       ├── database/                   [Database Scripts]
│       │   ├── migrations/
│       │   └── schema.sql
│       │
│       ├── config/
│       │   ├── feeds.example.yml
│       │   └── sigma_rules/
│       │
│       └── scripts/
│           ├── install.sh
│           └── migrate_db.sh
│
└── plugins/                            [Replication Plugins]
    └── cybersheppard-replication-plugin/
```

---

## Backend Integration

### Step 1: Module Discovery & Loading

MicroSIEM deve rilevare e caricare automaticamente i moduli disponibili.

**File**: `/opt/microsiem/backend/app/modules/__init__.py`

```python
"""
MicroSIEM Module System
Automatically discover and load extension modules
"""

import os
import importlib
from pathlib import Path
from typing import List, Dict, Optional

class ModuleLoader:
    """Discovers and loads MicroSIEM extension modules"""
    
    MODULES_DIR = Path("/opt/microsiem/modules")
    
    def __init__(self):
        self.modules: Dict[str, Dict] = {}
        self.discover_modules()
    
    def discover_modules(self):
        """Scan modules directory and load module metadata"""
        
        if not self.MODULES_DIR.exists():
            return
        
        for module_path in self.MODULES_DIR.iterdir():
            if not module_path.is_dir():
                continue
            
            # Check if module has proper structure
            if not (module_path / "backend").exists():
                continue
            
            module_name = module_path.name
            
            # Load module metadata
            metadata = self.load_module_metadata(module_path)
            
            if metadata:
                self.modules[module_name] = {
                    'path': module_path,
                    'metadata': metadata,
                    'enabled': self.check_module_enabled(module_name, metadata)
                }
                
                print(f"✓ Discovered module: {module_name}")
    
    def load_module_metadata(self, module_path: Path) -> Optional[Dict]:
        """Load module metadata from module.yml or __init__.py"""
        
        import yaml
        
        metadata_file = module_path / "module.yml"
        
        if metadata_file.exists():
            with open(metadata_file) as f:
                return yaml.safe_load(f)
        
        return None
    
    def check_module_enabled(self, module_name: str, metadata: Dict) -> bool:
        """Check if module is enabled via environment variable and license"""
        
        # Check environment variable
        env_var = f"{module_name.upper()}_ENABLED"
        if os.getenv(env_var, "false").lower() != "true":
            print(f"✗ Module {module_name} disabled (set {env_var}=true)")
            return False
        
        # Check license if required
        if metadata.get('requires_license', False):
            license_valid = self.validate_module_license(module_name)
            if not license_valid:
                print(f"✗ Module {module_name} disabled (invalid license)")
                return False
        
        return True
    
    def validate_module_license(self, module_name: str) -> bool:
        """Validate module license file"""
        
        license_file = self.MODULES_DIR / module_name / "LICENSE"
        
        if not license_file.exists():
            return False
        
        # Import module's license validator
        try:
            module_backend = importlib.import_module(
                f"modules.{module_name}.backend.services.license_validator"
            )
            validator = module_backend.LicenseValidator()
            result = validator.validate_license()
            return result.get('valid', False)
        except Exception as e:
            print(f"✗ License validation error: {e}")
            return False
    
    def get_enabled_modules(self) -> List[str]:
        """Get list of enabled module names"""
        return [
            name for name, info in self.modules.items() 
            if info['enabled']
        ]
    
    def load_module_routes(self, app):
        """Load API routes from enabled modules"""
        
        for module_name in self.get_enabled_modules():
            try:
                # Import module's API router
                module_api = importlib.import_module(
                    f"modules.{module_name}.backend.api.routes"
                )
                
                # Mount module routes under /api/{module_name}
                app.include_router(
                    module_api.router,
                    prefix=f"/api/{module_name}",
                    tags=[module_name]
                )
                
                print(f"✓ Loaded routes for module: {module_name}")
                
            except Exception as e:
                print(f"✗ Failed to load routes for {module_name}: {e}")
    
    def load_module_models(self, db):
        """Import SQLAlchemy models from enabled modules"""
        
        for module_name in self.get_enabled_modules():
            try:
                # Import module's models
                importlib.import_module(
                    f"modules.{module_name}.backend.models"
                )
                
                print(f"✓ Loaded models for module: {module_name}")
                
            except Exception as e:
                print(f"✗ Failed to load models for {module_name}: {e}")
    
    def load_module_tasks(self, celery_app):
        """Load Celery tasks from enabled modules"""
        
        for module_name in self.get_enabled_modules():
            try:
                # Import module's tasks
                importlib.import_module(
                    f"modules.{module_name}.backend.tasks"
                )
                
                print(f"✓ Loaded tasks for module: {module_name}")
                
            except Exception as e:
                print(f"✗ Failed to load tasks for {module_name}: {e}")


# Global module loader instance
module_loader = ModuleLoader()
```

---

### Step 2: FastAPI Application Integration

**File**: `/opt/microsiem/backend/app/main.py`

```python
"""
MicroSIEM FastAPI Application
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api import api_router
from app.modules import module_loader  # ⭐ NEW

def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        openapi_url=f"{settings.API_V1_STR}/openapi.json"
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.BACKEND_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include core API routes
    app.include_router(api_router, prefix=settings.API_V1_STR)
    
    # ⭐ NEW - Load module routes
    module_loader.load_module_routes(app)
    
    @app.on_event("startup")
    async def startup_event():
        """Application startup"""
        print("=" * 70)
        print(" MicroSIEM Starting")
        print("=" * 70)
        
        # Load module models
        from app.database.session import engine
        module_loader.load_module_models(engine)
        
        # Display enabled modules
        enabled = module_loader.get_enabled_modules()
        if enabled:
            print(f"\n✓ Enabled modules: {', '.join(enabled)}")
        else:
            print("\n✓ No extension modules enabled")
        
        print("=" * 70)
    
    return app


app = create_app()
```

---

### Step 3: Celery Worker Integration

**File**: `/opt/microsiem/backend/app/worker.py`

```python
"""
MicroSIEM Celery Worker
"""

from celery import Celery

from app.core.config import settings
from app.modules import module_loader  # ⭐ NEW

celery_app = Celery(
    "microsiem",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

# Import core tasks
from app.tasks import *  # noqa

# ⭐ NEW - Load module tasks
module_loader.load_module_tasks(celery_app)

print(f"✓ Celery worker initialized")
print(f"✓ Loaded tasks from modules: {', '.join(module_loader.get_enabled_modules())}")
```

---

### Step 4: Database Connection Sharing

Intellidog usa lo **stesso database PostgreSQL** di MicroSIEM.

**File**: `/opt/microsiem/modules/intellidog/backend/database/session.py`

```python
"""
Intellidog Database Session
Uses MicroSIEM's shared database connection
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# Import MicroSIEM database URL
from app.core.config import settings

# Use same database as MicroSIEM
engine = create_engine(
    settings.SQLALCHEMY_DATABASE_URI,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """Dependency for FastAPI routes"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

**Key Points**:
- ✅ Stesso database connection pool
- ✅ Schema dedicato: `intellidog` (tabelle native)
- ✅ Schema replica: `firedog_replica`, `sentinel_replica`
- ✅ Transazioni ACID condivise

---

### Step 5: API Routes Structure

**File**: `/opt/microsiem/modules/intellidog/backend/api/routes.py`

```python
"""
Intellidog API Routes
Mounted under /api/intellidog by MicroSIEM module loader
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db  # MicroSIEM shared DB
from app.api.deps import get_current_user  # MicroSIEM auth

from ..services.license_validator import LicenseValidator
from ..services.feed_manager import FeedManager
from ..models import IoC, Detection, VirtualPatch

router = APIRouter()

# License check middleware
def check_license():
    """Verify Intellidog license before API access"""
    validator = LicenseValidator()
    result = validator.validate_license()
    if not result['valid']:
        raise HTTPException(
            status_code=403,
            detail=f"Intellidog license invalid: {result.get('error')}"
        )

# ============================================================================
# Feed Management Endpoints
# ============================================================================

@router.get("/feeds")
def list_feeds(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
    _ = Depends(check_license)
):
    """List configured threat intelligence feeds"""
    
    feed_manager = FeedManager(db)
    feeds = feed_manager.list_feeds()
    
    return {"feeds": feeds}


@router.post("/feeds/{feed_name}/sync")
def trigger_feed_sync(
    feed_name: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
    _ = Depends(check_license)
):
    """Manually trigger feed synchronization"""
    
    from ..tasks.feed_sync import sync_feed_task
    
    # Trigger async Celery task
    task = sync_feed_task.delay(feed_name)
    
    return {
        "message": f"Feed sync triggered for {feed_name}",
        "task_id": task.id
    }

# ============================================================================
# IoC Management Endpoints
# ============================================================================

@router.get("/iocs")
def list_iocs(
    ioc_type: str = None,
    severity: str = None,
    feed_name: str = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
    _ = Depends(check_license)
):
    """List indicators of compromise with filtering"""
    
    query = db.query(IoC)
    
    if ioc_type:
        query = query.filter(IoC.ioc_type == ioc_type)
    if severity:
        query = query.filter(IoC.severity == severity)
    if feed_name:
        query = query.filter(IoC.feed_name == feed_name)
    
    total = query.count()
    iocs = query.offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "iocs": [ioc.to_dict() for ioc in iocs]
    }


@router.get("/iocs/{ioc_id}")
def get_ioc_details(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
    _ = Depends(check_license)
):
    """Get IoC details with enrichment data"""
    
    ioc = db.query(IoC).filter(IoC.id == ioc_id).first()
    
    if not ioc:
        raise HTTPException(status_code=404, detail="IoC not found")
    
    return ioc.to_dict(include_enrichment=True)

# ============================================================================
# Detection Management Endpoints
# ============================================================================

@router.get("/detections")
def list_detections(
    confidence_min: int = 0,
    severity: str = None,
    status: str = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
    _ = Depends(check_license)
):
    """List exploit detections with filtering"""
    
    query = db.query(Detection).filter(Detection.confidence >= confidence_min)
    
    if severity:
        query = query.filter(Detection.severity == severity)
    if status:
        query = query.filter(Detection.status == status)
    
    query = query.order_by(Detection.detected_at.desc())
    
    total = query.count()
    detections = query.offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "detections": [d.to_dict() for d in detections]
    }

# ============================================================================
# Virtual Patching Endpoints
# ============================================================================

@router.post("/vpatches")
def create_virtual_patch(
    machine_id: int,
    cve_id: str,
    mode: str = "alert",
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
    _ = Depends(check_license)
):
    """Create virtual patch for CVE"""
    
    from ..services.vpatch_generator import VirtualPatchGenerator
    
    generator = VirtualPatchGenerator(db)
    vpatch = generator.create_patch(machine_id, cve_id, mode)
    
    return vpatch.to_dict()


@router.get("/vpatches")
def list_virtual_patches(
    status: str = None,
    machine_id: int = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
    _ = Depends(check_license)
):
    """List active virtual patches"""
    
    query = db.query(VirtualPatch)
    
    if status:
        query = query.filter(VirtualPatch.status == status)
    if machine_id:
        query = query.filter(VirtualPatch.machine_id == machine_id)
    
    vpatches = query.all()
    
    return {
        "vpatches": [vp.to_dict() for vp in vpatches]
    }

# ... more endpoints (hunting, license, etc.)
```

**URL Structure**:
- `GET /api/intellidog/feeds` - List feeds
- `POST /api/intellidog/feeds/misp/sync` - Trigger sync
- `GET /api/intellidog/iocs` - List IoC
- `GET /api/intellidog/detections` - List detections
- `POST /api/intellidog/vpatches` - Create virtual patch

---

## Frontend Integration

### Step 1: React Component Integration

MicroSIEM frontend carica dinamicamente i componenti dei moduli.

**File**: `/opt/microsiem/frontend/src/modules/ModuleRegistry.tsx`

```typescript
/**
 * MicroSIEM Module Registry
 * Dynamically loads React components from extension modules
 */

import React, { lazy, Suspense } from 'react';
import { Route } from 'react-router-dom';

interface ModuleInfo {
  name: string;
  displayName: string;
  enabled: boolean;
  routes: ModuleRoute[];
  navigationItems: NavigationItem[];
}

interface ModuleRoute {
  path: string;
  component: string; // Component name to lazy load
}

interface NavigationItem {
  label: string;
  path: string;
  icon?: string;
}

class ModuleRegistry {
  private modules: Map<string, ModuleInfo> = new Map();

  /**
   * Register a module
   */
  register(info: ModuleInfo) {
    this.modules.set(info.name, info);
  }

  /**
   * Get all enabled modules
   */
  getEnabledModules(): ModuleInfo[] {
    return Array.from(this.modules.values()).filter(m => m.enabled);
  }

  /**
   * Get navigation items from all modules
   */
  getNavigationItems(): NavigationItem[] {
    const items: NavigationItem[] = [];
    
    for (const module of this.getEnabledModules()) {
      items.push(...module.navigationItems);
    }
    
    return items;
  }

  /**
   * Generate React Router routes for all modules
   */
  generateRoutes(): JSX.Element[] {
    const routes: JSX.Element[] = [];

    for (const module of this.getEnabledModules()) {
      for (const route of module.routes) {
        // Lazy load component
        const Component = lazy(() => 
          import(`../modules/${module.name}/pages/${route.component}`)
        );

        routes.push(
          <Route
            key={`${module.name}-${route.path}`}
            path={route.path}
            element={
              <Suspense fallback={<div>Loading...</div>}>
                <Component />
              </Suspense>
            }
          />
        );
      }
    }

    return routes;
  }
}

export const moduleRegistry = new ModuleRegistry();

// ============================================================================
// Register Intellidog Module (if enabled)
// ============================================================================

if (import.meta.env.VITE_INTELLIDOG_ENABLED === 'true') {
  moduleRegistry.register({
    name: 'intellidog',
    displayName: 'Threat Intelligence',
    enabled: true,
    routes: [
      { path: '/threat-intel', component: 'ThreatIntelPage' },
      { path: '/threat-intel/detections', component: 'DetectionsPage' },
      { path: '/threat-intel/detections/:id', component: 'DetectionDetailPage' },
      { path: '/threat-intel/vpatches', component: 'VirtualPatchesPage' },
      { path: '/threat-intel/hunting', component: 'HuntingPage' },
    ],
    navigationItems: [
      {
        label: 'Threat Intelligence',
        path: '/threat-intel',
        icon: 'shield-alert'
      },
      {
        label: 'Detections',
        path: '/threat-intel/detections',
        icon: 'alert-triangle'
      },
      {
        label: 'Virtual Patches',
        path: '/threat-intel/vpatches',
        icon: 'shield-check'
      },
      {
        label: 'Threat Hunting',
        path: '/threat-intel/hunting',
        icon: 'search'
      },
    ]
  });
}
```

---

### Step 2: Navigation Menu Integration

**File**: `/opt/microsiem/frontend/src/components/Navigation/Sidebar.tsx`

```typescript
import React from 'react';
import { Link } from 'react-router-dom';
import { moduleRegistry } from '../../modules/ModuleRegistry';

export const Sidebar: React.FC = () => {
  // Core navigation items
  const coreItems = [
    { label: 'Dashboard', path: '/', icon: 'home' },
    { label: 'Logs', path: '/logs', icon: 'file-text' },
    { label: 'Alerts', path: '/alerts', icon: 'bell' },
    { label: 'Reports', path: '/reports', icon: 'bar-chart' },
  ];

  // ⭐ NEW - Get navigation items from modules
  const moduleItems = moduleRegistry.getNavigationItems();

  return (
    <nav className="sidebar">
      <div className="sidebar-section">
        <h3>Core</h3>
        {coreItems.map(item => (
          <Link key={item.path} to={item.path} className="nav-item">
            <i className={`icon-${item.icon}`} />
            <span>{item.label}</span>
          </Link>
        ))}
      </div>

      {/* ⭐ NEW - Module navigation items */}
      {moduleItems.length > 0 && (
        <div className="sidebar-section">
          <h3>Modules</h3>
          {moduleItems.map(item => (
            <Link key={item.path} to={item.path} className="nav-item">
              <i className={`icon-${item.icon}`} />
              <span>{item.label}</span>
            </Link>
          ))}
        </div>
      )}

      <div className="sidebar-section">
        <h3>Settings</h3>
        <Link to="/settings" className="nav-item">
          <i className="icon-settings" />
          <span>Settings</span>
        </Link>
      </div>
    </nav>
  );
};
```

---

### Step 3: App Router Integration

**File**: `/opt/microsiem/frontend/src/App.tsx`

```typescript
import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';

import { Sidebar } from './components/Navigation/Sidebar';
import { Header } from './components/Navigation/Header';

// Core pages
import { Dashboard } from './pages/Dashboard';
import { LogsPage } from './pages/LogsPage';
import { AlertsPage } from './pages/AlertsPage';

// ⭐ NEW - Module registry
import { moduleRegistry } from './modules/ModuleRegistry';

export const App: React.FC = () => {
  // ⭐ NEW - Generate routes from modules
  const moduleRoutes = moduleRegistry.generateRoutes();

  return (
    <BrowserRouter>
      <div className="app-container">
        <Sidebar />
        
        <div className="main-content">
          <Header />
          
          <div className="content">
            <Routes>
              {/* Core routes */}
              <Route path="/" element={<Dashboard />} />
              <Route path="/logs" element={<LogsPage />} />
              <Route path="/alerts" element={<AlertsPage />} />
              
              {/* ⭐ NEW - Module routes */}
              {moduleRoutes}
              
              {/* 404 */}
              <Route path="*" element={<div>Page not found</div>} />
            </Routes>
          </div>
        </div>
      </div>
    </BrowserRouter>
  );
};
```

---

### Step 4: Example Intellidog Component

**File**: `/opt/microsiem/frontend/src/modules/intellidog/pages/ThreatIntelPage.tsx`

```typescript
import React, { useEffect, useState } from 'react';
import { intellidogApi } from '../services/api';

interface ThreatIntelStats {
  total_iocs: number;
  total_detections: number;
  active_vpatches: number;
  critical_detections: number;
}

export const ThreatIntelPage: React.FC = () => {
  const [stats, setStats] = useState<ThreatIntelStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      const data = await intellidogApi.getStats();
      setStats(data);
    } catch (error) {
      console.error('Failed to load stats:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="threat-intel-page">
      <h1>Threat Intelligence Dashboard</h1>

      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total IoCs</h3>
          <div className="stat-value">{stats?.total_iocs.toLocaleString()}</div>
        </div>

        <div className="stat-card">
          <h3>Detections</h3>
          <div className="stat-value">{stats?.total_detections}</div>
        </div>

        <div className="stat-card critical">
          <h3>Critical Detections</h3>
          <div className="stat-value">{stats?.critical_detections}</div>
        </div>

        <div className="stat-card">
          <h3>Active Virtual Patches</h3>
          <div className="stat-value">{stats?.active_vpatches}</div>
        </div>
      </div>

      {/* Additional components: IoC summary, recent detections, etc. */}
    </div>
  );
};
```

---

## Database Integration

### Schema Organization

```sql
-- MicroSIEM Database: microsiem (or intellidog)

-- Core MicroSIEM schemas (existing)
public.*                     -- Core tables (users, alerts, logs)

-- Intellidog native schemas (new)
intellidog_feeds             -- Feed configuration
intellidog_iocs              -- Indicators of Compromise
intellidog_detections        -- Exploit detections
intellidog_virtual_patches   -- Virtual patches
intellidog_hunting_queries   -- Saved hunting queries
intellidog_sigma_rules       -- Sigma rule library
intellidog_license           -- License validation
system_integrations          -- API keys (encrypted)

-- Replicated schemas (new, read-only)
firedog_replica.*            -- Firedog tables (replicated)
sentinel_replica.*           -- Sentinel Core tables (replicated)
```

### Migration Strategy

**Alembic Migrations**: Intellidog migrations **independent** from MicroSIEM core.

```bash
# MicroSIEM core migrations
/opt/microsiem/backend/migrations/
└── versions/
    ├── 001_create_users.py
    ├── 002_create_alerts.py
    └── ...

# Intellidog module migrations
/opt/microsiem/modules/intellidog/database/migrations/
└── versions/
    ├── 001_create_intellidog_tables.py
    ├── 002_create_replica_schemas.py
    └── ...
```

**Run migrations**:
```bash
# Core migrations (MicroSIEM)
cd /opt/microsiem/backend
alembic upgrade head

# Intellidog migrations
cd /opt/microsiem/modules/intellidog
alembic -c database/alembic.ini upgrade head
```

---

## Configuration Management

### Environment Variables

**File**: `/opt/microsiem/.env`

```bash
# ============================================================================
# MicroSIEM Core Configuration (existing)
# ============================================================================

DATABASE_URL=postgresql://microsiem:password@localhost:5432/microsiem
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=your_secret_key_here

# ============================================================================
# Intellidog Module Configuration (new)
# ============================================================================

# Module Enable/Disable
INTELLIDOG_ENABLED=true

# Threat Intel Feeds
INTELLIDOG_MISP_ENABLED=true
INTELLIDOG_MISP_URL=https://misp.example.com

INTELLIDOG_OTX_ENABLED=true

INTELLIDOG_ABUSEIPDB_ENABLED=true

# Note: API keys stored encrypted in database (not .env)
# Managed via UI: Settings → Integrations

# Encryption Master Key (for API key encryption)
APP_ENCRYPTION_KEY=<generated_32_character_key>

# Virtual Patching
INTELLIDOG_VPATCH_ENABLED=true
INTELLIDOG_VPATCH_TEST_MODE_DURATION=48h
INTELLIDOG_VPATCH_AUTO_DECOMMISSION=true

# Performance
INTELLIDOG_IOC_CACHE_SIZE=100000
INTELLIDOG_IOC_RETENTION_DAYS=90
INTELLIDOG_WORKER_THREADS=4

# Reporting
INTELLIDOG_WEEKLY_DIGEST=true
INTELLIDOG_DIGEST_RECIPIENTS=security-team@company.com

# InfluxDB (time-series metrics)
INFLUXDB_URL=http://localhost:8086
INFLUXDB_TOKEN=your_influxdb_token
INFLUXDB_ORG=microsiem
INFLUXDB_BUCKET=intellidog
```

### Module Configuration File

**File**: `/opt/microsiem/modules/intellidog/module.yml`

```yaml
name: intellidog
version: 1.0.0
display_name: Threat Intelligence
description: Advanced threat intelligence and exploit detection
author: Dognet Technologies
license_type: proprietary
requires_license: true

dependencies:
  microsiem_version: ">=3.0.0"
  python: ">=3.9"
  postgresql: ">=12.0"
  influxdb: ">=2.0"

features:
  - threat_intel_aggregation
  - exploit_detection
  - virtual_patching
  - threat_hunting

database:
  schemas:
    - name: intellidog
      description: Native Intellidog tables
    - name: firedog_replica
      description: Replicated Firedog data
    - name: sentinel_replica
      description: Replicated Sentinel Core data

api:
  base_path: /api/intellidog
  requires_auth: true
  rate_limit: 1000/hour

frontend:
  base_path: /threat-intel
  navigation_section: Modules

background_tasks:
  - name: feed_sync
    schedule: "0 */4 * * *"  # Every 4 hours
  - name: correlation_engine
    schedule: "*/5 * * * *"  # Every 5 minutes
  - name: license_check
    schedule: "0 2 * * *"    # Daily at 2 AM
```

---

## Authentication & Authorization

### Shared Authentication System

Intellidog usa il **sistema di autenticazione di MicroSIEM** (JWT tokens).

**Example**: Protecting Intellidog API endpoints

```python
from fastapi import Depends, HTTPException
from app.api.deps import get_current_user, get_current_active_user
from app.models import User

@router.get("/intellidog/detections")
def list_detections(
    current_user: User = Depends(get_current_active_user),
    # ⬆️ MicroSIEM's shared authentication dependency
):
    """List detections - requires authentication"""
    
    # User is already authenticated by MicroSIEM
    # Access user info: current_user.id, current_user.email, current_user.role
    
    # ... endpoint logic
    pass
```

### Permission Checks

**Role-Based Access Control (RBAC)**:

```python
from app.core.security import check_permission

@router.post("/intellidog/vpatches")
def create_virtual_patch(
    machine_id: int,
    cve_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Create virtual patch - requires 'intellidog:vpatch:create' permission"""
    
    # Check permission
    if not check_permission(current_user, "intellidog:vpatch:create"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # ... create vpatch
    pass
```

**Permission Matrix**:

| Role | View Detections | Create VPatch | Configure Feeds | Admin |
|------|----------------|---------------|-----------------|-------|
| **viewer** | ✅ | ❌ | ❌ | ❌ |
| **analyst** | ✅ | ✅ | ❌ | ❌ |
| **admin** | ✅ | ✅ | ✅ | ✅ |

---

## Deployment Process

### Step-by-Step Installation

#### 1. Install Replication Plugins

```bash
# On Firedog server
cd /opt/firedog/plugins
./plugin-manager install firedog-replication-plugin
cd firedog-replication-plugin
sudo ./scripts/install.sh

# On Sentinel Core server
cd /opt/sentinel/plugins
./plugin-manager install sentinelcore-replication-plugin
cd sentinelcore-replication-plugin
sudo ./scripts/install.sh

# On MicroSIEM server
cd /opt/microsiem/plugins
./plugin-manager install cybersheppard-replication-plugin
cd cybersheppard-replication-plugin
sudo ./scripts/configure_subscription.py
```

#### 2. Install Intellidog Module

```bash
# Clone Intellidog module
cd /opt/microsiem/modules
git clone https://github.com/dognet-tech/intellidog.git

# Install Python dependencies
cd intellidog
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run database migrations
cd database
alembic upgrade head
```

#### 3. Install License

```bash
# Copy license file to module directory
cp /path/to/LICENSE_YourCompany_20250115.txt /opt/microsiem/modules/intellidog/LICENSE

# Validate license
cd /opt/microsiem/modules/intellidog
python -c "from backend.services.license_validator import LicenseValidator; print(LicenseValidator().validate_license())"
```

#### 4. Configure Environment

```bash
# Add to MicroSIEM .env
cat >> /opt/microsiem/.env <<EOF

# Intellidog Module
INTELLIDOG_ENABLED=true
INTELLIDOG_MISP_ENABLED=true
INTELLIDOG_MISP_URL=https://misp.example.com
INTELLIDOG_OTX_ENABLED=true
INTELLIDOG_ABUSEIPDB_ENABLED=true
APP_ENCRYPTION_KEY=$(openssl rand -base64 32)
EOF
```

#### 5. Build Frontend

```bash
# Build Intellidog frontend components
cd /opt/microsiem/modules/intellidog/frontend
npm install
npm run build

# Copy built assets to MicroSIEM static directory
cp -r dist/* /opt/microsiem/frontend/static/modules/intellidog/
```

#### 6. Restart Services

```bash
# Restart MicroSIEM API
sudo systemctl restart microsiem-api

# Restart Celery workers
sudo systemctl restart microsiem-workers

# Restart frontend (if separate service)
sudo systemctl restart microsiem-frontend
```

#### 7. Verify Installation

```bash
# Check module loaded
curl -H "Authorization: Bearer $JWT_TOKEN" \
     http://localhost:8000/api/intellidog/feeds

# Check replication status
psql -d microsiem -c "SELECT * FROM intellidog_replication_status;"

# Run Intellidog test suite
cd /opt/microsiem/modules/intellidog
pytest tests/
```

---

## Testing & Verification

### Integration Tests

**File**: `/opt/microsiem/modules/intellidog/tests/test_integration.py`

```python
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database.session import SessionLocal

client = TestClient(app)

def test_module_loaded():
    """Test that Intellidog module is loaded"""
    response = client.get("/api/intellidog/feeds")
    assert response.status_code in [200, 401]  # 401 if not authenticated

def test_license_valid():
    """Test license validation"""
    from modules.intellidog.backend.services.license_validator import LicenseValidator
    
    validator = LicenseValidator()
    result = validator.validate_license()
    
    assert result['valid'] == True
    assert 'expires_at' in result

def test_replication_active():
    """Test database replication is working"""
    db = SessionLocal()
    
    result = db.execute("""
        SELECT COUNT(*) 
        FROM pg_stat_subscription 
        WHERE subname IN ('firedog_sub', 'sentinel_sub') 
        AND pid IS NOT NULL
    """).scalar()
    
    assert result == 2  # Both subscriptions active

def test_feed_sync():
    """Test feed synchronization"""
    # Trigger feed sync
    response = client.post(
        "/api/intellidog/feeds/misp/sync",
        headers={"Authorization": f"Bearer {get_test_token()}"}
    )
    
    assert response.status_code == 200
    assert 'task_id' in response.json()
```

### Manual Verification Checklist

```bash
# ============================================================================
# Intellidog Installation Verification Checklist
# ============================================================================

# 1. Module Discovery
✓ MicroSIEM detects Intellidog module:
  grep "Discovered module: intellidog" /var/log/microsiem/api.log

# 2. License Valid
✓ License file present:
  ls -la /opt/microsiem/modules/intellidog/LICENSE
✓ License validated:
  tail -f /var/log/microsiem/api.log | grep "License valid"

# 3. Database Replication
✓ Schemas created:
  psql -d microsiem -c "\dn" | grep -E "firedog_replica|sentinel_replica"
✓ Subscriptions active:
  psql -d microsiem -c "SELECT * FROM intellidog_replication_status;"
✓ Tables replicated:
  psql -d microsiem -c "SELECT COUNT(*) FROM firedog_replica.machines;"

# 4. API Endpoints
✓ Intellidog routes loaded:
  curl http://localhost:8000/api/intellidog/feeds
✓ Authentication works:
  curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/intellidog/feeds

# 5. Frontend Integration
✓ Navigation menu shows Intellidog:
  Open http://localhost:3000 → Check sidebar
✓ Threat Intel page loads:
  Navigate to /threat-intel

# 6. Background Tasks
✓ Celery tasks loaded:
  celery -A app.worker inspect registered | grep intellidog
✓ Feed sync scheduled:
  celery -A app.worker inspect scheduled

# 7. InfluxDB Metrics
✓ InfluxDB connection:
  influx ping
✓ Bucket exists:
  influx bucket list | grep intellidog
```

---

## Troubleshooting

### Common Issues

#### Module Not Loading

**Symptom**: Intellidog routes not available

**Check**:
```bash
# Verify environment variable set
echo $INTELLIDOG_ENABLED

# Check MicroSIEM logs
tail -f /var/log/microsiem/api.log | grep intellidog
```

**Solution**:
```bash
# Set environment variable
export INTELLIDOG_ENABLED=true

# Restart MicroSIEM
sudo systemctl restart microsiem-api
```

---

#### License Invalid

**Symptom**: 403 Forbidden on Intellidog endpoints

**Check**:
```bash
# Validate license manually
cd /opt/microsiem/modules/intellidog
python -c "from backend.services.license_validator import LicenseValidator; print(LicenseValidator().validate_license())"
```

**Solution**:
- Verify license file present: `/opt/microsiem/modules/intellidog/LICENSE`
- Check license not expired
- Contact support@dognet.tech for new license

---

#### Replication Not Working

**Symptom**: Empty replica tables

**Check**:
```bash
# Check subscription status
psql -d microsiem -c "SELECT * FROM pg_stat_subscription;"

# Test replication
cd /opt/microsiem/plugins/cybersheppard-replication-plugin
./scripts/test_replication.py
```

**Solution**:
- Verify network connectivity to Firedog/Sentinel servers
- Check replication credentials valid
- Review PostgreSQL logs on source servers

---

## Summary

### Integration Checklist

- [x] Module loader system implemented
- [x] FastAPI routes auto-discovery
- [x] Celery tasks auto-loading
- [x] Database connection sharing
- [x] Frontend component integration
- [x] Navigation menu integration
- [x] Authentication/authorization sharing
- [x] Environment configuration
- [x] Deployment process documented
- [x] Testing procedures defined

### Key Takeaways

1. **Modular Architecture**: Intellidog extends MicroSIEM without modifying core
2. **Shared Resources**: Database, auth, message queue all shared
3. **Dynamic Loading**: Modules discovered and loaded automatically
4. **License Enforcement**: GPG-signed license required for activation
5. **Production Ready**: Complete deployment and testing procedures

---

**Intellidog Integration Complete** ✅

Per ulteriori dettagli, consultare:
- ARCHITECTURE.md - Architettura completa
- DATABASE_REPLICATION.md - Setup replication
- Plugin READMEs - Installazione plugin

**Support**: support@dognet.tech
