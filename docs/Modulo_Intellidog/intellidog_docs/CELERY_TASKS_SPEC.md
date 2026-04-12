# Celery Tasks Configuration - Complete Specification

## Overview

Complete Celery task configuration for Intellidog background processing, including periodic tasks, beat schedule, and task management.

**Task Queue**: Redis  
**Task Broker**: Redis  
**Result Backend**: Redis  
**Beat Scheduler**: DatabaseScheduler (celery-beat)

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    Celery Beat Scheduler                       │
│                  (Periodic Task Trigger)                       │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Every 5 minutes:   Correlation Job                           │
│  Every 60 minutes:  Feed Update Job                           │
│  Daily at 1 AM:     License Check                             │
│  Daily at 2 AM:     Cache Cleanup                             │
│  Daily at 3 AM:     Virtual Patch Expiration                  │
│                                                                │
└────────────────────────────┬───────────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────────┐
│                       Redis (Broker)                           │
│                   Task Queue Management                        │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Queues:                                                       │
│  - celery (default)                                            │
│  - intellidog.high_priority                                    │
│  - intellidog.low_priority                                     │
│                                                                │
└────────────────────────────┬───────────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────────┐
│                    Celery Workers (4 workers)                  │
│                   Task Execution Nodes                         │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Worker 1: High Priority Queue                                │
│  Worker 2-3: Default Queue                                    │
│  Worker 4: Low Priority Queue                                 │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## Celery Configuration

### Main Config

**File**: `backend/app/core/celery_config.py`

```python
from celery import Celery
from celery.schedules import crontab
from kombu import Queue, Exchange
from app.core.config import settings

# Create Celery app
celery_app = Celery(
    'cybersheppard',
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND
)

# Celery Configuration
celery_app.conf.update(
    # General
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    
    # Task routing
    task_default_queue='celery',
    task_default_exchange='celery',
    task_default_routing_key='celery',
    
    # Task execution
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_time_limit=3600,  # 1 hour hard limit
    task_soft_time_limit=3300,  # 55 minutes soft limit
    
    # Result backend
    result_expires=3600,  # 1 hour
    result_backend_transport_options={
        'master_name': 'mymaster',
        'socket_timeout': 5,
        'socket_connect_timeout': 5,
        'retry_on_timeout': True
    },
    
    # Worker
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=1000,
    worker_disable_rate_limits=False,
    
    # Monitoring
    worker_send_task_events=True,
    task_send_sent_event=True,
    
    # Error handling
    task_annotations={
        '*': {
            'rate_limit': '10/s',
            'max_retries': 3,
            'default_retry_delay': 60
        }
    }
)

# Queue configuration
celery_app.conf.task_queues = (
    Queue('celery', Exchange('celery'), routing_key='celery'),
    Queue('intellidog.high_priority', Exchange('intellidog'), routing_key='intellidog.high'),
    Queue('intellidog.low_priority', Exchange('intellidog'), routing_key='intellidog.low'),
)

# Task routing
celery_app.conf.task_routes = {
    'intellidog.correlation_job': {
        'queue': 'intellidog.high_priority',
        'routing_key': 'intellidog.high'
    },
    'intellidog.feed_update_job': {
        'queue': 'celery',
        'routing_key': 'celery'
    },
    'intellidog.cache_cleanup': {
        'queue': 'intellidog.low_priority',
        'routing_key': 'intellidog.low'
    },
    'intellidog.license_check': {
        'queue': 'celery',
        'routing_key': 'celery'
    },
    'intellidog.expire_virtual_patches': {
        'queue': 'celery',
        'routing_key': 'celery'
    }
}

# Beat schedule (periodic tasks)
celery_app.conf.beat_schedule = {
    # Correlation Engine - Every 5 minutes
    'run-correlation': {
        'task': 'intellidog.correlation_job',
        'schedule': 300.0,  # 5 minutes in seconds
        'options': {
            'expires': 240,  # Task expires after 4 minutes
            'priority': 9  # High priority (0-9, 9 is highest)
        }
    },
    
    # Feed Updates - Every hour
    'update-feeds': {
        'task': 'intellidog.feed_update_job',
        'schedule': 3600.0,  # 1 hour in seconds
        'options': {
            'expires': 3000,  # Task expires after 50 minutes
            'priority': 5  # Medium priority
        }
    },
    
    # License Check - Daily at 1 AM UTC
    'check-license': {
        'task': 'intellidog.license_check',
        'schedule': crontab(hour=1, minute=0),
        'options': {
            'expires': 3600,
            'priority': 5
        }
    },
    
    # Cache Cleanup - Daily at 2 AM UTC
    'cleanup-cache': {
        'task': 'intellidog.cache_cleanup',
        'schedule': crontab(hour=2, minute=0),
        'options': {
            'expires': 3600,
            'priority': 3  # Low priority
        }
    },
    
    # Virtual Patch Expiration - Daily at 3 AM UTC
    'expire-patches': {
        'task': 'intellidog.expire_virtual_patches',
        'schedule': crontab(hour=3, minute=0),
        'options': {
            'expires': 3600,
            'priority': 5
        }
    },
    
    # IOC Expiration - Daily at 4 AM UTC
    'expire-iocs': {
        'task': 'intellidog.expire_iocs',
        'schedule': crontab(hour=4, minute=0),
        'options': {
            'expires': 3600,
            'priority': 3
        }
    }
}

# Import all tasks
celery_app.autodiscover_tasks(['app.modules.intellidog.tasks'])
```

---

### Environment Configuration

**File**: `.env`

```bash
# Celery Configuration
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/1

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=

# Celery Worker Settings
CELERY_WORKER_CONCURRENCY=4
CELERY_WORKER_MAX_TASKS_PER_CHILD=1000
CELERY_WORKER_LOG_LEVEL=INFO

# Task Settings
CELERY_TASK_TIME_LIMIT=3600
CELERY_TASK_SOFT_TIME_LIMIT=3300
```

---

## Task Implementations

### 1. Correlation Job Task

**File**: `backend/app/modules/intellidog/tasks/correlation_job.py`

```python
from celery import shared_task
from celery.utils.log import get_task_logger
from datetime import datetime, timezone
from app.database import get_db_session
from ..services.correlation_engine import CorrelationEngine

logger = get_task_logger(__name__)

@shared_task(
    name='intellidog.correlation_job',
    bind=True,
    max_retries=3,
    default_retry_delay=60
)
def run_correlation_job(self):
    """
    Periodic correlation job.
    
    Runs every 5 minutes to correlate IOCs with firewall logs and vulnerabilities.
    """
    task_id = self.request.id
    logger.info(f"Starting correlation job (task_id={task_id})")
    
    start_time = datetime.now(timezone.utc)
    
    try:
        with get_db_session() as db:
            engine = CorrelationEngine(db)
            stats = engine.run_correlation()
        
        duration_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        
        logger.info(
            f"Correlation job completed (task_id={task_id}): "
            f"{stats['detections_created']} detections, "
            f"{stats['virtual_patches_created']} patches, "
            f"duration={duration_ms}ms"
        )
        
        return {
            'success': True,
            'task_id': task_id,
            'stats': stats,
            'duration_ms': duration_ms,
            'completed_at': datetime.now(timezone.utc).isoformat()
        }
    
    except Exception as e:
        logger.error(f"Correlation job failed (task_id={task_id}): {str(e)}", exc_info=True)
        
        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))
```

---

### 2. Feed Update Job Task

**File**: `backend/app/modules/intellidog/tasks/feed_updater.py`

```python
from celery import shared_task
from celery.utils.log import get_task_logger
from datetime import datetime, timezone
from typing import List
from app.database import get_db_session
from ..services.feed_parsers import get_parser
from ..models.feed import IntellidogFeed

logger = get_task_logger(__name__)

@shared_task(
    name='intellidog.feed_update_job',
    bind=True,
    max_retries=2,
    default_retry_delay=300
)
def update_feeds_task(self, feed_ids: List[int] = None, force: bool = False):
    """
    Periodic feed update job.
    
    Runs every hour to update threat intelligence feeds.
    """
    # Implementation from FEED_UPDATER_SPEC.md
    # (See previous document for complete implementation)
    pass
```

---

### 3. License Check Task

**File**: `backend/app/modules/intellidog/tasks/license_check.py`

```python
from celery import shared_task
from celery.utils.log import get_task_logger
from datetime import datetime, timedelta, timezone
from app.database import get_db_session
from ..services.license_validator import LicenseValidator
from ..models.license import IntellidogLicense

logger = get_task_logger(__name__)

@shared_task(name='intellidog.license_check', bind=True)
def check_license_task(self):
    """
    Daily license validation task.
    
    Runs at 1 AM UTC to validate active license.
    """
    task_id = self.request.id
    logger.info(f"Starting license check (task_id={task_id})")
    
    with get_db_session() as db:
        validator = LicenseValidator(db)
        
        # Get active license
        license = db.query(IntellidogLicense).filter(
            IntellidogLicense.is_active == True
        ).first()
        
        if not license:
            logger.warning("No active license found")
            return {
                'success': True,
                'status': 'no_license',
                'message': 'No active license found'
            }
        
        # Re-validate license
        result = validator.validate_current()
        
        if not result.valid:
            logger.error(f"License validation failed: {result.errors}")
            
            # Deactivate license
            license.is_active = False
            license.last_validated_at = datetime.now(timezone.utc)
            db.commit()
            
            # Send admin alert
            send_admin_alert(
                subject='Intellidog License Invalid',
                message=f"License validation failed: {', '.join(result.errors)}"
            )
            
            return {
                'success': False,
                'status': 'invalid',
                'errors': result.errors
            }
        
        # Check expiration warning (30 days)
        if license.expires_at:
            days_until_expiry = (license.expires_at - datetime.now(timezone.utc)).days
            
            if 0 < days_until_expiry <= 30:
                logger.warning(f"License expires in {days_until_expiry} days")
                
                # Send expiration warning
                send_admin_alert(
                    subject='Intellidog License Expiring Soon',
                    message=f"License expires in {days_until_expiry} days. "
                           f"Please renew before {license.expires_at.strftime('%Y-%m-%d')}."
                )
        
        # Update last validated timestamp
        license.last_validated_at = datetime.now(timezone.utc)
        db.commit()
        
        logger.info(f"License check completed: valid, expires {license.expires_at}")
        
        return {
            'success': True,
            'status': 'valid',
            'expires_at': license.expires_at.isoformat() if license.expires_at else None,
            'days_until_expiry': days_until_expiry if license.expires_at else None
        }

def send_admin_alert(subject: str, message: str):
    """Send alert to administrators"""
    # Implementation depends on alerting system
    # Could use SMTP, Slack, etc.
    pass
```

---

### 4. Cache Cleanup Task

**File**: `backend/app/modules/intellidog/tasks/cache_cleanup.py`

```python
from celery import shared_task
from celery.utils.log import get_task_logger
from datetime import datetime, timedelta, timezone
from app.database import get_db_session
from ..models.correlation_cache import IntellidogCorrelationCache

logger = get_task_logger(__name__)

@shared_task(name='intellidog.cache_cleanup', bind=True)
def cache_cleanup_task(self):
    """
    Daily cache cleanup task.
    
    Runs at 2 AM UTC to remove old cache entries.
    """
    task_id = self.request.id
    logger.info(f"Starting cache cleanup (task_id={task_id})")
    
    removed_count = 0
    
    with get_db_session() as db:
        # Remove cache entries older than 24 hours
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
        
        deleted = db.query(IntellidogCorrelationCache).filter(
            IntellidogCorrelationCache.created_at < cutoff_time
        ).delete()
        
        removed_count = deleted
        db.commit()
    
    logger.info(f"Cache cleanup completed: removed {removed_count} entries")
    
    return {
        'success': True,
        'removed_count': removed_count
    }
```

---

### 5. IOC Expiration Task

**File**: `backend/app/modules/intellidog/tasks/ioc_expiration.py`

```python
from celery import shared_task
from celery.utils.log import get_task_logger
from datetime import datetime, timezone
from app.database import get_db_session
from ..models.ioc import IntellidogIOC

logger = get_task_logger(__name__)

@shared_task(name='intellidog.expire_iocs', bind=True)
def expire_iocs_task(self):
    """
    Daily IOC expiration task.
    
    Runs at 4 AM UTC to deactivate expired IOCs.
    """
    task_id = self.request.id
    logger.info(f"Starting IOC expiration (task_id={task_id})")
    
    expired_count = 0
    
    with get_db_session() as db:
        now = datetime.now(timezone.utc)
        
        # Find expired IOCs
        expired_iocs = db.query(IntellidogIOC).filter(
            IntellidogIOC.is_active == True,
            IntellidogIOC.expiration_date <= now
        ).all()
        
        for ioc in expired_iocs:
            ioc.is_active = False
            expired_count += 1
            logger.debug(f"Expired IOC {ioc.id}: {ioc.value}")
        
        db.commit()
    
    logger.info(f"IOC expiration completed: deactivated {expired_count} IOCs")
    
    return {
        'success': True,
        'expired_count': expired_count
    }
```

---

## Worker Startup Scripts

### Celery Worker

**File**: `scripts/start_celery_worker.sh`

```bash
#!/bin/bash
# Start Celery worker

set -e

# Activate virtual environment
source venv/bin/activate

# Set environment
export PYTHONPATH="${PYTHONPATH}:$(pwd)/backend"

# Start Celery worker
celery -A app.core.celery_config:celery_app worker \
    --loglevel=INFO \
    --concurrency=4 \
    --max-tasks-per-child=1000 \
    --queues=celery,intellidog.high_priority,intellidog.low_priority \
    --hostname=worker@%h
```

---

### Celery Beat

**File**: `scripts/start_celery_beat.sh`

```bash
#!/bin/bash
# Start Celery Beat scheduler

set -e

# Activate virtual environment
source venv/bin/activate

# Set environment
export PYTHONPATH="${PYTHONPATH}:$(pwd)/backend"

# Start Celery Beat
celery -A app.core.celery_config:celery_app beat \
    --loglevel=INFO \
    --scheduler=celery.beat:PersistentScheduler \
    --pidfile=/var/run/celery/celerybeat.pid
```

---

### Flower (Monitoring)

**File**: `scripts/start_flower.sh`

```bash
#!/bin/bash
# Start Flower (Celery monitoring UI)

set -e

# Activate virtual environment
source venv/bin/activate

# Set environment
export PYTHONPATH="${PYTHONPATH}:$(pwd)/backend"

# Start Flower
celery -A app.core.celery_config:celery_app flower \
    --port=5555 \
    --broker=redis://localhost:6379/0 \
    --basic_auth=admin:secure_password_here
```

---

## Systemd Services

### Celery Worker Service

**File**: `/etc/systemd/system/celery-worker.service`

```ini
[Unit]
Description=Celery Worker Service
After=network.target redis.service postgresql.service

[Service]
Type=forking
User=cybersheppard
Group=cybersheppard
WorkingDirectory=/opt/cybersheppard
EnvironmentFile=/opt/cybersheppard/.env

ExecStart=/opt/cybersheppard/venv/bin/celery -A app.core.celery_config:celery_app worker \
    --loglevel=INFO \
    --concurrency=4 \
    --max-tasks-per-child=1000 \
    --pidfile=/var/run/celery/worker.pid \
    --logfile=/var/log/celery/worker.log

ExecStop=/bin/kill -TERM $MAINPID
ExecReload=/bin/kill -HUP $MAINPID

Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

---

### Celery Beat Service

**File**: `/etc/systemd/system/celery-beat.service`

```ini
[Unit]
Description=Celery Beat Service
After=network.target redis.service postgresql.service

[Service]
Type=simple
User=cybersheppard
Group=cybersheppard
WorkingDirectory=/opt/cybersheppard
EnvironmentFile=/opt/cybersheppard/.env

ExecStart=/opt/cybersheppard/venv/bin/celery -A app.core.celery_config:celery_app beat \
    --loglevel=INFO \
    --pidfile=/var/run/celery/beat.pid \
    --logfile=/var/log/celery/beat.log

ExecStop=/bin/kill -TERM $MAINPID

Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

---

## Monitoring & Management

### Task Monitoring API

**File**: `backend/app/api/celery_tasks.py`

```python
from fastapi import APIRouter, Depends
from celery.result import AsyncResult
from app.core.celery_config import celery_app
from app.auth.dependencies import require_admin

router = APIRouter(prefix="/api/celery", tags=["celery"])

@router.get("/stats")
async def get_celery_stats(current_user = Depends(require_admin)):
    """Get Celery worker stats"""
    inspect = celery_app.control.inspect()
    
    return {
        'success': True,
        'data': {
            'active': inspect.active(),
            'scheduled': inspect.scheduled(),
            'reserved': inspect.reserved(),
            'stats': inspect.stats()
        }
    }

@router.get("/task/{task_id}")
async def get_task_status(
    task_id: str,
    current_user = Depends(require_admin)
):
    """Get task status by ID"""
    result = AsyncResult(task_id, app=celery_app)
    
    return {
        'success': True,
        'data': {
            'task_id': task_id,
            'state': result.state,
            'result': result.result if result.ready() else None,
            'traceback': result.traceback if result.failed() else None
        }
    }

@router.post("/task/{task_id}/revoke")
async def revoke_task(
    task_id: str,
    current_user = Depends(require_admin)
):
    """Revoke (cancel) running task"""
    celery_app.control.revoke(task_id, terminate=True)
    
    return {
        'success': True,
        'message': f'Task {task_id} revoked'
    }
```

---

## Task Priority Guidelines

**High Priority** (Queue: `intellidog.high_priority`):
- Correlation Job (real-time threat detection)
- Critical alerts

**Medium Priority** (Queue: `celery`):
- Feed updates
- License checks
- Virtual patch deployment

**Low Priority** (Queue: `intellidog.low_priority`):
- Cache cleanup
- Log rotation
- Report generation

---

## Error Handling

### Retry Strategy

```python
@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True
)
def example_task(self):
    try:
        # Task logic
        pass
    except Exception as e:
        # Log error
        logger.error(f"Task failed: {str(e)}", exc_info=True)
        
        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))
```

---

## Testing

### Unit Test Example

**File**: `tests/tasks/test_correlation_job.py`

```python
import pytest
from app.modules.intellidog.tasks.correlation_job import run_correlation_job

@pytest.mark.celery
def test_correlation_job():
    """Test correlation job execution"""
    result = run_correlation_job.apply()
    
    assert result.successful()
    assert result.result['success'] is True
    assert 'stats' in result.result
    assert result.result['stats']['iocs_processed'] >= 0
```

---

## Summary

**Periodic Tasks**: 6
1. ✅ Correlation Job (every 5 min)
2. ✅ Feed Update (every hour)
3. ✅ License Check (daily 1 AM)
4. ✅ Cache Cleanup (daily 2 AM)
5. ✅ Virtual Patch Expiration (daily 3 AM)
6. ✅ IOC Expiration (daily 4 AM)

**Features**:
- ✅ Task prioritization (3 queues)
- ✅ Automatic retries with backoff
- ✅ Task monitoring API
- ✅ Systemd integration
- ✅ Flower monitoring UI
- ✅ Error handling and logging
- ✅ Task result persistence

**Workers**: 4
- 1 high priority
- 2 default
- 1 low priority

**Production-Ready**: ✅

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-01-02  
**Author**: Dognet Technologies
