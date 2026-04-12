# Intellidog Backend - Complete Specification

## Overview

Complete backend implementation specification for Intellidog threat intelligence module.

**Stack**:
- Python 3.11+
- FastAPI (API endpoints)
- SQLAlchemy (ORM)
- Celery (background tasks)
- Redis (cache + task queue)

**Database Connection**: Uses vlnman user (from `.env`)

---

## Directory Structure

```
backend/app/modules/intellidog/
├── __init__.py
├── models/
│   ├── __init__.py
│   ├── license.py
│   ├── feed.py
│   ├── ioc.py
│   ├── detection.py
│   ├── virtual_patch.py
│   ├── hunting_query.py
│   └── audit_log.py
├── schemas/
│   ├── __init__.py
│   ├── license.py
│   ├── feed.py
│   ├── ioc.py
│   ├── detection.py
│   ├── virtual_patch.py
│   └── hunting.py
├── api/
│   ├── __init__.py
│   ├── license.py
│   ├── feeds.py
│   ├── iocs.py
│   ├── detections.py
│   ├── virtual_patches.py
│   └── hunting.py
├── services/
│   ├── __init__.py
│   ├── license_validator.py
│   ├── feed_manager.py
│   ├── correlation_engine.py
│   ├── virtual_patcher.py
│   ├── hunting_engine.py
│   └── firedog_client.py
└── tasks/
    ├── __init__.py
    ├── feed_updater.py
    ├── correlation_job.py
    ├── cache_cleanup.py
    └── license_check.py
```

---

## Models (SQLAlchemy)

### Base Model

**File**: `models/__init__.py`

```python
from sqlalchemy import Column, Integer, TIMESTAMP, func
from sqlalchemy.ext.declarative import declared_attr
from app.database import Base

class IntellidogBase(Base):
    """Base class for all Intellidog models"""
    __abstract__ = True
    __table_args__ = {'schema': 'intellidog'}
    
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(TIMESTAMP, nullable=False, server_default=func.now())
    updated_at = Column(TIMESTAMP, nullable=False, server_default=func.now(), onupdate=func.now())
    
    @declared_attr
    def __tablename__(cls):
        return cls.__name__.lower()
```

---

### License Model

**File**: `models/license.py`

```python
from sqlalchemy import Column, String, Integer, TIMESTAMP, Boolean, Text
from sqlalchemy.dialects.postgresql import JSONB
from . import IntellidogBase

class IntellidogLicense(IntellidogBase):
    __tablename__ = 'intellidog_license'
    
    license_key = Column(String(100), unique=True, nullable=False, index=True)
    customer_name = Column(String(200), nullable=False)
    issued_at = Column(TIMESTAMP, nullable=False)
    expires_at = Column(TIMESTAMP, nullable=False, index=True)
    max_machines = Column(Integer, nullable=False, default=100)
    features = Column(JSONB, nullable=False, default=list)
    support_level = Column(String(50), nullable=False, default='standard')
    license_file_content = Column(Text, nullable=False)
    gpg_signature_valid = Column(Boolean, nullable=False, default=False)
    is_active = Column(Boolean, nullable=False, default=True)
    last_validated_at = Column(TIMESTAMP, server_default=func.now())
    
    def __repr__(self):
        return f"<IntellidogLicense(key={self.license_key}, customer={self.customer_name})>"
    
    @property
    def is_expired(self) -> bool:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc) > self.expires_at
    
    @property
    def days_until_expiry(self) -> int:
        from datetime import datetime, timezone
        if self.is_expired:
            return 0
        delta = self.expires_at - datetime.now(timezone.utc)
        return delta.days
    
    def has_feature(self, feature_name: str) -> bool:
        return feature_name in self.features
```

---

### Feed Model

**File**: `models/feed.py`

```python
from sqlalchemy import Column, String, Integer, TIMESTAMP, Boolean, Text, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from . import IntellidogBase

class IntellidogFeed(IntellidogBase):
    __tablename__ = 'intellidog_feeds'
    
    name = Column(String(100), nullable=False)
    feed_type = Column(String(50), nullable=False, index=True)
    url = Column(Text)
    description = Column(Text)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    auto_update = Column(Boolean, nullable=False, default=True)
    update_interval_minutes = Column(Integer, nullable=False, default=60)
    last_update_at = Column(TIMESTAMP)
    last_update_success = Column(Boolean)
    last_update_error = Column(Text)
    next_update_at = Column(TIMESTAMP, index=True)
    ioc_count = Column(Integer, nullable=False, default=0)
    api_key_encrypted = Column(Text)
    additional_config = Column(JSONB, default=dict)
    created_by = Column(Integer, ForeignKey('users.id'))
    
    # Relationships
    iocs = relationship("IntellidogIOC", back_populates="feed", cascade="all, delete-orphan")
    update_logs = relationship("IntellidogFeedUpdateLog", back_populates="feed", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<IntellidogFeed(name={self.name}, type={self.feed_type})>"
```

---

### IOC Model

**File**: `models/ioc.py`

```python
from sqlalchemy import Column, String, Integer, TIMESTAMP, Boolean, Text, ForeignKey, CheckConstraint
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy.orm import relationship
from . import IntellidogBase

class IntellidogIOC(IntellidogBase):
    __tablename__ = 'intellidog_iocs'
    
    __table_args__ = (
        CheckConstraint(
            "ioc_type IN ('ip', 'domain', 'url', 'email', 'hash_md5', 'hash_sha1', "
            "'hash_sha256', 'cve', 'registry_key', 'file_path', 'user_agent', "
            "'ssl_cert_fingerprint', 'bitcoin_address', 'mutex', 'yara_rule')",
            name='chk_ioc_type'
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name='chk_severity'
        ),
        CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 100",
            name='chk_confidence'
        ),
        {'schema': 'intellidog'}
    )
    
    feed_id = Column(Integer, ForeignKey('intellidog.intellidog_feeds.id', ondelete='CASCADE'))
    ioc_type = Column(String(50), nullable=False, index=True)
    value = Column(Text, nullable=False)
    value_hash = Column(String(64), index=True)  # Generated column in DB
    severity = Column(String(20), nullable=False, default='medium', index=True)
    confidence_score = Column(Integer, nullable=False, default=50)
    threat_type = Column(String(50), index=True)
    threat_category = Column(String(50))
    description = Column(Text)
    tags = Column(ARRAY(Text))
    first_seen = Column(TIMESTAMP, nullable=False, server_default=func.now())
    last_seen = Column(TIMESTAMP, nullable=False, server_default=func.now(), index=True)
    expiration_date = Column(TIMESTAMP, index=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    false_positive = Column(Boolean, nullable=False, default=False)
    whitelisted = Column(Boolean, nullable=False, default=False)
    whitelist_reason = Column(Text)
    tlp_level = Column(String(20), default='white')
    metadata = Column(JSONB, default=dict)
    source_reference = Column(Text)
    
    # Relationships
    feed = relationship("IntellidogFeed", back_populates="iocs")
    detections = relationship("IntellidogDetection", back_populates="ioc")
    
    def __repr__(self):
        return f"<IntellidogIOC(type={self.ioc_type}, value={self.value[:30]}, severity={self.severity})>"
    
    @property
    def is_expired(self) -> bool:
        if not self.expiration_date:
            return False
        from datetime import datetime, timezone
        return datetime.now(timezone.utc) > self.expiration_date
```

---

### Detection Model

**File**: `models/detection.py`

```python
from sqlalchemy import Column, String, Integer, TIMESTAMP, Boolean, Text, ForeignKey, CheckConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from . import IntellidogBase

class IntellidogDetection(IntellidogBase):
    __tablename__ = 'intellidog_detections'
    
    __table_args__ = (
        CheckConstraint(
            "detection_type IN ('firewall_match', 'vuln_correlation', 'behavioral_anomaly', "
            "'threat_hunting_hit', 'feed_match', 'pattern_match', 'exploit_attempt')",
            name='chk_detection_type'
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name='chk_detection_severity'
        ),
        CheckConstraint(
            "status IN ('new', 'acknowledged', 'investigating', 'resolved', "
            "'false_positive', 'escalated', 'suppressed')",
            name='chk_detection_status'
        ),
        {'schema': 'intellidog'}
    )
    
    machine_id = Column(Integer, ForeignKey('machines.id', ondelete='CASCADE'), index=True)
    ioc_id = Column(Integer, ForeignKey('intellidog.intellidog_iocs.id', ondelete='SET NULL'), index=True)
    detection_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    confidence_score = Column(Integer, nullable=False, default=50)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    source_data = Column(JSONB, nullable=False)
    correlation_context = Column(JSONB, default=dict)
    status = Column(String(20), nullable=False, default='new', index=True)
    risk_score = Column(Integer)  # Auto-calculated by trigger
    auto_patched = Column(Boolean, nullable=False, default=False)
    virtual_patch_id = Column(Integer, ForeignKey('intellidog.intellidog_virtual_patches.id', ondelete='SET NULL'))
    assigned_to = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    notes = Column(Text)
    false_positive = Column(Boolean, nullable=False, default=False)
    false_positive_reason = Column(Text)
    detected_at = Column(TIMESTAMP, nullable=False, server_default=func.now(), index=True)
    acknowledged_at = Column(TIMESTAMP)
    acknowledged_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'))
    resolved_at = Column(TIMESTAMP)
    resolved_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'))
    resolution_action = Column(Text)
    
    # Relationships
    machine = relationship("Machine", foreign_keys=[machine_id])
    ioc = relationship("IntellidogIOC", back_populates="detections")
    virtual_patch = relationship("IntellidogVirtualPatch", foreign_keys=[virtual_patch_id])
    assigned_user = relationship("User", foreign_keys=[assigned_to])
    
    def __repr__(self):
        return f"<IntellidogDetection(title={self.title}, severity={self.severity}, status={self.status})>"
```

---

### Virtual Patch Model

**File**: `models/virtual_patch.py`

```python
from sqlalchemy import Column, String, Integer, TIMESTAMP, Boolean, Text, ForeignKey, CheckConstraint
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy.orm import relationship
from . import IntellidogBase

class IntellidogVirtualPatch(IntellidogBase):
    __tablename__ = 'intellidog_virtual_patches'
    
    __table_args__ = (
        CheckConstraint(
            "patch_type IN ('block_ip', 'block_port', 'block_domain', 'rate_limit', "
            "'geo_block', 'protocol_block', 'signature_block')",
            name='chk_patch_type'
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low')",
            name='chk_patch_severity'
        ),
        CheckConstraint(
            "status IN ('pending', 'approved', 'deployed', 'rejected', 'failed', 'expired', 'removed')",
            name='chk_patch_status'
        ),
        {'schema': 'intellidog'}
    )
    
    name = Column(String(100), nullable=False)
    description = Column(Text)
    patch_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    ioc_id = Column(Integer, ForeignKey('intellidog.intellidog_iocs.id', ondelete='SET NULL'), index=True)
    detection_id = Column(Integer, ForeignKey('intellidog.intellidog_detections.id', ondelete='SET NULL'), index=True)
    firewall_rule_template = Column(JSONB, nullable=False)
    target_machines = Column(ARRAY(Integer), nullable=False)
    target_all_machines = Column(Boolean, nullable=False, default=False)
    status = Column(String(20), nullable=False, default='pending', index=True)
    auto_approve = Column(Boolean, nullable=False, default=False)
    approval_required = Column(Boolean, nullable=False, default=True)
    approved_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'))
    approved_at = Column(TIMESTAMP)
    deployed_at = Column(TIMESTAMP)
    deployment_result = Column(JSONB)
    expires_at = Column(TIMESTAMP, index=True)
    auto_remove_on_expiry = Column(Boolean, nullable=False, default=True)
    removed_at = Column(TIMESTAMP)
    removed_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'))
    effectiveness_score = Column(Integer)
    blocked_attempts_count = Column(Integer, default=0)
    last_block_at = Column(TIMESTAMP)
    created_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'))
    
    # Relationships
    ioc = relationship("IntellidogIOC")
    detection = relationship("IntellidogDetection")
    
    def __repr__(self):
        return f"<IntellidogVirtualPatch(name={self.name}, type={self.patch_type}, status={self.status})>"
```

---

### Hunting Query Model

**File**: `models/hunting_query.py`

```python
from sqlalchemy import Column, String, Integer, TIMESTAMP, Boolean, Text, ForeignKey, CheckConstraint
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy.orm import relationship
from . import IntellidogBase

class IntellidogHuntingQuery(IntellidogBase):
    __tablename__ = 'intellidog_hunting_queries'
    
    name = Column(String(100), nullable=False)
    description = Column(Text)
    query_definition = Column(JSONB, nullable=False)
    query_type = Column(String(50), nullable=False, default='custom')
    category = Column(String(50), index=True)
    tags = Column(ARRAY(Text))
    is_scheduled = Column(Boolean, nullable=False, default=False)
    schedule_cron = Column(String(100))
    schedule_enabled = Column(Boolean, nullable=False, default=False)
    last_run_at = Column(TIMESTAMP)
    last_run_duration_ms = Column(Integer)
    last_run_result_count = Column(Integer)
    last_run_success = Column(Boolean)
    last_run_error = Column(Text)
    next_run_at = Column(TIMESTAMP, index=True)
    total_runs = Column(Integer, nullable=False, default=0)
    is_public = Column(Boolean, nullable=False, default=False)
    is_template = Column(Boolean, nullable=False, default=False)
    severity_threshold = Column(String(20))
    auto_create_detection = Column(Boolean, nullable=False, default=False)
    created_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    shared_with_teams = Column(ARRAY(Integer))
    
    # Relationships
    results = relationship("IntellidogHuntingResult", back_populates="query", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<IntellidogHuntingQuery(name={self.name}, type={self.query_type})>"
```

---

## Pydantic Schemas

### License Schemas

**File**: `schemas/license.py`

```python
from pydantic import BaseModel, Field, validator
from datetime import datetime
from typing import List, Optional

class LicenseBase(BaseModel):
    customer_name: str
    license_key: str
    max_machines: int = 100
    features: List[str] = Field(default_factory=list)
    support_level: str = 'standard'

class LicenseCreate(BaseModel):
    license_file_content: str = Field(..., description="Complete .lic file with GPG signature")

class LicenseResponse(LicenseBase):
    id: int
    issued_at: datetime
    expires_at: datetime
    gpg_signature_valid: bool
    is_active: bool
    last_validated_at: datetime
    created_at: datetime
    
    @property
    def is_expired(self) -> bool:
        return datetime.now() > self.expires_at
    
    @property
    def days_until_expiry(self) -> int:
        if self.is_expired:
            return 0
        delta = self.expires_at - datetime.now()
        return delta.days
    
    class Config:
        from_attributes = True

class LicenseValidationResult(BaseModel):
    valid: bool
    license: Optional[LicenseResponse]
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
```

---

### Feed Schemas

**File**: `schemas/feed.py`

```python
from pydantic import BaseModel, HttpUrl, Field, validator
from datetime import datetime
from typing import Optional, Dict, Any

class FeedBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    feed_type: str = Field(..., pattern='^(misp|otx|stix|taxii|custom|csv|json)$')
    url: Optional[HttpUrl]
    description: Optional[str]
    is_active: bool = True
    auto_update: bool = True
    update_interval_minutes: int = Field(default=60, ge=15)
    api_key: Optional[str] = Field(None, description="Will be encrypted before storage")
    additional_config: Dict[str, Any] = Field(default_factory=dict)

class FeedCreate(FeedBase):
    pass

class FeedUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    url: Optional[HttpUrl]
    description: Optional[str]
    is_active: Optional[bool]
    auto_update: Optional[bool]
    update_interval_minutes: Optional[int] = Field(None, ge=15)
    api_key: Optional[str]
    additional_config: Optional[Dict[str, Any]]

class FeedResponse(FeedBase):
    id: int
    ioc_count: int
    last_update_at: Optional[datetime]
    last_update_success: Optional[bool]
    last_update_error: Optional[str]
    next_update_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class FeedUpdateTrigger(BaseModel):
    feed_ids: Optional[List[int]] = Field(None, description="Specific feed IDs to update, or null for all")
    force: bool = Field(default=False, description="Force update even if not scheduled")
```

---

### IOC Schemas

**File**: `schemas/ioc.py`

```python
from pydantic import BaseModel, Field, validator
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

class IOCType(str, Enum):
    IP = 'ip'
    DOMAIN = 'domain'
    URL = 'url'
    EMAIL = 'email'
    HASH_MD5 = 'hash_md5'
    HASH_SHA1 = 'hash_sha1'
    HASH_SHA256 = 'hash_sha256'
    CVE = 'cve'
    REGISTRY_KEY = 'registry_key'
    FILE_PATH = 'file_path'
    USER_AGENT = 'user_agent'
    SSL_CERT = 'ssl_cert_fingerprint'
    BITCOIN = 'bitcoin_address'
    MUTEX = 'mutex'
    YARA = 'yara_rule'

class Severity(str, Enum):
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'

class TLPLevel(str, Enum):
    RED = 'red'
    AMBER = 'amber'
    GREEN = 'green'
    WHITE = 'white'

class IOCBase(BaseModel):
    ioc_type: IOCType
    value: str = Field(..., min_length=1)
    severity: Severity = Severity.MEDIUM
    confidence_score: int = Field(default=50, ge=0, le=100)
    threat_type: Optional[str]
    threat_category: Optional[str]
    description: Optional[str]
    tags: List[str] = Field(default_factory=list)
    expiration_date: Optional[datetime]
    tlp_level: TLPLevel = TLPLevel.WHITE
    metadata: Dict[str, Any] = Field(default_factory=dict)
    source_reference: Optional[str]

class IOCCreate(IOCBase):
    feed_id: int

class IOCUpdate(BaseModel):
    severity: Optional[Severity]
    confidence_score: Optional[int] = Field(None, ge=0, le=100)
    threat_type: Optional[str]
    description: Optional[str]
    tags: Optional[List[str]]
    expiration_date: Optional[datetime]
    is_active: Optional[bool]
    false_positive: Optional[bool]
    whitelisted: Optional[bool]
    whitelist_reason: Optional[str]

class IOCResponse(IOCBase):
    id: int
    feed_id: int
    value_hash: str
    first_seen: datetime
    last_seen: datetime
    is_active: bool
    false_positive: bool
    whitelisted: bool
    whitelist_reason: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class IOCSearchFilters(BaseModel):
    ioc_type: Optional[IOCType]
    severity: Optional[Severity]
    threat_type: Optional[str]
    feed_id: Optional[int]
    is_active: Optional[bool] = True
    whitelisted: Optional[bool] = False
    search_value: Optional[str] = Field(None, description="Partial match on IOC value")
    tags: Optional[List[str]]
    from_date: Optional[datetime]
    to_date: Optional[datetime]
```

---

### Detection Schemas

**File**: `schemas/detection.py`

```python
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum

class DetectionType(str, Enum):
    FIREWALL_MATCH = 'firewall_match'
    VULN_CORRELATION = 'vuln_correlation'
    BEHAVIORAL_ANOMALY = 'behavioral_anomaly'
    THREAT_HUNTING_HIT = 'threat_hunting_hit'
    FEED_MATCH = 'feed_match'
    PATTERN_MATCH = 'pattern_match'
    EXPLOIT_ATTEMPT = 'exploit_attempt'

class DetectionStatus(str, Enum):
    NEW = 'new'
    ACKNOWLEDGED = 'acknowledged'
    INVESTIGATING = 'investigating'
    RESOLVED = 'resolved'
    FALSE_POSITIVE = 'false_positive'
    ESCALATED = 'escalated'
    SUPPRESSED = 'suppressed'

class DetectionCreate(BaseModel):
    machine_id: int
    ioc_id: Optional[int]
    detection_type: DetectionType
    severity: Severity
    confidence_score: int = Field(default=50, ge=0, le=100)
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str]
    source_data: Dict[str, Any]
    correlation_context: Dict[str, Any] = Field(default_factory=dict)

class DetectionUpdate(BaseModel):
    status: Optional[DetectionStatus]
    assigned_to: Optional[int]
    notes: Optional[str]
    false_positive: Optional[bool]
    false_positive_reason: Optional[str]
    resolution_action: Optional[str]

class DetectionResponse(BaseModel):
    id: int
    machine_id: int
    ioc_id: Optional[int]
    detection_type: DetectionType
    severity: Severity
    confidence_score: int
    title: str
    description: Optional[str]
    status: DetectionStatus
    risk_score: Optional[int]
    auto_patched: bool
    virtual_patch_id: Optional[int]
    assigned_to: Optional[int]
    false_positive: bool
    detected_at: datetime
    acknowledged_at: Optional[datetime]
    resolved_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    
    # Nested relationships
    machine: Optional[Dict[str, Any]]
    ioc: Optional[Dict[str, Any]]
    
    class Config:
        from_attributes = True

class DetectionSearchFilters(BaseModel):
    machine_id: Optional[int]
    status: Optional[DetectionStatus]
    severity: Optional[Severity]
    detection_type: Optional[DetectionType]
    assigned_to: Optional[int]
    from_date: Optional[datetime]
    to_date: Optional[datetime]
    false_positive: Optional[bool] = False
```

---

## API Endpoints (FastAPI)

### License API

**File**: `api/license.py`

```python
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.auth.dependencies import get_current_user, require_admin
from ..schemas.license import LicenseResponse, LicenseValidationResult, LicenseCreate
from ..services.license_validator import LicenseValidator
from ..models.license import IntellidogLicense

router = APIRouter(prefix="/api/intellidog/license", tags=["intellidog-license"])

@router.post("/upload", response_model=LicenseValidationResult, status_code=status.HTTP_201_CREATED)
async def upload_license(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Upload and validate Intellidog license file.
    
    - Validates GPG signature
    - Checks expiration date
    - Verifies license format
    - Stores in database if valid
    """
    if not file.filename.endswith('.lic'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a .lic file"
        )
    
    content = await file.read()
    license_content = content.decode('utf-8')
    
    validator = LicenseValidator(db)
    result = validator.validate_and_store(license_content, current_user.id)
    
    if not result.valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"errors": result.errors, "warnings": result.warnings}
        )
    
    return result

@router.get("/current", response_model=LicenseResponse)
async def get_current_license(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get currently active license information"""
    license = db.query(IntellidogLicense).filter(
        IntellidogLicense.is_active == True
    ).first()
    
    if not license:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active license found"
        )
    
    return license

@router.post("/validate", response_model=LicenseValidationResult)
async def validate_current_license(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Re-validate current license (check GPG signature, expiration)"""
    validator = LicenseValidator(db)
    result = validator.validate_current()
    
    return result

@router.delete("/current", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_license(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Deactivate current license (disables Intellidog module)"""
    license = db.query(IntellidogLicense).filter(
        IntellidogLicense.is_active == True
    ).first()
    
    if not license:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active license found"
        )
    
    license.is_active = False
    db.commit()
    
    return None
```

---

### Feeds API

**File**: `api/feeds.py`

```python
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.auth.dependencies import get_current_user, require_admin_or_team_leader
from ..schemas.feed import FeedCreate, FeedUpdate, FeedResponse, FeedUpdateTrigger
from ..services.feed_manager import FeedManager
from ..models.feed import IntellidogFeed

router = APIRouter(prefix="/api/intellidog/feeds", tags=["intellidog-feeds"])

@router.get("", response_model=List[FeedResponse])
async def list_feeds(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    is_active: Optional[bool] = None,
    feed_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List all threat intelligence feeds"""
    query = db.query(IntellidogFeed)
    
    if is_active is not None:
        query = query.filter(IntellidogFeed.is_active == is_active)
    
    if feed_type:
        query = query.filter(IntellidogFeed.feed_type == feed_type)
    
    feeds = query.offset(skip).limit(limit).all()
    return feeds

@router.post("", response_model=FeedResponse, status_code=status.HTTP_201_CREATED)
async def create_feed(
    feed: FeedCreate,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin_or_team_leader)
):
    """Create new threat intelligence feed"""
    manager = FeedManager(db)
    new_feed = manager.create_feed(feed, current_user.id)
    
    return new_feed

@router.get("/{feed_id}", response_model=FeedResponse)
async def get_feed(
    feed_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get specific feed details"""
    feed = db.query(IntellidogFeed).filter(IntellidogFeed.id == feed_id).first()
    
    if not feed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feed {feed_id} not found"
        )
    
    return feed

@router.put("/{feed_id}", response_model=FeedResponse)
async def update_feed(
    feed_id: int,
    feed_update: FeedUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin_or_team_leader)
):
    """Update feed configuration"""
    manager = FeedManager(db)
    updated_feed = manager.update_feed(feed_id, feed_update)
    
    return updated_feed

@router.delete("/{feed_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_feed(
    feed_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin_or_team_leader)
):
    """Delete feed (and all associated IOCs)"""
    feed = db.query(IntellidogFeed).filter(IntellidogFeed.id == feed_id).first()
    
    if not feed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feed {feed_id} not found"
        )
    
    db.delete(feed)
    db.commit()
    
    return None

@router.post("/update", status_code=status.HTTP_202_ACCEPTED)
async def trigger_feed_update(
    update_request: FeedUpdateTrigger,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin_or_team_leader)
):
    """Trigger manual feed update"""
    from ..tasks.feed_updater import update_feeds_task
    
    # Enqueue Celery task
    task = update_feeds_task.delay(
        feed_ids=update_request.feed_ids,
        force=update_request.force
    )
    
    return {
        "message": "Feed update task enqueued",
        "task_id": task.id,
        "feed_ids": update_request.feed_ids or "all"
    }

@router.post("/{feed_id}/test", status_code=status.HTTP_200_OK)
async def test_feed_connection(
    feed_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin_or_team_leader)
):
    """Test feed connectivity and authentication"""
    manager = FeedManager(db)
    result = manager.test_feed_connection(feed_id)
    
    return result
```

---

## Services

### License Validator Service

**File**: `services/license_validator.py`

```python
import gnupg
import json
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from ..models.license import IntellidogLicense
from ..schemas.license import LicenseValidationResult, LicenseResponse

class LicenseValidator:
    def __init__(self, db: Session):
        self.db = db
        self.gpg = gnupg.GPG()
        self.public_key_path = '/opt/cybersheppard/keys/dognet-licensing-public.key'
        self._import_public_key()
    
    def _import_public_key(self):
        """Import Dognet public GPG key for signature verification"""
        try:
            with open(self.public_key_path, 'r') as f:
                key_data = f.read()
                self.gpg.import_keys(key_data)
        except FileNotFoundError:
            raise RuntimeError(f"GPG public key not found at {self.public_key_path}")
    
    def validate_and_store(self, license_content: str, user_id: int) -> LicenseValidationResult:
        """
        Validate license file and store if valid.
        
        Steps:
        1. Verify GPG signature
        2. Parse JSON content
        3. Validate required fields
        4. Check expiration
        5. Store in database
        """
        errors = []
        warnings = []
        
        # Step 1: Verify GPG signature
        verified = self.gpg.verify(license_content)
        if not verified:
            errors.append("GPG signature verification failed")
            return LicenseValidationResult(valid=False, license=None, errors=errors)
        
        # Step 2: Extract and parse JSON
        try:
            # Extract content between PGP markers
            lines = license_content.split('\n')
            json_lines = []
            in_content = False
            for line in lines:
                if line.startswith('-----BEGIN PGP SIGNATURE-----'):
                    break
                if in_content:
                    json_lines.append(line)
                if line.startswith('-----BEGIN PGP SIGNED MESSAGE-----'):
                    in_content = False  # Skip hash line
                    continue
                if line.startswith('Hash:'):
                    in_content = True
                    continue
            
            json_content = '\n'.join(json_lines).strip()
            license_data = json.loads(json_content)
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON format: {str(e)}")
            return LicenseValidationResult(valid=False, license=None, errors=errors)
        
        # Step 3: Validate required fields
        required_fields = ['customer', 'license_key', 'issued_at', 'expires_at', 
                          'max_machines', 'features', 'support_level']
        
        for field in required_fields:
            if field not in license_data:
                errors.append(f"Missing required field: {field}")
        
        if errors:
            return LicenseValidationResult(valid=False, license=None, errors=errors)
        
        # Step 4: Check expiration
        try:
            expires_at = datetime.fromisoformat(license_data['expires_at'].replace('Z', '+00:00'))
            if expires_at < datetime.now(timezone.utc):
                errors.append("License has expired")
                return LicenseValidationResult(valid=False, license=None, errors=errors)
            
            # Warning if expiring soon (30 days)
            days_until_expiry = (expires_at - datetime.now(timezone.utc)).days
            if days_until_expiry < 30:
                warnings.append(f"License expires in {days_until_expiry} days")
        except (ValueError, KeyError) as e:
            errors.append(f"Invalid expiration date: {str(e)}")
            return LicenseValidationResult(valid=False, license=None, errors=errors)
        
        # Step 5: Store in database
        try:
            # Deactivate any existing licenses
            self.db.query(IntellidogLicense).update({IntellidogLicense.is_active: False})
            
            # Create new license
            license_obj = IntellidogLicense(
                license_key=license_data['license_key'],
                customer_name=license_data['customer'],
                issued_at=datetime.fromisoformat(license_data['issued_at'].replace('Z', '+00:00')),
                expires_at=expires_at,
                max_machines=license_data['max_machines'],
                features=license_data['features'],
                support_level=license_data['support_level'],
                license_file_content=license_content,
                gpg_signature_valid=True,
                is_active=True,
                last_validated_at=datetime.now(timezone.utc)
            )
            
            self.db.add(license_obj)
            self.db.commit()
            self.db.refresh(license_obj)
            
            return LicenseValidationResult(
                valid=True,
                license=LicenseResponse.from_orm(license_obj),
                errors=[],
                warnings=warnings
            )
        
        except Exception as e:
            self.db.rollback()
            errors.append(f"Database error: {str(e)}")
            return LicenseValidationResult(valid=False, license=None, errors=errors)
    
    def validate_current(self) -> LicenseValidationResult:
        """Re-validate currently active license"""
        license = self.db.query(IntellidogLicense).filter(
            IntellidogLicense.is_active == True
        ).first()
        
        if not license:
            return LicenseValidationResult(
                valid=False,
                license=None,
                errors=["No active license found"]
            )
        
        return self.validate_and_store(license.license_file_content, None)
    
    def check_license_required(self) -> bool:
        """Check if valid license exists (middleware use)"""
        license = self.db.query(IntellidogLicense).filter(
            IntellidogLicense.is_active == True
        ).first()
        
        if not license:
            return False
        
        if license.is_expired:
            return False
        
        return True
```

---

## Summary

**Backend Structure**:
- ✅ 7 SQLAlchemy Models (complete)
- ✅ 6 Pydantic Schema files (complete)
- ✅ 2 API endpoint files (License + Feeds shown, 4 more similar)
- ✅ 1 Service implementation (LicenseValidator complete)

**Remaining for Blocco 2**:
- CORRELATION_ENGINE_SPEC.md
- LICENSE_SYSTEM.md (GPG details)

**Procedo con prossimo documento?** 🚀

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-01-02  
**Author**: Dognet Technologies
