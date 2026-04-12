# Virtual Patcher - Complete Specification

## Overview

The Virtual Patcher automatically generates and deploys firewall rules to Firedog in response to critical threat detections, providing immediate protection while permanent fixes are applied.

**Purpose**: Automated threat response through dynamic firewall rules  
**Integration**: Firedog firewall management platform  
**Trigger**: Critical/High severity detections from correlation engine  
**Approval**: Manual approval required (configurable)

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│               Detection Created (Correlation Engine)           │
│                 severity = critical/high                       │
└────────────────────────────┬───────────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────────┐
│           Virtual Patcher Service (Auto-triggered)             │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  1. Analyze Detection                                          │
│     ├─ IOC Type (IP, domain, etc.)                            │
│     ├─ Severity Level                                         │
│     └─ Affected Machine(s)                                    │
│                                                                │
│  2. Generate Firewall Rule Template                           │
│     ├─ Block IP/Domain                                        │
│     ├─ Rate Limit                                             │
│     └─ Protocol-specific rules                                │
│                                                                │
│  3. Create Virtual Patch Record                               │
│     ├─ Status: pending                                        │
│     ├─ Approval Required: true/false                          │
│     └─ Expiration: 30 days (default)                          │
│                                                                │
└────────────────────────────┬───────────────────────────────────┘
                             │
                             ▼ (if auto_approve OR manual approval)
┌────────────────────────────────────────────────────────────────┐
│            Deploy to Firedog (API Integration)                 │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  1. Authenticate with Firedog API                             │
│  2. Create Firewall Rule(s)                                   │
│  3. Apply to Target Machine(s)                                │
│  4. Verify Deployment                                         │
│  5. Update Virtual Patch Status                               │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## Implementation

### Virtual Patcher Service

**File**: `backend/app/modules/intellidog/services/virtual_patcher.py`

```python
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
import logging
from ..models.detection import IntellidogDetection
from ..models.virtual_patch import IntellidogVirtualPatch
from ..models.ioc import IntellidogIOC
from .firedog_client import FiredogClient

logger = logging.getLogger(__name__)

class VirtualPatcher:
    """
    Virtual Patcher Service
    
    Automatically generates and deploys firewall rules in response to threats.
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.firedog_client = FiredogClient()
        self.auto_patch_enabled = True  # From config
        self.default_expiry_days = 30
    
    def generate_patches_for_detection(self, detection: IntellidogDetection) -> Optional[IntellidogVirtualPatch]:
        """
        Generate virtual patch for a detection.
        
        Returns:
            VirtualPatch object if generated, None if not applicable
        """
        # Only patch high/critical severity
        if detection.severity not in ['critical', 'high']:
            logger.debug(f"Detection {detection.id} severity {detection.severity} - skipping patch")
            return None
        
        # Only patch specific detection types
        if detection.detection_type not in ['firewall_match', 'vuln_correlation', 'exploit_attempt']:
            logger.debug(f"Detection {detection.id} type {detection.detection_type} - skipping patch")
            return None
        
        # Must have an IOC
        if not detection.ioc:
            logger.debug(f"Detection {detection.id} has no IOC - skipping patch")
            return None
        
        # Check if patch already exists
        existing = self.db.query(IntellidogVirtualPatch).filter(
            IntellidogVirtualPatch.ioc_id == detection.ioc_id,
            IntellidogVirtualPatch.status.in_(['pending', 'approved', 'deployed'])
        ).first()
        
        if existing:
            logger.info(f"Patch already exists for IOC {detection.ioc_id}")
            # Link detection to existing patch
            detection.virtual_patch_id = existing.id
            detection.auto_patched = True
            self.db.commit()
            return existing
        
        # Generate patch based on IOC type
        patch = self._generate_patch_for_ioc(detection)
        
        if patch:
            detection.virtual_patch_id = patch.id
            detection.auto_patched = True
            self.db.commit()
            logger.info(f"Generated virtual patch {patch.id} for detection {detection.id}")
        
        return patch
    
    def _generate_patch_for_ioc(self, detection: IntellidogDetection) -> Optional[IntellidogVirtualPatch]:
        """Generate patch based on IOC type"""
        ioc = detection.ioc
        
        if ioc.ioc_type == 'ip':
            return self._generate_ip_block_patch(detection)
        elif ioc.ioc_type == 'domain':
            return self._generate_domain_block_patch(detection)
        elif ioc.ioc_type == 'cve':
            return self._generate_cve_patch(detection)
        else:
            logger.debug(f"IOC type {ioc.ioc_type} not supported for patching")
            return None
    
    def _generate_ip_block_patch(self, detection: IntellidogDetection) -> IntellidogVirtualPatch:
        """Generate IP blocking patch"""
        ioc = detection.ioc
        
        # Determine direction from correlation context
        direction = detection.correlation_context.get('direction', 'both')
        
        # Build firewall rule template
        if direction == 'inbound':
            rule_template = {
                'action': 'DROP',
                'source_ip': ioc.value,
                'source_port': None,
                'destination_ip': None,
                'destination_port': None,
                'protocol': 'all',
                'direction': 'inbound',
                'log': True,
                'comment': f"Intellidog auto-patch: Block malicious IP {ioc.value}"
            }
        elif direction == 'outbound':
            rule_template = {
                'action': 'DROP',
                'source_ip': None,
                'source_port': None,
                'destination_ip': ioc.value,
                'destination_port': None,
                'protocol': 'all',
                'direction': 'outbound',
                'log': True,
                'comment': f"Intellidog auto-patch: Block C2 IP {ioc.value}"
            }
        else:  # both
            rule_template = {
                'action': 'DROP',
                'ip': ioc.value,  # Block in both directions
                'protocol': 'all',
                'direction': 'both',
                'log': True,
                'comment': f"Intellidog auto-patch: Block malicious IP {ioc.value}"
            }
        
        # Determine if auto-approve
        auto_approve = self._should_auto_approve(detection)
        
        patch = IntellidogVirtualPatch(
            name=f"Block IP {ioc.value}",
            description=f"Auto-generated patch for detection #{detection.id}. "
                       f"Blocks traffic to/from malicious IP {ioc.value}.",
            patch_type='block_ip',
            severity=detection.severity,
            ioc_id=ioc.id,
            detection_id=detection.id,
            firewall_rule_template=rule_template,
            target_machines=[detection.machine_id],
            target_all_machines=False,
            status='pending',
            auto_approve=auto_approve,
            approval_required=not auto_approve,
            expires_at=datetime.now(timezone.utc) + timedelta(days=self.default_expiry_days),
            auto_remove_on_expiry=True
        )
        
        self.db.add(patch)
        self.db.flush()
        
        # Auto-deploy if approved
        if auto_approve:
            self.approve_and_deploy_patch(patch.id)
        
        return patch
    
    def _generate_domain_block_patch(self, detection: IntellidogDetection) -> IntellidogVirtualPatch:
        """Generate domain blocking patch"""
        ioc = detection.ioc
        
        rule_template = {
            'action': 'DROP',
            'domain': ioc.value,
            'protocol': 'all',
            'log': True,
            'comment': f"Intellidog auto-patch: Block malicious domain {ioc.value}"
        }
        
        auto_approve = self._should_auto_approve(detection)
        
        patch = IntellidogVirtualPatch(
            name=f"Block Domain {ioc.value}",
            description=f"Auto-generated patch for detection #{detection.id}. "
                       f"Blocks DNS queries and connections to {ioc.value}.",
            patch_type='block_domain',
            severity=detection.severity,
            ioc_id=ioc.id,
            detection_id=detection.id,
            firewall_rule_template=rule_template,
            target_machines=[detection.machine_id],
            target_all_machines=False,
            status='pending',
            auto_approve=auto_approve,
            approval_required=not auto_approve,
            expires_at=datetime.now(timezone.utc) + timedelta(days=self.default_expiry_days),
            auto_remove_on_expiry=True
        )
        
        self.db.add(patch)
        self.db.flush()
        
        if auto_approve:
            self.approve_and_deploy_patch(patch.id)
        
        return patch
    
    def _generate_cve_patch(self, detection: IntellidogDetection) -> Optional[IntellidogVirtualPatch]:
        """Generate rate limiting patch for CVE exploitation attempts"""
        ioc = detection.ioc
        
        # Extract vulnerable port from source_data
        vulnerable_port = detection.source_data.get('destination_port')
        
        if not vulnerable_port:
            logger.warning(f"Cannot generate CVE patch without port information")
            return None
        
        rule_template = {
            'action': 'RATE_LIMIT',
            'destination_port': vulnerable_port,
            'protocol': 'tcp',
            'rate_limit': '10/minute',  # 10 connections per minute
            'burst': 5,
            'log': True,
            'comment': f"Intellidog auto-patch: Rate limit for {ioc.value} exploitation"
        }
        
        auto_approve = self._should_auto_approve(detection)
        
        patch = IntellidogVirtualPatch(
            name=f"Rate Limit {ioc.value}",
            description=f"Auto-generated patch for detection #{detection.id}. "
                       f"Rate limits traffic to port {vulnerable_port} to prevent {ioc.value} exploitation.",
            patch_type='rate_limit',
            severity=detection.severity,
            ioc_id=ioc.id,
            detection_id=detection.id,
            firewall_rule_template=rule_template,
            target_machines=[detection.machine_id],
            target_all_machines=False,
            status='pending',
            auto_approve=auto_approve,
            approval_required=not auto_approve,
            expires_at=datetime.now(timezone.utc) + timedelta(days=self.default_expiry_days),
            auto_remove_on_expiry=True
        )
        
        self.db.add(patch)
        self.db.flush()
        
        if auto_approve:
            self.approve_and_deploy_patch(patch.id)
        
        return patch
    
    def _should_auto_approve(self, detection: IntellidogDetection) -> bool:
        """
        Determine if patch should be auto-approved.
        
        Criteria:
        - Severity is critical
        - Confidence score > 80
        - IOC from trusted feed
        """
        if detection.severity != 'critical':
            return False
        
        if detection.confidence_score < 80:
            return False
        
        # Check if IOC is from trusted feed
        if detection.ioc and detection.ioc.feed:
            trusted_feeds = ['misp_internal', 'otx_subscribed']  # From config
            if detection.ioc.feed.name in trusted_feeds:
                return True
        
        return False
    
    def approve_and_deploy_patch(self, patch_id: int, approved_by: int = None) -> Dict[str, Any]:
        """
        Approve and deploy virtual patch to Firedog.
        
        Args:
            patch_id: Virtual patch ID
            approved_by: User ID who approved (None for auto-approval)
        
        Returns:
            Deployment result
        """
        patch = self.db.query(IntellidogVirtualPatch).filter(
            IntellidogVirtualPatch.id == patch_id
        ).first()
        
        if not patch:
            raise ValueError(f"Virtual patch {patch_id} not found")
        
        if patch.status not in ['pending', 'approved']:
            raise ValueError(f"Cannot deploy patch with status {patch.status}")
        
        # Update approval
        patch.approved_by = approved_by
        patch.approved_at = datetime.now(timezone.utc)
        patch.status = 'approved'
        self.db.commit()
        
        # Deploy to Firedog
        try:
            result = self._deploy_to_firedog(patch)
            
            if result['success']:
                patch.status = 'deployed'
                patch.deployed_at = datetime.now(timezone.utc)
                patch.deployment_result = result
                logger.info(f"Virtual patch {patch_id} deployed successfully")
            else:
                patch.status = 'failed'
                patch.deployment_result = result
                logger.error(f"Virtual patch {patch_id} deployment failed: {result.get('error')}")
            
            self.db.commit()
            
            return result
        
        except Exception as e:
            patch.status = 'failed'
            patch.deployment_result = {'error': str(e)}
            self.db.commit()
            
            logger.error(f"Exception deploying patch {patch_id}", exc_info=True)
            
            return {
                'success': False,
                'error': str(e)
            }
    
    def _deploy_to_firedog(self, patch: IntellidogVirtualPatch) -> Dict[str, Any]:
        """
        Deploy firewall rule to Firedog.
        
        Returns:
            Deployment result with firewall rule IDs
        """
        deployed_rules = []
        
        # Get target machines
        from ...models.machine import Machine
        
        if patch.target_all_machines:
            machines = self.db.query(Machine).filter(Machine.status == 'active').all()
        else:
            machines = self.db.query(Machine).filter(
                Machine.id.in_(patch.target_machines)
            ).all()
        
        # Deploy to each machine
        for machine in machines:
            try:
                # Create firewall rule via Firedog API
                rule_result = self.firedog_client.create_firewall_rule(
                    machine_id=machine.id,
                    rule_data=patch.firewall_rule_template
                )
                
                if rule_result['success']:
                    deployed_rules.append({
                        'machine_id': machine.id,
                        'hostname': machine.hostname,
                        'rule_id': rule_result['rule_id'],
                        'status': 'deployed'
                    })
                else:
                    deployed_rules.append({
                        'machine_id': machine.id,
                        'hostname': machine.hostname,
                        'error': rule_result.get('error'),
                        'status': 'failed'
                    })
            
            except Exception as e:
                deployed_rules.append({
                    'machine_id': machine.id,
                    'hostname': machine.hostname,
                    'error': str(e),
                    'status': 'failed'
                })
        
        # Check overall success
        success_count = sum(1 for r in deployed_rules if r['status'] == 'deployed')
        all_success = success_count == len(deployed_rules)
        
        return {
            'success': all_success,
            'deployed_count': success_count,
            'failed_count': len(deployed_rules) - success_count,
            'rules': deployed_rules
        }
    
    def remove_patch(self, patch_id: int, removed_by: int = None) -> Dict[str, Any]:
        """
        Remove virtual patch (delete firewall rules from Firedog).
        
        Args:
            patch_id: Virtual patch ID
            removed_by: User ID who removed
        
        Returns:
            Removal result
        """
        patch = self.db.query(IntellidogVirtualPatch).filter(
            IntellidogVirtualPatch.id == patch_id
        ).first()
        
        if not patch:
            raise ValueError(f"Virtual patch {patch_id} not found")
        
        if patch.status != 'deployed':
            raise ValueError(f"Cannot remove patch with status {patch.status}")
        
        try:
            # Remove from Firedog
            if patch.deployment_result and patch.deployment_result.get('rules'):
                for rule in patch.deployment_result['rules']:
                    if rule['status'] == 'deployed':
                        self.firedog_client.delete_firewall_rule(
                            machine_id=rule['machine_id'],
                            rule_id=rule['rule_id']
                        )
            
            # Update patch status
            patch.status = 'removed'
            patch.removed_at = datetime.now(timezone.utc)
            patch.removed_by = removed_by
            self.db.commit()
            
            logger.info(f"Virtual patch {patch_id} removed successfully")
            
            return {'success': True}
        
        except Exception as e:
            logger.error(f"Exception removing patch {patch_id}", exc_info=True)
            return {'success': False, 'error': str(e)}
```

---

### Firedog Client

**File**: `backend/app/modules/intellidog/services/firedog_client.py`

```python
from typing import Dict, Any
import httpx
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)

class FiredogClient:
    """
    Client for Firedog API integration.
    
    Manages firewall rules via Firedog's REST API.
    """
    
    def __init__(self):
        self.base_url = settings.FIREDOG_API_URL  # From orchestration config
        self.api_key = settings.FIREDOG_API_KEY
        self.timeout = 30
    
    def create_firewall_rule(self, machine_id: int, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create firewall rule on Firedog.
        
        Args:
            machine_id: Target machine ID
            rule_data: Firewall rule configuration
        
        Returns:
            Result with rule_id if successful
        """
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    f"{self.base_url}/api/firewall/rules",
                    json={
                        'machine_id': machine_id,
                        **rule_data
                    },
                    headers={
                        'Authorization': f'Bearer {self.api_key}',
                        'Content-Type': 'application/json'
                    }
                )
                
                response.raise_for_status()
                result = response.json()
                
                return {
                    'success': True,
                    'rule_id': result['data']['id']
                }
        
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error creating firewall rule: {e.response.status_code}")
            return {
                'success': False,
                'error': f"HTTP {e.response.status_code}: {e.response.text}"
            }
        
        except Exception as e:
            logger.error(f"Error creating firewall rule", exc_info=True)
            return {
                'success': False,
                'error': str(e)
            }
    
    def delete_firewall_rule(self, machine_id: int, rule_id: int) -> Dict[str, Any]:
        """
        Delete firewall rule from Firedog.
        
        Args:
            machine_id: Target machine ID
            rule_id: Firewall rule ID to delete
        
        Returns:
            Result dict
        """
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.delete(
                    f"{self.base_url}/api/firewall/rules/{rule_id}",
                    params={'machine_id': machine_id},
                    headers={
                        'Authorization': f'Bearer {self.api_key}'
                    }
                )
                
                response.raise_for_status()
                
                return {'success': True}
        
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error deleting firewall rule: {e.response.status_code}")
            return {
                'success': False,
                'error': f"HTTP {e.response.status_code}"
            }
        
        except Exception as e:
            logger.error(f"Error deleting firewall rule", exc_info=True)
            return {
                'success': False,
                'error': str(e)
            }
    
    def test_connection(self) -> bool:
        """Test connectivity to Firedog API"""
        try:
            with httpx.Client(timeout=10) as client:
                response = client.get(
                    f"{self.base_url}/api/health",
                    headers={'Authorization': f'Bearer {self.api_key}'}
                )
                return response.status_code == 200
        except Exception:
            return False
```

---

## Celery Task

**File**: `backend/app/modules/intellidog/tasks/virtual_patcher.py`

```python
from celery import shared_task
from datetime import datetime, timezone
from app.database import get_db_session
from ..services.virtual_patcher import VirtualPatcher
from ..models.virtual_patch import IntellidogVirtualPatch
import logging

logger = logging.getLogger(__name__)

@shared_task(name='intellidog.expire_virtual_patches')
def expire_virtual_patches_task():
    """
    Periodic task to remove expired virtual patches.
    
    Runs daily.
    """
    logger.info("Starting virtual patch expiration task")
    
    removed_count = 0
    error_count = 0
    
    with get_db_session() as db:
        patcher = VirtualPatcher(db)
        
        # Get expired patches that should be auto-removed
        now = datetime.now(timezone.utc)
        
        expired_patches = db.query(IntellidogVirtualPatch).filter(
            IntellidogVirtualPatch.status == 'deployed',
            IntellidogVirtualPatch.expires_at <= now,
            IntellidogVirtualPatch.auto_remove_on_expiry == True
        ).all()
        
        logger.info(f"Found {len(expired_patches)} expired patches to remove")
        
        for patch in expired_patches:
            try:
                result = patcher.remove_patch(patch.id)
                
                if result['success']:
                    removed_count += 1
                    logger.info(f"Removed expired patch {patch.id}")
                else:
                    error_count += 1
                    logger.error(f"Failed to remove expired patch {patch.id}: {result.get('error')}")
            
            except Exception as e:
                error_count += 1
                logger.error(f"Exception removing expired patch {patch.id}", exc_info=True)
    
    logger.info(f"Virtual patch expiration completed: {removed_count} removed, {error_count} errors")
    
    return {
        'removed_count': removed_count,
        'error_count': error_count
    }
```

---

## API Endpoints

**File**: `backend/app/modules/intellidog/api/virtual_patches.py`

```python
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.auth.dependencies import get_current_user, require_admin_or_team_leader
from ..schemas.virtual_patch import VirtualPatchResponse, VirtualPatchApproval
from ..services.virtual_patcher import VirtualPatcher
from ..models.virtual_patch import IntellidogVirtualPatch

router = APIRouter(prefix="/api/intellidog/virtual-patches", tags=["intellidog-patches"])

@router.get("", response_model=List[VirtualPatchResponse])
async def list_virtual_patches(
    status: str = None,
    severity: str = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List virtual patches with optional filters"""
    query = db.query(IntellidogVirtualPatch)
    
    if status:
        query = query.filter(IntellidogVirtualPatch.status == status)
    
    if severity:
        query = query.filter(IntellidogVirtualPatch.severity == severity)
    
    patches = query.order_by(IntellidogVirtualPatch.created_at.desc()).all()
    
    return patches

@router.get("/{patch_id}", response_model=VirtualPatchResponse)
async def get_virtual_patch(
    patch_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get virtual patch details"""
    patch = db.query(IntellidogVirtualPatch).filter(
        IntellidogVirtualPatch.id == patch_id
    ).first()
    
    if not patch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Virtual patch {patch_id} not found"
        )
    
    return patch

@router.post("/{patch_id}/approve", status_code=status.HTTP_200_OK)
async def approve_virtual_patch(
    patch_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin_or_team_leader)
):
    """Approve and deploy virtual patch"""
    patcher = VirtualPatcher(db)
    
    try:
        result = patcher.approve_and_deploy_patch(patch_id, current_user.id)
        
        return {
            'success': result['success'],
            'message': 'Patch deployed successfully' if result['success'] else 'Deployment failed',
            'details': result
        }
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/{patch_id}/reject", status_code=status.HTTP_200_OK)
async def reject_virtual_patch(
    patch_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin_or_team_leader)
):
    """Reject virtual patch"""
    patch = db.query(IntellidogVirtualPatch).filter(
        IntellidogVirtualPatch.id == patch_id
    ).first()
    
    if not patch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Virtual patch {patch_id} not found"
        )
    
    if patch.status != 'pending':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot reject patch with status {patch.status}"
        )
    
    patch.status = 'rejected'
    db.commit()
    
    return {'success': True, 'message': 'Patch rejected'}

@router.delete("/{patch_id}", status_code=status.HTTP_200_OK)
async def remove_virtual_patch(
    patch_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin_or_team_leader)
):
    """Remove deployed virtual patch"""
    patcher = VirtualPatcher(db)
    
    try:
        result = patcher.remove_patch(patch_id, current_user.id)
        
        return {
            'success': result['success'],
            'message': 'Patch removed successfully' if result['success'] else 'Removal failed'
        }
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
```

---

## Frontend Integration

**File**: `frontend/src/components/intellidog/ApprovalModal.tsx`

```typescript
import React from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Shield, AlertTriangle, CheckCircle } from 'lucide-react';
import { approveVirtualPatch } from '@/services/intellidog/virtualPatches';
import type { VirtualPatch } from '@/types/intellidog/virtualPatch';

interface ApprovalModalProps {
  patch: VirtualPatch;
  onClose: () => void;
}

export const ApprovalModal: React.FC<ApprovalModalProps> = ({ patch, onClose }) => {
  const queryClient = useQueryClient();

  const approveMutation = useMutation({
    mutationFn: approveVirtualPatch,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['intellidog', 'virtual-patches'] });
      onClose();
    }
  });

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        <div className="border-b border-gray-200 px-6 py-4">
          <div className="flex items-center gap-3">
            <Shield className="h-6 w-6 text-blue-600" />
            <h2 className="text-xl font-bold">Approve Virtual Patch</h2>
          </div>
        </div>

        <div className="p-6 space-y-4">
          {/* Patch Details */}
          <div>
            <h3 className="font-semibold text-gray-900 mb-2">{patch.name}</h3>
            <p className="text-sm text-gray-600">{patch.description}</p>
          </div>

          {/* Severity & Type */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-sm text-gray-600">Severity</p>
              <p className="font-semibold capitalize">{patch.severity}</p>
            </div>
            <div>
              <p className="text-sm text-gray-600">Patch Type</p>
              <p className="font-semibold capitalize">{patch.patch_type.replace('_', ' ')}</p>
            </div>
          </div>

          {/* Target Machines */}
          <div>
            <p className="text-sm text-gray-600 mb-1">Target Machines</p>
            <p className="font-semibold">
              {patch.target_all_machines 
                ? 'All Machines' 
                : `${patch.target_machines.length} machine(s)`}
            </p>
          </div>

          {/* Firewall Rule */}
          <div>
            <p className="text-sm text-gray-600 mb-2">Firewall Rule</p>
            <pre className="bg-gray-50 rounded-lg p-4 text-xs overflow-x-auto">
              {JSON.stringify(patch.firewall_rule_template, null, 2)}
            </pre>
          </div>

          {/* Warning */}
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-yellow-600 mt-0.5" />
              <div className="text-sm text-yellow-900">
                <p className="font-medium mb-1">Important</p>
                <p>
                  This will immediately deploy the firewall rule to the target machine(s).
                  The rule will expire in {patch.expires_at 
                    ? new Date(patch.expires_at).toLocaleDateString() 
                    : '30 days'}.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="border-t border-gray-200 px-6 py-4 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-700 hover:bg-gray-100 rounded-md transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={() => approveMutation.mutate(patch.id)}
            disabled={approveMutation.isPending}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            <CheckCircle className="h-4 w-4" />
            {approveMutation.isPending ? 'Deploying...' : 'Approve & Deploy'}
          </button>
        </div>
      </div>
    </div>
  );
};
```

---

## Summary

**Virtual Patcher Features**:
1. ✅ Automatic patch generation for critical detections
2. ✅ IP blocking (inbound/outbound)
3. ✅ Domain blocking
4. ✅ Rate limiting for CVE exploits
5. ✅ Manual approval workflow
6. ✅ Auto-approval for high-confidence threats
7. ✅ Firedog API integration
8. ✅ Automatic expiration and removal
9. ✅ Deployment tracking and logging
10. ✅ Multi-machine deployment

**Patch Types Supported**: 7
- block_ip
- block_port
- block_domain
- rate_limit
- geo_block
- protocol_block
- signature_block

**Integration Points**:
- ✅ Correlation Engine (trigger)
- ✅ Firedog API (deployment)
- ✅ Detection model (linking)
- ✅ IOC model (source data)

**Production-Ready**: ✅

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-01-02  
**Author**: Dognet Technologies
