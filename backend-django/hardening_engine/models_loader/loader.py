"""
============================================================================
CYBERSHEPPARD - Hardening Models Loader
============================================================================
Loads and parses hardening configuration files.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class FileOperation:
    """Represents a file operation (create, modify, append)"""
    path: str
    action: str  # create, modify, append, delete
    content: Optional[str] = None
    mode: Optional[str] = None  # File permissions (e.g., "0644")
    owner: Optional[str] = None
    group: Optional[str] = None
    backup: bool = True


@dataclass
class PackageOperation:
    """Represents a package operation (install, remove, update)"""
    name: str
    action: str  # install, remove, update
    version: Optional[str] = None


@dataclass
class ServiceOperation:
    """Represents a service operation (enable, disable, start, stop)"""
    name: str
    action: str  # enable, disable, start, stop, restart
    enabled: Optional[bool] = None


@dataclass
class SysctlParameter:
    """Represents a sysctl kernel parameter"""
    name: str
    value: str
    description: Optional[str] = None


@dataclass
class HardeningModel:
    """Represents a complete hardening configuration model"""
    name: str
    description: str
    compliance_standards: List[str] = field(default_factory=list)
    severity: str = "base"  # base or severo
    file_operations: List[FileOperation] = field(default_factory=list)
    package_operations: List[PackageOperation] = field(default_factory=list)
    service_operations: List[ServiceOperation] = field(default_factory=list)
    sysctl_parameters: List[SysctlParameter] = field(default_factory=list)
    custom_commands: List[str] = field(default_factory=list)
    validation_commands: List[str] = field(default_factory=list)


class HardeningModelLoader:
    """
    Loads hardening models from filesystem.
    Supports YAML and JSON formats.
    """

    def __init__(self, models_path: Optional[str] = None):
        """
        Initialize model loader.

        Args:
            models_path: Path to hardening models directory
        """
        self.models_path = Path(models_path or os.getenv('HARDENING_MODELS_PATH', '/app/hardening-models'))

        if not self.models_path.exists():
            logger.warning(f"Hardening models path does not exist: {self.models_path}")

    def list_available_models(self) -> List[str]:
        """
        List all available hardening models.

        Returns:
            List of model names
        """
        models = []

        if not self.models_path.exists():
            return models

        for severity_dir in ['base', 'severo']:
            severity_path = self.models_path / severity_dir
            if severity_path.exists():
                for file_path in severity_path.glob('*.y*ml'):
                    model_name = f"{severity_dir}/{file_path.stem}"
                    models.append(model_name)
                for file_path in severity_path.glob('*.json'):
                    model_name = f"{severity_dir}/{file_path.stem}"
                    models.append(model_name)

        logger.info(f"Found {len(models)} hardening models")
        return models

    def load_model(self, model_name: str) -> Optional[HardeningModel]:
        """
        Load a specific hardening model.

        Args:
            model_name: Model name (e.g., "base/ssh" or "severo/firewall")

        Returns:
            HardeningModel instance, or None if not found
        """
        # Parse model name (severity/name)
        parts = model_name.split('/')
        if len(parts) == 2:
            severity, name = parts
        else:
            severity = 'base'
            name = model_name

        # Try YAML first, then JSON
        for ext in ['.yml', '.yaml', '.json']:
            model_path = self.models_path / severity / f"{name}{ext}"
            if model_path.exists():
                try:
                    return self._parse_model_file(model_path, severity)
                except Exception as e:
                    logger.error(f"Failed to parse model file {model_path}: {e}")
                    return None

        logger.error(f"Model not found: {model_name}")
        return None

    def _parse_model_file(self, file_path: Path, severity: str) -> HardeningModel:
        """
        Parse a model file (YAML or JSON).

        Args:
            file_path: Path to model file
            severity: Severity level (base or severo)

        Returns:
            HardeningModel instance
        """
        with open(file_path, 'r') as f:
            if file_path.suffix in ['.yml', '.yaml']:
                data = yaml.safe_load(f)
            else:
                data = json.load(f)

        # Parse file operations
        file_ops = []
        for file_op in data.get('file_operations', []):
            file_ops.append(FileOperation(
                path=file_op['path'],
                action=file_op['action'],
                content=file_op.get('content'),
                mode=file_op.get('mode'),
                owner=file_op.get('owner'),
                group=file_op.get('group'),
                backup=file_op.get('backup', True)
            ))

        # Parse package operations
        pkg_ops = []
        for pkg_op in data.get('package_operations', []):
            pkg_ops.append(PackageOperation(
                name=pkg_op['name'],
                action=pkg_op['action'],
                version=pkg_op.get('version')
            ))

        # Parse service operations
        svc_ops = []
        for svc_op in data.get('service_operations', []):
            svc_ops.append(ServiceOperation(
                name=svc_op['name'],
                action=svc_op['action'],
                enabled=svc_op.get('enabled')
            ))

        # Parse sysctl parameters
        sysctl_params = []
        for param in data.get('sysctl_parameters', []):
            sysctl_params.append(SysctlParameter(
                name=param['name'],
                value=param['value'],
                description=param.get('description')
            ))

        return HardeningModel(
            name=data.get('name', file_path.stem),
            description=data.get('description', ''),
            compliance_standards=data.get('compliance_standards', []),
            severity=severity,
            file_operations=file_ops,
            package_operations=pkg_ops,
            service_operations=svc_ops,
            sysctl_parameters=sysctl_params,
            custom_commands=data.get('custom_commands', []),
            validation_commands=data.get('validation_commands', [])
        )

    def get_model_info(self, model_name: str) -> Optional[Dict]:
        """
        Get basic information about a model without fully loading it.

        Args:
            model_name: Model name

        Returns:
            Dictionary with model info
        """
        model = self.load_model(model_name)
        if not model:
            return None

        return {
            'name': model.name,
            'description': model.description,
            'severity': model.severity,
            'compliance_standards': model.compliance_standards,
            'operations_count': {
                'files': len(model.file_operations),
                'packages': len(model.package_operations),
                'services': len(model.service_operations),
                'sysctl': len(model.sysctl_parameters),
                'custom': len(model.custom_commands),
            }
        }

    def validate_model(self, model: HardeningModel) -> List[str]:
        """
        Validate a hardening model for correctness.

        Args:
            model: HardeningModel to validate

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Validate file operations
        for file_op in model.file_operations:
            if file_op.action not in ['create', 'modify', 'append', 'delete']:
                errors.append(f"Invalid file action: {file_op.action} for {file_op.path}")
            if file_op.action in ['create', 'modify', 'append'] and not file_op.content:
                errors.append(f"File operation {file_op.action} requires content: {file_op.path}")

        # Validate package operations
        for pkg_op in model.package_operations:
            if pkg_op.action not in ['install', 'remove', 'update']:
                errors.append(f"Invalid package action: {pkg_op.action} for {pkg_op.name}")

        # Validate service operations
        for svc_op in model.service_operations:
            if svc_op.action not in ['enable', 'disable', 'start', 'stop', 'restart']:
                errors.append(f"Invalid service action: {svc_op.action} for {svc_op.name}")

        # Validate sysctl parameters
        for param in model.sysctl_parameters:
            if not param.name or not param.value:
                errors.append(f"Sysctl parameter missing name or value: {param}")

        return errors
