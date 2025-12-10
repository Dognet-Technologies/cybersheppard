# MicroSIEM (CyberSheppard) - Hardening Engine Specification

## 📋 Indice

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Model Structure](#model-structure)
4. [Python Components](#python-components)
5. [Flask Micro-API](#flask-micro-api)
6. [SSH Operations](#ssh-operations)
7. [Model Validation](#model-validation)
8. [Rollback System](#rollback-system)
9. [Security Considerations](#security-considerations)

---

## Overview

**Hardening Engine**: Sistema Python per applicare configurazioni di sicurezza ai target Linux tramite SSH.

### Key Features

✅ **File-based models** - Configurazioni reali pronte per deployment  
✅ **Dot notation naming** - Mapping diretto file → path sistema  
✅ **SHA512 integrity** - Verifica integrità modelli  
✅ **SSH deployment** - Paramiko + Ed25519 keys (riusato da FireDog)  
✅ **Automatic rollback** - Backup e restore automatico  
✅ **Validation** - Syntax check pre-deploy  
✅ **Flask micro-API** - Interfaccia HTTP per Rust backend  

---

## Architecture

### Component Overview

```
┌──────────────────────────────────────────────────────────────┐
│  Rust Backend (Axum)                                         │
│  POST /api/hardening/apply                                   │
└────────────────────┬─────────────────────────────────────────┘
                     │ HTTP (localhost:5001)
                     ▼
┌──────────────────────────────────────────────────────────────┐
│  Python Hardening Engine (Flask Micro-API)                   │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌────────────────────────────────────────────────┐          │
│  │  Flask App (Port 5001)                         │          │
│  │  POST /apply_hardening                         │          │
│  │  POST /validate_model                          │          │
│  │  POST /rollback                                │          │
│  │  GET /check_connection                         │          │
│  └────────────┬───────────────────────────────────┘          │
│               │                                               │
│  ┌────────────▼───────────────────────────────────┐          │
│  │  ModelLoader                                   │          │
│  │  - read_model()                                │          │
│  │  - validate_integrity()                        │          │
│  │  - list_files()                                │          │
│  └────────────┬───────────────────────────────────┘          │
│               │                                               │
│  ┌────────────▼───────────────────────────────────┐          │
│  │  ModelValidator                                │          │
│  │  - validate_syntax()                           │          │
│  │  - check_conflicts()                           │          │
│  │  - verify_permissions()                        │          │
│  └────────────┬───────────────────────────────────┘          │
│               │                                               │
│  ┌────────────▼───────────────────────────────────┐          │
│  │  HardeningApplier                              │          │
│  │  - apply_model()                               │          │
│  │  - create_backup()                             │          │
│  │  - deploy_files()                              │          │
│  │  - run_post_actions()                          │          │
│  └────────────┬───────────────────────────────────┘          │
│               │                                               │
│  ┌────────────▼───────────────────────────────────┐          │
│  │  SSHManager (RIUSATO DA FIREDOG)               │          │
│  │  - connect()                                   │          │
│  │  - execute_command()                           │          │
│  │  - upload_file()                               │          │
│  │  - download_file()                             │          │
│  └────────────┬───────────────────────────────────┘          │
│               │ SSH (Ed25519)                                │
│               ▼                                               │
└──────────────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────┐
│  Target System (Debian/Ubuntu)                               │
│  - Receive files via SCP                                     │
│  - Apply configurations                                      │
│  - Enable/disable services                                   │
│  - Install/remove packages                                   │
└──────────────────────────────────────────────────────────────┘
```

---

## Model Structure

### Directory Layout

```
hardening_models/
├── base/                           # Livello "base"
│   ├── generic/
│   │   ├── model.json
│   │   ├── etc.ssh.sshd_config
│   │   ├── etc.sysctl.d.99-hardening.conf
│   │   ├── etc.iptables.rules.v4
│   │   ├── etc.audit.rules.d.audit.rules
│   │   └── etc.sudoers.d.microsiem
│   │
│   ├── web/
│   │   ├── model.json
│   │   ├── etc.ssh.sshd_config
│   │   ├── etc.sysctl.d.99-hardening.conf
│   │   ├── etc.iptables.rules.v4
│   │   ├── etc.audit.rules.d.audit.rules
│   │   ├── etc.sudoers.d.microsiem
│   │   ├── etc.nginx.nginx.conf
│   │   └── etc.apparmor.d.usr.sbin.nginx
│   │
│   └── database/
│       ├── model.json
│       ├── etc.ssh.sshd_config
│       ├── etc.postgresql.14.main.postgresql.conf
│       └── etc.postgresql.14.main.pg_hba.conf
│
├── severo/                         # Livello "severo"
│   ├── generic/
│   ├── web_nis2/
│   ├── web_pci/
│   └── database_pci/
│
└── custom/                         # Modelli utente
    └── my_custom_model/
```

---

### File Naming Convention

**Rule**: Replace all `/` with `.` and remove leading `/`

```
System Path                    →  Model Filename
──────────────────────────────────────────────────────────
/etc/ssh/sshd_config           →  etc.ssh.sshd_config
/etc/sysctl.d/99-hardening.conf →  etc.sysctl.d.99-hardening.conf
/etc/iptables/rules.v4         →  etc.iptables.rules.v4
/etc/audit/rules.d/audit.rules →  etc.audit.rules.d.audit.rules
/etc/sudoers.d/microsiem       →  etc.sudoers.d.microsiem
```

---

### model.json Schema

```json
{
  "name": "web_severo_nis2",
  "version": "1.0.0",
  "description": "Strict hardening for web servers with NIS2 compliance",
  "role": "web",
  "compliance": "nis2",
  "level": "severo",
  "author": "MicroSIEM Team",
  "created_at": "2025-11-28",
  "supported_os": ["debian11", "debian12", "ubuntu20.04", "ubuntu22.04"],
  
  "services_to_enable": [
    "nginx",
    "auditd",
    "fail2ban",
    "ulogd2"
  ],
  
  "services_to_disable": [
    "apache2",
    "telnet",
    "ftp",
    "vsftpd",
    "rsh-server"
  ],
  
  "packages_to_install": [
    "auditd",
    "audispd-plugins",
    "iptables-persistent",
    "fail2ban",
    "ulogd2",
    "apparmor-utils"
  ],
  
  "packages_to_remove": [
    "telnetd",
    "rsh-server",
    "rsh-client",
    "nis"
  ],
  
  "requires_reboot": false,
  "estimated_apply_time_seconds": 120,
  
  "pre_checks": [
    "check_ssh_access",
    "check_disk_space",
    "verify_os_version"
  ],
  
  "post_checks": [
    "verify_ssh_still_works",
    "verify_services_running",
    "verify_firewall_active"
  ],
  
  "notes": [
    "This model enforces strict NIS2 compliance",
    "All unnecessary services are disabled",
    "AppArmor profiles are set to enforce mode"
  ],
  
  "warnings": [
    "⚠️ Test on non-production system first",
    "⚠️ Ensure console/physical access before applying",
    "⚠️ Review firewall rules before applying"
  ]
}
```

---

## Python Components

### 1. Project Structure

```
hardening_engine/
├── __init__.py
├── app.py                    # Flask micro-API
├── config.py                 # Configuration
│
├── models/
│   ├── __init__.py
│   ├── loader.py             # ModelLoader
│   ├── validator.py          # ModelValidator
│   └── schema.py             # Pydantic schemas
│
├── applier/
│   ├── __init__.py
│   ├── applier.py            # HardeningApplier
│   ├── backup.py             # BackupManager
│   └── rollback.py           # RollbackManager
│
├── ssh/
│   ├── __init__.py
│   └── manager.py            # SSHManager (from FireDog)
│
├── utils/
│   ├── __init__.py
│   ├── integrity.py          # SHA512 hashing
│   ├── parsers.py            # Config file parsers
│   └── logger.py             # Logging setup
│
├── requirements.txt
└── tests/
    ├── test_loader.py
    ├── test_validator.py
    └── test_applier.py
```

---

### 2. ModelLoader

```python
# hardening_engine/models/loader.py

import os
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class HardeningModel:
    """Rappresentazione di un modello di hardening"""
    
    # Metadata
    name: str
    version: str
    description: str
    role: str
    compliance: str
    level: str
    author: str
    
    # Paths
    model_path: Path
    
    # Files
    files: Dict[str, str]  # filename -> content
    
    # Actions
    services_to_enable: List[str]
    services_to_disable: List[str]
    packages_to_install: List[str]
    packages_to_remove: List[str]
    
    # Metadata
    requires_reboot: bool
    supported_os: List[str]
    pre_checks: List[str]
    post_checks: List[str]
    
    # Integrity
    hash_sha512: str


class ModelLoader:
    """
    Caricatore di modelli di hardening da filesystem
    """
    
    def __init__(self, models_base_path: str = "/opt/microsiem/hardening_models"):
        self.models_base_path = Path(models_base_path)
        self._validate_base_path()
    
    def _validate_base_path(self):
        """Verifica che la directory base esista"""
        if not self.models_base_path.exists():
            raise FileNotFoundError(f"Models directory not found: {self.models_base_path}")
        
        if not self.models_base_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {self.models_base_path}")
    
    def list_available_models(self) -> List[Dict[str, str]]:
        """
        Elenca tutti i modelli disponibili
        
        Returns:
            List of dicts: [{"name": "web_base", "path": "/path/to/model", "level": "base"}]
        """
        models = []
        
        # Scan base/ and severo/ directories
        for level in ["base", "severo"]:
            level_path = self.models_base_path / level
            if not level_path.exists():
                continue
            
            for model_dir in level_path.iterdir():
                if not model_dir.is_dir():
                    continue
                
                model_json_path = model_dir / "model.json"
                if not model_json_path.exists():
                    logger.warning(f"No model.json found in {model_dir}")
                    continue
                
                try:
                    with open(model_json_path, 'r') as f:
                        metadata = json.load(f)
                    
                    models.append({
                        "name": metadata.get("name", model_dir.name),
                        "path": str(model_dir),
                        "level": level,
                        "role": metadata.get("role"),
                        "compliance": metadata.get("compliance"),
                        "description": metadata.get("description")
                    })
                except Exception as e:
                    logger.error(f"Error reading {model_json_path}: {e}")
                    continue
        
        return models
    
    def load_model(self, model_name: str) -> HardeningModel:
        """
        Carica un modello dal filesystem
        
        Args:
            model_name: Nome del modello (es. "web_severo_nis2")
        
        Returns:
            HardeningModel object
        
        Raises:
            FileNotFoundError: Se il modello non esiste
            ValueError: Se il modello è invalido
        """
        # Find model directory
        model_path = self._find_model_path(model_name)
        if not model_path:
            raise FileNotFoundError(f"Model not found: {model_name}")
        
        logger.info(f"Loading model from {model_path}")
        
        # Load model.json
        model_json_path = model_path / "model.json"
        if not model_json_path.exists():
            raise FileNotFoundError(f"model.json not found in {model_path}")
        
        with open(model_json_path, 'r') as f:
            metadata = json.load(f)
        
        # Load all configuration files
        files = self._load_config_files(model_path)
        
        if not files:
            raise ValueError(f"No configuration files found in {model_path}")
        
        # Calculate hash
        hash_sha512 = self._calculate_model_hash(files)
        
        # Create HardeningModel object
        model = HardeningModel(
            name=metadata.get("name", model_name),
            version=metadata.get("version", "1.0.0"),
            description=metadata.get("description", ""),
            role=metadata.get("role", "generic"),
            compliance=metadata.get("compliance", "none"),
            level=metadata.get("level", "base"),
            author=metadata.get("author", "Unknown"),
            model_path=model_path,
            files=files,
            services_to_enable=metadata.get("services_to_enable", []),
            services_to_disable=metadata.get("services_to_disable", []),
            packages_to_install=metadata.get("packages_to_install", []),
            packages_to_remove=metadata.get("packages_to_remove", []),
            requires_reboot=metadata.get("requires_reboot", False),
            supported_os=metadata.get("supported_os", []),
            pre_checks=metadata.get("pre_checks", []),
            post_checks=metadata.get("post_checks", []),
            hash_sha512=hash_sha512
        )
        
        logger.info(f"Model loaded: {model.name} (hash: {hash_sha512[:16]}...)")
        return model
    
    def _find_model_path(self, model_name: str) -> Optional[Path]:
        """
        Cerca un modello nelle directory base/ e severo/
        
        Args:
            model_name: Nome del modello
        
        Returns:
            Path del modello o None se non trovato
        """
        # Try in base/
        for level in ["base", "severo", "custom"]:
            potential_path = self.models_base_path / level / model_name
            if potential_path.exists() and potential_path.is_dir():
                return potential_path
        
        return None
    
    def _load_config_files(self, model_path: Path) -> Dict[str, str]:
        """
        Carica tutti i file di configurazione dal modello
        
        Args:
            model_path: Path alla directory del modello
        
        Returns:
            Dict: {filename: content}
        """
        files = {}
        
        for file_path in model_path.iterdir():
            # Skip model.json and directories
            if file_path.name == "model.json" or file_path.is_dir():
                continue
            
            # Only load files with dot notation naming
            if not self._is_config_file(file_path.name):
                logger.debug(f"Skipping non-config file: {file_path.name}")
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                files[file_path.name] = content
                logger.debug(f"Loaded file: {file_path.name} ({len(content)} bytes)")
            
            except Exception as e:
                logger.error(f"Error reading {file_path}: {e}")
                continue
        
        return files
    
    def _is_config_file(self, filename: str) -> bool:
        """
        Verifica se un file segue la convenzione dot notation
        
        Args:
            filename: Nome del file
        
        Returns:
            True se è un file di configurazione valido
        """
        # Must start with common paths
        valid_prefixes = ["etc.", "usr.", "var.", "opt."]
        return any(filename.startswith(prefix) for prefix in valid_prefixes)
    
    def _calculate_model_hash(self, files: Dict[str, str]) -> str:
        """
        Calcola hash SHA512 del modello
        
        Args:
            files: Dict dei file del modello
        
        Returns:
            Hash SHA512 hex string
        """
        hasher = hashlib.sha512()
        
        # Sort files by name for consistent hashing
        for filename in sorted(files.keys()):
            content = files[filename]
            hasher.update(filename.encode('utf-8'))
            hasher.update(content.encode('utf-8'))
        
        return hasher.hexdigest()
    
    def verify_model_integrity(self, model_name: str, expected_hash: str) -> bool:
        """
        Verifica l'integrità di un modello confrontando l'hash
        
        Args:
            model_name: Nome del modello
            expected_hash: Hash SHA512 atteso
        
        Returns:
            True se l'hash corrisponde
        """
        try:
            model = self.load_model(model_name)
            
            if model.hash_sha512 != expected_hash:
                logger.error(
                    f"Hash mismatch for {model_name}: "
                    f"expected {expected_hash[:16]}..., "
                    f"got {model.hash_sha512[:16]}..."
                )
                return False
            
            logger.info(f"Integrity check passed for {model_name}")
            return True
        
        except Exception as e:
            logger.error(f"Error verifying model integrity: {e}")
            return False
    
    def get_target_path(self, filename: str) -> str:
        """
        Converte filename dot notation → path sistema
        
        Args:
            filename: Nome file con dot notation (es. "etc.ssh.sshd_config")
        
        Returns:
            Path sistema (es. "/etc/ssh/sshd_config")
        """
        # Replace dots with slashes and prepend /
        path = "/" + filename.replace(".", "/")
        return path
```

---

### 3. ModelValidator

```python
# hardening_engine/models/validator.py

import re
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass
import logging

from .loader import HardeningModel

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Risultato della validazione"""
    passed: bool
    errors: List[str]
    warnings: List[str]
    suggestions: List[str]


class ModelValidator:
    """
    Validatore di modelli di hardening
    """
    
    def __init__(self):
        self.validators = {
            "etc.ssh.sshd_config": self._validate_sshd_config,
            "etc.iptables.rules.v4": self._validate_iptables,
            "etc.sysctl.d": self._validate_sysctl,
            "etc.audit.rules.d": self._validate_auditd,
            "etc.sudoers.d": self._validate_sudoers
        }
    
    def validate_model(self, model: HardeningModel) -> ValidationResult:
        """
        Valida un modello di hardening completo
        
        Args:
            model: HardeningModel da validare
        
        Returns:
            ValidationResult con errori, warnings, suggestions
        """
        errors = []
        warnings = []
        suggestions = []
        
        # Validate metadata
        meta_result = self._validate_metadata(model)
        errors.extend(meta_result.errors)
        warnings.extend(meta_result.warnings)
        
        # Validate each configuration file
        for filename, content in model.files.items():
            file_result = self._validate_file(filename, content)
            errors.extend(file_result.errors)
            warnings.extend(file_result.warnings)
            suggestions.extend(file_result.suggestions)
        
        # Check for conflicts
        conflict_result = self._check_conflicts(model)
        errors.extend(conflict_result.errors)
        warnings.extend(conflict_result.warnings)
        
        # Check SSH accessibility
        ssh_result = self._check_ssh_safety(model)
        errors.extend(ssh_result.errors)
        warnings.extend(ssh_result.warnings)
        
        passed = len(errors) == 0
        
        return ValidationResult(
            passed=passed,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions
        )
    
    def _validate_metadata(self, model: HardeningModel) -> ValidationResult:
        """Valida i metadata del modello"""
        errors = []
        warnings = []
        suggestions = []
        
        # Check required fields
        if not model.name:
            errors.append("Model name is required")
        
        if not model.version:
            warnings.append("Model version not specified")
        
        if not model.description:
            warnings.append("Model description is empty")
        
        # Validate version format (semver)
        if model.version and not re.match(r'^\d+\.\d+\.\d+$', model.version):
            warnings.append(f"Invalid version format: {model.version} (expected x.y.z)")
        
        # Check supported OS
        if not model.supported_os:
            warnings.append("No supported OS specified")
        
        return ValidationResult(
            passed=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions
        )
    
    def _validate_file(self, filename: str, content: str) -> ValidationResult:
        """
        Valida un singolo file di configurazione
        
        Args:
            filename: Nome del file (dot notation)
            content: Contenuto del file
        
        Returns:
            ValidationResult
        """
        errors = []
        warnings = []
        suggestions = []
        
        # Find appropriate validator
        validator = None
        for pattern, validator_func in self.validators.items():
            if filename.startswith(pattern):
                validator = validator_func
                break
        
        if validator:
            result = validator(filename, content)
            errors.extend(result.errors)
            warnings.extend(result.warnings)
            suggestions.extend(result.suggestions)
        else:
            # Generic validation
            result = self._validate_generic(filename, content)
            warnings.extend(result.warnings)
        
        return ValidationResult(
            passed=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions
        )
    
    def _validate_sshd_config(self, filename: str, content: str) -> ValidationResult:
        """Valida configurazione sshd_config"""
        errors = []
        warnings = []
        suggestions = []
        
        lines = content.split('\n')
        
        # Critical checks
        if not any('PermitRootLogin no' in line for line in lines):
            errors.append("PermitRootLogin should be 'no'")
        
        if not any('PasswordAuthentication no' in line for line in lines):
            errors.append("PasswordAuthentication should be 'no'")
        
        if not any('PubkeyAuthentication yes' in line for line in lines):
            warnings.append("PubkeyAuthentication should be 'yes'")
        
        # Check Port is specified
        port_specified = any(line.startswith('Port ') for line in lines)
        if not port_specified:
            warnings.append("SSH Port not explicitly specified (will use default 22)")
        
        # Check MaxAuthTries
        max_auth_found = False
        for line in lines:
            if line.startswith('MaxAuthTries '):
                max_auth_found = True
                try:
                    value = int(line.split()[1])
                    if value > 6:
                        warnings.append(f"MaxAuthTries is {value}, recommend ≤ 6")
                except:
                    pass
        
        if not max_auth_found:
            suggestions.append("Consider setting MaxAuthTries ≤ 6")
        
        return ValidationResult(
            passed=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions
        )
    
    def _validate_iptables(self, filename: str, content: str) -> ValidationResult:
        """Valida regole iptables"""
        errors = []
        warnings = []
        suggestions = []
        
        lines = content.split('\n')
        
        # Check for basic structure
        if '*filter' not in content:
            errors.append("Missing *filter table in iptables rules")
        
        if 'COMMIT' not in content:
            errors.append("Missing COMMIT statement in iptables rules")
        
        # Check default policies
        has_input_policy = any(':INPUT DROP' in line or ':INPUT ACCEPT' in line for line in lines)
        if not has_input_policy:
            errors.append("No INPUT chain policy defined")
        
        # Check for SSH rule
        ssh_rule_found = any('--dport 22' in line or '--dport ssh' in line for line in lines)
        if not ssh_rule_found:
            errors.append("⚠️ CRITICAL: No SSH rule found - may lock out access!")
        
        # Check for loopback
        loopback_found = any('-i lo' in line for line in lines)
        if not loopback_found:
            warnings.append("No loopback interface rule found")
        
        # Check for ESTABLISHED,RELATED
        stateful_found = any('ESTABLISHED,RELATED' in line for line in lines)
        if not stateful_found:
            warnings.append("No stateful firewall rule found (ESTABLISHED,RELATED)")
        
        return ValidationResult(
            passed=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions
        )
    
    def _validate_sysctl(self, filename: str, content: str) -> ValidationResult:
        """Valida parametri sysctl"""
        errors = []
        warnings = []
        suggestions = []
        
        lines = content.split('\n')
        
        # Parse key=value pairs
        params = {}
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if '=' in line:
                key, value = line.split('=', 1)
                params[key.strip()] = value.strip()
        
        # Check critical parameters
        if params.get('net.ipv4.ip_forward') == '1':
            warnings.append("IP forwarding is enabled - only enable on routers/gateways")
        
        if params.get('net.ipv4.tcp_syncookies') != '1':
            suggestions.append("Consider enabling SYN cookies (net.ipv4.tcp_syncookies = 1)")
        
        return ValidationResult(
            passed=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions
        )
    
    def _validate_auditd(self, filename: str, content: str) -> ValidationResult:
        """Valida regole auditd"""
        errors = []
        warnings = []
        suggestions = []
        
        lines = content.split('\n')
        
        # Check for buffer size
        buffer_found = any(line.startswith('-b ') for line in lines)
        if not buffer_found:
            warnings.append("No buffer size specified (-b), using default")
        
        # Check for failure mode
        failure_found = any(line.startswith('-f ') for line in lines)
        if not failure_found:
            warnings.append("No failure mode specified (-f)")
        
        # Check for immutable flag
        immutable_found = any(line.strip() == '-e 2' for line in lines)
        if immutable_found:
            warnings.append(
                "Rules are set to immutable (-e 2). "
                "Changes require reboot. "
                "Comment out during testing."
            )
        
        return ValidationResult(
            passed=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions
        )
    
    def _validate_sudoers(self, filename: str, content: str) -> ValidationResult:
        """Valida file sudoers"""
        errors = []
        warnings = []
        suggestions = []
        
        # Use visudo to validate syntax (if available)
        try:
            # Write content to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(content)
                temp_path = f.name
            
            # Run visudo -c
            result = subprocess.run(
                ['visudo', '-c', '-f', temp_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                errors.append(f"visudo validation failed: {result.stderr}")
            
            # Cleanup
            Path(temp_path).unlink()
        
        except FileNotFoundError:
            warnings.append("visudo not found - skipping syntax validation")
        except Exception as e:
            warnings.append(f"Could not validate with visudo: {e}")
        
        # Check for dangerous permissions
        if 'NOPASSWD: ALL' in content:
            errors.append("⚠️ SECURITY: NOPASSWD: ALL grants full sudo without password!")
        
        # Check for specific command restrictions
        if 'ALL=(ALL) ALL' in content:
            warnings.append("User has full sudo access - consider restricting to specific commands")
        
        return ValidationResult(
            passed=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions
        )
    
    def _validate_generic(self, filename: str, content: str) -> ValidationResult:
        """Validazione generica per file sconosciuti"""
        warnings = []
        
        # Check file size
        if len(content) == 0:
            warnings.append(f"File {filename} is empty")
        
        if len(content) > 1024 * 1024:  # 1MB
            warnings.append(f"File {filename} is very large ({len(content)} bytes)")
        
        return ValidationResult(
            passed=True,
            errors=[],
            warnings=warnings,
            suggestions=[]
        )
    
    def _check_conflicts(self, model: HardeningModel) -> ValidationResult:
        """Controlla conflitti tra configurazioni"""
        errors = []
        warnings = []
        
        # Check service conflicts
        enable_set = set(model.services_to_enable)
        disable_set = set(model.services_to_disable)
        
        conflicts = enable_set & disable_set
        if conflicts:
            errors.append(
                f"Service conflict: {conflicts} in both enable and disable lists"
            )
        
        # Check package conflicts
        install_set = set(model.packages_to_install)
        remove_set = set(model.packages_to_remove)
        
        pkg_conflicts = install_set & remove_set
        if pkg_conflicts:
            errors.append(
                f"Package conflict: {pkg_conflicts} in both install and remove lists"
            )
        
        return ValidationResult(
            passed=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            suggestions=[]
        )
    
    def _check_ssh_safety(self, model: HardeningModel) -> ValidationResult:
        """Verifica che SSH rimanga accessibile dopo hardening"""
        errors = []
        warnings = []
        
        # Check if SSH is in services_to_disable
        if 'ssh' in model.services_to_disable or 'sshd' in model.services_to_disable:
            errors.append(
                "⚠️ CRITICAL: SSH is marked for disabling - will lose access!"
            )
        
        # Check sshd_config file
        sshd_file = None
        for filename, content in model.files.items():
            if 'sshd_config' in filename:
                sshd_file = content
                break
        
        if sshd_file:
            # Check that microcyber user is not blocked
            if 'DenyUsers' in sshd_file and 'microcyber' in sshd_file:
                errors.append("microcyber user is in DenyUsers list!")
            
            # Check that key auth is still enabled
            if 'PubkeyAuthentication no' in sshd_file:
                errors.append("PubkeyAuthentication is disabled - cannot connect!")
        
        # Check iptables
        iptables_file = None
        for filename, content in model.files.items():
            if 'iptables' in filename:
                iptables_file = content
                break
        
        if iptables_file:
            # Check for SSH rule
            if '--dport 22' not in iptables_file and '--dport ssh' not in iptables_file:
                errors.append(
                    "⚠️ CRITICAL: No SSH rule in iptables - will be locked out!"
                )
        
        return ValidationResult(
            passed=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            suggestions=[]
        )
```

---

### 4. HardeningApplier

```python
# hardening_engine/applier/applier.py

import os
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import logging

from ..models.loader import HardeningModel, ModelLoader
from ..ssh.manager import SSHManager
from .backup import BackupManager

logger = logging.getLogger(__name__)

@dataclass
class ApplicationResult:
    """Risultato dell'applicazione di un modello"""
    success: bool
    steps_total: int
    steps_completed: int
    steps_failed: int
    duration_seconds: float
    log: List[str]
    error_message: Optional[str]
    backup_path: Optional[str]
    rollback_available: bool


class HardeningApplier:
    """
    Applica modelli di hardening ai target tramite SSH
    """
    
    def __init__(self, models_base_path: str = "/opt/microsiem/hardening_models"):
        self.model_loader = ModelLoader(models_base_path)
        self.backup_manager = BackupManager()
    
    def apply_model(
        self,
        model_name: str,
        target_ip: str,
        ssh_port: int,
        ssh_username: str,
        ssh_key_path: str,
        create_backup: bool = True,
        dry_run: bool = False
    ) -> ApplicationResult:
        """
        Applica un modello di hardening a un target
        
        Args:
            model_name: Nome del modello
            target_ip: IP del target
            ssh_port: Porta SSH
            ssh_username: Username SSH
            ssh_key_path: Path della chiave SSH privata
            create_backup: Se creare backup prima di applicare
            dry_run: Se True, simula senza applicare modifiche
        
        Returns:
            ApplicationResult con dettagli dell'operazione
        """
        start_time = datetime.now()
        log = []
        steps_completed = 0
        steps_failed = 0
        backup_path = None
        
        try:
            # Load model
            log.append(f"Loading model: {model_name}")
            model = self.model_loader.load_model(model_name)
            
            steps_total = self._calculate_total_steps(model)
            log.append(f"Total steps: {steps_total}")
            
            # Connect to target via SSH
            log.append(f"Connecting to {target_ip}:{ssh_port}")
            ssh = SSHManager(
                target_ip=target_ip,
                ssh_port=ssh_port,
                username=ssh_username
            )
            
            if not ssh.connect(ssh_key_path):
                raise Exception(f"SSH connection failed to {target_ip}")
            
            log.append("SSH connected successfully")
            steps_completed += 1
            
            # Verify OS compatibility
            log.append("Verifying OS compatibility")
            if not self._verify_os_compatibility(ssh, model):
                raise Exception("OS not compatible with this model")
            log.append("OS compatibility verified")
            steps_completed += 1
            
            # Create backup
            if create_backup and not dry_run:
                log.append("Creating backup of existing configurations")
                backup_path = self.backup_manager.create_backup(ssh, model, target_ip)
                log.append(f"Backup created: {backup_path}")
                steps_completed += 1
            
            # Pre-checks
            log.append("Running pre-checks")
            pre_check_result = self._run_pre_checks(ssh, model)
            if not pre_check_result['passed']:
                log.append(f"Pre-checks failed: {pre_check_result['errors']}")
                raise Exception("Pre-checks failed")
            log.append("Pre-checks passed")
            steps_completed += 1
            
            if dry_run:
                log.append("DRY RUN MODE - Skipping actual deployment")
                return ApplicationResult(
                    success=True,
                    steps_total=steps_total,
                    steps_completed=steps_completed,
                    steps_failed=0,
                    duration_seconds=(datetime.now() - start_time).total_seconds(),
                    log=log,
                    error_message=None,
                    backup_path=backup_path,
                    rollback_available=backup_path is not None
                )
            
            # Deploy configuration files
            log.append(f"Deploying {len(model.files)} configuration files")
            deploy_result = self._deploy_files(ssh, model)
            steps_completed += deploy_result['success_count']
            steps_failed += deploy_result['failed_count']
            log.extend(deploy_result['log'])
            
            if deploy_result['failed_count'] > 0:
                log.append(f"⚠️ {deploy_result['failed_count']} files failed to deploy")
            
            # Install packages
            if model.packages_to_install:
                log.append(f"Installing packages: {model.packages_to_install}")
                install_result = self._install_packages(ssh, model.packages_to_install)
                if install_result['success']:
                    steps_completed += 1
                    log.append("Packages installed successfully")
                else:
                    steps_failed += 1
                    log.append(f"Package installation failed: {install_result['error']}")
            
            # Remove packages
            if model.packages_to_remove:
                log.append(f"Removing packages: {model.packages_to_remove}")
                remove_result = self._remove_packages(ssh, model.packages_to_remove)
                if remove_result['success']:
                    steps_completed += 1
                    log.append("Packages removed successfully")
                else:
                    steps_failed += 1
                    log.append(f"Package removal failed: {remove_result['error']}")
            
            # Enable services
            if model.services_to_enable:
                log.append(f"Enabling services: {model.services_to_enable}")
                enable_result = self._manage_services(ssh, model.services_to_enable, 'enable')
                steps_completed += enable_result['success_count']
                steps_failed += enable_result['failed_count']
                log.extend(enable_result['log'])
            
            # Disable services
            if model.services_to_disable:
                log.append(f"Disabling services: {model.services_to_disable}")
                disable_result = self._manage_services(ssh, model.services_to_disable, 'disable')
                steps_completed += disable_result['success_count']
                steps_failed += disable_result['failed_count']
                log.extend(disable_result['log'])
            
            # Post-checks
            log.append("Running post-checks")
            post_check_result = self._run_post_checks(ssh, model)
            if not post_check_result['passed']:
                log.append(f"⚠️ Post-checks failed: {post_check_result['errors']}")
                log.append("Consider rollback if issues detected")
            else:
                log.append("Post-checks passed")
            steps_completed += 1
            
            # Disconnect
            ssh.disconnect()
            log.append("Hardening applied successfully")
            
            duration = (datetime.now() - start_time).total_seconds()
            
            return ApplicationResult(
                success=True,
                steps_total=steps_total,
                steps_completed=steps_completed,
                steps_failed=steps_failed,
                duration_seconds=duration,
                log=log,
                error_message=None,
                backup_path=backup_path,
                rollback_available=backup_path is not None
            )
        
        except Exception as e:
            logger.error(f"Hardening application failed: {e}")
            log.append(f"ERROR: {str(e)}")
            
            duration = (datetime.now() - start_time).total_seconds()
            
            return ApplicationResult(
                success=False,
                steps_total=steps_total if 'steps_total' in locals() else 0,
                steps_completed=steps_completed,
                steps_failed=steps_failed + 1,
                duration_seconds=duration,
                log=log,
                error_message=str(e),
                backup_path=backup_path,
                rollback_available=backup_path is not None
            )
    
    def _calculate_total_steps(self, model: HardeningModel) -> int:
        """Calcola numero totale di step"""
        steps = 2  # SSH connect + OS verify
        steps += 1  # Backup
        steps += 1  # Pre-checks
        steps += len(model.files)  # File deployments
        
        if model.packages_to_install:
            steps += 1
        if model.packages_to_remove:
            steps += 1
        if model.services_to_enable:
            steps += len(model.services_to_enable)
        if model.services_to_disable:
            steps += len(model.services_to_disable)
        
        steps += 1  # Post-checks
        
        return steps
    
    def _verify_os_compatibility(self, ssh: SSHManager, model: HardeningModel) -> bool:
        """Verifica compatibilità OS"""
        if not model.supported_os:
            return True  # No restrictions
        
        # Get OS info
        exit_code, stdout, stderr = ssh.execute_command('cat /etc/os-release')
        if exit_code != 0:
            logger.warning("Could not detect OS version")
            return True  # Proceed with caution
        
        os_release = stdout.lower()
        
        # Check if any supported OS matches
        for supported in model.supported_os:
            if supported.lower() in os_release:
                return True
        
        logger.error(f"OS not in supported list: {model.supported_os}")
        return False
    
    def _run_pre_checks(self, ssh: SSHManager, model: HardeningModel) -> Dict:
        """Esegue pre-checks"""
        checks = {
            'passed': True,
            'errors': []
        }
        
        # Check disk space
        exit_code, stdout, stderr = ssh.execute_command('df / | tail -1')
        if exit_code == 0:
            parts = stdout.split()
            if len(parts) >= 5:
                usage = int(parts[4].rstrip('%'))
                if usage > 90:
                    checks['errors'].append(f"Disk usage is {usage}% - low space!")
                    checks['passed'] = False
        
        # Check SSH still works (implicit - we're connected)
        # This is redundant but serves as a placeholder for more checks
        
        return checks
    
    def _deploy_files(self, ssh: SSHManager, model: HardeningModel) -> Dict:
        """Deploya i file di configurazione"""
        success_count = 0
        failed_count = 0
        log = []
        
        # Create temp directory on target
        temp_dir = f"/tmp/microsiem_hardening_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        ssh.execute_command(f'mkdir -p {temp_dir}')
        
        for filename, content in model.files.items():
            target_path = self.model_loader.get_target_path(filename)
            temp_file = f"{temp_dir}/{filename}"
            
            try:
                # Write content to local temp file
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                    f.write(content)
                    local_temp_path = f.name
                
                # Upload to temp dir on target
                if not ssh.upload_file(local_temp_path, temp_file):
                    raise Exception("Upload failed")
                
                # Move to final location with sudo
                exit_code, stdout, stderr = ssh.execute_command(
                    f'sudo mkdir -p $(dirname {target_path}) && '
                    f'sudo mv {temp_file} {target_path} && '
                    f'sudo chown root:root {target_path} && '
                    f'sudo chmod 644 {target_path}'
                )
                
                if exit_code != 0:
                    raise Exception(f"Move failed: {stderr}")
                
                log.append(f"✓ Deployed: {target_path}")
                success_count += 1
                
                # Cleanup local temp
                Path(local_temp_path).unlink()
            
            except Exception as e:
                log.append(f"✗ Failed: {target_path} - {str(e)}")
                failed_count += 1
        
        # Cleanup temp dir on target
        ssh.execute_command(f'rm -rf {temp_dir}')
        
        return {
            'success_count': success_count,
            'failed_count': failed_count,
            'log': log
        }
    
    def _install_packages(self, ssh: SSHManager, packages: List[str]) -> Dict:
        """Installa pacchetti"""
        pkg_list = ' '.join(packages)
        
        # Update apt cache
        ssh.execute_command('sudo apt-get update -qq')
        
        # Install packages
        exit_code, stdout, stderr = ssh.execute_command(
            f'sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg_list}',
            timeout=300  # 5 minutes timeout
        )
        
        if exit_code != 0:
            return {'success': False, 'error': stderr}
        
        return {'success': True, 'error': None}
    
    def _remove_packages(self, ssh: SSHManager, packages: List[str]) -> Dict:
        """Rimuove pacchetti"""
        pkg_list = ' '.join(packages)
        
        exit_code, stdout, stderr = ssh.execute_command(
            f'sudo DEBIAN_FRONTEND=noninteractive apt-get remove -y {pkg_list}',
            timeout=300
        )
        
        if exit_code != 0:
            return {'success': False, 'error': stderr}
        
        return {'success': True, 'error': None}
    
    def _manage_services(self, ssh: SSHManager, services: List[str], action: str) -> Dict:
        """Gestisce servizi (enable/disable)"""
        success_count = 0
        failed_count = 0
        log = []
        
        for service in services:
            if action == 'enable':
                cmd = f'sudo systemctl enable {service} && sudo systemctl start {service}'
            else:  # disable
                cmd = f'sudo systemctl stop {service} && sudo systemctl disable {service}'
            
            exit_code, stdout, stderr = ssh.execute_command(cmd)
            
            if exit_code == 0:
                log.append(f"✓ {action.capitalize()}d service: {service}")
                success_count += 1
            else:
                log.append(f"✗ Failed to {action} {service}: {stderr}")
                failed_count += 1
        
        return {
            'success_count': success_count,
            'failed_count': failed_count,
            'log': log
        }
    
    def _run_post_checks(self, ssh: SSHManager, model: HardeningModel) -> Dict:
        """Esegue post-checks"""
        checks = {
            'passed': True,
            'errors': []
        }
        
        # Verify SSH still works (we're connected, so it works)
        # But let's check sshd is running
        exit_code, stdout, stderr = ssh.execute_command('systemctl is-active sshd')
        if exit_code != 0 or 'active' not in stdout:
            checks['errors'].append("SSH daemon not active!")
            checks['passed'] = False
        
        # Check enabled services are running
        for service in model.services_to_enable:
            exit_code, stdout, stderr = ssh.execute_command(f'systemctl is-active {service}')
            if exit_code != 0:
                checks['errors'].append(f"Service {service} not running")
                checks['passed'] = False
        
        return checks
```

*[Continua nel prossimo messaggio per limiti di spazio...]*

---

**Versione**: 1.0.0  
**Data**: 2025-11-28  
**Autore**: Development Team
