# MicroSIEM - HARDENING_SPEC.md (Part 2)

## Flask Micro-API

### API Server

```python
# hardening_engine/app.py

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from typing import Dict

from .models.loader import ModelLoader
from .models.validator import ModelValidator
from .applier.applier import HardeningApplier
from .applier.rollback import RollbackManager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for Rust backend

# Initialize components
model_loader = ModelLoader()
model_validator = ModelValidator()
hardening_applier = HardeningApplier()
rollback_manager = RollbackManager()


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'hardening-engine',
        'version': '1.0.0'
    })


@app.route('/models', methods=['GET'])
def list_models():
    """
    GET /models
    
    Lista tutti i modelli disponibili
    """
    try:
        models = model_loader.list_available_models()
        
        return jsonify({
            'success': True,
            'data': {
                'models': models,
                'count': len(models)
            }
        }), 200
    
    except Exception as e:
        logger.error(f"Error listing models: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/models/<model_name>', methods=['GET'])
def get_model(model_name: str):
    """
    GET /models/{model_name}
    
    Ottiene dettagli di un modello
    """
    try:
        model = model_loader.load_model(model_name)
        
        return jsonify({
            'success': True,
            'data': {
                'name': model.name,
                'version': model.version,
                'description': model.description,
                'role': model.role,
                'compliance': model.compliance,
                'level': model.level,
                'author': model.author,
                'files_count': len(model.files),
                'services_to_enable': model.services_to_enable,
                'services_to_disable': model.services_to_disable,
                'packages_to_install': model.packages_to_install,
                'packages_to_remove': model.packages_to_remove,
                'requires_reboot': model.requires_reboot,
                'supported_os': model.supported_os,
                'hash_sha512': model.hash_sha512
            }
        }), 200
    
    except FileNotFoundError as e:
        return jsonify({
            'success': False,
            'error': f"Model not found: {model_name}"
        }), 404
    
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/validate', methods=['POST'])
def validate_model():
    """
    POST /validate
    Body: {"model_name": "web_severo_nis2"}
    
    Valida un modello
    """
    try:
        data = request.get_json()
        model_name = data.get('model_name')
        
        if not model_name:
            return jsonify({
                'success': False,
                'error': 'model_name is required'
            }), 400
        
        # Load model
        model = model_loader.load_model(model_name)
        
        # Validate
        result = model_validator.validate_model(model)
        
        return jsonify({
            'success': True,
            'data': {
                'passed': result.passed,
                'errors': result.errors,
                'warnings': result.warnings,
                'suggestions': result.suggestions
            }
        }), 200
    
    except Exception as e:
        logger.error(f"Error validating model: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/apply', methods=['POST'])
def apply_hardening():
    """
    POST /apply
    Body: {
        "model_name": "web_severo_nis2",
        "target_ip": "192.168.1.10",
        "ssh_port": 22,
        "ssh_username": "microcyber",
        "ssh_key_path": "/opt/microsiem/keys/id_ed25519",
        "create_backup": true,
        "dry_run": false
    }
    
    Applica hardening a un target
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['model_name', 'target_ip', 'ssh_key_path']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'{field} is required'
                }), 400
        
        # Apply hardening
        result = hardening_applier.apply_model(
            model_name=data['model_name'],
            target_ip=data['target_ip'],
            ssh_port=data.get('ssh_port', 22),
            ssh_username=data.get('ssh_username', 'microcyber'),
            ssh_key_path=data['ssh_key_path'],
            create_backup=data.get('create_backup', True),
            dry_run=data.get('dry_run', False)
        )
        
        return jsonify({
            'success': result.success,
            'data': {
                'steps_total': result.steps_total,
                'steps_completed': result.steps_completed,
                'steps_failed': result.steps_failed,
                'duration_seconds': result.duration_seconds,
                'log': result.log,
                'error_message': result.error_message,
                'backup_path': result.backup_path,
                'rollback_available': result.rollback_available
            }
        }), 200 if result.success else 500
    
    except Exception as e:
        logger.error(f"Error applying hardening: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/rollback', methods=['POST'])
def rollback_hardening():
    """
    POST /rollback
    Body: {
        "target_ip": "192.168.1.10",
        "ssh_port": 22,
        "ssh_username": "microcyber",
        "ssh_key_path": "/opt/microsiem/keys/id_ed25519",
        "backup_path": "/backups/192.168.1.10_20251128_103045"
    }
    
    Rollback hardening da backup
    """
    try:
        data = request.get_json()
        
        required_fields = ['target_ip', 'ssh_key_path', 'backup_path']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'{field} is required'
                }), 400
        
        # Perform rollback
        result = rollback_manager.rollback(
            target_ip=data['target_ip'],
            ssh_port=data.get('ssh_port', 22),
            ssh_username=data.get('ssh_username', 'microcyber'),
            ssh_key_path=data['ssh_key_path'],
            backup_path=data['backup_path']
        )
        
        return jsonify({
            'success': result['success'],
            'data': {
                'files_restored': result.get('files_restored', 0),
                'log': result.get('log', [])
            },
            'error': result.get('error')
        }), 200 if result['success'] else 500
    
    except Exception as e:
        logger.error(f"Error during rollback: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/check_connection', methods=['POST'])
def check_connection():
    """
    POST /check_connection
    Body: {
        "target_ip": "192.168.1.10",
        "ssh_port": 22,
        "ssh_username": "microcyber",
        "ssh_key_path": "/opt/microsiem/keys/id_ed25519"
    }
    
    Verifica connessione SSH al target
    """
    try:
        from .ssh.manager import SSHManager
        
        data = request.get_json()
        
        ssh = SSHManager(
            target_ip=data['target_ip'],
            ssh_port=data.get('ssh_port', 22),
            username=data.get('ssh_username', 'microcyber')
        )
        
        connected = ssh.connect(data['ssh_key_path'])
        
        if connected:
            # Get OS info
            exit_code, stdout, stderr = ssh.execute_command('cat /etc/os-release')
            os_info = stdout if exit_code == 0 else "Unknown"
            
            ssh.disconnect()
            
            return jsonify({
                'success': True,
                'data': {
                    'connected': True,
                    'os_info': os_info
                }
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Connection failed'
            }), 500
    
    except Exception as e:
        logger.error(f"Error checking connection: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    # Run Flask app
    app.run(
        host='127.0.0.1',  # Only localhost (Rust backend is on same machine)
        port=5001,
        debug=False
    )
```

---

## Backup Manager

```python
# hardening_engine/applier/backup.py

import os
import shutil
import tarfile
from pathlib import Path
from datetime import datetime
from typing import Dict, List
import logging

from ..models.loader import HardeningModel
from ..ssh.manager import SSHManager

logger = logging.getLogger(__name__)


class BackupManager:
    """
    Gestisce backup delle configurazioni prima di applicare hardening
    """
    
    def __init__(self, backup_base_path: str = "/opt/microsiem/backups"):
        self.backup_base_path = Path(backup_base_path)
        self.backup_base_path.mkdir(parents=True, exist_ok=True)
    
    def create_backup(
        self,
        ssh: SSHManager,
        model: HardeningModel,
        target_ip: str
    ) -> str:
        """
        Crea backup dei file che verranno modificati
        
        Args:
            ssh: Connessione SSH al target
            model: Modello che verrà applicato
            target_ip: IP del target
        
        Returns:
            Path del backup creato
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"{target_ip.replace('.', '_')}_{timestamp}"
        backup_path = self.backup_base_path / backup_name
        backup_path.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Creating backup: {backup_path}")
        
        # Create manifest
        manifest = {
            'target_ip': target_ip,
            'timestamp': timestamp,
            'model_name': model.name,
            'files': []
        }
        
        # Backup each file that will be modified
        for filename, content in model.files.items():
            target_path = self._dot_notation_to_path(filename)
            
            try:
                # Download existing file from target
                local_backup_file = backup_path / filename
                
                # Check if file exists on target
                exit_code, stdout, stderr = ssh.execute_command(
                    f'test -f {target_path} && echo "exists"'
                )
                
                if 'exists' in stdout:
                    # File exists, download it
                    success = ssh.download_file(target_path, str(local_backup_file))
                    
                    if success:
                        manifest['files'].append({
                            'filename': filename,
                            'target_path': target_path,
                            'backed_up': True
                        })
                        logger.debug(f"Backed up: {target_path}")
                    else:
                        manifest['files'].append({
                            'filename': filename,
                            'target_path': target_path,
                            'backed_up': False,
                            'error': 'Download failed'
                        })
                        logger.warning(f"Failed to backup: {target_path}")
                else:
                    # File doesn't exist on target (new file)
                    manifest['files'].append({
                        'filename': filename,
                        'target_path': target_path,
                        'backed_up': False,
                        'reason': 'File does not exist on target'
                    })
                    logger.debug(f"File doesn't exist on target: {target_path}")
            
            except Exception as e:
                logger.error(f"Error backing up {target_path}: {e}")
                manifest['files'].append({
                    'filename': filename,
                    'target_path': target_path,
                    'backed_up': False,
                    'error': str(e)
                })
        
        # Write manifest
        import json
        manifest_path = backup_path / 'manifest.json'
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        # Create tarball
        tarball_path = backup_path.parent / f"{backup_name}.tar.gz"
        with tarfile.open(tarball_path, 'w:gz') as tar:
            tar.add(backup_path, arcname=backup_name)
        
        logger.info(f"Backup completed: {tarball_path}")
        
        return str(backup_path)
    
    def _dot_notation_to_path(self, filename: str) -> str:
        """Converte dot notation → system path"""
        return "/" + filename.replace(".", "/")


# hardening_engine/applier/rollback.py

class RollbackManager:
    """
    Gestisce rollback delle configurazioni
    """
    
    def __init__(self, backup_base_path: str = "/opt/microsiem/backups"):
        self.backup_base_path = Path(backup_base_path)
    
    def rollback(
        self,
        target_ip: str,
        ssh_port: int,
        ssh_username: str,
        ssh_key_path: str,
        backup_path: str
    ) -> Dict:
        """
        Esegue rollback da backup
        
        Args:
            target_ip: IP del target
            ssh_port: Porta SSH
            ssh_username: Username SSH
            ssh_key_path: Path chiave SSH
            backup_path: Path del backup da ripristinare
        
        Returns:
            Dict con risultato operazione
        """
        log = []
        files_restored = 0
        
        try:
            backup_path = Path(backup_path)
            
            if not backup_path.exists():
                return {
                    'success': False,
                    'error': f'Backup not found: {backup_path}'
                }
            
            # Load manifest
            manifest_path = backup_path / 'manifest.json'
            if not manifest_path.exists():
                return {
                    'success': False,
                    'error': 'Backup manifest not found'
                }
            
            import json
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)
            
            log.append(f"Rolling back to backup: {backup_path.name}")
            log.append(f"Original model: {manifest.get('model_name')}")
            
            # Connect to target
            from ..ssh.manager import SSHManager
            ssh = SSHManager(
                target_ip=target_ip,
                ssh_port=ssh_port,
                username=ssh_username
            )
            
            if not ssh.connect(ssh_key_path):
                return {
                    'success': False,
                    'error': f'SSH connection failed to {target_ip}'
                }
            
            log.append("SSH connected")
            
            # Restore each file
            for file_info in manifest['files']:
                if not file_info.get('backed_up'):
                    log.append(f"Skipping {file_info['filename']} (not in backup)")
                    continue
                
                filename = file_info['filename']
                target_path = file_info['target_path']
                local_file = backup_path / filename
                
                try:
                    # Upload backup file to temp location
                    temp_path = f"/tmp/rollback_{filename}"
                    if not ssh.upload_file(str(local_file), temp_path):
                        raise Exception("Upload failed")
                    
                    # Move to final location
                    exit_code, stdout, stderr = ssh.execute_command(
                        f'sudo mv {temp_path} {target_path} && '
                        f'sudo chown root:root {target_path} && '
                        f'sudo chmod 644 {target_path}'
                    )
                    
                    if exit_code != 0:
                        raise Exception(f"Move failed: {stderr}")
                    
                    log.append(f"✓ Restored: {target_path}")
                    files_restored += 1
                
                except Exception as e:
                    log.append(f"✗ Failed to restore {target_path}: {e}")
            
            ssh.disconnect()
            log.append(f"Rollback completed: {files_restored} files restored")
            
            return {
                'success': True,
                'files_restored': files_restored,
                'log': log
            }
        
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'log': log
            }
```

---

## Security Considerations

### 1. SSH Key Management

```python
# Encryption of private keys at rest
from cryptography.fernet import Fernet
import os

def encrypt_private_key(private_key: str, encryption_key: bytes) -> str:
    """
    Encrypts SSH private key before storing
    
    Args:
        private_key: Plain text private key
        encryption_key: Fernet encryption key (32 bytes)
    
    Returns:
        Encrypted private key (base64 encoded)
    """
    cipher = Fernet(encryption_key)
    encrypted = cipher.encrypt(private_key.encode())
    return encrypted.decode()


def decrypt_private_key(encrypted_key: str, encryption_key: bytes) -> str:
    """
    Decrypts SSH private key for use
    
    Args:
        encrypted_key: Encrypted private key
        encryption_key: Fernet encryption key
    
    Returns:
        Plain text private key
    """
    cipher = Fernet(encryption_key)
    decrypted = cipher.decrypt(encrypted_key.encode())
    return decrypted.decode()


def get_encryption_key() -> bytes:
    """
    Gets encryption key from environment or generates new one
    
    Returns:
        32-byte Fernet key
    """
    key = os.getenv('MICROSIEM_ENCRYPTION_KEY')
    
    if not key:
        raise ValueError(
            "MICROSIEM_ENCRYPTION_KEY not set in environment. "
            "Generate with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
        )
    
    return key.encode()
```

---

### 2. Input Validation

```python
# hardening_engine/utils/validators.py

import ipaddress
import re
from pathlib import Path
from typing import Tuple


def validate_ip_address(ip: str) -> Tuple[bool, str]:
    """Valida indirizzo IP"""
    try:
        ipaddress.ip_address(ip)
        return True, ""
    except ValueError as e:
        return False, str(e)


def validate_ssh_port(port: int) -> Tuple[bool, str]:
    """Valida porta SSH"""
    if not isinstance(port, int):
        return False, "Port must be integer"
    
    if port < 1 or port > 65535:
        return False, "Port must be between 1 and 65535"
    
    return True, ""


def validate_model_name(name: str) -> Tuple[bool, str]:
    """Valida nome modello (no path traversal)"""
    # Only allow alphanumeric, underscore, hyphen
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return False, "Invalid model name format"
    
    # Check for path traversal attempts
    if '..' in name or '/' in name or '\\' in name:
        return False, "Path traversal not allowed"
    
    return True, ""


def validate_file_path(path: str) -> Tuple[bool, str]:
    """Valida file path (no command injection)"""
    # Check for dangerous characters
    dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r']
    for char in dangerous_chars:
        if char in path:
            return False, f"Dangerous character not allowed: {char}"
    
    # Must be absolute path
    if not path.startswith('/'):
        return False, "Path must be absolute"
    
    return True, ""
```

---

### 3. Command Injection Prevention

```python
# NEVER use string formatting for SSH commands

# ❌ WRONG - Command injection vulnerability
def bad_execute(ssh, filename):
    cmd = f"cat /etc/{filename}"  # VULNERABLE!
    ssh.execute_command(cmd)

# ✅ CORRECT - Use whitelist and validation
def good_execute(ssh, filename):
    import shlex
    
    # Validate filename
    if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
        raise ValueError("Invalid filename")
    
    # Use shlex.quote for safety
    safe_filename = shlex.quote(filename)
    cmd = f"cat /etc/{safe_filename}"
    ssh.execute_command(cmd)
```

---

### 4. Rate Limiting (in Rust backend)

Flask micro-API should only be accessible from localhost (Rust backend), but add basic protection:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour", "20 per minute"],
    storage_uri="memory://"  # Or use Redis for distributed
)

@app.route('/apply', methods=['POST'])
@limiter.limit("5 per hour")  # Max 5 hardening applications per hour
def apply_hardening():
    # ...
```

---

### 5. Logging & Audit

```python
# All actions should be logged with full context

def log_hardening_action(
    action: str,
    model_name: str,
    target_ip: str,
    user_id: int,
    success: bool,
    details: dict = None
):
    """
    Logs hardening actions for audit trail
    
    This should be called from Rust backend after Flask micro-API response
    """
    logger.info(
        f"AUDIT: {action} | Model: {model_name} | "
        f"Target: {target_ip} | User: {user_id} | "
        f"Success: {success} | Details: {details}"
    )
    
    # Also write to database audit_logs table via Rust backend
```

---

## Testing

### Unit Tests

```python
# hardening_engine/tests/test_loader.py

import pytest
from hardening_engine.models.loader import ModelLoader

def test_load_model():
    """Test model loading"""
    loader = ModelLoader("/path/to/test/models")
    model = loader.load_model("generic_base")
    
    assert model.name == "generic_base"
    assert len(model.files) > 0
    assert model.hash_sha512 is not None


def test_integrity_check():
    """Test integrity verification"""
    loader = ModelLoader("/path/to/test/models")
    model = loader.load_model("generic_base")
    
    # Should pass with correct hash
    assert loader.verify_model_integrity("generic_base", model.hash_sha512)
    
    # Should fail with wrong hash
    assert not loader.verify_model_integrity("generic_base", "wrong_hash")


# hardening_engine/tests/test_validator.py

def test_validate_sshd_config():
    """Test sshd_config validation"""
    from hardening_engine.models.validator import ModelValidator
    
    validator = ModelValidator()
    
    # Valid config
    valid_config = """
    PermitRootLogin no
    PasswordAuthentication no
    PubkeyAuthentication yes
    """
    
    result = validator._validate_sshd_config("etc.ssh.sshd_config", valid_config)
    assert result.passed
    assert len(result.errors) == 0
```

---

## Deployment

### Systemd Service

```ini
# /etc/systemd/system/microsiem-hardening.service

[Unit]
Description=MicroSIEM Hardening Engine API
After=network.target

[Service]
Type=simple
User=microsiem
Group=microsiem
WorkingDirectory=/opt/microsiem/hardening_engine
Environment="MICROSIEM_ENCRYPTION_KEY=<your-key-here>"
ExecStart=/opt/microsiem/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

## Summary

### Python Components Created

| Componente | File | Descrizione |
|------------|------|-------------|
| **Model Loader** | `models/loader.py` | Carica modelli da filesystem, calcola hash |
| **Model Validator** | `models/validator.py` | Valida sintassi configurazioni |
| **Hardening Applier** | `applier/applier.py` | Applica modelli via SSH |
| **Backup Manager** | `applier/backup.py` | Crea backup pre-hardening |
| **Rollback Manager** | `applier/rollback.py` | Ripristina da backup |
| **SSH Manager** | `ssh/manager.py` | Gestione SSH (riusato da FireDog) |
| **Flask API** | `app.py` | API HTTP per Rust backend |

### API Endpoints

| Endpoint | Method | Descrizione |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/models` | GET | Lista modelli disponibili |
| `/models/<name>` | GET | Dettaglio modello |
| `/validate` | POST | Valida modello |
| `/apply` | POST | Applica hardening |
| `/rollback` | POST | Rollback da backup |
| `/check_connection` | POST | Verifica SSH |

### Security Features

✅ **Input validation** - Tutti gli input validati  
✅ **Command injection prevention** - shlex.quote, whitelist  
✅ **SSH key encryption** - Fernet encryption at rest  
✅ **Rate limiting** - Max 5 hardening/hour  
✅ **Audit logging** - Tutte le azioni loggato  
✅ **Backup automatico** - Sempre prima di applicare  
✅ **Rollback** - Ripristino rapido in caso di errori  

---

**Versione**: 1.0.0  
**Data**: 2025-11-28  
**Autore**: Development Team
