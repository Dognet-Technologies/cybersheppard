# CyberSheppard - Piano di Sviluppo Dettagliato

**Data**: 2025-12-28
**Branch di Sviluppo**: sviluppo
**Versione Target**: 1.0.0
**Timeline**: 14 settimane (~3.5 mesi)

---

## 📋 Indice

1. [Roadmap Overview](#roadmap-overview)
2. [Fase 1: Backend Hardening](#fase-1-backend-hardening-settimane-1-2)
3. [Fase 2: Monitoring System](#fase-2-monitoring-system-settimane-3-4)
4. [Fase 3: Frontend Core](#fase-3-frontend-core-settimane-5-6)
5. [Fase 4: Hardening UI](#fase-4-hardening-ui-settimana-7)
6. [Fase 5: Integrations](#fase-5-integrations--correlation-settimane-8-9)
7. [Fase 6: Compliance & Alerts](#fase-6-compliance--alerts-settimane-10-11)
8. [Fase 7: Testing & QA](#fase-7-testing--qa-settimane-12-13)
9. [Fase 8: Deployment](#fase-8-deployment--documentation-settimana-14)
10. [Task Checklist](#task-checklist-completa)

---

## Roadmap Overview

```
Settimane 1-2:  ████████░░░░░░ Backend Hardening (P0)
Settimane 3-4:  ░░░░░░██████░░ Monitoring System (P0)
Settimane 5-6:  ░░░░░░░░░░████ Frontend Core (P0)
Settimana 7:    ░░░░░░░░░░░░██ Hardening UI (P1)
Settimane 8-9:  ░░░░░░░░░░░░░░ Integrations (P1)
Settimane 10-11:░░░░░░░░░░░░░░ Compliance & Alerts (P1)
Settimane 12-13:░░░░░░░░░░░░░░ Testing & QA (P1)
Settimana 14:   ░░░░░░░░░░░░░░ Deployment (P0)
```

**Completamento Attuale**: 45%
**Obiettivo Fine Fase 8**: 100%

---

## Fase 1: Backend Hardening (Settimane 1-2)

### 🎯 Obiettivo
Sistema di hardening funzionante end-to-end: modelli caricabili, validazione, applicazione via SSH, backup e rollback.

### 📦 Deliverables
1. ✅ Django hardening engine funzionante
2. ✅ Rust backend integrato con Django engine
3. ✅ Almeno 2 modelli di hardening testati
4. ✅ Backup automatico funzionante
5. ✅ Rollback testato

---

### Settimana 1: Django Hardening Engine

#### Giorno 1-2: SSHManager (da FireDog)

**File**: `backend-django/hardening_engine/ssh/manager.py`

**Task**:
1. Copiare `ssh_manager.py` da FireDog repository
2. Adattare per rimuovere dipendenze Django models
3. Passare parametri esplicitamente (target_ip, username, ssh_port, private_key_path)
4. Testare connessione SSH a target di test

**Codice di Riferimento**: `documentazione/CODE_REUSE_MAP.md` linee 183-326

**Metodi da Implementare**:
```python
class SSHManager:
    def __init__(self, target_ip, ssh_port, username, timeout)
    def connect(self, private_key_path) -> bool
    def disconnect(self)
    def execute_command(self, command) -> Tuple[int, str, str]
    def upload_file(self, local_path, remote_path) -> bool
    def download_file(self, remote_path, local_path) -> bool
    def upload_directory(self, local_dir, remote_dir) -> bool
```

**Testing**:
```bash
cd backend-django/hardening_engine
python -c "
from ssh.manager import SSHManager
ssh = SSHManager('192.168.1.10', 22, 'microcyber', 30)
if ssh.connect('/path/to/key'):
    code, out, err = ssh.execute_command('hostname')
    print(f'Output: {out}')
    ssh.disconnect()
"
```

**Tempo Stimato**: 8 ore

---

#### Giorno 3: ModelLoader

**File**: `backend-django/hardening_engine/models_loader/loader.py`

**Task**:
1. Implementare caricamento modelli YAML da filesystem
2. Supportare dot notation per file paths (`etc.ssh.sshd_config` → `/etc/ssh/sshd_config`)
3. Calcolare SHA512 hash per integrity check
4. Gestire metadata (nome, descrizione, versione, compatibilità OS)

**Struttura Modello YAML**:
```yaml
# hardening-models/base/ssh.yml
metadata:
  name: "ssh_base_generic"
  description: "SSH hardening base per Debian/Ubuntu"
  version: "1.0.0"
  os_compatibility:
    - "Debian 11"
    - "Debian 12"
    - "Ubuntu 20.04"
    - "Ubuntu 22.04"

files:
  - path: "/etc/ssh/sshd_config"
    content: |
      # SSH Configuration - Base Hardening
      Port 22
      PermitRootLogin no
      PasswordAuthentication no
      PubkeyAuthentication yes
      # ... (contenuto completo)

packages:
  install:
    - openssh-server
    - fail2ban
  remove:
    - telnet
    - rsh-server

services:
  enable:
    - ssh
    - fail2ban
  disable:
    - telnet
```

**Codice**:
```python
import yaml
import hashlib
from pathlib import Path
from typing import Dict, List

class ModelLoader:
    """Load hardening models from YAML files"""

    def __init__(self, models_dir: str):
        self.models_dir = Path(models_dir)

    def load_model(self, model_path: str) -> Dict:
        """
        Load model from YAML file

        Args:
            model_path: Relative path like "base/ssh.yml"

        Returns:
            Dict with model data + integrity hash
        """
        full_path = self.models_dir / model_path

        if not full_path.exists():
            raise FileNotFoundError(f"Model not found: {full_path}")

        with open(full_path, 'r') as f:
            content = f.read()
            model = yaml.safe_load(content)

        # Calculate SHA512 hash for integrity
        model['_hash'] = hashlib.sha512(content.encode()).hexdigest()
        model['_path'] = str(full_path)

        return model

    def list_models(self) -> List[Dict]:
        """List all available models"""
        models = []

        for yaml_file in self.models_dir.rglob('*.yml'):
            relative_path = yaml_file.relative_to(self.models_dir)
            try:
                model = self.load_model(str(relative_path))
                models.append({
                    'path': str(relative_path),
                    'name': model['metadata']['name'],
                    'description': model['metadata']['description'],
                    'version': model['metadata']['version']
                })
            except Exception as e:
                print(f"Error loading {relative_path}: {e}")

        return models
```

**Testing**:
```python
loader = ModelLoader('/path/to/hardening-models')
models = loader.list_models()
print(f"Found {len(models)} models")

ssh_model = loader.load_model('base/ssh.yml')
print(f"Model: {ssh_model['metadata']['name']}")
print(f"Hash: {ssh_model['_hash'][:16]}...")
```

**Tempo Stimato**: 4 ore

---

#### Giorno 4: ModelValidator

**File**: `backend-django/hardening_engine/models_loader/validator.py`

**Task**:
1. Validare che SSH non venga disabilitato (critico!)
2. Validare iptables include regola SSH
3. Validare sysctl syntax
4. Validare sudoers syntax
5. Check conflitti tra file

**Codice**:
```python
import re
from typing import Dict, List, Tuple

class ModelValidator:
    """Validate hardening models for safety and correctness"""

    def validate_model(self, model: Dict) -> Tuple[bool, List[str]]:
        """
        Validate model

        Returns:
            (is_valid, list_of_errors)
        """
        errors = []

        # Validate SSH safety
        ssh_errors = self._validate_ssh_safety(model)
        errors.extend(ssh_errors)

        # Validate iptables
        iptables_errors = self._validate_iptables(model)
        errors.extend(iptables_errors)

        # Validate sysctl
        sysctl_errors = self._validate_sysctl(model)
        errors.extend(sysctl_errors)

        return (len(errors) == 0, errors)

    def _validate_ssh_safety(self, model: Dict) -> List[str]:
        """Ensure SSH won't be disabled or blocked"""
        errors = []

        # Check services
        if 'services' in model:
            if 'disable' in model['services']:
                if 'ssh' in model['services']['disable'] or 'sshd' in model['services']['disable']:
                    errors.append("CRITICAL: SSH service cannot be disabled")

        # Check files for sshd_config
        if 'files' in model:
            for file_entry in model['files']:
                if file_entry['path'] in ['/etc/ssh/sshd_config', '/etc/ssh/ssh_config']:
                    content = file_entry.get('content', '')

                    # Check for dangerous settings
                    if re.search(r'^\\s*Port\\s+0', content, re.MULTILINE):
                        errors.append("CRITICAL: SSH port cannot be 0")

                    if re.search(r'^\\s*PermitRootLogin\\s+yes', content, re.MULTILINE):
                        errors.append("WARNING: PermitRootLogin yes is not recommended")

        return errors

    def _validate_iptables(self, model: Dict) -> List[str]:
        """Ensure iptables rules allow SSH"""
        errors = []

        # Check if iptables rules exist and include SSH
        if 'files' in model:
            for file_entry in model['files']:
                if 'iptables' in file_entry['path'] or 'firewall' in file_entry['path']:
                    content = file_entry.get('content', '')

                    # Check for SSH rule (port 22)
                    if not re.search(r'--dport\\s+22\\s+.*ACCEPT', content):
                        errors.append("WARNING: iptables rules should allow SSH port 22")

        return errors

    def _validate_sysctl(self, model: Dict) -> List[str]:
        """Validate sysctl parameters syntax"""
        errors = []

        if 'files' in model:
            for file_entry in model['files']:
                if file_entry['path'] == '/etc/sysctl.conf' or 'sysctl.d' in file_entry['path']:
                    content = file_entry.get('content', '')

                    # Validate each line
                    for line in content.split('\\n'):
                        line = line.strip()

                        # Skip comments and empty lines
                        if not line or line.startswith('#'):
                            continue

                        # Check format: key = value
                        if '=' not in line:
                            errors.append(f"Invalid sysctl line: {line}")

        return errors
```

**Testing**:
```python
validator = ModelValidator()

# Test with a model
loader = ModelLoader('/path/to/hardening-models')
model = loader.load_model('base/ssh.yml')

is_valid, errors = validator.validate_model(model)
if is_valid:
    print("✅ Model is valid")
else:
    print("❌ Validation errors:")
    for error in errors:
        print(f"  - {error}")
```

**Tempo Stimato**: 6 ore

---

#### Giorno 5: HardeningApplier (Parte 1)

**File**: `backend-django/hardening_engine/applier/applier.py`

**Task**:
1. Implementare workflow applicazione hardening (13 steps)
2. Integrazione con SSHManager
3. Deploy file di configurazione
4. Install/remove packages

**Workflow**:
```
1. Load model
2. Validate model
3. SSH connect to target
4. Verify OS compatibility
5. Run pre-checks (disk space, etc.)
6. Create backup
7. Deploy configuration files
8. Install/remove packages
9. Enable/disable services
10. Run post-checks (SSH still active)
11. Return result
```

**Codice**:
```python
from ssh.manager import SSHManager
from models_loader.loader import ModelLoader
from models_loader.validator import ModelValidator
from applier.backup import BackupManager
import logging
from typing import Dict, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

class HardeningApplier:
    """Apply hardening models to target systems"""

    def __init__(self, models_dir: str, backups_dir: str):
        self.loader = ModelLoader(models_dir)
        self.validator = ModelValidator()
        self.backup_manager = BackupManager(backups_dir)

    def apply_hardening(self,
                       target_ip: str,
                       model_path: str,
                       ssh_key_path: str,
                       ssh_port: int = 22,
                       username: str = "microcyber") -> Dict:
        """
        Apply hardening model to target

        Returns:
            {
                'success': bool,
                'steps_completed': int,
                'steps_failed': int,
                'backup_path': str,
                'duration_seconds': float,
                'log': List[str]
            }
        """
        start_time = datetime.now()
        log = []
        steps_completed = 0

        try:
            # Step 1: Load model
            log.append("Loading model...")
            model = self.loader.load_model(model_path)
            steps_completed += 1
            log.append(f"✅ Loaded model: {model['metadata']['name']}")

            # Step 2: Validate model
            log.append("Validating model...")
            is_valid, errors = self.validator.validate_model(model)
            if not is_valid:
                return {
                    'success': False,
                    'steps_completed': steps_completed,
                    'steps_failed': 1,
                    'error': f"Model validation failed: {errors}",
                    'log': log
                }
            steps_completed += 1
            log.append("✅ Model is valid")

            # Step 3: SSH connect
            log.append(f"Connecting to {target_ip}...")
            ssh = SSHManager(target_ip, ssh_port, username, 60)

            if not ssh.connect(ssh_key_path):
                return {
                    'success': False,
                    'steps_completed': steps_completed,
                    'steps_failed': 1,
                    'error': "SSH connection failed",
                    'log': log
                }
            steps_completed += 1
            log.append("✅ SSH connected")

            # Step 4: Verify OS
            log.append("Verifying OS compatibility...")
            code, stdout, stderr = ssh.execute_command('cat /etc/os-release')
            if code != 0:
                ssh.disconnect()
                return {
                    'success': False,
                    'steps_completed': steps_completed,
                    'steps_failed': 1,
                    'error': "Cannot read OS version",
                    'log': log
                }

            # Check if OS is compatible
            os_compatible = False
            for compatible_os in model['metadata'].get('os_compatibility', []):
                if compatible_os.lower() in stdout.lower():
                    os_compatible = True
                    break

            if not os_compatible:
                log.append(f"⚠️ OS may not be compatible. Detected: {stdout[:100]}")
            else:
                log.append("✅ OS is compatible")
            steps_completed += 1

            # Step 5: Pre-checks (disk space)
            log.append("Running pre-checks...")
            code, stdout, stderr = ssh.execute_command('df -BG / | tail -1 | awk \"{print $4}\"')
            if code == 0:
                disk_space_gb = int(stdout.strip().replace('G', ''))
                if disk_space_gb < 1:
                    ssh.disconnect()
                    return {
                        'success': False,
                        'steps_completed': steps_completed,
                        'steps_failed': 1,
                        'error': f"Insufficient disk space: {disk_space_gb}GB (need 1GB)",
                        'log': log
                    }
                log.append(f"✅ Disk space OK: {disk_space_gb}GB available")
            steps_completed += 1

            # Step 6: Create backup
            log.append("Creating backup...")
            backup_path = self.backup_manager.create_backup(ssh, model, target_ip)
            steps_completed += 1
            log.append(f"✅ Backup created: {backup_path}")

            # Step 7: Deploy configuration files
            log.append("Deploying configuration files...")
            files_deployed = self._deploy_files(ssh, model.get('files', []))
            steps_completed += 1
            log.append(f"✅ Deployed {files_deployed} files")

            # Step 8: Install/remove packages
            if 'packages' in model:
                log.append("Managing packages...")
                self._manage_packages(ssh, model['packages'])
                steps_completed += 1
                log.append("✅ Packages updated")

            # Step 9: Enable/disable services
            if 'services' in model:
                log.append("Managing services...")
                self._manage_services(ssh, model['services'])
                steps_completed += 1
                log.append("✅ Services configured")

            # Step 10: Post-checks (SSH still active)
            log.append("Running post-checks...")
            code, stdout, stderr = ssh.execute_command('systemctl is-active ssh || systemctl is-active sshd')
            if code != 0 or 'active' not in stdout:
                log.append("⚠️ WARNING: SSH service may not be active!")
            else:
                log.append("✅ SSH service is active")
            steps_completed += 1

            # Disconnect
            ssh.disconnect()

            # Calculate duration
            duration = (datetime.now() - start_time).total_seconds()

            return {
                'success': True,
                'steps_completed': steps_completed,
                'steps_failed': 0,
                'backup_path': backup_path,
                'duration_seconds': duration,
                'log': log
            }

        except Exception as e:
            logger.error(f"Hardening failed: {e}")
            return {
                'success': False,
                'steps_completed': steps_completed,
                'steps_failed': 1,
                'error': str(e),
                'log': log
            }

    def _deploy_files(self, ssh: SSHManager, files: list) -> int:
        """Deploy configuration files to target"""
        deployed = 0

        for file_entry in files:
            remote_path = file_entry['path']
            content = file_entry.get('content', '')

            # Create temp file locally
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name

            # Upload to temp location on target
            remote_tmp = f"/tmp/microsiem_config_{deployed}"
            if ssh.upload_file(tmp_path, remote_tmp):
                # Move to final location with sudo
                code, stdout, stderr = ssh.execute_command(
                    f"sudo mv {remote_tmp} {remote_path} && sudo chown root:root {remote_path} && sudo chmod 644 {remote_path}"
                )

                if code == 0:
                    deployed += 1

            # Cleanup local temp file
            import os
            os.unlink(tmp_path)

        return deployed

    def _manage_packages(self, ssh: SSHManager, packages: Dict):
        """Install/remove packages"""
        # Update package lists
        ssh.execute_command("sudo apt-get update -qq")

        # Install packages
        if 'install' in packages and packages['install']:
            packages_str = ' '.join(packages['install'])
            ssh.execute_command(f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {packages_str}")

        # Remove packages
        if 'remove' in packages and packages['remove']:
            packages_str = ' '.join(packages['remove'])
            ssh.execute_command(f"sudo DEBIAN_FRONTEND=noninteractive apt-get remove -y {packages_str}")

    def _manage_services(self, ssh: SSHManager, services: Dict):
        """Enable/disable/start/stop services"""
        # Enable services
        if 'enable' in services and services['enable']:
            for service in services['enable']:
                ssh.execute_command(f"sudo systemctl enable {service}")
                ssh.execute_command(f"sudo systemctl start {service}")

        # Disable services
        if 'disable' in services and services['disable']:
            for service in services['disable']:
                ssh.execute_command(f"sudo systemctl stop {service}")
                ssh.execute_command(f"sudo systemctl disable {service}")
```

**Tempo Stimato**: 8 ore

---

### Settimana 2: Backup, Rollback & Rust Integration

#### Giorno 6-7: BackupManager & RollbackManager

**File**: `backend-django/hardening_engine/applier/backup.py`

**Codice**:
```python
import os
import json
import tarfile
from datetime import datetime
from pathlib import Path
from typing import Dict
from ssh.manager import SSHManager

class BackupManager:
    """Manage backups of target configurations before hardening"""

    def __init__(self, backups_dir: str):
        self.backups_dir = Path(backups_dir)
        self.backups_dir.mkdir(parents=True, exist_ok=True)

    def create_backup(self, ssh: SSHManager, model: Dict, target_ip: str) -> str:
        """
        Create backup of files that will be modified

        Returns:
            Backup directory path
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"{target_ip.replace('.', '_')}_{timestamp}"
        backup_dir = self.backups_dir / backup_name
        backup_dir.mkdir()

        files_to_backup = model.get('files', [])

        manifest = {
            'target_ip': target_ip,
            'model_name': model['metadata']['name'],
            'model_version': model['metadata']['version'],
            'timestamp': timestamp,
            'files': []
        }

        for file_entry in files_to_backup:
            remote_path = file_entry['path']

            # Download original file if exists
            local_backup_path = backup_dir / remote_path.lstrip('/')
            local_backup_path.parent.mkdir(parents=True, exist_ok=True)

            # Check if file exists
            code, stdout, stderr = ssh.execute_command(f"test -f {remote_path} && echo EXISTS")

            if 'EXISTS' in stdout:
                # Download file
                if ssh.download_file(remote_path, str(local_backup_path)):
                    manifest['files'].append({
                        'path': remote_path,
                        'backed_up': True
                    })
                else:
                    manifest['files'].append({
                        'path': remote_path,
                        'backed_up': False,
                        'error': 'Download failed'
                    })
            else:
                # File doesn't exist, no backup needed
                manifest['files'].append({
                    'path': remote_path,
                    'backed_up': False,
                    'reason': 'File did not exist'
                })

        # Save manifest
        with open(backup_dir / 'manifest.json', 'w') as f:
            json.dump(manifest, f, indent=2)

        # Create tarball
        tarball_path = self.backups_dir / f"{backup_name}.tar.gz"
        with tarfile.open(tarball_path, 'w:gz') as tar:
            tar.add(backup_dir, arcname=backup_name)

        return str(tarball_path)
```

**File**: `backend-django/hardening_engine/applier/rollback.py`

```python
import json
import tarfile
from pathlib import Path
from typing import Dict
from ssh.manager import SSHManager

class RollbackManager:
    """Rollback hardening changes using backups"""

    def __init__(self, backups_dir: str):
        self.backups_dir = Path(backups_dir)

    def rollback(self, backup_tarball: str, ssh: SSHManager) -> Dict:
        """
        Rollback changes by restoring backup

        Returns:
            {
                'success': bool,
                'files_restored': int,
                'log': List[str]
            }
        """
        log = []
        files_restored = 0

        # Extract tarball
        tarball_path = Path(backup_tarball)
        if not tarball_path.exists():
            return {
                'success': False,
                'error': f"Backup not found: {backup_tarball}",
                'log': log
            }

        # Create temp extraction directory
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            # Extract
            with tarfile.open(tarball_path, 'r:gz') as tar:
                tar.extractall(temp_dir)

            # Find manifest
            extracted_dirs = list(Path(temp_dir).iterdir())
            if not extracted_dirs:
                return {
                    'success': False,
                    'error': 'Empty backup',
                    'log': log
                }

            backup_dir = extracted_dirs[0]
            manifest_path = backup_dir / 'manifest.json'

            if not manifest_path.exists():
                return {
                    'success': False,
                    'error': 'Manifest not found',
                    'log': log
                }

            # Load manifest
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)

            log.append(f"Restoring backup for {manifest['target_ip']}")
            log.append(f"Model: {manifest['model_name']} v{manifest['model_version']}")

            # Restore each file
            for file_info in manifest['files']:
                if not file_info.get('backed_up'):
                    continue

                remote_path = file_info['path']
                local_backup = backup_dir / remote_path.lstrip('/')

                if not local_backup.exists():
                    log.append(f"⚠️ Backup file not found: {remote_path}")
                    continue

                # Upload backup file to temp location
                remote_tmp = f"/tmp/microsiem_rollback_{files_restored}"
                if ssh.upload_file(str(local_backup), remote_tmp):
                    # Move to original location
                    code, stdout, stderr = ssh.execute_command(
                        f"sudo mv {remote_tmp} {remote_path} && sudo chmod 644 {remote_path}"
                    )

                    if code == 0:
                        files_restored += 1
                        log.append(f"✅ Restored: {remote_path}")
                    else:
                        log.append(f"❌ Failed to restore: {remote_path}")

            # Reload services
            ssh.execute_command("sudo systemctl daemon-reload")

            return {
                'success': True,
                'files_restored': files_restored,
                'log': log
            }
```

**Tempo Stimato**: 8 ore

---

#### Giorno 8-9: Django REST API Endpoints

**File**: `backend-django/hardening_engine/views.py`

**Task**:
1. Creare API endpoints Flask/Django
2. Implementare POST /apply
3. Implementare GET /models
4. Implementare POST /rollback
5. Testare integrazione

**Endpoints**:
```python
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
from hardening_engine.applier.applier import HardeningApplier
from hardening_engine.applier.rollback import RollbackManager
from hardening_engine.models_loader.loader import ModelLoader

# Configuration
MODELS_DIR = '/path/to/hardening-models'
BACKUPS_DIR = '/opt/microsiem/backups'

applier = HardeningApplier(MODELS_DIR, BACKUPS_DIR)
rollback_manager = RollbackManager(BACKUPS_DIR)
loader = ModelLoader(MODELS_DIR)

@csrf_exempt
@require_http_methods(["POST"])
def apply_hardening(request):
    """
    POST /api/hardening/apply

    Body:
    {
        "target_ip": "192.168.1.10",
        "model_path": "base/ssh.yml",
        "ssh_key_path": "/path/to/key",
        "ssh_port": 22,
        "username": "microcyber"
    }
    """
    try:
        data = json.loads(request.body)

        target_ip = data['target_ip']
        model_path = data['model_path']
        ssh_key_path = data['ssh_key_path']
        ssh_port = data.get('ssh_port', 22)
        username = data.get('username', 'microcyber')

        result = applier.apply_hardening(
            target_ip=target_ip,
            model_path=model_path,
            ssh_key_path=ssh_key_path,
            ssh_port=ssh_port,
            username=username
        )

        return JsonResponse(result)

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@require_http_methods(["GET"])
def list_models(request):
    """
    GET /api/hardening/models
    """
    try:
        models = loader.list_models()
        return JsonResponse({
            'models': models
        })
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)

@require_http_methods(["GET"])
def get_model(request, model_path):
    """
    GET /api/hardening/models/<path:model_path>
    """
    try:
        model = loader.load_model(model_path)
        return JsonResponse({
            'model': model
        })
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=404)

@csrf_exempt
@require_http_methods(["POST"])
def rollback_hardening(request):
    """
    POST /api/hardening/rollback

    Body:
    {
        "backup_tarball": "/path/to/backup.tar.gz",
        "target_ip": "192.168.1.10",
        "ssh_key_path": "/path/to/key",
        "ssh_port": 22,
        "username": "microcyber"
    }
    """
    try:
        data = json.loads(request.body)

        backup_tarball = data['backup_tarball']
        target_ip = data['target_ip']
        ssh_key_path = data['ssh_key_path']
        ssh_port = data.get('ssh_port', 22)
        username = data.get('username', 'microcyber')

        # Connect SSH
        from hardening_engine.ssh.manager import SSHManager
        ssh = SSHManager(target_ip, ssh_port, username, 60)

        if not ssh.connect(ssh_key_path):
            return JsonResponse({
                'success': False,
                'error': 'SSH connection failed'
            }, status=500)

        result = rollback_manager.rollback(backup_tarball, ssh)
        ssh.disconnect()

        return JsonResponse(result)

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
```

**URL Configuration** (`hardening_engine/urls.py`):
```python
from django.urls import path
from . import views

urlpatterns = [
    path('apply', views.apply_hardening, name='apply_hardening'),
    path('models', views.list_models, name='list_models'),
    path('models/<path:model_path>', views.get_model, name='get_model'),
    path('rollback', views.rollback_hardening, name='rollback_hardening'),
]
```

**Tempo Stimato**: 8 ore

---

#### Giorno 10: Rust Backend Integration

**File**: `backend-rust/src/api/hardening.rs`

**Task**:
1. Implementare client HTTP per Django engine
2. Implementare POST /api/hardening/apply endpoint
3. Implementare GET /api/hardening/models
4. Salvare risultati in PostgreSQL

**Codice**:
```rust
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use reqwest::Client;
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/models", get(list_models))
        .route("/models/:model_path", get(get_model))
        .route("/apply", post(apply_hardening))
        .route("/rollback", post(rollback_hardening))
}

#[derive(Deserialize)]
struct ApplyHardeningRequest {
    target_id: i32,
    model_path: String,
}

#[derive(Serialize, Deserialize)]
struct ApplyHardeningResponse {
    success: bool,
    steps_completed: i32,
    steps_failed: i32,
    backup_path: Option<String>,
    duration_seconds: Option<f64>,
    log: Vec<String>,
    error: Option<String>,
}

async fn apply_hardening(
    State(state): State<AppState>,
    Json(payload): Json<ApplyHardeningRequest>,
) -> impl IntoResponse {
    // Get target from database
    let target = match sqlx::query!(
        r#"
        SELECT id, ip_address, ssh_port, ssh_username, ssh_key_id
        FROM targets
        WHERE id = $1 AND is_active = true
        "#,
        payload.target_id
    )
    .fetch_one(&state.pg_pool)
    .await
    {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "Target not found"
                }))
            ).into_response()
        }
    };

    // Get SSH key path
    let ssh_key = sqlx::query!(
        r#"
        SELECT private_key_path
        FROM ssh_keys
        WHERE id = $1
        "#,
        target.ssh_key_id.unwrap()
    )
    .fetch_one(&state.pg_pool)
    .await
    .expect("SSH key not found");

    // Call Django hardening engine
    let client = Client::new();
    let django_url = std::env::var("DJANGO_HARDENING_URL")
        .unwrap_or_else(|_| "http://localhost:5001".to_string());

    let response = client
        .post(format!("{}/api/hardening/apply", django_url))
        .json(&serde_json::json!({
            "target_ip": target.ip_address,
            "model_path": payload.model_path,
            "ssh_key_path": ssh_key.private_key_path,
            "ssh_port": target.ssh_port.unwrap_or(22),
            "username": target.ssh_username.unwrap_or_else(|| "microcyber".to_string())
        }))
        .send()
        .await;

    match response {
        Ok(resp) => {
            let result: ApplyHardeningResponse = resp.json().await.unwrap();

            // Save to database
            let _ = sqlx::query!(
                r#"
                INSERT INTO hardening_applications
                (target_id, model_path, success, steps_completed, steps_failed,
                 backup_path, duration_seconds, result_log)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                "#,
                payload.target_id,
                payload.model_path,
                result.success,
                result.steps_completed,
                result.steps_failed,
                result.backup_path,
                result.duration_seconds,
                serde_json::to_value(&result.log).unwrap()
            )
            .execute(&state.pg_pool)
            .await;

            (StatusCode::OK, Json(result)).into_response()
        }
        Err(e) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Django engine error: {}", e)
                }))
            ).into_response()
        }
    }
}

async fn list_models(State(state): State<AppState>) -> impl IntoResponse {
    let client = Client::new();
    let django_url = std::env::var("DJANGO_HARDENING_URL")
        .unwrap_or_else(|_| "http://localhost:5001".to_string());

    let response = client
        .get(format!("{}/api/hardening/models", django_url))
        .send()
        .await;

    match response {
        Ok(resp) => {
            let models: serde_json::Value = resp.json().await.unwrap();
            (StatusCode::OK, Json(models)).into_response()
        }
        Err(e) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Django engine error: {}", e)
                }))
            ).into_response()
        }
    }
}

// Similar implementations for get_model and rollback_hardening...
```

**Tempo Stimato**: 8 ore

---

### ✅ Fine Fase 1 - Checklist

- [ ] SSHManager implementato e testato
- [ ] ModelLoader funzionante
- [ ] ModelValidator implementato
- [ ] HardeningApplier completo
- [ ] BackupManager funzionante
- [ ] RollbackManager testato
- [ ] Django API endpoints creati
- [ ] Rust backend integrato
- [ ] Almeno 2 modelli testati su target reale
- [ ] Backup e rollback testati

**Deliverable**: Sistema di hardening end-to-end funzionante

---

## Task Checklist Completa

### Backend Django - Hardening Engine
- [ ] `ssh/manager.py` - SSHManager (8h)
- [ ] `models_loader/loader.py` - ModelLoader (4h)
- [ ] `models_loader/validator.py` - ModelValidator (6h)
- [ ] `applier/applier.py` - HardeningApplier (8h)
- [ ] `applier/backup.py` - BackupManager (4h)
- [ ] `applier/rollback.py` - RollbackManager (4h)
- [ ] `views.py` - API endpoints (8h)
- [ ] Test integrazione end-to-end (4h)

**Totale Fase 1**: ~46 ore (2 settimane)

---

## Prossime Fasi (Sommario)

### Fase 2: Monitoring (Settimane 3-4)
- Completare collectors mancanti (files, packages, users, services)
- Implementare data collection service in Rust
- Setup InfluxDB buckets e retention
- Testare monitoring end-to-end

### Fase 3: Frontend Core (Settimane 5-6)
- Authentication UI
- Layout components
- Dashboard con charts
- Targets management UI

### Fase 4-8: Vedere sezioni dedicate nel documento

---

**Versione**: 1.0.0
**Ultimo Aggiornamento**: 2025-12-28
**Autore**: Development Planning Team
