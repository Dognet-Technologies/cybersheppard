"""
Hardening Applier

Applies hardening models to target systems via SSH.
Handles the complete workflow: validation, backup, deployment, verification.
"""

import os
import tempfile
from datetime import datetime
from typing import Dict, Tuple, List
import logging

from ..ssh.manager import SSHManager
from ..models_loader.loader import ModelLoader
from ..models_loader.validator import ModelValidator
from .backup import BackupManager

logger = logging.getLogger(__name__)


class HardeningApplier:
    """
    Apply hardening models to target systems

    Workflow:
    1. Load model
    2. Validate model (safety checks)
    3. Connect to target via SSH
    4. Verify OS compatibility
    5. Run pre-checks (disk space, etc.)
    6. Create backup of existing configs
    7. Deploy configuration files
    8. Install/remove packages
    9. Enable/disable services
    10. Run post-checks (SSH still active, services running)
    11. Return detailed results
    """

    def __init__(self, models_dir: str, backups_dir: str):
        """
        Initialize hardening applier

        Args:
            models_dir: Directory containing hardening models
            backups_dir: Directory for storing backups
        """
        self.loader = ModelLoader(models_dir)
        self.validator = ModelValidator()
        self.backup_manager = BackupManager(backups_dir)

    def apply_hardening(self,
                       target_ip: str,
                       model_path: str,
                       ssh_key_path: str,
                       ssh_port: int = 22,
                       username: str = "microcyber",
                       skip_backup: bool = False) -> Dict:
        """
        Apply hardening model to target system

        Args:
            target_ip: Target system IP address
            model_path: Relative path to hardening model
            ssh_key_path: Path to SSH private key
            ssh_port: SSH port (default 22)
            username: SSH username (default microcyber)
            skip_backup: Skip backup creation (NOT RECOMMENDED, default False)

        Returns:
            Dictionary with detailed results:
            {
                'success': bool,
                'steps_completed': int,
                'steps_failed': int,
                'backup_path': str or None,
                'duration_seconds': float,
                'log': List[str],
                'error': str (if failed)
            }
        """
        start_time = datetime.now()
        log = []
        steps_completed = 0
        total_steps = 11

        ssh = None

        try:
            # Step 1: Load model
            log.append(f"[1/{total_steps}] Loading hardening model: {model_path}")
            try:
                model = self.loader.load_model(model_path)
                steps_completed += 1
                log.append(f"✅ Model loaded: {model['metadata']['name']} v{model['metadata']['version']}")
            except Exception as e:
                return self._build_error_response(
                    steps_completed, log,
                    f"Failed to load model: {e}"
                )

            # Step 2: Validate model
            log.append(f"[2/{total_steps}] Validating model for safety...")
            is_valid, errors = self.validator.validate_model(model)

            if not is_valid:
                # Critical errors found
                critical_errors = [e for e in errors if e.startswith('CRITICAL:')]
                return self._build_error_response(
                    steps_completed, log,
                    f"Model validation failed with {len(critical_errors)} critical error(s): {'; '.join(critical_errors)}"
                )

            steps_completed += 1
            if errors:
                warnings = [e for e in errors if e.startswith('WARNING:')]
                log.append(f"✅ Model is valid (with {len(warnings)} warnings)")
                for warning in warnings[:3]:  # Show first 3 warnings
                    log.append(f"  ⚠️  {warning}")
            else:
                log.append("✅ Model is valid (no issues)")

            # Step 3: Connect to target via SSH
            log.append(f"[3/{total_steps}] Connecting to {username}@{target_ip}:{ssh_port}...")
            ssh = SSHManager(target_ip, ssh_port, username, timeout=60)

            if not ssh.connect(ssh_key_path):
                return self._build_error_response(
                    steps_completed, log,
                    "SSH connection failed"
                )

            steps_completed += 1
            log.append("✅ SSH connection established")

            # Step 4: Verify OS compatibility
            log.append(f"[4/{total_steps}] Checking OS compatibility...")
            os_info = ssh.get_os_info()

            if not os_info:
                log.append("⚠️  Could not determine OS version, proceeding anyway")
            else:
                os_name = os_info.get('NAME', 'Unknown')
                os_version = os_info.get('VERSION', 'Unknown')
                log.append(f"  Detected: {os_name} {os_version}")

                # Check compatibility
                compatible_os = model['metadata'].get('os_compatibility', [])
                if compatible_os:
                    is_compatible = any(
                        compat.lower() in f"{os_name} {os_version}".lower()
                        for compat in compatible_os
                    )

                    if not is_compatible:
                        log.append(f"⚠️  OS may not be compatible. Model expects: {', '.join(compatible_os)}")
                    else:
                        log.append(f"✅ OS is compatible")

            steps_completed += 1

            # Step 5: Pre-checks (disk space)
            log.append(f"[5/{total_steps}] Running pre-flight checks...")
            disk_info = ssh.get_disk_space('/')

            if disk_info:
                available = disk_info['available']
                log.append(f"  Disk space: {available} available")

                # Parse available space (remove 'G' suffix if present)
                try:
                    available_gb = float(available.replace('G', ''))
                    if available_gb < 1:
                        return self._build_error_response(
                            steps_completed, log,
                            f"Insufficient disk space: {available} (need at least 1GB)",
                            ssh
                        )
                except:
                    log.append("  ⚠️  Could not parse disk space, proceeding anyway")

            log.append("✅ Pre-flight checks passed")
            steps_completed += 1

            # Step 6: Create backup
            backup_path = None
            if not skip_backup:
                log.append(f"[6/{total_steps}] Creating backup of existing configurations...")
                try:
                    backup_path = self.backup_manager.create_backup(ssh, model, target_ip)
                    log.append(f"✅ Backup created: {backup_path}")
                except Exception as e:
                    log.append(f"⚠️  Backup failed: {e} - continuing anyway")
            else:
                log.append(f"[6/{total_steps}] Skipping backup (as requested)")

            steps_completed += 1

            # Step 7: Deploy configuration files
            log.append(f"[7/{total_steps}] Deploying configuration files...")
            files_deployed = self._deploy_files(ssh, model.get('files', []), log)
            log.append(f"✅ Deployed {files_deployed} configuration file(s)")
            steps_completed += 1

            # Step 8: Manage packages
            if 'packages' in model and model['packages']:
                log.append(f"[8/{total_steps}] Managing packages...")
                packages_result = self._manage_packages(ssh, model['packages'], log)
                log.append(f"✅ {packages_result}")
            else:
                log.append(f"[8/{total_steps}] No package changes required")

            steps_completed += 1

            # Step 9: Manage services
            if 'services' in model and model['services']:
                log.append(f"[9/{total_steps}] Managing services...")
                services_result = self._manage_services(ssh, model['services'], log)
                log.append(f"✅ {services_result}")
            else:
                log.append(f"[9/{total_steps}] No service changes required")

            steps_completed += 1

            # Step 10: Post-checks (verify SSH and critical services)
            log.append(f"[10/{total_steps}] Running post-deployment checks...")

            # Check SSH is still active
            code, stdout, stderr = ssh.execute_command(
                'systemctl is-active ssh || systemctl is-active sshd'
            )

            if code != 0 or 'active' not in stdout:
                log.append("⚠️  WARNING: SSH service may not be active!")
                log.append("  If you lose connection, you may need physical/console access")
            else:
                log.append("✅ SSH service is active")

            # Verify services that should be enabled are running
            if 'services' in model and 'enable' in model['services']:
                for service in model['services']['enable'][:3]:  # Check first 3
                    code, stdout, stderr = ssh.execute_command(f'systemctl is-active {service}')
                    if 'active' in stdout:
                        log.append(f"  ✅ {service} is active")
                    else:
                        log.append(f"  ⚠️  {service} is not active (may be starting)")

            log.append("✅ Post-deployment checks completed")
            steps_completed += 1

            # Step 11: Finalize
            log.append(f"[11/{total_steps}] Finalizing...")
            ssh.disconnect()
            ssh = None

            duration = (datetime.now() - start_time).total_seconds()
            log.append(f"✅ Hardening completed successfully in {duration:.2f}s")
            steps_completed += 1

            return {
                'success': True,
                'steps_completed': steps_completed,
                'steps_failed': 0,
                'backup_path': backup_path,
                'duration_seconds': duration,
                'log': log
            }

        except Exception as e:
            logger.exception(f"Hardening failed: {e}")
            if ssh:
                ssh.disconnect()

            duration = (datetime.now() - start_time).total_seconds()

            return {
                'success': False,
                'steps_completed': steps_completed,
                'steps_failed': total_steps - steps_completed,
                'backup_path': None,
                'duration_seconds': duration,
                'error': str(e),
                'log': log
            }

    def _deploy_files(self, ssh: SSHManager, files: List[Dict], log: List[str]) -> int:
        """
        Deploy configuration files to target

        Args:
            ssh: Active SSH connection
            files: List of file entries from model
            log: Log list to append messages

        Returns:
            Number of files successfully deployed
        """
        deployed = 0

        for i, file_entry in enumerate(files):
            remote_path = file_entry.get('path')
            content = file_entry.get('content', '')

            log.append(f"  Deploying {remote_path}...")

            try:
                # Create temporary local file
                with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name

                # Upload to temporary location on target
                remote_tmp = f"/tmp/cybersheppard_config_{i}_{datetime.now().strftime('%Y%m%d%H%M%S')}"

                if ssh.upload_file(tmp_path, remote_tmp):
                    # Ensure parent directory exists
                    remote_dir = os.path.dirname(remote_path)
                    ssh.execute_command(f'mkdir -p {remote_dir}', sudo=True)

                    # Move to final location with proper permissions
                    code, stdout, stderr = ssh.execute_command(
                        f'mv {remote_tmp} {remote_path} && '
                        f'chown root:root {remote_path} && '
                        f'chmod 644 {remote_path}',
                        sudo=True
                    )

                    if code == 0:
                        deployed += 1
                        log.append(f"    ✅ {remote_path}")
                    else:
                        log.append(f"    ❌ {remote_path}: {stderr.strip()[:100]}")
                else:
                    log.append(f"    ❌ {remote_path}: Upload failed")

                # Cleanup local temp file
                try:
                    os.unlink(tmp_path)
                except:
                    pass

            except Exception as e:
                log.append(f"    ❌ {remote_path}: {str(e)[:100]}")

        return deployed

    def _manage_packages(self, ssh: SSHManager, packages: Dict, log: List[str]) -> str:
        """
        Install and remove packages

        Args:
            ssh: Active SSH connection
            packages: Package configuration dict
            log: Log list to append messages

        Returns:
            Summary string
        """
        installed = 0
        removed = 0

        # Update package lists first
        log.append("  Updating package lists...")
        ssh.execute_command('apt-get update -qq', sudo=True)

        # Install packages
        if 'install' in packages and packages['install']:
            install_list = packages['install']
            packages_str = ' '.join(install_list)

            log.append(f"  Installing {len(install_list)} package(s)...")

            code, stdout, stderr = ssh.execute_command(
                f'DEBIAN_FRONTEND=noninteractive apt-get install -y {packages_str}',
                sudo=True
            )

            if code == 0:
                installed = len(install_list)
                log.append(f"    ✅ Installed: {', '.join(install_list[:5])}" +
                          (f" and {len(install_list)-5} more" if len(install_list) > 5 else ""))
            else:
                log.append(f"    ⚠️  Some packages may have failed to install")

        # Remove packages
        if 'remove' in packages and packages['remove']:
            remove_list = packages['remove']
            packages_str = ' '.join(remove_list)

            log.append(f"  Removing {len(remove_list)} package(s)...")

            code, stdout, stderr = ssh.execute_command(
                f'DEBIAN_FRONTEND=noninteractive apt-get remove -y {packages_str}',
                sudo=True
            )

            if code == 0:
                removed = len(remove_list)
                log.append(f"    ✅ Removed: {', '.join(remove_list[:5])}" +
                          (f" and {len(remove_list)-5} more" if len(remove_list) > 5 else ""))
            else:
                log.append(f"    ⚠️  Some packages may have failed to remove")

        return f"Packages: {installed} installed, {removed} removed"

    def _manage_services(self, ssh: SSHManager, services: Dict, log: List[str]) -> str:
        """
        Enable, disable, start, stop services

        Args:
            ssh: Active SSH connection
            services: Services configuration dict
            log: Log list to append messages

        Returns:
            Summary string
        """
        enabled = 0
        disabled = 0
        started = 0
        stopped = 0

        # Enable services
        if 'enable' in services and services['enable']:
            for service in services['enable']:
                log.append(f"  Enabling {service}...")
                code1, _, _ = ssh.execute_command(f'systemctl enable {service}', sudo=True)
                code2, _, _ = ssh.execute_command(f'systemctl start {service}', sudo=True)

                if code1 == 0:
                    enabled += 1

                if code2 == 0:
                    started += 1

        # Disable services
        if 'disable' in services and services['disable']:
            for service in services['disable']:
                log.append(f"  Disabling {service}...")
                code1, _, _ = ssh.execute_command(f'systemctl stop {service}', sudo=True)
                code2, _, _ = ssh.execute_command(f'systemctl disable {service}', sudo=True)

                if code1 == 0:
                    stopped += 1

                if code2 == 0:
                    disabled += 1

        # Reload systemd
        ssh.execute_command('systemctl daemon-reload', sudo=True)

        return f"Services: {enabled} enabled, {disabled} disabled"

    def _build_error_response(self,
                             steps_completed: int,
                             log: List[str],
                             error_msg: str,
                             ssh: SSHManager = None) -> Dict:
        """
        Build error response dict

        Args:
            steps_completed: Number of steps completed before error
            log: Log messages
            error_msg: Error message
            ssh: SSH connection to close (if any)

        Returns:
            Error response dict
        """
        if ssh:
            ssh.disconnect()

        log.append(f"❌ ERROR: {error_msg}")

        return {
            'success': False,
            'steps_completed': steps_completed,
            'steps_failed': 1,
            'backup_path': None,
            'error': error_msg,
            'log': log
        }
