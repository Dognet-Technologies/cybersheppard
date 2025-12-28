"""
Rollback Manager for Hardening Engine

Restores system configuration from backups created before hardening.
Allows rolling back failed or unwanted hardening changes.
"""

import json
import tarfile
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List
import logging

from ..ssh.manager import SSHManager

logger = logging.getLogger(__name__)


class RollbackManager:
    """
    Rollback hardening changes using backups

    Restores configuration files from backup tarballs to undo
    hardening changes that failed or are no longer wanted.
    """

    def __init__(self, backups_dir: str):
        """
        Initialize rollback manager

        Args:
            backups_dir: Directory containing backup tarballs
        """
        self.backups_dir = Path(backups_dir)

        if not self.backups_dir.exists():
            logger.warning(f"Backups directory does not exist: {backups_dir}")
            self.backups_dir.mkdir(parents=True, exist_ok=True)

    def rollback(self,
                backup_tarball: str,
                ssh: SSHManager,
                selective_files: List[str] = None) -> Dict:
        """
        Rollback hardening changes by restoring backup

        Args:
            backup_tarball: Path to backup tarball
            ssh: Active SSH connection to target
            selective_files: Optional list of specific files to restore (None = all)

        Returns:
            Dictionary with rollback results:
            {
                'success': bool,
                'files_restored': int,
                'files_failed': int,
                'log': List[str],
                'error': str (if failed)
            }
        """
        log = []
        files_restored = 0
        files_failed = 0

        logger.info(f"Starting rollback from: {backup_tarball}")

        # Verify backup exists
        tarball_path = Path(backup_tarball)
        if not tarball_path.exists():
            return {
                'success': False,
                'files_restored': 0,
                'files_failed': 0,
                'error': f"Backup not found: {backup_tarball}",
                'log': log
            }

        # Extract backup to temporary directory
        temp_dir = tempfile.mkdtemp(prefix='cybersheppard_rollback_')

        try:
            log.append(f"Extracting backup: {tarball_path.name}")

            # Extract tarball
            with tarfile.open(tarball_path, 'r:gz') as tar:
                tar.extractall(temp_dir)

            # Find extracted directory (should be only one)
            extracted_dirs = list(Path(temp_dir).iterdir())
            if not extracted_dirs:
                return {
                    'success': False,
                    'files_restored': 0,
                    'files_failed': 0,
                    'error': 'Empty backup tarball',
                    'log': log
                }

            backup_dir = extracted_dirs[0]

            # Load manifest
            manifest_path = backup_dir / 'manifest.json'
            if not manifest_path.exists():
                return {
                    'success': False,
                    'files_restored': 0,
                    'files_failed': 0,
                    'error': 'Manifest not found in backup',
                    'log': log
                }

            with open(manifest_path, 'r') as f:
                manifest = json.load(f)

            log.append(f"Backup info:")
            log.append(f"  Target: {manifest.get('target_ip')} ({manifest.get('target_hostname')})")
            log.append(f"  Model: {manifest.get('model_name')} v{manifest.get('model_version')}")
            log.append(f"  Created: {manifest.get('created_at')}")
            log.append(f"  Files: {len(manifest.get('files', []))}")
            log.append("")

            # Restore files
            files_to_restore = manifest.get('files', [])

            # Filter by selective_files if provided
            if selective_files:
                files_to_restore = [
                    f for f in files_to_restore
                    if f['path'] in selective_files
                ]
                log.append(f"Restoring {len(files_to_restore)} selected file(s)")
            else:
                log.append(f"Restoring all {len(files_to_restore)} file(s)")

            log.append("")

            for file_info in files_to_restore:
                # Skip files that weren't backed up
                if not file_info.get('backed_up'):
                    log.append(f"⊘ {file_info['path']} (was not backed up)")
                    continue

                remote_path = file_info['path']

                # Find local backup file
                # Path is stored without leading / in backup
                local_relative_path = remote_path.lstrip('/')
                local_backup_path = backup_dir / local_relative_path

                if not local_backup_path.exists():
                    log.append(f"❌ {remote_path} (backup file not found)")
                    files_failed += 1
                    continue

                # Restore file
                success = self._restore_single_file(
                    ssh, local_backup_path, remote_path, log
                )

                if success:
                    files_restored += 1
                else:
                    files_failed += 1

            # Reload systemd daemon
            log.append("")
            log.append("Reloading systemd daemon...")
            ssh.execute_command('systemctl daemon-reload', sudo=True)

            # Restart services if needed (based on model metadata)
            if 'services' in manifest.get('model_metadata', {}):
                log.append("Restarting affected services...")
                # This is a placeholder - in production, we'd track which services to restart
                log.append("  (Manual service restart may be required)")

            log.append("")
            log.append(f"✅ Rollback complete: {files_restored} restored, {files_failed} failed")

            return {
                'success': True,
                'files_restored': files_restored,
                'files_failed': files_failed,
                'log': log
            }

        except Exception as e:
            logger.exception(f"Rollback failed: {e}")

            return {
                'success': False,
                'files_restored': files_restored,
                'files_failed': files_failed,
                'error': str(e),
                'log': log
            }

        finally:
            # Cleanup temporary directory
            try:
                shutil.rmtree(temp_dir)
            except:
                pass

    def _restore_single_file(self,
                            ssh: SSHManager,
                            local_backup_path: Path,
                            remote_path: str,
                            log: List[str]) -> bool:
        """
        Restore a single file to target system

        Args:
            ssh: SSH connection
            local_backup_path: Local backup file path
            remote_path: Remote destination path
            log: Log list to append messages

        Returns:
            True if successful, False otherwise
        """
        try:
            # Upload backup file to temp location on target
            remote_tmp = f"/tmp/cybersheppard_rollback_{local_backup_path.name}"

            if not ssh.upload_file(str(local_backup_path), remote_tmp):
                log.append(f"❌ {remote_path} (upload failed)")
                return False

            # Ensure parent directory exists
            import os
            remote_dir = os.path.dirname(remote_path)
            ssh.execute_command(f'mkdir -p {remote_dir}', sudo=True)

            # Move to final location with proper permissions
            code, stdout, stderr = ssh.execute_command(
                f'mv {remote_tmp} {remote_path} && chmod 644 {remote_path}',
                sudo=True
            )

            if code == 0:
                log.append(f"✅ {remote_path}")
                return True
            else:
                error_msg = stderr.strip()[:100]
                log.append(f"❌ {remote_path} ({error_msg})")
                return False

        except Exception as e:
            log.append(f"❌ {remote_path} ({str(e)[:100]})")
            return False

    def verify_backup_compatibility(self,
                                   backup_tarball: str,
                                   target_ip: str) -> Dict:
        """
        Verify if a backup is compatible with a target system

        Args:
            backup_tarball: Path to backup tarball
            target_ip: Target IP address to check compatibility

        Returns:
            Dictionary with compatibility info:
            {
                'compatible': bool,
                'target_ip': str,
                'backup_target_ip': str,
                'warnings': List[str]
            }
        """
        warnings = []

        tarball_path = Path(backup_tarball)
        if not tarball_path.exists():
            return {
                'compatible': False,
                'error': f"Backup not found: {backup_tarball}"
            }

        try:
            # Extract manifest only
            with tarfile.open(tarball_path, 'r:gz') as tar:
                manifest_members = [
                    m for m in tar.getmembers()
                    if m.name.endswith('manifest.json')
                ]

                if not manifest_members:
                    return {
                        'compatible': False,
                        'error': 'No manifest found in backup'
                    }

                manifest_file = tar.extractfile(manifest_members[0])
                manifest = json.load(manifest_file)

            backup_target_ip = manifest.get('target_ip', 'unknown')

            # Check if target IP matches
            if backup_target_ip != target_ip:
                warnings.append(
                    f"Target IP mismatch: backup is from {backup_target_ip}, "
                    f"attempting to restore to {target_ip}"
                )

            # Check backup age
            from datetime import datetime
            created_at = manifest.get('created_at')
            if created_at:
                backup_date = datetime.fromisoformat(created_at)
                age_days = (datetime.now() - backup_date).days

                if age_days > 30:
                    warnings.append(
                        f"Backup is {age_days} days old - "
                        "system configuration may have changed significantly"
                    )

            return {
                'compatible': True,
                'target_ip': target_ip,
                'backup_target_ip': backup_target_ip,
                'backup_date': manifest.get('created_at'),
                'model_name': manifest.get('model_name'),
                'files_count': len(manifest.get('files', [])),
                'warnings': warnings
            }

        except Exception as e:
            return {
                'compatible': False,
                'error': f"Failed to read backup: {e}"
            }

    def list_restorable_files(self, backup_tarball: str) -> List[Dict]:
        """
        List files that can be restored from a backup

        Args:
            backup_tarball: Path to backup tarball

        Returns:
            List of file info dictionaries
        """
        tarball_path = Path(backup_tarball)

        if not tarball_path.exists():
            raise FileNotFoundError(f"Backup not found: {backup_tarball}")

        with tarfile.open(tarball_path, 'r:gz') as tar:
            # Find and read manifest
            manifest_members = [
                m for m in tar.getmembers()
                if m.name.endswith('manifest.json')
            ]

            if not manifest_members:
                raise ValueError("No manifest found in backup")

            manifest_file = tar.extractfile(manifest_members[0])
            manifest = json.load(manifest_file)

            # Return only files that were backed up
            restorable = [
                {
                    'path': f['path'],
                    'size_bytes': f.get('size_bytes', 0),
                    'backed_up_at': f.get('timestamp')
                }
                for f in manifest.get('files', [])
                if f.get('backed_up')
            ]

            return restorable
