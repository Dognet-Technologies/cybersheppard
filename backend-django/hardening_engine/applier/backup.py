"""
Backup Manager for Hardening Engine

Creates backups of configuration files before applying hardening changes.
Backups are stored as compressed tarballs with manifests for easy rollback.
"""

import os
import json
import tarfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List
import logging

from ..ssh.manager import SSHManager

logger = logging.getLogger(__name__)


class BackupManager:
    """
    Manage backups of target system configurations

    Creates backups before hardening to enable rollback if needed.
    Each backup includes:
    - Original configuration files
    - Manifest with metadata (target, model, timestamp)
    - Compressed tarball for storage efficiency
    """

    def __init__(self, backups_dir: str):
        """
        Initialize backup manager

        Args:
            backups_dir: Directory where backups will be stored
        """
        self.backups_dir = Path(backups_dir)
        self.backups_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Backup manager initialized: {self.backups_dir}")

    def create_backup(self,
                     ssh: SSHManager,
                     model: Dict,
                     target_ip: str) -> str:
        """
        Create backup of files that will be modified by hardening model

        Args:
            ssh: Active SSH connection to target
            model: Hardening model dictionary
            target_ip: Target system IP address

        Returns:
            Path to created backup tarball

        Raises:
            Exception if backup creation fails
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"{target_ip.replace('.', '_')}_{timestamp}"
        backup_dir = self.backups_dir / backup_name

        logger.info(f"Creating backup: {backup_name}")

        try:
            # Create backup directory
            backup_dir.mkdir(parents=True, exist_ok=True)

            files_to_backup = model.get('files', [])

            manifest = {
                'target_ip': target_ip,
                'target_hostname': self._get_hostname(ssh),
                'model_name': model['metadata']['name'],
                'model_version': model['metadata']['version'],
                'model_path': model.get('_relative_path', 'unknown'),
                'timestamp': timestamp,
                'created_at': datetime.now().isoformat(),
                'files': []
            }

            logger.info(f"Backing up {len(files_to_backup)} file(s)")

            # Backup each file
            for i, file_entry in enumerate(files_to_backup):
                remote_path = file_entry.get('path')

                logger.debug(f"Backing up {remote_path}")

                file_result = self._backup_single_file(
                    ssh, remote_path, backup_dir
                )

                manifest['files'].append(file_result)

            # Save manifest
            manifest_path = backup_dir / 'manifest.json'
            with open(manifest_path, 'w') as f:
                json.dump(manifest, f, indent=2)

            logger.info(f"Manifest saved: {manifest_path}")

            # Create compressed tarball
            tarball_path = self.backups_dir / f"{backup_name}.tar.gz"

            with tarfile.open(tarball_path, 'w:gz') as tar:
                tar.add(backup_dir, arcname=backup_name)

            logger.info(f"Backup tarball created: {tarball_path}")

            # Cleanup temporary backup directory
            shutil.rmtree(backup_dir)

            # Calculate tarball size
            tarball_size_mb = os.path.getsize(tarball_path) / (1024 * 1024)
            logger.info(f"Backup complete: {tarball_size_mb:.2f} MB")

            return str(tarball_path)

        except Exception as e:
            logger.error(f"Backup creation failed: {e}")

            # Cleanup on failure
            if backup_dir.exists():
                shutil.rmtree(backup_dir)

            raise

    def _backup_single_file(self,
                           ssh: SSHManager,
                           remote_path: str,
                           backup_dir: Path) -> Dict:
        """
        Backup a single file from target system

        Args:
            ssh: SSH connection
            remote_path: Remote file path
            backup_dir: Local backup directory

        Returns:
            Dict with backup result metadata
        """
        result = {
            'path': remote_path,
            'backed_up': False,
            'size_bytes': 0,
            'timestamp': datetime.now().isoformat()
        }

        # Check if file exists on target
        if not ssh.file_exists(remote_path):
            result['backed_up'] = False
            result['reason'] = 'File did not exist on target'
            logger.debug(f"Skipping {remote_path} - does not exist")
            return result

        # Create local path preserving directory structure
        # /etc/ssh/sshd_config -> etc/ssh/sshd_config
        local_relative_path = remote_path.lstrip('/')
        local_backup_path = backup_dir / local_relative_path

        # Ensure parent directories exist
        local_backup_path.parent.mkdir(parents=True, exist_ok=True)

        # Download file
        try:
            if ssh.download_file(remote_path, str(local_backup_path)):
                # Get file size
                file_size = os.path.getsize(local_backup_path)

                result['backed_up'] = True
                result['size_bytes'] = file_size
                result['local_path'] = str(local_backup_path)

                logger.debug(f"Backed up {remote_path} ({file_size} bytes)")
            else:
                result['backed_up'] = False
                result['error'] = 'Download failed'
                logger.warning(f"Failed to download {remote_path}")

        except Exception as e:
            result['backed_up'] = False
            result['error'] = str(e)
            logger.error(f"Error backing up {remote_path}: {e}")

        return result

    def _get_hostname(self, ssh: SSHManager) -> str:
        """
        Get hostname from target system

        Args:
            ssh: SSH connection

        Returns:
            Hostname string or 'unknown' if retrieval fails
        """
        try:
            code, stdout, stderr = ssh.execute_command('hostname')
            if code == 0:
                return stdout.strip()
        except:
            pass

        return 'unknown'

    def list_backups(self, target_ip: str = None) -> List[Dict]:
        """
        List available backups

        Args:
            target_ip: Optional filter by target IP

        Returns:
            List of backup metadata dictionaries
        """
        backups = []

        # Find all backup tarballs
        pattern = f"{target_ip.replace('.', '_')}_*.tar.gz" if target_ip else "*.tar.gz"

        for tarball_path in self.backups_dir.glob(pattern):
            try:
                # Extract manifest from tarball without fully extracting
                with tarfile.open(tarball_path, 'r:gz') as tar:
                    # Find manifest file
                    manifest_members = [
                        m for m in tar.getmembers()
                        if m.name.endswith('manifest.json')
                    ]

                    if manifest_members:
                        manifest_file = tar.extractfile(manifest_members[0])
                        manifest = json.load(manifest_file)

                        # Add tarball metadata
                        manifest['tarball_path'] = str(tarball_path)
                        manifest['tarball_size_mb'] = os.path.getsize(tarball_path) / (1024 * 1024)
                        manifest['files_count'] = len(manifest.get('files', []))

                        backups.append(manifest)

            except Exception as e:
                logger.error(f"Error reading backup {tarball_path}: {e}")
                continue

        # Sort by timestamp (newest first)
        backups.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        return backups

    def get_backup_info(self, backup_tarball: str) -> Dict:
        """
        Get detailed information about a specific backup

        Args:
            backup_tarball: Path to backup tarball

        Returns:
            Dictionary with backup information

        Raises:
            FileNotFoundError if backup doesn't exist
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
                raise ValueError(f"No manifest found in backup: {backup_tarball}")

            manifest_file = tar.extractfile(manifest_members[0])
            manifest = json.load(manifest_file)

            # Add file stats
            manifest['tarball_path'] = str(tarball_path)
            manifest['tarball_size_mb'] = os.path.getsize(tarball_path) / (1024 * 1024)
            manifest['created_date'] = datetime.fromtimestamp(
                os.path.getctime(tarball_path)
            ).isoformat()

            return manifest

    def delete_backup(self, backup_tarball: str) -> bool:
        """
        Delete a backup tarball

        Args:
            backup_tarball: Path to backup tarball

        Returns:
            True if deleted successfully, False otherwise
        """
        tarball_path = Path(backup_tarball)

        try:
            if tarball_path.exists():
                os.remove(tarball_path)
                logger.info(f"Deleted backup: {backup_tarball}")
                return True
            else:
                logger.warning(f"Backup not found: {backup_tarball}")
                return False

        except Exception as e:
            logger.error(f"Failed to delete backup {backup_tarball}: {e}")
            return False

    def cleanup_old_backups(self, days: int = 30, max_count: int = 50) -> int:
        """
        Cleanup old backups based on age and count

        Args:
            days: Delete backups older than this many days
            max_count: Keep at most this many backups

        Returns:
            Number of backups deleted
        """
        deleted = 0
        cutoff_time = datetime.now().timestamp() - (days * 24 * 60 * 60)

        backups = []

        # Collect all backups with their metadata
        for tarball_path in self.backups_dir.glob("*.tar.gz"):
            try:
                mtime = os.path.getmtime(tarball_path)
                backups.append((tarball_path, mtime))
            except:
                continue

        # Sort by modification time (oldest first)
        backups.sort(key=lambda x: x[1])

        # Delete old backups
        for tarball_path, mtime in backups:
            # Delete if too old
            if mtime < cutoff_time:
                try:
                    os.remove(tarball_path)
                    deleted += 1
                    logger.info(f"Deleted old backup: {tarball_path.name}")
                except Exception as e:
                    logger.error(f"Failed to delete {tarball_path}: {e}")

        # If still over max_count, delete oldest
        remaining_backups = [
            b for b in backups
            if b[0].exists()
        ]

        if len(remaining_backups) > max_count:
            to_delete = len(remaining_backups) - max_count

            for tarball_path, _ in remaining_backups[:to_delete]:
                try:
                    os.remove(tarball_path)
                    deleted += 1
                    logger.info(f"Deleted excess backup: {tarball_path.name}")
                except Exception as e:
                    logger.error(f"Failed to delete {tarball_path}: {e}")

        if deleted > 0:
            logger.info(f"Cleanup complete: {deleted} backup(s) deleted")

        return deleted
