"""
============================================================================
CYBERSHEPPARD - Hardening Applier
============================================================================
Applies hardening configurations to target systems via SSH.
"""

import os
import tempfile
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime
import logging

from ..ssh.ssh_manager import SSHManager, SSHCommandError
from ..models_loader.loader import HardeningModel, FileOperation, PackageOperation, ServiceOperation, SysctlParameter

logger = logging.getLogger(__name__)


@dataclass
class OperationResult:
    """Result of a single operation"""
    operation_type: str
    operation_name: str
    success: bool
    message: str
    exit_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None


@dataclass
class ApplyResult:
    """Result of applying a complete hardening model"""
    model_name: str
    target_id: int
    success: bool
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    operations: List[OperationResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    score: int = 0  # Hardening score (0-100)


class HardeningApplier:
    """
    Applies hardening configurations to target systems.
    """

    def __init__(self, ssh_manager: SSHManager, backup_path: Optional[str] = None):
        """
        Initialize hardening applier.

        Args:
            ssh_manager: SSHManager instance for target
            backup_path: Path for configuration backups
        """
        self.ssh = ssh_manager
        self.backup_path = backup_path or os.getenv('HARDENING_BACKUP_PATH', '/app/tmp/backups')

    def apply_model(self, model: HardeningModel, target_id: int, dry_run: bool = False) -> ApplyResult:
        """
        Apply a hardening model to the target.

        Args:
            model: HardeningModel to apply
            target_id: Target system ID
            dry_run: If True, only simulate without making changes

        Returns:
            ApplyResult with detailed results
        """
        result = ApplyResult(
            model_name=model.name,
            target_id=target_id,
            success=False
        )

        logger.info(f"{'[DRY RUN] ' if dry_run else ''}Applying model '{model.name}' to target {target_id}")

        try:
            # Connect to target
            self.ssh.connect()

            # Apply package operations
            for pkg_op in model.package_operations:
                op_result = self._apply_package_operation(pkg_op, dry_run)
                result.operations.append(op_result)
                if not op_result.success:
                    result.errors.append(f"Package operation failed: {pkg_op.name}")

            # Apply file operations
            for file_op in model.file_operations:
                op_result = self._apply_file_operation(file_op, dry_run)
                result.operations.append(op_result)
                if not op_result.success:
                    result.errors.append(f"File operation failed: {file_op.path}")

            # Apply service operations
            for svc_op in model.service_operations:
                op_result = self._apply_service_operation(svc_op, dry_run)
                result.operations.append(op_result)
                if not op_result.success:
                    result.errors.append(f"Service operation failed: {svc_op.name}")

            # Apply sysctl parameters
            for sysctl_param in model.sysctl_parameters:
                op_result = self._apply_sysctl_parameter(sysctl_param, dry_run)
                result.operations.append(op_result)
                if not op_result.success:
                    result.errors.append(f"Sysctl parameter failed: {sysctl_param.name}")

            # Execute custom commands
            for cmd in model.custom_commands:
                op_result = self._execute_custom_command(cmd, dry_run)
                result.operations.append(op_result)
                if not op_result.success:
                    result.errors.append(f"Custom command failed: {cmd}")

            # Calculate success rate
            total_ops = len(result.operations)
            successful_ops = sum(1 for op in result.operations if op.success)

            if total_ops > 0:
                result.score = int((successful_ops / total_ops) * 100)
                result.success = result.score >= 80  # 80% success rate required
            else:
                result.success = True  # No operations means nothing failed

            result.completed_at = datetime.utcnow()
            logger.info(f"Model application completed. Score: {result.score}%")

        except Exception as e:
            logger.error(f"Failed to apply model: {e}")
            result.errors.append(str(e))
            result.success = False
        finally:
            self.ssh.disconnect()

        return result

    def _apply_package_operation(self, pkg_op: PackageOperation, dry_run: bool) -> OperationResult:
        """Apply a package operation (install/remove/update)"""
        logger.info(f"Package {pkg_op.action}: {pkg_op.name}")

        # Detect package manager (apt, yum, dnf)
        exit_code, stdout, stderr = self.ssh.execute_command('which apt-get')
        if exit_code == 0:
            pkg_manager = 'apt-get'
        else:
            exit_code, stdout, stderr = self.ssh.execute_command('which yum')
            if exit_code == 0:
                pkg_manager = 'yum'
            else:
                pkg_manager = 'dnf'

        # Build command
        if pkg_op.action == 'install':
            cmd = f"{pkg_manager} install -y {pkg_op.name}"
            if pkg_op.version:
                cmd += f"={pkg_op.version}" if pkg_manager == 'apt-get' else f"-{pkg_op.version}"
        elif pkg_op.action == 'remove':
            cmd = f"{pkg_manager} remove -y {pkg_op.name}"
        elif pkg_op.action == 'update':
            cmd = f"{pkg_manager} upgrade -y {pkg_op.name}"
        else:
            return OperationResult(
                operation_type='package',
                operation_name=pkg_op.name,
                success=False,
                message=f"Unknown action: {pkg_op.action}"
            )

        if dry_run:
            return OperationResult(
                operation_type='package',
                operation_name=pkg_op.name,
                success=True,
                message=f"[DRY RUN] Would execute: {cmd}"
            )

        try:
            exit_code, stdout, stderr = self.ssh.execute_command(cmd, timeout=300)
            return OperationResult(
                operation_type='package',
                operation_name=pkg_op.name,
                success=(exit_code == 0),
                message=f"Package {pkg_op.action} {'succeeded' if exit_code == 0 else 'failed'}",
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr
            )
        except SSHCommandError as e:
            return OperationResult(
                operation_type='package',
                operation_name=pkg_op.name,
                success=False,
                message=str(e)
            )

    def _apply_file_operation(self, file_op: FileOperation, dry_run: bool) -> OperationResult:
        """Apply a file operation (create/modify/append/delete)"""
        logger.info(f"File {file_op.action}: {file_op.path}")

        if dry_run:
            return OperationResult(
                operation_type='file',
                operation_name=file_op.path,
                success=True,
                message=f"[DRY RUN] Would {file_op.action} file: {file_op.path}"
            )

        try:
            # Backup existing file if needed
            if file_op.backup and file_op.action in ['modify', 'delete']:
                timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                backup_cmd = f"cp {file_op.path} {file_op.path}.bak.{timestamp}"
                self.ssh.execute_command(backup_cmd)

            if file_op.action == 'create' or file_op.action == 'modify':
                # Create temp file with content
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                    temp_file.write(file_op.content or '')
                    temp_path = temp_file.name

                # Upload file
                self.ssh.upload_file(temp_path, file_op.path)
                os.unlink(temp_path)

                # Set permissions and ownership
                if file_op.mode:
                    self.ssh.execute_command(f"chmod {file_op.mode} {file_op.path}")
                if file_op.owner:
                    owner_group = f"{file_op.owner}:{file_op.group}" if file_op.group else file_op.owner
                    self.ssh.execute_command(f"chown {owner_group} {file_op.path}")

                message = f"File {file_op.action}d successfully"

            elif file_op.action == 'append':
                # Append to existing file
                content_escaped = file_op.content.replace("'", "'\\''")
                cmd = f"echo '{content_escaped}' >> {file_op.path}"
                exit_code, stdout, stderr = self.ssh.execute_command(cmd)

                if exit_code != 0:
                    return OperationResult(
                        operation_type='file',
                        operation_name=file_op.path,
                        success=False,
                        message=f"Failed to append to file: {stderr}",
                        exit_code=exit_code
                    )

                message = "Content appended successfully"

            elif file_op.action == 'delete':
                cmd = f"rm -f {file_op.path}"
                exit_code, stdout, stderr = self.ssh.execute_command(cmd)

                if exit_code != 0:
                    return OperationResult(
                        operation_type='file',
                        operation_name=file_op.path,
                        success=False,
                        message=f"Failed to delete file: {stderr}",
                        exit_code=exit_code
                    )

                message = "File deleted successfully"

            else:
                return OperationResult(
                    operation_type='file',
                    operation_name=file_op.path,
                    success=False,
                    message=f"Unknown action: {file_op.action}"
                )

            return OperationResult(
                operation_type='file',
                operation_name=file_op.path,
                success=True,
                message=message
            )

        except Exception as e:
            return OperationResult(
                operation_type='file',
                operation_name=file_op.path,
                success=False,
                message=str(e)
            )

    def _apply_service_operation(self, svc_op: ServiceOperation, dry_run: bool) -> OperationResult:
        """Apply a service operation (enable/disable/start/stop/restart)"""
        logger.info(f"Service {svc_op.action}: {svc_op.name}")

        # Detect init system (systemd or sysvinit)
        exit_code, _, _ = self.ssh.execute_command('which systemctl')
        use_systemctl = (exit_code == 0)

        if dry_run:
            return OperationResult(
                operation_type='service',
                operation_name=svc_op.name,
                success=True,
                message=f"[DRY RUN] Would {svc_op.action} service: {svc_op.name}"
            )

        try:
            if use_systemctl:
                cmd = f"systemctl {svc_op.action} {svc_op.name}"
            else:
                cmd = f"service {svc_op.name} {svc_op.action}"

            exit_code, stdout, stderr = self.ssh.execute_command(cmd)

            return OperationResult(
                operation_type='service',
                operation_name=svc_op.name,
                success=(exit_code == 0),
                message=f"Service {svc_op.action} {'succeeded' if exit_code == 0 else 'failed'}",
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr
            )

        except SSHCommandError as e:
            return OperationResult(
                operation_type='service',
                operation_name=svc_op.name,
                success=False,
                message=str(e)
            )

    def _apply_sysctl_parameter(self, param: SysctlParameter, dry_run: bool) -> OperationResult:
        """Apply a sysctl kernel parameter"""
        logger.info(f"Sysctl parameter: {param.name} = {param.value}")

        if dry_run:
            return OperationResult(
                operation_type='sysctl',
                operation_name=param.name,
                success=True,
                message=f"[DRY RUN] Would set {param.name} = {param.value}"
            )

        try:
            # Apply immediately
            cmd = f"sysctl -w {param.name}={param.value}"
            exit_code, stdout, stderr = self.ssh.execute_command(cmd)

            if exit_code != 0:
                return OperationResult(
                    operation_type='sysctl',
                    operation_name=param.name,
                    success=False,
                    message=f"Failed to set parameter: {stderr}",
                    exit_code=exit_code
                )

            # Make persistent in /etc/sysctl.conf
            persist_cmd = f"echo '{param.name}={param.value}' >> /etc/sysctl.conf"
            self.ssh.execute_command(persist_cmd)

            return OperationResult(
                operation_type='sysctl',
                operation_name=param.name,
                success=True,
                message="Parameter set successfully"
            )

        except SSHCommandError as e:
            return OperationResult(
                operation_type='sysctl',
                operation_name=param.name,
                success=False,
                message=str(e)
            )

    def _execute_custom_command(self, command: str, dry_run: bool) -> OperationResult:
        """Execute a custom shell command"""
        logger.info(f"Custom command: {command}")

        if dry_run:
            return OperationResult(
                operation_type='custom',
                operation_name=command[:50],
                success=True,
                message=f"[DRY RUN] Would execute: {command}"
            )

        try:
            exit_code, stdout, stderr = self.ssh.execute_command(command, timeout=300)

            return OperationResult(
                operation_type='custom',
                operation_name=command[:50],
                success=(exit_code == 0),
                message=f"Command {'succeeded' if exit_code == 0 else 'failed'}",
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr
            )

        except SSHCommandError as e:
            return OperationResult(
                operation_type='custom',
                operation_name=command[:50],
                success=False,
                message=str(e)
            )
