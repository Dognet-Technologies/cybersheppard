"""
SSH Manager for CyberSheppard Hardening Engine

This module provides SSH connection management for executing commands
and transferring files to target systems.

Based on FireDog ssh_manager.py with adaptations for MicroSIEM.
"""

import paramiko
import os
from pathlib import Path
from scp import SCPClient
from typing import Optional, Tuple, Dict, List
import logging

logger = logging.getLogger(__name__)


class SSHManager:
    """
    Manage SSH connections to target systems

    Provides methods for:
    - Connecting to remote systems via SSH
    - Executing remote commands
    - File transfer (upload/download) via SCP
    - Directory operations

    Uses Ed25519 key-based authentication for security.
    """

    def __init__(self,
                 target_ip: str,
                 ssh_port: int = 22,
                 username: str = "microcyber",
                 timeout: int = 30):
        """
        Initialize SSH manager

        Args:
            target_ip: IP address or hostname of target system
            ssh_port: SSH port (default 22)
            username: Username for SSH connection (default microcyber)
            timeout: Connection timeout in seconds (default 30)
        """
        self.target_ip = target_ip
        self.ssh_port = ssh_port
        self.username = username
        self.timeout = timeout
        self.client = None
        self.scp_client = None
        self._connected = False

    def connect(self, private_key_path: str) -> bool:
        """
        Connect to target via SSH using Ed25519 key

        Args:
            private_key_path: Path to Ed25519 private key file

        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Load Ed25519 private key
            if not os.path.exists(private_key_path):
                logger.error(f"Private key not found: {private_key_path}")
                return False

            try:
                # Try Ed25519 first
                private_key = paramiko.Ed25519Key.from_private_key_file(
                    private_key_path
                )
            except paramiko.ssh_exception.SSHException:
                # Fallback to RSA if Ed25519 fails
                logger.warning(f"Failed to load as Ed25519, trying RSA")
                try:
                    private_key = paramiko.RSAKey.from_private_key_file(
                        private_key_path
                    )
                except Exception as e:
                    logger.error(f"Failed to load private key: {e}")
                    return False

            # Connect
            self.client.connect(
                hostname=self.target_ip,
                port=self.ssh_port,
                username=self.username,
                pkey=private_key,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False
            )

            self._connected = True
            logger.info(f"SSH connected to {self.username}@{self.target_ip}:{self.ssh_port}")
            return True

        except paramiko.AuthenticationException:
            logger.error(f"Authentication failed for {self.target_ip}")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH error connecting to {self.target_ip}: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to {self.target_ip}: {e}")
            return False

    def disconnect(self):
        """Close SSH and SCP connections"""
        if self.scp_client:
            try:
                self.scp_client.close()
            except:
                pass
            self.scp_client = None

        if self.client:
            try:
                self.client.close()
            except:
                pass
            self.client = None

        self._connected = False
        logger.info(f"SSH disconnected from {self.target_ip}")

    def is_connected(self) -> bool:
        """Check if SSH connection is active"""
        return self._connected and self.client is not None

    def execute_command(self, command: str, sudo: bool = False) -> Tuple[int, str, str]:
        """
        Execute command on remote system

        Args:
            command: Command to execute
            sudo: If True, prepend 'sudo ' to command

        Returns:
            Tuple of (exit_code, stdout, stderr)

        Raises:
            Exception if not connected or command execution fails
        """
        if not self.is_connected():
            raise Exception("Not connected to target system")

        try:
            # Prepend sudo if requested
            if sudo and not command.startswith('sudo '):
                command = f'sudo {command}'

            stdin, stdout, stderr = self.client.exec_command(
                command,
                timeout=self.timeout
            )

            # Wait for command to complete
            exit_code = stdout.channel.recv_exit_status()

            # Read output
            stdout_str = stdout.read().decode('utf-8', errors='replace')
            stderr_str = stderr.read().decode('utf-8', errors='replace')

            logger.debug(f"Command executed: {command[:100]}... (exit: {exit_code})")

            return exit_code, stdout_str, stderr_str

        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """
        Upload file to remote system via SCP

        Args:
            local_path: Local file path
            remote_path: Remote destination path

        Returns:
            True if upload successful, False otherwise
        """
        if not self.is_connected():
            raise Exception("Not connected to target system")

        if not os.path.exists(local_path):
            logger.error(f"Local file not found: {local_path}")
            return False

        try:
            # Initialize SCP client if needed
            if not self.scp_client:
                self.scp_client = SCPClient(self.client.get_transport())

            self.scp_client.put(local_path, remote_path)
            logger.info(f"Uploaded {local_path} to {self.target_ip}:{remote_path}")
            return True

        except Exception as e:
            logger.error(f"Upload failed: {e}")
            return False

    def download_file(self, remote_path: str, local_path: str) -> bool:
        """
        Download file from remote system via SCP

        Args:
            remote_path: Remote file path
            local_path: Local destination path

        Returns:
            True if download successful, False otherwise
        """
        if not self.is_connected():
            raise Exception("Not connected to target system")

        try:
            # Initialize SCP client if needed
            if not self.scp_client:
                self.scp_client = SCPClient(self.client.get_transport())

            # Ensure local directory exists
            local_dir = os.path.dirname(local_path)
            if local_dir:
                os.makedirs(local_dir, exist_ok=True)

            self.scp_client.get(remote_path, local_path)
            logger.info(f"Downloaded {remote_path} from {self.target_ip} to {local_path}")
            return True

        except Exception as e:
            logger.error(f"Download failed: {e}")
            return False

    def upload_directory(self, local_dir: str, remote_dir: str) -> bool:
        """
        Upload entire directory to remote system

        Args:
            local_dir: Local directory path
            remote_dir: Remote destination directory path

        Returns:
            True if upload successful, False otherwise
        """
        if not self.is_connected():
            raise Exception("Not connected to target system")

        if not os.path.exists(local_dir):
            logger.error(f"Local directory not found: {local_dir}")
            return False

        try:
            # Initialize SCP client if needed
            if not self.scp_client:
                self.scp_client = SCPClient(self.client.get_transport())

            self.scp_client.put(local_dir, remote_dir, recursive=True)
            logger.info(f"Uploaded directory {local_dir} to {self.target_ip}:{remote_dir}")
            return True

        except Exception as e:
            logger.error(f"Directory upload failed: {e}")
            return False

    def file_exists(self, remote_path: str) -> bool:
        """
        Check if file exists on remote system

        Args:
            remote_path: Remote file path to check

        Returns:
            True if file exists, False otherwise
        """
        try:
            code, stdout, stderr = self.execute_command(f'test -f {remote_path} && echo EXISTS')
            return 'EXISTS' in stdout
        except:
            return False

    def directory_exists(self, remote_path: str) -> bool:
        """
        Check if directory exists on remote system

        Args:
            remote_path: Remote directory path to check

        Returns:
            True if directory exists, False otherwise
        """
        try:
            code, stdout, stderr = self.execute_command(f'test -d {remote_path} && echo EXISTS')
            return 'EXISTS' in stdout
        except:
            return False

    def create_directory(self, remote_path: str, sudo: bool = False) -> bool:
        """
        Create directory on remote system

        Args:
            remote_path: Directory path to create
            sudo: Use sudo for creation

        Returns:
            True if successful, False otherwise
        """
        try:
            code, stdout, stderr = self.execute_command(
                f'mkdir -p {remote_path}',
                sudo=sudo
            )
            return code == 0
        except:
            return False

    def get_os_info(self) -> Dict[str, str]:
        """
        Get OS information from remote system

        Returns:
            Dict with OS info (name, version, etc.) or empty dict if failed
        """
        try:
            code, stdout, stderr = self.execute_command('cat /etc/os-release')

            if code != 0:
                return {}

            os_info = {}
            for line in stdout.split('\n'):
                line = line.strip()
                if '=' in line:
                    key, value = line.split('=', 1)
                    # Remove quotes
                    value = value.strip('"').strip("'")
                    os_info[key] = value

            return os_info

        except:
            return {}

    def get_disk_space(self, path: str = '/') -> Optional[Dict[str, str]]:
        """
        Get disk space information for a path

        Args:
            path: Filesystem path to check (default: /)

        Returns:
            Dict with total, used, available, percent or None if failed
        """
        try:
            code, stdout, stderr = self.execute_command(f'df -h {path} | tail -1')

            if code != 0:
                return None

            parts = stdout.split()
            if len(parts) >= 6:
                return {
                    'total': parts[1],
                    'used': parts[2],
                    'available': parts[3],
                    'percent': parts[4],
                    'mount': parts[5]
                }

            return None

        except:
            return None

    def __enter__(self):
        """Context manager enter"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - automatically disconnect"""
        self.disconnect()
        return False
