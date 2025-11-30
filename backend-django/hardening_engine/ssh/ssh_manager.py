"""
============================================================================
CYBERSHEPPARD - SSH Manager
============================================================================
Manages SSH connections and operations to target systems.
Reused and adapted from FireDog project.
"""

import os
import io
import logging
import paramiko
from typing import Optional, Tuple, List, Dict
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.backends import default_backend
from scp import SCPClient

logger = logging.getLogger(__name__)


class SSHConnectionError(Exception):
    """Raised when SSH connection fails"""
    pass


class SSHCommandError(Exception):
    """Raised when SSH command execution fails"""
    pass


class SSHManager:
    """
    Manages SSH connections to remote Linux targets.
    Handles authentication, command execution, and file transfers.
    """

    def __init__(self, hostname: str, port: int = 22, username: str = 'root',
                 password: Optional[str] = None, private_key: Optional[str] = None,
                 timeout: int = 30):
        """
        Initialize SSH manager.

        Args:
            hostname: Target hostname or IP address
            port: SSH port (default 22)
            username: SSH username
            password: SSH password (if using password auth)
            private_key: SSH private key content (if using key auth)
            timeout: Connection timeout in seconds
        """
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.private_key_content = private_key
        self.timeout = timeout
        self.client: Optional[paramiko.SSHClient] = None
        self._connected = False

    def connect(self) -> bool:
        """
        Establish SSH connection to the target.

        Returns:
            True if connection successful, False otherwise

        Raises:
            SSHConnectionError: If connection fails
        """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                'hostname': self.hostname,
                'port': self.port,
                'username': self.username,
                'timeout': self.timeout,
                'banner_timeout': self.timeout,
                'auth_timeout': self.timeout,
            }

            # Use private key if provided, otherwise use password
            if self.private_key_content:
                try:
                    private_key = paramiko.RSAKey.from_private_key(
                        io.StringIO(self.private_key_content)
                    )
                    connect_kwargs['pkey'] = private_key
                except Exception as e:
                    # Try Ed25519 key
                    try:
                        private_key = paramiko.Ed25519Key.from_private_key(
                            io.StringIO(self.private_key_content)
                        )
                        connect_kwargs['pkey'] = private_key
                    except Exception:
                        logger.error(f"Failed to load private key: {e}")
                        raise SSHConnectionError(f"Invalid private key: {e}")
            elif self.password:
                connect_kwargs['password'] = self.password
            else:
                raise SSHConnectionError("No authentication method provided")

            self.client.connect(**connect_kwargs)
            self._connected = True
            logger.info(f"SSH connection established to {self.hostname}:{self.port}")
            return True

        except paramiko.AuthenticationException as e:
            logger.error(f"SSH authentication failed for {self.hostname}: {e}")
            raise SSHConnectionError(f"Authentication failed: {e}")
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error to {self.hostname}: {e}")
            raise SSHConnectionError(f"SSH error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error connecting to {self.hostname}: {e}")
            raise SSHConnectionError(f"Connection error: {e}")

    def disconnect(self):
        """Close SSH connection."""
        if self.client:
            try:
                self.client.close()
                self._connected = False
                logger.info(f"SSH connection closed to {self.hostname}")
            except Exception as e:
                logger.error(f"Error closing SSH connection: {e}")

    def execute_command(self, command: str, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """
        Execute a command on the remote system.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds (uses connection timeout if not specified)

        Returns:
            Tuple of (exit_code, stdout, stderr)

        Raises:
            SSHCommandError: If command execution fails
        """
        if not self._connected or not self.client:
            raise SSHCommandError("Not connected to SSH server")

        try:
            cmd_timeout = timeout if timeout is not None else self.timeout
            stdin, stdout, stderr = self.client.exec_command(
                command,
                timeout=cmd_timeout
            )

            exit_code = stdout.channel.recv_exit_status()
            stdout_data = stdout.read().decode('utf-8', errors='replace')
            stderr_data = stderr.read().decode('utf-8', errors='replace')

            logger.debug(f"Command '{command}' executed with exit code {exit_code}")
            return exit_code, stdout_data, stderr_data

        except paramiko.SSHException as e:
            logger.error(f"SSH command execution failed: {e}")
            raise SSHCommandError(f"Command failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error executing command: {e}")
            raise SSHCommandError(f"Execution error: {e}")

    def execute_commands(self, commands: List[str], stop_on_error: bool = True) -> List[Tuple[str, int, str, str]]:
        """
        Execute multiple commands sequentially.

        Args:
            commands: List of commands to execute
            stop_on_error: Stop execution if a command fails

        Returns:
            List of tuples (command, exit_code, stdout, stderr)
        """
        results = []
        for cmd in commands:
            try:
                exit_code, stdout, stderr = self.execute_command(cmd)
                results.append((cmd, exit_code, stdout, stderr))

                if stop_on_error and exit_code != 0:
                    logger.warning(f"Command failed with exit code {exit_code}, stopping execution")
                    break
            except SSHCommandError as e:
                logger.error(f"Command '{cmd}' failed: {e}")
                results.append((cmd, -1, '', str(e)))
                if stop_on_error:
                    break

        return results

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """
        Upload a file to the remote system via SCP.

        Args:
            local_path: Local file path
            remote_path: Remote destination path

        Returns:
            True if upload successful

        Raises:
            SSHCommandError: If upload fails
        """
        if not self._connected or not self.client:
            raise SSHCommandError("Not connected to SSH server")

        try:
            with SCPClient(self.client.get_transport()) as scp:
                scp.put(local_path, remote_path)
            logger.info(f"File uploaded: {local_path} -> {remote_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to upload file: {e}")
            raise SSHCommandError(f"Upload failed: {e}")

    def download_file(self, remote_path: str, local_path: str) -> bool:
        """
        Download a file from the remote system via SCP.

        Args:
            remote_path: Remote file path
            local_path: Local destination path

        Returns:
            True if download successful

        Raises:
            SSHCommandError: If download fails
        """
        if not self._connected or not self.client:
            raise SSHCommandError("Not connected to SSH server")

        try:
            with SCPClient(self.client.get_transport()) as scp:
                scp.get(remote_path, local_path)
            logger.info(f"File downloaded: {remote_path} -> {local_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to download file: {e}")
            raise SSHCommandError(f"Download failed: {e}")

    def test_connection(self) -> Dict[str, any]:
        """
        Test SSH connection and gather basic system info.

        Returns:
            Dictionary with connection test results
        """
        result = {
            'success': False,
            'hostname': self.hostname,
            'port': self.port,
            'username': self.username,
            'error': None,
            'system_info': {}
        }

        try:
            self.connect()

            # Get basic system information
            exit_code, stdout, stderr = self.execute_command('uname -a')
            if exit_code == 0:
                result['system_info']['uname'] = stdout.strip()

            exit_code, stdout, stderr = self.execute_command('hostname')
            if exit_code == 0:
                result['system_info']['hostname'] = stdout.strip()

            exit_code, stdout, stderr = self.execute_command('whoami')
            if exit_code == 0:
                result['system_info']['user'] = stdout.strip()

            result['success'] = True

        except SSHConnectionError as e:
            result['error'] = str(e)
        except SSHCommandError as e:
            result['error'] = f"Connected but command failed: {e}"
        finally:
            self.disconnect()

        return result

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()

    @staticmethod
    def generate_ssh_keypair(key_type: str = 'ed25519', key_size: int = 4096) -> Tuple[str, str]:
        """
        Generate a new SSH key pair.

        Args:
            key_type: Type of key to generate ('ed25519' or 'rsa')
            key_size: Key size in bits (only for RSA, default 4096)

        Returns:
            Tuple of (private_key_pem, public_key_openssh)

        Raises:
            ValueError: If invalid key type
        """
        if key_type.lower() == 'ed25519':
            # Generate Ed25519 key (modern, secure, fast)
            private_key = ed25519.Ed25519PrivateKey.generate()

            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            # Get public key
            public_key = private_key.public_key()
            public_openssh = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            ).decode('utf-8')

        elif key_type.lower() == 'rsa':
            # Generate RSA key (traditional, widely supported)
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )

            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            # Get public key
            public_key = private_key.public_key()
            public_openssh = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            ).decode('utf-8')

        else:
            raise ValueError(f"Unsupported key type: {key_type}. Use 'ed25519' or 'rsa'")

        logger.info(f"Generated {key_type.upper()} SSH key pair")
        return private_pem, public_openssh

    @staticmethod
    def validate_private_key(private_key_content: str) -> bool:
        """
        Validate SSH private key format.

        Args:
            private_key_content: Private key content to validate

        Returns:
            True if valid, False otherwise
        """
        try:
            # Try RSA
            try:
                paramiko.RSAKey.from_private_key(io.StringIO(private_key_content))
                return True
            except:
                pass

            # Try Ed25519
            try:
                paramiko.Ed25519Key.from_private_key(io.StringIO(private_key_content))
                return True
            except:
                pass

            return False
        except Exception:
            return False
