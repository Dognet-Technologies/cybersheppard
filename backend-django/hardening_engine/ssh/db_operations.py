"""
============================================================================
CYBERSHEPPARD - SSH Database Operations
============================================================================
Database operations for SSH keys and target management.
"""

import psycopg2
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timedelta
import os
import logging

from .encryption import encrypt_data, decrypt_data
from .ssh_manager import SSHManager

logger = logging.getLogger(__name__)


def get_db_connection():
    """
    Create PostgreSQL database connection.

    Returns:
        psycopg2 connection
    """
    return psycopg2.connect(
        host=os.getenv('POSTGRES_HOST', 'localhost'),
        port=os.getenv('POSTGRES_PORT', '5432'),
        database=os.getenv('POSTGRES_DB', 'cybersheppard'),
        user=os.getenv('POSTGRES_USER', 'cybersheppard'),
        password=os.getenv('POSTGRES_PASSWORD', 'change_me_in_production')
    )


def get_ssh_key(key_id: int) -> Optional[Dict]:
    """
    Retrieve SSH key from database.

    Args:
        key_id: SSH key ID

    Returns:
        Dictionary with key information, or None if not found
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, name, key_type, public_key, private_key_encrypted,
                           passphrase_encrypted, fingerprint, created_at, expires_at,
                           last_rotated_at, is_active
                    FROM ssh_keys
                    WHERE id = %s
                """, (key_id,))

                row = cur.fetchone()
                if not row:
                    return None

                return {
                    'id': row[0],
                    'name': row[1],
                    'key_type': row[2],
                    'public_key': row[3],
                    'private_key_encrypted': row[4],
                    'passphrase_encrypted': row[5],
                    'fingerprint': row[6],
                    'created_at': row[7],
                    'expires_at': row[8],
                    'last_rotated_at': row[9],
                    'is_active': row[10],
                }
    except Exception as e:
        logger.error(f"Failed to retrieve SSH key {key_id}: {e}")
        return None


def store_ssh_key(name: str, key_type: str, public_key: str,
                  private_key: str, fingerprint: str,
                  rotation_days: int = 90) -> Optional[int]:
    """
    Store SSH key pair in database with encryption.

    Args:
        name: Key name/identifier
        key_type: Type of key (ed25519, rsa)
        public_key: Public key content
        private_key: Private key content (will be encrypted)
        fingerprint: SSH key fingerprint
        rotation_days: Days until key rotation required

    Returns:
        SSH key ID if successful, None otherwise
    """
    try:
        # Encrypt private key
        private_key_encrypted = encrypt_data(private_key)

        expires_at = datetime.utcnow() + timedelta(days=rotation_days)

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO ssh_keys (
                        name, key_type, public_key, private_key_encrypted,
                        fingerprint, expires_at, is_active
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, TRUE)
                    RETURNING id
                """, (name, key_type, public_key, private_key_encrypted,
                      fingerprint, expires_at))

                key_id = cur.fetchone()[0]
                conn.commit()
                logger.info(f"SSH key '{name}' stored with ID {key_id}")
                return key_id
    except Exception as e:
        logger.error(f"Failed to store SSH key: {e}")
        return None


def get_decrypted_private_key(key_id: int) -> Optional[str]:
    """
    Retrieve and decrypt private key.

    Args:
        key_id: SSH key ID

    Returns:
        Decrypted private key content, or None if not found
    """
    key_data = get_ssh_key(key_id)
    if not key_data or not key_data['private_key_encrypted']:
        return None

    try:
        return decrypt_data(key_data['private_key_encrypted'])
    except Exception as e:
        logger.error(f"Failed to decrypt private key {key_id}: {e}")
        return None


def get_target_ssh_config(target_id: int) -> Optional[Dict]:
    """
    Get SSH configuration for a target.

    Args:
        target_id: Target ID

    Returns:
        Dictionary with SSH configuration
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT t.id, t.hostname, t.ip_address, t.ssh_port,
                           t.ssh_username, t.ssh_key_id,
                           k.private_key_encrypted
                    FROM targets t
                    LEFT JOIN ssh_keys k ON t.ssh_key_id = k.id
                    WHERE t.id = %s
                """, (target_id,))

                row = cur.fetchone()
                if not row:
                    return None

                config = {
                    'target_id': row[0],
                    'hostname': row[1],
                    'ip_address': row[2],
                    'port': row[3],
                    'username': row[4],
                    'ssh_key_id': row[5],
                    'private_key': None,
                }

                # Decrypt private key if available
                if row[6]:
                    try:
                        config['private_key'] = decrypt_data(row[6])
                    except Exception as e:
                        logger.error(f"Failed to decrypt private key: {e}")

                return config
    except Exception as e:
        logger.error(f"Failed to get target SSH config for target {target_id}: {e}")
        return None


def create_ssh_manager_for_target(target_id: int) -> Optional[SSHManager]:
    """
    Create SSHManager instance for a target.

    Args:
        target_id: Target ID

    Returns:
        SSHManager instance, or None if configuration not found
    """
    config = get_target_ssh_config(target_id)
    if not config:
        logger.error(f"Target {target_id} not found or has no SSH configuration")
        return None

    return SSHManager(
        hostname=config['ip_address'],
        port=config['port'],
        username=config['username'],
        private_key=config['private_key']
    )


def update_target_status(target_id: int, status: str, status_message: Optional[str] = None):
    """
    Update target status in database.

    Args:
        target_id: Target ID
        status: New status (active, offline, error, etc.)
        status_message: Optional status message
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE targets
                    SET status = %s,
                        status_message = %s,
                        last_seen = NOW(),
                        updated_at = NOW()
                    WHERE id = %s
                """, (status, status_message, target_id))
                conn.commit()
                logger.info(f"Updated target {target_id} status to '{status}'")
    except Exception as e:
        logger.error(f"Failed to update target status: {e}")


def list_active_ssh_keys() -> List[Dict]:
    """
    List all active SSH keys.

    Returns:
        List of SSH key dictionaries
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, name, key_type, fingerprint, created_at,
                           expires_at, last_rotated_at, is_active
                    FROM ssh_keys
                    WHERE is_active = TRUE
                    ORDER BY created_at DESC
                """)

                keys = []
                for row in cur.fetchall():
                    keys.append({
                        'id': row[0],
                        'name': row[1],
                        'key_type': row[2],
                        'fingerprint': row[3],
                        'created_at': row[4],
                        'expires_at': row[5],
                        'last_rotated_at': row[6],
                        'is_active': row[7],
                    })
                return keys
    except Exception as e:
        logger.error(f"Failed to list SSH keys: {e}")
        return []
