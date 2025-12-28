"""
Django API Views for Hardening Engine

Provides REST API endpoints for hardening operations:
- Apply hardening models to targets
- Validate models
- Rollback changes
- List available models
- Manage backups
"""

import os
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
import logging

from .applier.applier import HardeningApplier
from .applier.backup import BackupManager
from .applier.rollback import RollbackManager
from .models_loader.loader import ModelLoader
from .models_loader.validator import ModelValidator
from .ssh.manager import SSHManager

logger = logging.getLogger(__name__)

# Configuration from environment variables
MODELS_DIR = os.getenv('HARDENING_MODELS_DIR', '/home/user/cybersheppard/hardening-models')
BACKUPS_DIR = os.getenv('HARDENING_BACKUPS_DIR', '/opt/cybersheppard/backups')

# Initialize services
applier = HardeningApplier(MODELS_DIR, BACKUPS_DIR)
backup_manager = BackupManager(BACKUPS_DIR)
rollback_manager = RollbackManager(BACKUPS_DIR)
model_loader = ModelLoader(MODELS_DIR)
model_validator = ModelValidator()

logger.info(f"Hardening Engine initialized:")
logger.info(f"  Models dir: {MODELS_DIR}")
logger.info(f"  Backups dir: {BACKUPS_DIR}")


@csrf_exempt
@require_http_methods(["POST"])
def apply_hardening(request):
    """
    Apply hardening model to target system

    POST /api/hardening/apply

    Request Body:
    {
        "target_ip": "192.168.1.10",
        "model_path": "base/ssh.yml",
        "ssh_key_path": "/path/to/key",
        "ssh_port": 22,  (optional, default 22)
        "username": "microcyber",  (optional, default microcyber)
        "skip_backup": false  (optional, default false)
    }

    Response:
    {
        "success": true,
        "steps_completed": 11,
        "steps_failed": 0,
        "backup_path": "/opt/cybersheppard/backups/...",
        "duration_seconds": 45.3,
        "log": ["Step 1...", "Step 2..."]
    }
    """
    try:
        data = json.loads(request.body)

        # Required fields
        target_ip = data.get('target_ip')
        model_path = data.get('model_path')
        ssh_key_path = data.get('ssh_key_path')

        if not all([target_ip, model_path, ssh_key_path]):
            return JsonResponse({
                'success': False,
                'error': 'Missing required fields: target_ip, model_path, ssh_key_path'
            }, status=400)

        # Optional fields
        ssh_port = data.get('ssh_port', 22)
        username = data.get('username', 'microcyber')
        skip_backup = data.get('skip_backup', False)

        logger.info(f"Applying hardening: {model_path} to {target_ip}")

        # Apply hardening
        result = applier.apply_hardening(
            target_ip=target_ip,
            model_path=model_path,
            ssh_key_path=ssh_key_path,
            ssh_port=ssh_port,
            username=username,
            skip_backup=skip_backup
        )

        status_code = 200 if result['success'] else 500

        return JsonResponse(result, status=status_code)

    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request body'
        }, status=400)

    except Exception as e:
        logger.exception(f"Apply hardening failed: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def list_models(request):
    """
    List all available hardening models

    GET /api/hardening/models?category=base

    Query Parameters:
    - category: Optional category filter (base, severo, compliance)

    Response:
    {
        "models": [
            {
                "path": "base/ssh.yml",
                "name": "ssh_base_generic",
                "description": "SSH hardening...",
                "version": "1.0.0",
                "category": "base",
                "os_compatibility": ["Debian 11", "Ubuntu 22.04"],
                "hash": "abc123..."
            },
            ...
        ],
        "total": 8,
        "categories": ["base", "severo", "compliance"]
    }
    """
    try:
        category = request.GET.get('category', None)

        models = model_loader.list_models(category=category)
        categories = model_loader.get_model_categories()

        return JsonResponse({
            'models': models,
            'total': len(models),
            'categories': categories
        })

    except Exception as e:
        logger.exception(f"List models failed: {e}")
        return JsonResponse({
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def get_model(request, model_path):
    """
    Get detailed information about a specific model

    GET /api/hardening/models/<path:model_path>

    Response:
    {
        "model": {
            "metadata": {...},
            "files": [...],
            "packages": {...},
            "services": {...},
            "_hash": "...",
            "_path": "..."
        }
    }
    """
    try:
        model = model_loader.load_model(model_path)

        return JsonResponse({
            'model': model
        })

    except FileNotFoundError:
        return JsonResponse({
            'error': f'Model not found: {model_path}'
        }, status=404)

    except Exception as e:
        logger.exception(f"Get model failed: {e}")
        return JsonResponse({
            'error': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def validate_model(request):
    """
    Validate a hardening model for safety

    POST /api/hardening/validate

    Request Body:
    {
        "model_path": "base/ssh.yml"
    }

    Response:
    {
        "is_valid": true,
        "errors": [],
        "summary": {
            "total": 0,
            "critical": 0,
            "errors": 0,
            "warnings": 0,
            "is_safe": true
        }
    }
    """
    try:
        data = json.loads(request.body)

        model_path = data.get('model_path')
        if not model_path:
            return JsonResponse({
                'error': 'Missing required field: model_path'
            }, status=400)

        # Load model
        model = model_loader.load_model(model_path)

        # Validate
        is_valid, errors = model_validator.validate_model(model)
        summary = model_validator.get_validation_summary(errors)

        return JsonResponse({
            'is_valid': is_valid,
            'errors': errors,
            'summary': summary
        })

    except FileNotFoundError:
        return JsonResponse({
            'error': f'Model not found: {data.get("model_path")}'
        }, status=404)

    except Exception as e:
        logger.exception(f"Validate model failed: {e}")
        return JsonResponse({
            'error': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def rollback_hardening(request):
    """
    Rollback hardening changes using backup

    POST /api/hardening/rollback

    Request Body:
    {
        "backup_tarball": "/opt/cybersheppard/backups/...",
        "target_ip": "192.168.1.10",
        "ssh_key_path": "/path/to/key",
        "ssh_port": 22,  (optional)
        "username": "microcyber",  (optional)
        "selective_files": ["/etc/ssh/sshd_config"]  (optional)
    }

    Response:
    {
        "success": true,
        "files_restored": 5,
        "files_failed": 0,
        "log": ["Restoring...", "..."]
    }
    """
    try:
        data = json.loads(request.body)

        backup_tarball = data.get('backup_tarball')
        target_ip = data.get('target_ip')
        ssh_key_path = data.get('ssh_key_path')

        if not all([backup_tarball, target_ip, ssh_key_path]):
            return JsonResponse({
                'success': False,
                'error': 'Missing required fields: backup_tarball, target_ip, ssh_key_path'
            }, status=400)

        ssh_port = data.get('ssh_port', 22)
        username = data.get('username', 'microcyber')
        selective_files = data.get('selective_files', None)

        logger.info(f"Rolling back from backup: {backup_tarball}")

        # Connect SSH
        ssh = SSHManager(target_ip, ssh_port, username, 60)

        if not ssh.connect(ssh_key_path):
            return JsonResponse({
                'success': False,
                'error': 'SSH connection failed'
            }, status=500)

        # Rollback
        result = rollback_manager.rollback(
            backup_tarball,
            ssh,
            selective_files=selective_files
        )

        ssh.disconnect()

        status_code = 200 if result['success'] else 500

        return JsonResponse(result, status=status_code)

    except Exception as e:
        logger.exception(f"Rollback failed: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def list_backups(request):
    """
    List available backups

    GET /api/hardening/backups?target_ip=192.168.1.10

    Query Parameters:
    - target_ip: Optional filter by target IP

    Response:
    {
        "backups": [
            {
                "target_ip": "192.168.1.10",
                "target_hostname": "server1",
                "model_name": "ssh_base_generic",
                "timestamp": "20251228_150030",
                "tarball_path": "/opt/...",
                "tarball_size_mb": 1.23,
                "files_count": 5
            },
            ...
        ],
        "total": 15
    }
    """
    try:
        target_ip = request.GET.get('target_ip', None)

        backups = backup_manager.list_backups(target_ip=target_ip)

        return JsonResponse({
            'backups': backups,
            'total': len(backups)
        })

    except Exception as e:
        logger.exception(f"List backups failed: {e}")
        return JsonResponse({
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def get_backup_info(request, backup_id):
    """
    Get detailed information about a specific backup

    GET /api/hardening/backups/<backup_id>

    Response:
    {
        "target_ip": "192.168.1.10",
        "model_name": "...",
        "files": [...],
        ...
    }
    """
    try:
        # Construct backup path from ID
        backup_tarball = os.path.join(BACKUPS_DIR, f"{backup_id}.tar.gz")

        info = backup_manager.get_backup_info(backup_tarball)

        return JsonResponse(info)

    except FileNotFoundError:
        return JsonResponse({
            'error': f'Backup not found: {backup_id}'
        }, status=404)

    except Exception as e:
        logger.exception(f"Get backup info failed: {e}")
        return JsonResponse({
            'error': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def test_connection(request):
    """
    Test SSH connection to target

    POST /api/hardening/test-connection

    Request Body:
    {
        "target_ip": "192.168.1.10",
        "ssh_key_path": "/path/to/key",
        "ssh_port": 22,  (optional)
        "username": "microcyber"  (optional)
    }

    Response:
    {
        "success": true,
        "hostname": "server1",
        "os_info": {
            "NAME": "Debian GNU/Linux",
            "VERSION": "12 (bookworm)"
        }
    }
    """
    try:
        data = json.loads(request.body)

        target_ip = data.get('target_ip')
        ssh_key_path = data.get('ssh_key_path')

        if not all([target_ip, ssh_key_path]):
            return JsonResponse({
                'success': False,
                'error': 'Missing required fields: target_ip, ssh_key_path'
            }, status=400)

        ssh_port = data.get('ssh_port', 22)
        username = data.get('username', 'microcyber')

        # Test connection
        ssh = SSHManager(target_ip, ssh_port, username, 30)

        if not ssh.connect(ssh_key_path):
            return JsonResponse({
                'success': False,
                'error': 'SSH connection failed'
            })

        # Get system info
        code, hostname, stderr = ssh.execute_command('hostname')
        os_info = ssh.get_os_info()

        ssh.disconnect()

        return JsonResponse({
            'success': True,
            'hostname': hostname.strip() if code == 0 else 'unknown',
            'os_info': os_info
        })

    except Exception as e:
        logger.exception(f"Test connection failed: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def health_check(request):
    """
    Health check endpoint

    GET /api/hardening/health

    Response:
    {
        "status": "ok",
        "models_dir": "...",
        "models_count": 8,
        "backups_dir": "...",
        "backups_count": 15
    }
    """
    try:
        models_stats = model_loader.get_model_stats()
        backups = backup_manager.list_backups()

        return JsonResponse({
            'status': 'ok',
            'models_dir': MODELS_DIR,
            'models_count': models_stats['total_models'],
            'categories': models_stats['categories'],
            'backups_dir': BACKUPS_DIR,
            'backups_count': len(backups)
        })

    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)
