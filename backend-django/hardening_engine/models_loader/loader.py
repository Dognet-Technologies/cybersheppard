"""
Hardening Model Loader

Loads hardening models from YAML files and provides model management functionality.
"""

import yaml
import hashlib
from pathlib import Path
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class ModelLoader:
    """
    Load and manage hardening models from filesystem

    Models are stored as YAML files with the following structure:

    metadata:
      name: "model_name"
      description: "Model description"
      version: "1.0.0"
      os_compatibility:
        - "Debian 11"
        - "Ubuntu 22.04"

    files:
      - path: "/etc/ssh/sshd_config"
        content: |
          # Configuration content...

    packages:
      install:
        - package1
        - package2
      remove:
        - bad_package

    services:
      enable:
        - service1
      disable:
        - service2
    """

    def __init__(self, models_dir: str):
        """
        Initialize model loader

        Args:
            models_dir: Base directory containing hardening models
        """
        self.models_dir = Path(models_dir)

        if not self.models_dir.exists():
            logger.warning(f"Models directory does not exist: {models_dir}")
            self.models_dir.mkdir(parents=True, exist_ok=True)

    def load_model(self, model_path: str) -> Dict:
        """
        Load a single hardening model from YAML file

        Args:
            model_path: Relative path to model file (e.g., "base/ssh.yml")

        Returns:
            Dictionary containing model data with added metadata:
            - _hash: SHA512 hash of model content for integrity verification
            - _path: Full filesystem path to model file

        Raises:
            FileNotFoundError: If model file doesn't exist
            yaml.YAMLError: If YAML parsing fails
        """
        full_path = self.models_dir / model_path

        if not full_path.exists():
            raise FileNotFoundError(f"Model not found: {full_path}")

        logger.info(f"Loading model: {model_path}")

        # Read file content
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Parse YAML
        try:
            model = yaml.safe_load(content)
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse YAML in {model_path}: {e}")
            raise

        # Validate basic structure
        if not isinstance(model, dict):
            raise ValueError(f"Model file must contain a dictionary: {model_path}")

        if 'metadata' not in model:
            raise ValueError(f"Model missing 'metadata' section: {model_path}")

        # Calculate SHA512 hash for integrity
        content_hash = hashlib.sha512(content.encode('utf-8')).hexdigest()

        # Add internal metadata
        model['_hash'] = content_hash
        model['_path'] = str(full_path)
        model['_relative_path'] = model_path

        logger.debug(f"Model loaded: {model['metadata'].get('name', 'unknown')} "
                    f"(hash: {content_hash[:16]}...)")

        return model

    def list_models(self, category: Optional[str] = None) -> List[Dict]:
        """
        List all available hardening models

        Args:
            category: Optional category filter (e.g., "base", "severo")

        Returns:
            List of dictionaries with model summaries:
            - path: Relative path to model file
            - name: Model name from metadata
            - description: Model description
            - version: Model version
            - category: Model category (base, severo, compliance, etc.)
            - os_compatibility: List of compatible OS versions
        """
        models = []

        # Search pattern
        if category:
            search_pattern = f"{category}/**/*.yml"
        else:
            search_pattern = "**/*.yml"

        # Find all YAML files
        for yaml_file in self.models_dir.glob(search_pattern):
            relative_path = yaml_file.relative_to(self.models_dir)

            try:
                # Load model
                model = self.load_model(str(relative_path))
                metadata = model.get('metadata', {})

                # Extract category from path
                path_parts = str(relative_path).split('/')
                model_category = path_parts[0] if len(path_parts) > 1 else 'unknown'

                # Create summary
                summary = {
                    'path': str(relative_path),
                    'name': metadata.get('name', 'unnamed'),
                    'description': metadata.get('description', ''),
                    'version': metadata.get('version', '1.0.0'),
                    'category': model_category,
                    'os_compatibility': metadata.get('os_compatibility', []),
                    'hash': model['_hash'][:16] + '...'  # Truncated hash for display
                }

                models.append(summary)

            except Exception as e:
                logger.error(f"Error loading model {relative_path}: {e}")
                continue

        logger.info(f"Found {len(models)} models" +
                   (f" in category '{category}'" if category else ""))

        return models

    def get_model_categories(self) -> List[str]:
        """
        Get list of available model categories

        Returns:
            List of category names (e.g., ['base', 'severo', 'compliance'])
        """
        categories = set()

        for yaml_file in self.models_dir.glob("*/*.yml"):
            relative_path = yaml_file.relative_to(self.models_dir)
            category = str(relative_path).split('/')[0]
            categories.add(category)

        return sorted(list(categories))

    def validate_model_structure(self, model: Dict) -> tuple[bool, List[str]]:
        """
        Validate basic model structure

        Args:
            model: Model dictionary to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Check metadata section
        if 'metadata' not in model:
            errors.append("Missing 'metadata' section")
        else:
            metadata = model['metadata']

            required_metadata_fields = ['name', 'description', 'version']
            for field in required_metadata_fields:
                if field not in metadata:
                    errors.append(f"Missing metadata field: {field}")

        # Check at least one action is defined
        has_actions = False
        action_sections = ['files', 'packages', 'services']

        for section in action_sections:
            if section in model and model[section]:
                has_actions = True
                break

        if not has_actions:
            errors.append("Model has no actions defined (files, packages, or services)")

        # Validate files section if present
        if 'files' in model:
            if not isinstance(model['files'], list):
                errors.append("'files' must be a list")
            else:
                for i, file_entry in enumerate(model['files']):
                    if not isinstance(file_entry, dict):
                        errors.append(f"File entry {i} must be a dictionary")
                        continue

                    if 'path' not in file_entry:
                        errors.append(f"File entry {i} missing 'path'")

                    if 'content' not in file_entry:
                        errors.append(f"File entry {i} missing 'content'")

        # Validate packages section if present
        if 'packages' in model:
            if not isinstance(model['packages'], dict):
                errors.append("'packages' must be a dictionary")
            else:
                valid_package_keys = ['install', 'remove']
                for key in model['packages']:
                    if key not in valid_package_keys:
                        errors.append(f"Unknown packages key: {key}")
                    elif not isinstance(model['packages'][key], list):
                        errors.append(f"packages.{key} must be a list")

        # Validate services section if present
        if 'services' in model:
            if not isinstance(model['services'], dict):
                errors.append("'services' must be a dictionary")
            else:
                valid_service_keys = ['enable', 'disable', 'start', 'stop', 'restart']
                for key in model['services']:
                    if key not in valid_service_keys:
                        errors.append(f"Unknown services key: {key}")
                    elif not isinstance(model['services'][key], list):
                        errors.append(f"services.{key} must be a list")

        return (len(errors) == 0, errors)

    def get_model_stats(self) -> Dict:
        """
        Get statistics about available models

        Returns:
            Dictionary with stats:
            - total_models: Total number of models
            - categories: Dict of category -> count
            - total_files: Total configuration files across all models
            - total_packages: Total packages to install/remove
            - total_services: Total services to enable/disable
        """
        stats = {
            'total_models': 0,
            'categories': {},
            'total_files': 0,
            'total_packages': 0,
            'total_services': 0
        }

        for yaml_file in self.models_dir.glob("**/*.yml"):
            relative_path = yaml_file.relative_to(self.models_dir)

            try:
                model = self.load_model(str(relative_path))
                stats['total_models'] += 1

                # Count category
                category = str(relative_path).split('/')[0]
                stats['categories'][category] = stats['categories'].get(category, 0) + 1

                # Count files
                if 'files' in model:
                    stats['total_files'] += len(model['files'])

                # Count packages
                if 'packages' in model:
                    if 'install' in model['packages']:
                        stats['total_packages'] += len(model['packages']['install'])
                    if 'remove' in model['packages']:
                        stats['total_packages'] += len(model['packages']['remove'])

                # Count services
                if 'services' in model:
                    for action in ['enable', 'disable', 'start', 'stop', 'restart']:
                        if action in model['services']:
                            stats['total_services'] += len(model['services'][action])

            except Exception as e:
                logger.error(f"Error processing {relative_path} for stats: {e}")
                continue

        return stats
