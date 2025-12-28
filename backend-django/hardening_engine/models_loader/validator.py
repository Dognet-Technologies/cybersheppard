"""
Hardening Model Validator

Validates hardening models for safety and correctness to prevent
dangerous configurations that could lock out SSH access or break the system.
"""

import re
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)


class ModelValidator:
    """
    Validate hardening models for safety and correctness

    Performs critical safety checks:
    - Ensures SSH service won't be disabled
    - Validates SSH configuration won't block access
    - Checks iptables rules allow SSH port
    - Validates sysctl parameters syntax
    - Checks for conflicting configurations
    """

    # Critical services that should never be disabled during hardening
    CRITICAL_SERVICES = ['ssh', 'sshd', 'network-manager', 'systemd-networkd']

    # Dangerous sysctl values that could break networking
    DANGEROUS_SYSCTL = {
        'net.ipv4.ip_forward': ['0'],  # Would break routing
    }

    def validate_model(self, model: Dict) -> Tuple[bool, List[str]]:
        """
        Comprehensive model validation

        Args:
            model: Hardening model dictionary

        Returns:
            Tuple of (is_valid, list_of_errors)
            Errors are categorized as CRITICAL, ERROR, or WARNING
        """
        errors = []

        # Critical safety checks
        ssh_errors = self._validate_ssh_safety(model)
        errors.extend(ssh_errors)

        # Firewall validation
        firewall_errors = self._validate_firewall(model)
        errors.extend(firewall_errors)

        # Sysctl validation
        sysctl_errors = self._validate_sysctl(model)
        errors.extend(sysctl_errors)

        # Service validation
        service_errors = self._validate_services(model)
        errors.extend(service_errors)

        # Package validation
        package_errors = self._validate_packages(model)
        errors.extend(package_errors)

        # File paths validation
        file_errors = self._validate_file_paths(model)
        errors.extend(file_errors)

        # Check for conflicts
        conflict_errors = self._check_conflicts(model)
        errors.extend(conflict_errors)

        # Determine if model is valid (no CRITICAL errors)
        is_valid = not any(error.startswith('CRITICAL:') for error in errors)

        if errors:
            logger.warning(f"Model validation found {len(errors)} issues")
            for error in errors:
                if error.startswith('CRITICAL:'):
                    logger.error(error)
                elif error.startswith('ERROR:'):
                    logger.error(error)
                else:
                    logger.warning(error)

        return (is_valid, errors)

    def _validate_ssh_safety(self, model: Dict) -> List[str]:
        """
        Ensure SSH access won't be blocked

        This is CRITICAL - losing SSH access means losing access to the server!
        """
        errors = []

        # Check if SSH service is being disabled
        if 'services' in model:
            services_config = model['services']

            # Check disable list
            disabled_services = services_config.get('disable', [])
            for critical_service in ['ssh', 'sshd']:
                if critical_service in disabled_services:
                    errors.append(
                        f"CRITICAL: SSH service '{critical_service}' cannot be disabled - "
                        "this will lock you out of the server!"
                    )

            # Check stop list
            stopped_services = services_config.get('stop', [])
            for critical_service in ['ssh', 'sshd']:
                if critical_service in stopped_services:
                    errors.append(
                        f"CRITICAL: SSH service '{critical_service}' cannot be stopped - "
                        "this will lock you out of the server!"
                    )

        # Check sshd_config file if present
        if 'files' in model:
            for file_entry in model['files']:
                file_path = file_entry.get('path', '')

                # Check SSH configuration files
                if file_path in ['/etc/ssh/sshd_config', '/etc/ssh/ssh_config']:
                    content = file_entry.get('content', '')

                    # Check for Port 0 (invalid)
                    if re.search(r'^\s*Port\s+0\s*$', content, re.MULTILINE):
                        errors.append(
                            "CRITICAL: SSH Port cannot be 0 in sshd_config"
                        )

                    # Check for ListenAddress being commented out or set to invalid
                    listen_lines = re.findall(r'^\s*ListenAddress\s+(.+)$', content, re.MULTILINE)
                    if listen_lines:
                        for addr in listen_lines:
                            if addr.strip() == '0.0.0.0' or addr.strip() == '::':
                                # This is actually fine - listens on all interfaces
                                pass
                            elif not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', addr.strip()):
                                errors.append(
                                    f"WARNING: ListenAddress '{addr}' may be invalid"
                                )

                    # Warn about PermitRootLogin yes
                    if re.search(r'^\s*PermitRootLogin\s+yes\s*$', content, re.MULTILINE):
                        errors.append(
                            "WARNING: PermitRootLogin yes is not recommended for security"
                        )

                    # Check PasswordAuthentication is handled properly
                    if re.search(r'^\s*PasswordAuthentication\s+no\s*$', content, re.MULTILINE):
                        if not re.search(r'^\s*PubkeyAuthentication\s+yes\s*$', content, re.MULTILINE):
                            errors.append(
                                "WARNING: Disabling PasswordAuthentication without enabling "
                                "PubkeyAuthentication may lock you out"
                            )

        return errors

    def _validate_firewall(self, model: Dict) -> List[str]:
        """
        Validate firewall rules to ensure SSH port remains accessible
        """
        errors = []

        if 'files' in model:
            for file_entry in model['files']:
                file_path = file_entry.get('path', '')
                content = file_entry.get('content', '')

                # Check iptables rules
                if 'iptables' in file_path.lower() or 'firewall' in file_path.lower():

                    # Check for SSH rule (port 22 or custom port)
                    # Look for common patterns
                    ssh_rule_patterns = [
                        r'--dport\s+22\s+.*ACCEPT',
                        r'--dport\s+22\s+.*-j\s+ACCEPT',
                        r'-p\s+tcp\s+--dport\s+22',
                    ]

                    has_ssh_rule = any(
                        re.search(pattern, content, re.MULTILINE)
                        for pattern in ssh_rule_patterns
                    )

                    if not has_ssh_rule:
                        errors.append(
                            "WARNING: iptables/firewall rules should explicitly allow SSH port 22. "
                            "Without this rule, you may be locked out after firewall activation."
                        )

                    # Check for default DROP policy
                    if re.search(r'-P\s+INPUT\s+DROP', content):
                        if not has_ssh_rule:
                            errors.append(
                                "CRITICAL: Default DROP policy without SSH ACCEPT rule will lock you out!"
                            )

        return errors

    def _validate_sysctl(self, model: Dict) -> List[str]:
        """
        Validate sysctl kernel parameters for syntax and dangerous values
        """
        errors = []

        if 'files' in model:
            for file_entry in model['files']:
                file_path = file_entry.get('path', '')
                content = file_entry.get('content', '')

                # Check sysctl configuration files
                if file_path == '/etc/sysctl.conf' or 'sysctl.d' in file_path:

                    for line_num, line in enumerate(content.split('\n'), 1):
                        line = line.strip()

                        # Skip comments and empty lines
                        if not line or line.startswith('#'):
                            continue

                        # Check format: key = value
                        if '=' not in line:
                            errors.append(
                                f"ERROR: Invalid sysctl syntax at line {line_num}: '{line}' "
                                "(expected format: key = value)"
                            )
                            continue

                        # Parse key and value
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()

                        # Check for dangerous values
                        if key in self.DANGEROUS_SYSCTL:
                            if value in self.DANGEROUS_SYSCTL[key]:
                                errors.append(
                                    f"WARNING: Potentially dangerous sysctl value: {key} = {value}"
                                )

        return errors

    def _validate_services(self, model: Dict) -> List[str]:
        """
        Validate service configurations for conflicts and critical services
        """
        errors = []

        if 'services' not in model:
            return errors

        services_config = model['services']

        # Get all service lists
        enable_list = set(services_config.get('enable', []))
        disable_list = set(services_config.get('disable', []))
        start_list = set(services_config.get('start', []))
        stop_list = set(services_config.get('stop', []))

        # Check for conflicts: enable + disable same service
        conflicts = enable_list & disable_list
        if conflicts:
            errors.append(
                f"ERROR: Services both enabled and disabled: {', '.join(conflicts)}"
            )

        # Check for conflicts: start + stop same service
        conflicts = start_list & stop_list
        if conflicts:
            errors.append(
                f"ERROR: Services both started and stopped: {', '.join(conflicts)}"
            )

        # Warn about disabling critical services
        for critical_service in self.CRITICAL_SERVICES:
            if critical_service in disable_list:
                errors.append(
                    f"WARNING: Disabling critical service '{critical_service}' - "
                    "this may break system functionality"
                )

        return errors

    def _validate_packages(self, model: Dict) -> List[str]:
        """
        Validate package installation/removal for conflicts
        """
        errors = []

        if 'packages' not in model:
            return errors

        packages_config = model['packages']

        install_list = set(packages_config.get('install', []))
        remove_list = set(packages_config.get('remove', []))

        # Check for conflicts: install + remove same package
        conflicts = install_list & remove_list
        if conflicts:
            errors.append(
                f"ERROR: Packages both installed and removed: {', '.join(conflicts)}"
            )

        # Warn about removing critical packages
        critical_packages = ['openssh-server', 'systemd', 'sudo']
        for pkg in critical_packages:
            if pkg in remove_list:
                errors.append(
                    f"CRITICAL: Removing critical package '{pkg}' will break system functionality"
                )

        return errors

    def _validate_file_paths(self, model: Dict) -> List[str]:
        """
        Validate file paths for safety and correctness
        """
        errors = []

        if 'files' not in model:
            return errors

        seen_paths = set()

        for i, file_entry in enumerate(model['files']):
            if not isinstance(file_entry, dict):
                errors.append(f"ERROR: File entry {i} is not a dictionary")
                continue

            file_path = file_entry.get('path', '')

            # Check path is absolute
            if not file_path.startswith('/'):
                errors.append(
                    f"ERROR: File path must be absolute: '{file_path}'"
                )

            # Check for duplicate paths
            if file_path in seen_paths:
                errors.append(
                    f"WARNING: Duplicate file path: '{file_path}'"
                )
            seen_paths.add(file_path)

            # Warn about modifying critical system files
            critical_paths = [
                '/etc/passwd',
                '/etc/shadow',
                '/etc/group',
                '/boot/',
                '/etc/fstab'
            ]

            for critical_path in critical_paths:
                if file_path.startswith(critical_path):
                    errors.append(
                        f"WARNING: Modifying critical system file: '{file_path}' - "
                        "ensure you know what you're doing!"
                    )

        return errors

    def _check_conflicts(self, model: Dict) -> List[str]:
        """
        Check for logical conflicts across different sections
        """
        errors = []

        # Check if we're installing packages for services we're disabling
        if 'packages' in model and 'services' in model:
            install_packages = set(model['packages'].get('install', []))
            disabled_services = set(model['services'].get('disable', []))

            # Common package-service mappings
            package_service_map = {
                'apache2': 'apache2',
                'nginx': 'nginx',
                'mysql-server': 'mysql',
                'postgresql': 'postgresql',
                'redis-server': 'redis',
                'fail2ban': 'fail2ban'
            }

            for package, service in package_service_map.items():
                if package in install_packages and service in disabled_services:
                    errors.append(
                        f"WARNING: Installing '{package}' but disabling '{service}' service - "
                        "this may be intentional but seems contradictory"
                    )

        return errors

    def get_validation_summary(self, errors: List[str]) -> Dict:
        """
        Get summary of validation results

        Args:
            errors: List of error messages

        Returns:
            Dictionary with counts of critical, error, and warning issues
        """
        summary = {
            'total': len(errors),
            'critical': sum(1 for e in errors if e.startswith('CRITICAL:')),
            'errors': sum(1 for e in errors if e.startswith('ERROR:')),
            'warnings': sum(1 for e in errors if e.startswith('WARNING:')),
            'is_safe': not any(e.startswith('CRITICAL:') for e in errors)
        }

        return summary
