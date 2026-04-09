"""
SentinelCore Example Vulnerability Scanner Plugin

This plugin demonstrates how to integrate a vulnerability scanner with SentinelCore:
- Target scanning
- Vulnerability discovery and reporting
- Severity classification
- Result export
- Event handling
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import aiohttp
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(Enum):
    """Scan execution status"""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VulnerabilityScanner:
    """
    Example vulnerability scanner plugin for SentinelCore

    This plugin demonstrates:
    - Target scanning
    - Vulnerability detection and reporting
    - Integration with external scanner APIs
    - Event emission for discovered vulnerabilities
    - Scan result management
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the vulnerability scanner plugin

        Args:
            config: Plugin configuration from manifest.json
        """
        self.config = config
        self.scanner_api_url = config.get('scanner_api_url')
        self.api_key = config.get('api_key')
        self.api_secret = config.get('api_secret')
        self.scan_timeout = config.get('scan_timeout', 3600)
        self.max_concurrent_scans = config.get('max_concurrent_scans', 5)
        self.severity_threshold = SeverityLevel(
            config.get('severity_threshold', 'medium')
        )
        self.auto_retry_failed = config.get('auto_retry_failed', True)
        self.export_format = config.get('export_format', 'json')
        self.enable_notifications = config.get('enable_notifications', True)

        # Internal state
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self.scan_semaphore = asyncio.Semaphore(self.max_concurrent_scans)

        logger.info(
            "Vulnerability scanner plugin initialized",
            extra={
                "plugin": "example-vulnerability-scanner",
                "version": "1.0.0",
                "max_concurrent": self.max_concurrent_scans,
                "severity_threshold": self.severity_threshold.value
            }
        )

    async def scan_target(
        self,
        target: str,
        port_range: Optional[str] = None,
        scan_type: str = "full"
    ) -> Dict[str, Any]:
        """
        Initiate a vulnerability scan on a target

        Args:
            target: Target IP address or hostname
            port_range: Optional port range (e.g., "1-1000")
            scan_type: Type of scan (quick, full, compliance)

        Returns:
            Scan information including scan_id and status
        """
        async with self.scan_semaphore:
            scan_id = f"scan_{datetime.utcnow().timestamp()}"

            logger.info(
                "Starting vulnerability scan",
                extra={
                    "scan_id": scan_id,
                    "target": target,
                    "scan_type": scan_type
                }
            )

            # Emit scan started event
            await self.emit_event("scan.started", {
                "scan_id": scan_id,
                "target": target,
                "scan_type": scan_type,
                "timestamp": datetime.utcnow().isoformat()
            })

            try:
                # Create scan in external scanner
                scan_info = await self.create_scan(
                    target=target,
                    port_range=port_range,
                    scan_type=scan_type
                )

                # Track active scan
                self.active_scans[scan_id] = {
                    "target": target,
                    "status": ScanStatus.RUNNING.value,
                    "started_at": datetime.utcnow().isoformat(),
                    "external_scan_id": scan_info.get('id'),
                    "vulnerabilities": []
                }

                # Wait for scan to complete
                result = await self.wait_for_scan_completion(
                    scan_id,
                    scan_info.get('id')
                )

                # Process results
                await self.process_scan_results(scan_id, result)

                # Mark scan as completed
                self.active_scans[scan_id]["status"] = ScanStatus.COMPLETED.value
                self.active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()

                # Emit scan completed event
                await self.emit_event("scan.completed", {
                    "scan_id": scan_id,
                    "target": target,
                    "vulnerabilities_found": len(result.get('vulnerabilities', [])),
                    "timestamp": datetime.utcnow().isoformat()
                })

                logger.info(
                    "Scan completed successfully",
                    extra={
                        "scan_id": scan_id,
                        "vulnerabilities": len(result.get('vulnerabilities', []))
                    }
                )

                return self.active_scans[scan_id]

            except Exception as e:
                logger.error(
                    f"Scan failed: {e}",
                    extra={"scan_id": scan_id, "target": target},
                    exc_info=True
                )

                # Mark scan as failed
                if scan_id in self.active_scans:
                    self.active_scans[scan_id]["status"] = ScanStatus.FAILED.value
                    self.active_scans[scan_id]["error"] = str(e)

                # Retry if enabled
                if self.auto_retry_failed:
                    logger.info(f"Scheduling retry for scan {scan_id}")
                    # Schedule retry logic here

                raise

    async def create_scan(
        self,
        target: str,
        port_range: Optional[str],
        scan_type: str
    ) -> Dict[str, Any]:
        """
        Create a new scan in the external scanner API

        Args:
            target: Target to scan
            port_range: Port range to scan
            scan_type: Type of scan

        Returns:
            Scan creation response with scan ID
        """
        url = f"{self.scanner_api_url}/scans"
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        payload = {
            'target': target,
            'scan_type': scan_type,
            'settings': {
                'port_range': port_range or '1-65535',
                'timeout': self.scan_timeout
            }
        }

        if self.api_secret:
            headers['X-API-Secret'] = self.api_secret

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 201:
                        data = await response.json()
                        logger.debug(
                            "Scan created in external scanner",
                            extra={"external_scan_id": data.get('id')}
                        )
                        return data
                    else:
                        error_text = await response.text()
                        raise Exception(
                            f"Failed to create scan: {response.status} - {error_text}"
                        )

        except Exception as e:
            logger.error(f"Error creating scan: {e}", exc_info=True)
            raise

    async def wait_for_scan_completion(
        self,
        scan_id: str,
        external_scan_id: str
    ) -> Dict[str, Any]:
        """
        Poll external scanner until scan completes

        Args:
            scan_id: Internal scan ID
            external_scan_id: External scanner's scan ID

        Returns:
            Complete scan results
        """
        url = f"{self.scanner_api_url}/scans/{external_scan_id}"
        headers = {'Authorization': f'Bearer {self.api_key}'}

        poll_interval = 10  # seconds
        max_wait = self.scan_timeout

        elapsed = 0
        while elapsed < max_wait:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            status = data.get('status')

                            if status == 'completed':
                                return data
                            elif status == 'failed':
                                raise Exception("External scan failed")

                            # Still running, wait and retry
                            await asyncio.sleep(poll_interval)
                            elapsed += poll_interval
                        else:
                            raise Exception(f"Failed to get scan status: {response.status}")

            except Exception as e:
                logger.error(f"Error polling scan status: {e}")
                await asyncio.sleep(poll_interval)
                elapsed += poll_interval

        raise TimeoutError(f"Scan {scan_id} exceeded timeout of {max_wait}s")

    async def process_scan_results(
        self,
        scan_id: str,
        scan_data: Dict[str, Any]
    ) -> None:
        """
        Process and store scan results, emit events for vulnerabilities

        Args:
            scan_id: Internal scan ID
            scan_data: Raw scan results from external scanner
        """
        vulnerabilities = scan_data.get('vulnerabilities', [])

        logger.info(
            "Processing scan results",
            extra={
                "scan_id": scan_id,
                "vulnerabilities": len(vulnerabilities)
            }
        )

        for vuln in vulnerabilities:
            # Parse vulnerability data
            severity = SeverityLevel(vuln.get('severity', 'low').lower())

            # Check if meets severity threshold
            severity_order = {
                SeverityLevel.LOW: 1,
                SeverityLevel.MEDIUM: 2,
                SeverityLevel.HIGH: 3,
                SeverityLevel.CRITICAL: 4
            }

            if severity_order[severity] < severity_order[self.severity_threshold]:
                continue  # Skip low severity vulnerabilities

            # Store vulnerability
            vulnerability_data = {
                "scan_id": scan_id,
                "cve_id": vuln.get('cve_id'),
                "title": vuln.get('title'),
                "description": vuln.get('description'),
                "severity": severity.value,
                "cvss_score": vuln.get('cvss_score'),
                "affected_component": vuln.get('component'),
                "remediation": vuln.get('remediation'),
                "discovered_at": datetime.utcnow().isoformat()
            }

            self.active_scans[scan_id]["vulnerabilities"].append(vulnerability_data)

            # Emit vulnerability discovered event
            await self.emit_event("vulnerability.discovered", vulnerability_data)

            # Emit high severity alert if applicable
            if severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
                await self.emit_event("severity.high.detected", {
                    **vulnerability_data,
                    "alert_type": "high_severity_vulnerability"
                })

                # Send notification if enabled
                if self.enable_notifications:
                    await self.send_notification(vulnerability_data)

    async def emit_event(self, event_type: str, event_data: Dict[str, Any]) -> None:
        """
        Emit an event to SentinelCore event bus

        Args:
            event_type: Type of event
            event_data: Event payload
        """
        logger.debug(
            f"Emitting event: {event_type}",
            extra={"event_data": event_data}
        )

        # This would integrate with SentinelCore's event bus
        # For now, just log it
        pass

    async def send_notification(self, vulnerability: Dict[str, Any]) -> None:
        """
        Send notification for high-severity vulnerability

        Args:
            vulnerability: Vulnerability data
        """
        logger.info(
            "Sending vulnerability notification",
            extra={
                "cve": vulnerability.get('cve_id'),
                "severity": vulnerability.get('severity')
            }
        )

        # Implementation would send to notification system
        pass

    async def export_results(
        self,
        scan_id: str,
        format: Optional[str] = None
    ) -> bytes:
        """
        Export scan results in specified format

        Args:
            scan_id: Scan ID to export
            format: Export format (json, xml, csv, pdf)

        Returns:
            Exported data as bytes
        """
        if scan_id not in self.active_scans:
            raise ValueError(f"Scan {scan_id} not found")

        export_format = format or self.export_format
        scan_data = self.active_scans[scan_id]

        logger.info(
            "Exporting scan results",
            extra={"scan_id": scan_id, "format": export_format}
        )

        # Implementation would generate export in requested format
        # For now, return JSON
        import json
        return json.dumps(scan_data, indent=2).encode('utf-8')

    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """
        Get current status of a scan

        Args:
            scan_id: Scan ID to query

        Returns:
            Scan status information
        """
        if scan_id not in self.active_scans:
            raise ValueError(f"Scan {scan_id} not found")

        return self.active_scans[scan_id]

    async def cancel_scan(self, scan_id: str) -> bool:
        """
        Cancel a running scan

        Args:
            scan_id: Scan ID to cancel

        Returns:
            True if cancelled successfully
        """
        if scan_id not in self.active_scans:
            return False

        scan = self.active_scans[scan_id]
        if scan["status"] != ScanStatus.RUNNING.value:
            return False

        logger.info(f"Cancelling scan {scan_id}")

        # Cancel in external scanner
        # ... implementation here ...

        scan["status"] = ScanStatus.CANCELLED.value
        scan["cancelled_at"] = datetime.utcnow().isoformat()

        return True

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of plugin and scanner API

        Returns:
            Health status information
        """
        try:
            # Check scanner API connectivity
            url = f"{self.scanner_api_url}/health"
            headers = {'Authorization': f'Bearer {self.api_key}'}

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    api_healthy = response.status == 200

            return {
                'status': 'healthy' if api_healthy else 'degraded',
                'scanner_api_reachable': api_healthy,
                'active_scans': len([
                    s for s in self.active_scans.values()
                    if s['status'] == ScanStatus.RUNNING.value
                ]),
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }

    async def shutdown(self) -> None:
        """
        Cleanup resources before plugin shutdown
        """
        logger.info("Shutting down vulnerability scanner plugin")

        # Cancel all running scans
        running_scans = [
            scan_id for scan_id, scan in self.active_scans.items()
            if scan['status'] == ScanStatus.RUNNING.value
        ]

        for scan_id in running_scans:
            await self.cancel_scan(scan_id)


# Plugin entry point
async def initialize(config: Dict[str, Any]) -> VulnerabilityScanner:
    """
    Initialize and return plugin instance

    This function is called by the plugin manager when loading the plugin.

    Args:
        config: Plugin configuration from database

    Returns:
        Initialized plugin instance
    """
    plugin = VulnerabilityScanner(config)

    # Perform health check
    health = await plugin.health_check()
    logger.info(f"Plugin health check: {health['status']}")

    return plugin
