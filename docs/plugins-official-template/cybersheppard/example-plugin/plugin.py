"""
CyberSheppard Example Plugin

This is a complete example plugin demonstrating all plugin capabilities:
- Event handling
- Configuration management
- External API calls
- Data enrichment
- Error handling
- Logging
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
import aiohttp
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)


class ExamplePlugin:
    """
    Example plugin for CyberSheppard MicroSIEM

    This plugin demonstrates:
    - Subscribing to security events
    - Making external API calls
    - Enriching security data
    - Sending notifications
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the plugin with configuration

        Args:
            config: Plugin configuration from manifest.json
        """
        self.config = config
        self.api_endpoint = config.get('api_endpoint')
        self.api_key = config.get('api_key')
        self.timeout = config.get('timeout', 30)
        self.retry_attempts = config.get('retry_attempts', 3)
        self.enabled_features = config.get('enabled_features', ['enrichment'])
        self.debug_mode = config.get('debug_mode', False)

        # Set logging level based on debug mode
        if self.debug_mode:
            logger.setLevel(logging.DEBUG)

        logger.info(
            "Example plugin initialized",
            extra={
                "plugin": "example-plugin",
                "version": "1.0.0",
                "features": self.enabled_features
            }
        )

    async def on_event(self, event_type: str, event_data: Dict[str, Any]) -> None:
        """
        Main event handler - called when subscribed events occur

        Args:
            event_type: Type of event (e.g., 'security.violation.detected')
            event_data: Event payload data
        """
        logger.debug(f"Received event: {event_type}", extra={"data": event_data})

        try:
            # Route to appropriate handler
            if event_type == "security.violation.detected":
                await self.handle_violation(event_data)
            elif event_type == "target.scan.complete":
                await self.handle_scan_complete(event_data)
            elif event_type == "alert.triggered":
                await self.handle_alert(event_data)
            else:
                logger.warning(f"Unknown event type: {event_type}")

        except Exception as e:
            logger.error(
                f"Error handling event {event_type}: {e}",
                extra={"event_data": event_data},
                exc_info=True
            )

    async def handle_violation(self, data: Dict[str, Any]) -> None:
        """
        Handle security violation detected event

        Args:
            data: Violation data including severity, description, target, etc.
        """
        logger.info(
            "Processing security violation",
            extra={
                "violation_id": data.get('id'),
                "severity": data.get('severity'),
                "target": data.get('target_ip')
            }
        )

        # Enrich violation data if feature is enabled
        if 'enrichment' in self.enabled_features:
            enriched_data = await self.enrich_violation(data)
            logger.debug("Violation enriched", extra={"enriched": enriched_data})

        # Send notification if feature is enabled
        if 'notification' in self.enabled_features:
            await self.send_notification(
                title=f"Security Violation: {data.get('title')}",
                message=f"Severity: {data.get('severity')} - {data.get('description')}",
                severity=data.get('severity', 'medium')
            )

    async def handle_scan_complete(self, data: Dict[str, Any]) -> None:
        """
        Handle target scan completion event

        Args:
            data: Scan results including target info and findings
        """
        logger.info(
            "Processing scan completion",
            extra={
                "scan_id": data.get('id'),
                "target": data.get('target_ip'),
                "findings": data.get('findings_count', 0)
            }
        )

        # Export results if feature is enabled
        if 'export' in self.enabled_features:
            await self.export_results(data)

    async def handle_alert(self, data: Dict[str, Any]) -> None:
        """
        Handle alert triggered event

        Args:
            data: Alert data including conditions and affected resources
        """
        logger.info(
            "Processing alert",
            extra={
                "alert_id": data.get('id'),
                "alert_type": data.get('alert_type'),
                "severity": data.get('severity')
            }
        )

        # Forward alert to external system
        await self.forward_alert(data)

    async def enrich_violation(self, violation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich violation data with external threat intelligence

        Args:
            violation: Original violation data

        Returns:
            Enriched violation data
        """
        try:
            # Example: Query external API for threat intelligence
            threat_data = await self.query_threat_intel(
                indicator=violation.get('target_ip'),
                indicator_type='ip'
            )

            if threat_data:
                violation['threat_intel'] = threat_data
                logger.info(
                    "Violation enriched with threat intelligence",
                    extra={"threat_score": threat_data.get('score')}
                )

            return violation

        except Exception as e:
            logger.error(f"Enrichment failed: {e}", exc_info=True)
            return violation

    async def query_threat_intel(
        self,
        indicator: str,
        indicator_type: str
    ) -> Optional[Dict[str, Any]]:
        """
        Query external threat intelligence API

        Args:
            indicator: The indicator to query (IP, domain, hash, etc.)
            indicator_type: Type of indicator (ip, domain, hash)

        Returns:
            Threat intelligence data or None if not found
        """
        url = f"{self.api_endpoint}/threat-intel/{indicator_type}/{indicator}"
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

        for attempt in range(self.retry_attempts):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=self.timeout)
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            logger.debug(
                                "Threat intel retrieved",
                                extra={"indicator": indicator}
                            )
                            return data
                        elif response.status == 404:
                            logger.debug(f"No threat intel found for {indicator}")
                            return None
                        else:
                            logger.warning(
                                f"API returned status {response.status}",
                                extra={"url": url}
                            )

            except asyncio.TimeoutError:
                logger.warning(
                    f"Timeout on attempt {attempt + 1}/{self.retry_attempts}",
                    extra={"url": url}
                )
                if attempt < self.retry_attempts - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff

            except Exception as e:
                logger.error(f"API request failed: {e}", exc_info=True)
                break

        return None

    async def send_notification(
        self,
        title: str,
        message: str,
        severity: str = 'medium'
    ) -> bool:
        """
        Send notification to external service

        Args:
            title: Notification title
            message: Notification message
            severity: Severity level (low, medium, high, critical)

        Returns:
            True if notification sent successfully
        """
        url = f"{self.api_endpoint}/notifications"
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        payload = {
            'title': title,
            'message': message,
            'severity': severity,
            'timestamp': datetime.utcnow().isoformat(),
            'source': 'cybersheppard-plugin'
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status in [200, 201]:
                        logger.info("Notification sent successfully")
                        return True
                    else:
                        logger.error(f"Failed to send notification: {response.status}")
                        return False

        except Exception as e:
            logger.error(f"Notification failed: {e}", exc_info=True)
            return False

    async def export_results(self, scan_data: Dict[str, Any]) -> bool:
        """
        Export scan results to external system

        Args:
            scan_data: Scan results to export

        Returns:
            True if export successful
        """
        logger.info(
            "Exporting scan results",
            extra={"scan_id": scan_data.get('id')}
        )

        # Implementation would export to external system
        # This is a placeholder
        return True

    async def forward_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Forward alert to external alerting system

        Args:
            alert_data: Alert data to forward

        Returns:
            True if forwarding successful
        """
        logger.info(
            "Forwarding alert",
            extra={"alert_id": alert_data.get('id')}
        )

        # Implementation would forward to external system
        # This is a placeholder
        return True

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of plugin and external dependencies

        Returns:
            Health status information
        """
        try:
            # Check external API connectivity
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.api_endpoint}/health",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    api_healthy = response.status == 200

            return {
                'status': 'healthy' if api_healthy else 'degraded',
                'api_reachable': api_healthy,
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
        logger.info("Shutting down example plugin")
        # Cleanup code here (close connections, save state, etc.)


# Plugin entry point
async def initialize(config: Dict[str, Any]) -> ExamplePlugin:
    """
    Initialize and return plugin instance

    This function is called by the plugin manager when loading the plugin.

    Args:
        config: Plugin configuration from database

    Returns:
        Initialized plugin instance
    """
    plugin = ExamplePlugin(config)

    # Perform any async initialization here
    health = await plugin.health_check()
    logger.info(f"Plugin health check: {health['status']}")

    return plugin
