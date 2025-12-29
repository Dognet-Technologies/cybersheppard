# SentinelCore Example Vulnerability Scanner Plugin

A complete example plugin demonstrating vulnerability scanner integration with the SentinelCore platform.

## Features

- 🔍 Target vulnerability scanning
- 🚨 Real-time vulnerability discovery
- 📊 Severity classification (Low/Medium/High/Critical)
- 🔔 Automatic notifications for high-severity findings
- 📤 Multi-format export (JSON, XML, CSV, PDF)
- ⚡ Concurrent scan management
- 🎯 Event-driven architecture
- 🏥 Health monitoring

## Installation

### From Plugin Manager (Recommended)

1. Navigate to **Plugins** in SentinelCore UI
2. Find "Example Vulnerability Scanner" in the Available tab
3. Click **Install**
4. Configure scanner API credentials
5. Enable the plugin

### Manual Installation

```bash
# Copy plugin to SentinelCore plugins directory
cp -r example-plugin /path/to/sentinelcore/plugins/

# Restart SentinelCore
systemctl restart sentinelcore
```

## Configuration

Configure the plugin in the Plugin Manager UI:

```json
{
  "scanner_api_url": "https://scanner.example.com/api/v1",
  "api_key": "your-scanner-api-key",
  "api_secret": "your-scanner-api-secret",
  "scan_timeout": 3600,
  "max_concurrent_scans": 5,
  "severity_threshold": "medium",
  "auto_retry_failed": true,
  "export_format": "json",
  "enable_notifications": true
}
```

### Configuration Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `scanner_api_url` | string | Yes | - | Vulnerability scanner API endpoint |
| `api_key` | string | Yes | - | API key for authentication (sensitive) |
| `api_secret` | string | No | - | API secret for enhanced auth (sensitive) |
| `scan_timeout` | integer | No | 3600 | Max scan duration in seconds (300-14400) |
| `max_concurrent_scans` | integer | No | 5 | Max concurrent scans (1-20) |
| `severity_threshold` | string | No | "medium" | Minimum severity to report |
| `auto_retry_failed` | boolean | No | true | Retry failed scans automatically |
| `export_format` | string | No | "json" | Default export format |
| `enable_notifications` | boolean | No | true | Send notifications for high severity |

### Severity Threshold

Controls which vulnerabilities are reported:

- **low**: Report all vulnerabilities
- **medium**: Report medium, high, and critical (default)
- **high**: Report only high and critical
- **critical**: Report only critical vulnerabilities

## Usage

### Programmatic API

```python
# Scan a target
result = await scanner.scan_target(
    target="192.168.1.100",
    port_range="1-65535",
    scan_type="full"
)

# Check scan status
status = await scanner.get_scan_status(result['scan_id'])

# Export results
report = await scanner.export_results(
    scan_id=result['scan_id'],
    format='pdf'
)

# Cancel running scan
await scanner.cancel_scan(result['scan_id'])
```

### Events

The plugin emits the following events:

- **scan.started**: Scan initiated
  ```json
  {
    "scan_id": "scan_1735468800.123",
    "target": "192.168.1.100",
    "scan_type": "full",
    "timestamp": "2025-12-29T10:00:00Z"
  }
  ```

- **scan.completed**: Scan finished successfully
  ```json
  {
    "scan_id": "scan_1735468800.123",
    "target": "192.168.1.100",
    "vulnerabilities_found": 15,
    "timestamp": "2025-12-29T11:00:00Z"
  }
  ```

- **vulnerability.discovered**: New vulnerability found
  ```json
  {
    "cve_id": "CVE-2024-1234",
    "title": "Remote Code Execution",
    "severity": "critical",
    "cvss_score": 9.8,
    "affected_component": "OpenSSL 1.1.1",
    "remediation": "Update to OpenSSL 3.0+"
  }
  ```

- **severity.high.detected**: High/Critical severity found
  ```json
  {
    "cve_id": "CVE-2024-1234",
    "severity": "critical",
    "alert_type": "high_severity_vulnerability"
  }
  ```

## Scan Types

- **quick**: Fast scan of common vulnerabilities (5-15 minutes)
- **full**: Comprehensive vulnerability assessment (1-2 hours)
- **compliance**: Compliance-focused scan (PCI-DSS, HIPAA, etc.)

## Permissions

Required permissions:

- `network.http` - HTTPS requests to scanner API
- `network.dns` - DNS resolution for targets
- `storage.read` - Read scan results
- `storage.write` - Store scan results
- `database.read` - Read target information
- `database.write` - Store vulnerabilities

## Integration

### External Scanner API

The plugin integrates with any vulnerability scanner that implements this API:

#### Create Scan
```http
POST /scans
Authorization: Bearer {api_key}
Content-Type: application/json

{
  "target": "192.168.1.100",
  "scan_type": "full",
  "settings": {
    "port_range": "1-65535",
    "timeout": 3600
  }
}
```

Response:
```json
{
  "id": "ext_scan_12345",
  "status": "queued",
  "created_at": "2025-12-29T10:00:00Z"
}
```

#### Get Scan Status
```http
GET /scans/{scan_id}
Authorization: Bearer {api_key}
```

Response:
```json
{
  "id": "ext_scan_12345",
  "status": "completed",
  "vulnerabilities": [
    {
      "cve_id": "CVE-2024-1234",
      "title": "Remote Code Execution",
      "description": "...",
      "severity": "critical",
      "cvss_score": 9.8,
      "component": "OpenSSL 1.1.1",
      "remediation": "Update to OpenSSL 3.0+"
    }
  ]
}
```

## Development

### Project Structure

```
example-plugin/
├── manifest.json       # Plugin metadata
├── plugin.py          # Main implementation
├── README.md          # This file
├── requirements.txt   # Dependencies
└── tests/            # Tests
    ├── test_scanner.py
    └── test_integration.py
```

### Dependencies

```bash
pip install aiohttp>=3.9.0
```

### Running Tests

```bash
pytest tests/
pytest --cov=plugin --cov-report=html tests/
```

## Troubleshooting

### Scan Failures

**Check scanner API connectivity:**
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://scanner.example.com/api/v1/health
```

**Enable debug logging:**
Set `SENTINELCORE_LOG_LEVEL=DEBUG` in environment

### Timeout Issues

- Increase `scan_timeout` for large targets
- Reduce `port_range` for faster scans
- Check network connectivity to targets

### High Severity Alerts Not Triggering

- Verify `severity_threshold` is not set too high
- Check `enable_notifications` is true
- Review scan results for actual high-severity findings

## Performance

### Concurrent Scans

The `max_concurrent_scans` setting controls parallelism:

- **1-5**: Conservative, suitable for limited resources
- **5-10**: Balanced, recommended for most deployments
- **10-20**: Aggressive, requires powerful infrastructure

### Resource Usage

Typical resource usage per scan:

- **Memory**: 100-500 MB
- **CPU**: 10-30% of one core
- **Network**: 1-10 Mbps
- **Duration**: 15 min - 2 hours (depends on scan type)

## Security

- **API credentials** are stored encrypted
- **Scan results** are stored with access controls
- **Network traffic** uses TLS 1.2+
- **Input validation** prevents injection attacks

## License

MIT License - see LICENSE file for details

## Support

- **Issues**: https://github.com/your-org/plugins-official/issues
- **Documentation**: https://docs.sentinelcore.com/plugins
- **Email**: support@sentinelcore.com

## Changelog

### v1.0.0 (2025-12-29)

- Initial release
- Full vulnerability scanning
- Multi-format export
- Event-driven architecture
- Concurrent scan management
- Auto-retry for failed scans
