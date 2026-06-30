# CyberSheppard Example Plugin

A complete example plugin demonstrating all capabilities of the CyberSheppard plugin system.

## Features

- 🎯 Event subscription and handling
- 🔌 External API integration
- 📊 Data enrichment
- 🔔 Notification sending
- 📤 Data export
- ⚙️ Configuration management
- 🏥 Health checks
- 📝 Comprehensive logging

## Installation

### From Plugin Manager (Recommended)

1. Navigate to **Plugins** in CyberSheppard UI
2. Find "Example Plugin" in the Available tab
3. Click **Install**
4. Configure the plugin settings
5. Enable the plugin

### Manual Installation

```bash
# Copy plugin to CyberSheppard plugins directory
cp -r example-plugin /path/to/cybersheppard/plugins/

# Restart CyberSheppard
systemctl restart cybersheppard
```

## Configuration

Configure the plugin in the Plugin Manager UI or directly in the database:

```json
{
  "api_endpoint": "https://api.example.com/v1",
  "api_key": "your-secret-api-key",
  "timeout": 30,
  "retry_attempts": 3,
  "enabled_features": ["enrichment", "notification"],
  "debug_mode": false
}
```

### Configuration Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `api_endpoint` | string | Yes | - | External API endpoint URL |
| `api_key` | string | Yes | - | API authentication key (sensitive) |
| `timeout` | integer | No | 30 | Request timeout in seconds (5-300) |
| `retry_attempts` | integer | No | 3 | Number of retry attempts (0-10) |
| `enabled_features` | array | No | `["enrichment"]` | Enabled features list |
| `debug_mode` | boolean | No | false | Enable verbose debug logging |

### Enabled Features

- **enrichment**: Enrich security violations with threat intelligence
- **notification**: Send notifications for security events
- **export**: Export scan results to external systems

## Events

The plugin subscribes to the following CyberSheppard events:

- `security.violation.detected` - Triggered when a security violation is detected
- `target.scan.complete` - Triggered when a target scan completes
- `alert.triggered` - Triggered when an alert condition is met

## Permissions

Required permissions:

- `network.http` - Make HTTP/HTTPS requests to external APIs
- `storage.read` - Read plugin data from storage
- `storage.write` - Write plugin data to storage

## Usage

Once installed and configured, the plugin automatically:

1. Subscribes to security events
2. Enriches violation data with threat intelligence
3. Sends notifications for critical events
4. Exports scan results to external systems

## Development

### Project Structure

```
example-plugin/
├── manifest.json       # Plugin metadata and configuration schema
├── plugin.py          # Main plugin implementation
├── README.md          # This file
├── requirements.txt   # Python dependencies
└── tests/            # Unit and integration tests
    ├── test_core.py
    └── test_integration.py
```

### Dependencies

```bash
pip install aiohttp>=3.9.0
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov pytest-asyncio

# Run tests
pytest tests/

# Run with coverage
pytest --cov=plugin --cov-report=html tests/
```

### Local Development

1. Clone the plugins repository
2. Create a virtual environment
3. Install dependencies
4. Make your changes
5. Run tests
6. Submit a pull request

```bash
git clone https://github.com/your-org/plugins-official.git
cd plugins-official/cybersheppard/example-plugin
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest tests/
```

## API Integration

The plugin integrates with an external API for threat intelligence and notifications.

### Threat Intelligence Endpoint

```
GET /threat-intel/{type}/{indicator}
Authorization: Bearer {api_key}
```

Response:
```json
{
  "indicator": "192.168.1.100",
  "type": "ip",
  "score": 85,
  "tags": ["malware", "botnet"],
  "last_seen": "2025-12-29T10:30:00Z"
}
```

### Notification Endpoint

```
POST /notifications
Authorization: Bearer {api_key}
Content-Type: application/json

{
  "title": "Security Violation",
  "message": "High severity violation detected",
  "severity": "high",
  "timestamp": "2025-12-29T10:35:00Z",
  "source": "cybersheppard-plugin"
}
```

## Troubleshooting

### Plugin Not Loading

Check the plugin logs:
```bash
tail -f /var/log/cybersheppard/plugins.log
```

Verify manifest.json is valid:
```bash
python -m json.tool manifest.json
```

### API Connection Issues

- Verify `api_endpoint` is correct and reachable
- Check `api_key` is valid
- Review firewall rules
- Enable `debug_mode` for verbose logging

### Performance Issues

- Reduce `timeout` value
- Decrease `retry_attempts`
- Check external API rate limits
- Review plugin execution logs

## License

MIT License - see LICENSE file for details

## Support

- **Issues**: https://github.com/your-org/plugins-official/issues
- **Documentation**: https://docs.cybersheppard.com/plugins/example
- **Email**: support@cybersheppard.com

## Changelog

### v1.0.0 (2025-12-29)

- Initial release
- Event handling for violations, scans, and alerts
- Threat intelligence enrichment
- Notification system
- Export functionality
- Configuration management
- Health checks
