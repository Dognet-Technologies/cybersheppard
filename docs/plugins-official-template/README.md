# CyberSheppard & SentinelCore - Official Plugin Repository

Official plugin repository for **CyberSheppard MicroSIEM** and **SentinelCore Vulnerability Management Platform**.

## 📦 Available Plugins

### CyberSheppard Plugins

| Plugin | Version | Status | Stability | Description |
|--------|---------|--------|-----------|-------------|
| **theme-pack-professional-dark** | 1.0.0 | stable | beta | Professional dark theme collection for CyberSheppard UI |
| **language-pack-italian** | 1.0.0 | stable | complete | Italian language pack with full translation |
| **enrichment-geoip** | 1.0.0 | stable | beta | GeoIP enrichment for IP addresses in security events |
| **integration-firedog** | 1.0.0 | stable | complete | FireDog SIEM integration connector |
| **notification-slack** | 1.0.0 | stable | beta | Slack notifications for security alerts |
| **notification-telegram** | 1.0.0 | stable | beta | Telegram bot integration for alerts |

### SentinelCore Plugins

| Plugin | Version | Status | Stability | Description |
|--------|---------|--------|-----------|-------------|
| **vulnerability-scanner-nexpose** | 1.0.0 | stable | beta | Rapid7 Nexpose vulnerability scanner integration |
| **vulnerability-scanner-qualys** | 1.0.0 | stable | beta | Qualys Cloud Platform vulnerability scanner |
| **vulnerability-scanner-nessus** | 1.0.0 | stable | complete | Tenable Nessus Professional scanner integration |
| **vulnerability-scanner-openvas** | 1.0.0 | stable | beta | OpenVAS open-source vulnerability scanner |
| **vulnerability-scanner-burp** | 1.0.0 | stable | beta | Burp Suite Enterprise web application scanner |

## 🏗️ Repository Structure

```
plugins-official/
├── cybersheppard/           # CyberSheppard MicroSIEM plugins
│   ├── theme-pack-professional-dark/
│   │   ├── manifest.json
│   │   ├── plugin.py
│   │   └── themes/
│   ├── language-pack-italian/
│   │   ├── manifest.json
│   │   └── translations/
│   └── ...
│
└── sentinelcore/            # SentinelCore Vulnerability Management plugins
    ├── vulnerability-scanner-nexpose/
    │   ├── manifest.json
    │   ├── plugin.py
    │   └── config/
    └── ...
```

## 📋 Plugin Stability Levels

- **alpha**: Early development, may have breaking changes
- **beta**: Feature complete, testing in progress
- **complete**: Production-ready, fully tested and documented

## 🔧 Installation

Plugins are automatically discovered and listed in the CyberSheppard/SentinelCore Plugin Manager UI.

### From UI (Recommended)

1. Navigate to **Plugins** in the sidebar
2. Browse available plugins from the **Available** tab
3. Click **Install** on desired plugin
4. Configure plugin settings if required
5. Enable the plugin

### Manual Installation (Advanced)

```bash
# Clone this repository
git clone https://github.com/YOUR_ORG/plugins-official.git

# Copy plugin to CyberSheppard plugins directory
cp -r plugins-official/cybersheppard/theme-pack-professional-dark \
      /path/to/cybersheppard/plugins/

# Copy plugin to SentinelCore plugins directory
cp -r plugins-official/sentinelcore/vulnerability-scanner-nexpose \
      /path/to/sentinelcore/plugins/
```

## 🛠️ Plugin Development

### Quick Start

1. Choose product directory (`cybersheppard/` or `sentinelcore/`)
2. Create plugin directory: `your-plugin-name/`
3. Create `manifest.json` with plugin metadata
4. Implement plugin logic in `plugin.py` or `plugin.rs`
5. Test locally
6. Submit pull request

### Manifest.json Structure

```json
{
  "name": "your-plugin-name",
  "version": "1.0.0",
  "product": "cybersheppard",
  "stato": "stable",
  "stability_level": "beta",
  "description": "Brief description of your plugin",
  "author": "Your Name",
  "author_email": "your.email@example.com",
  "homepage": "https://github.com/your/plugin",
  "license": "MIT",
  "requires_version": ">=1.0.0",
  "entry_point": "plugin.py",
  "checksum_sha256": "auto-generated-by-ci",
  "permissions": [
    "network.http",
    "storage.read",
    "storage.write"
  ],
  "events": [
    "security.violation.detected",
    "target.scan.complete"
  ],
  "configuration_schema": {
    "api_key": {
      "type": "string",
      "required": true,
      "description": "API key for external service"
    },
    "timeout": {
      "type": "integer",
      "default": 30,
      "description": "Request timeout in seconds"
    }
  }
}
```

### Required Fields

- **name**: Unique plugin identifier (lowercase, hyphens)
- **version**: Semantic versioning (MAJOR.MINOR.PATCH)
- **product**: Either `cybersheppard` or `sentinelcore`
- **stato**: Either `stable` or `unstable`
- **stability_level**: `alpha`, `beta`, or `complete`
- **description**: Clear, concise plugin description
- **author**: Plugin author name
- **entry_point**: Main plugin file (e.g., `plugin.py`, `plugin.rs`)

### Permission System

Declare all required permissions in manifest:

- `network.http` - HTTP/HTTPS requests
- `network.dns` - DNS lookups
- `storage.read` - Read from plugin storage
- `storage.write` - Write to plugin storage
- `system.exec` - Execute system commands
- `database.read` - Read from application database
- `database.write` - Write to application database

### Event System

Plugins can subscribe to system events:

**CyberSheppard Events:**
- `security.violation.detected` - New security violation detected
- `target.scan.complete` - Target scan completed
- `alert.triggered` - Alert condition met
- `integration.data.received` - Data received from integration

**SentinelCore Events:**
- `vulnerability.discovered` - New vulnerability found
- `scan.started` - Vulnerability scan started
- `scan.completed` - Vulnerability scan completed
- `severity.high.detected` - High severity vulnerability detected

### Example Plugin

See `cybersheppard/example-plugin/` and `sentinelcore/example-plugin/` for complete working examples.

## 🔐 Security

### Checksum Verification

All plugins include SHA256 checksums auto-generated by CI/CD. The platform verifies checksums before installation.

### Security Scanning

All pull requests are automatically scanned for:
- Known vulnerabilities (Trivy)
- Code quality issues (SonarQube)
- Dependency vulnerabilities (Dependabot)

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Email security concerns to: **security@your-domain.com**

## 🤝 Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Contribution Workflow

1. Fork this repository
2. Create feature branch: `git checkout -b feature/my-plugin`
3. Develop and test your plugin
4. Ensure all tests pass
5. Submit pull request to `develop` branch

### Code Quality Standards

- Clean, readable code with comments
- Follow language-specific style guides
- Include unit tests (minimum 70% coverage)
- Update documentation
- Pass all CI/CD checks

## 📄 License

This repository and all official plugins are licensed under **MIT License**.

Individual community plugins may have different licenses - check each plugin's manifest.json.

## 🆘 Support

- **Documentation**: https://docs.your-domain.com/plugins
- **Issues**: https://github.com/YOUR_ORG/plugins-official/issues
- **Discord**: https://discord.gg/your-server
- **Email**: support@your-domain.com

## 🏷️ Versioning

This repository uses Git tags for versioning:

- Tags format: `v{MAJOR}.{MINOR}.{PATCH}`
- Example: `v1.0.0`, `v1.2.3`
- Each plugin maintains its own version in manifest.json

## 📊 Statistics

- **Total Plugins**: 11
- **CyberSheppard Plugins**: 6
- **SentinelCore Plugins**: 5
- **Production Ready**: 4
- **Beta**: 7
- **Active Contributors**: Updated monthly

---

**Made with ❤️ by the CyberSheppard & SentinelCore Team**
