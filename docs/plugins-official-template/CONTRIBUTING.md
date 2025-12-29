# Contributing to Official Plugins Repository

Thank you for your interest in contributing to the CyberSheppard & SentinelCore plugin ecosystem!

## 📖 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Plugin Development Guidelines](#plugin-development-guidelines)
- [Testing Requirements](#testing-requirements)
- [Submission Process](#submission-process)
- [Review Process](#review-process)

## 🤝 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors.

### Standards

- Use welcoming and inclusive language
- Respect differing viewpoints and experiences
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards other community members

## 🚀 Getting Started

### Prerequisites

**For CyberSheppard Plugins:**
- Rust 1.70+ or Python 3.11+
- CyberSheppard development environment
- PostgreSQL 14+ and InfluxDB 2.x

**For SentinelCore Plugins:**
- Python 3.11+ or Rust 1.70+
- SentinelCore development environment
- Access to vulnerability scanner APIs (for scanner plugins)

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/YOUR_ORG/plugins-official.git
cd plugins-official

# Create a feature branch
git checkout -b feature/my-awesome-plugin

# Install dependencies (Python example)
cd cybersheppard/my-plugin
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Or for Rust
cd sentinelcore/my-plugin
cargo build
```

## 🔄 Development Workflow

### Branch Strategy

- **main**: Production-ready plugins (protected)
- **develop**: Integration branch for new features
- **feature/**: Feature branches for new plugins
- **fix/**: Bug fix branches
- **hotfix/**: Critical production fixes

### Creating a New Plugin

1. **Choose Product Directory**
   ```bash
   # For CyberSheppard
   cd cybersheppard/

   # For SentinelCore
   cd sentinelcore/
   ```

2. **Create Plugin Directory**
   ```bash
   mkdir my-plugin-name
   cd my-plugin-name
   ```

3. **Create Manifest**
   ```bash
   touch manifest.json
   ```

4. **Implement Plugin Logic**
   ```bash
   touch plugin.py  # or plugin.rs for Rust
   ```

## 📝 Plugin Development Guidelines

### Naming Conventions

- Plugin directory: `lowercase-with-hyphens`
- Python files: `snake_case.py`
- Rust files: `snake_case.rs`
- Classes: `PascalCase`
- Functions: `snake_case`

### Manifest.json Requirements

**Mandatory Fields:**
```json
{
  "name": "my-plugin-name",
  "version": "1.0.0",
  "product": "cybersheppard",
  "stato": "stable",
  "stability_level": "alpha",
  "description": "Clear description (max 200 chars)",
  "author": "Your Name",
  "author_email": "you@example.com",
  "license": "MIT",
  "requires_version": ">=1.0.0",
  "entry_point": "plugin.py"
}
```

**Optional But Recommended:**
```json
{
  "homepage": "https://github.com/your/plugin",
  "documentation": "https://docs.example.com",
  "repository": "https://github.com/your/plugin",
  "keywords": ["security", "monitoring", "siem"],
  "permissions": ["network.http", "storage.write"],
  "events": ["security.violation.detected"],
  "configuration_schema": {}
}
```

### Code Quality Standards

**Python Plugins:**
- Follow PEP 8 style guide
- Use type hints (Python 3.11+)
- Maximum line length: 100 characters
- Docstrings for all public functions/classes
- Use `black` for formatting
- Use `pylint` for linting (score > 8.0)

**Rust Plugins:**
- Follow Rust style guide (`rustfmt`)
- Use `clippy` for linting (no warnings)
- Comprehensive error handling
- Documentation comments for public APIs
- Minimum Rust version: 1.70

### Error Handling

**Always handle errors gracefully:**

```python
# Python example
try:
    result = risky_operation()
except Exception as e:
    logger.error(f"Operation failed: {e}")
    return {"status": "error", "message": str(e)}
```

```rust
// Rust example
match risky_operation() {
    Ok(result) => result,
    Err(e) => {
        tracing::error!("Operation failed: {}", e);
        return Err(PluginError::from(e));
    }
}
```

### Logging

Use structured logging:

```python
# Python
import logging
logger = logging.getLogger(__name__)

logger.info("Plugin initialized", extra={"plugin": "my-plugin"})
logger.warning("API rate limit approaching", extra={"remaining": 10})
logger.error("Failed to connect", extra={"endpoint": url})
```

```rust
// Rust
use tracing::{info, warn, error};

info!(plugin = "my-plugin", "Plugin initialized");
warn!(remaining = 10, "API rate limit approaching");
error!(endpoint = %url, "Failed to connect");
```

### Security Best Practices

1. **Never hardcode credentials**
   - Use configuration schema
   - Support environment variables
   - Document credential requirements

2. **Validate all inputs**
   ```python
   def process_data(user_input: str) -> str:
       # Validate and sanitize
       if not isinstance(user_input, str):
           raise ValueError("Invalid input type")

       # Limit input size
       if len(user_input) > 1000:
           raise ValueError("Input too large")

       # Sanitize
       safe_input = sanitize(user_input)
       return safe_input
   ```

3. **Use least privilege permissions**
   - Request only necessary permissions
   - Document why each permission is needed

4. **Protect sensitive data**
   - Never log credentials or tokens
   - Use secure storage for secrets
   - Clear sensitive data from memory

### Performance Guidelines

1. **Async operations** for I/O-bound tasks
2. **Connection pooling** for database/API calls
3. **Caching** for frequently accessed data
4. **Timeouts** for all external calls
5. **Resource limits** to prevent exhaustion

### Configuration Schema

Provide clear configuration schema:

```json
{
  "configuration_schema": {
    "api_key": {
      "type": "string",
      "required": true,
      "description": "API key for authentication",
      "sensitive": true
    },
    "timeout": {
      "type": "integer",
      "default": 30,
      "min": 5,
      "max": 300,
      "description": "Request timeout in seconds"
    },
    "enabled_features": {
      "type": "array",
      "items": {"type": "string"},
      "default": ["feature1", "feature2"],
      "description": "List of enabled features"
    }
  }
}
```

## 🧪 Testing Requirements

### Minimum Requirements

- **Unit test coverage**: Minimum 70%
- **Integration tests**: For external API calls
- **Error handling tests**: For all error paths
- **Configuration validation**: Test all config options

### Python Testing

```bash
# Install test dependencies
pip install pytest pytest-cov pytest-asyncio

# Run tests with coverage
pytest --cov=plugin --cov-report=html tests/

# Coverage must be > 70%
```

### Rust Testing

```bash
# Run tests
cargo test

# Run tests with coverage (requires tarpaulin)
cargo tarpaulin --out Html --output-dir coverage
```

### Test Structure

```
my-plugin/
├── plugin.py
├── manifest.json
├── requirements.txt
└── tests/
    ├── __init__.py
    ├── test_core.py
    ├── test_integration.py
    └── test_config.py
```

## 📤 Submission Process

### Pre-submission Checklist

- [ ] Code follows style guidelines
- [ ] All tests pass locally
- [ ] Test coverage > 70%
- [ ] Documentation is complete
- [ ] manifest.json is valid
- [ ] No hardcoded credentials
- [ ] CHANGELOG.md updated
- [ ] README.md included in plugin directory

### Creating a Pull Request

1. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: Add [plugin-name] for [product]

   - Implements [feature]
   - Adds [capability]
   - Fixes [issue]"
   ```

2. **Push to your fork**
   ```bash
   git push origin feature/my-awesome-plugin
   ```

3. **Open Pull Request**
   - Target branch: `develop`
   - Use PR template
   - Link related issues
   - Provide testing evidence

### Pull Request Template

```markdown
## Description
Brief description of the plugin and what it does.

## Type of Change
- [ ] New plugin
- [ ] Bug fix
- [ ] Enhancement
- [ ] Documentation update

## Product
- [ ] CyberSheppard
- [ ] SentinelCore

## Checklist
- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] manifest.json is valid
- [ ] No security vulnerabilities

## Testing
Describe testing performed:
- Unit tests: [coverage %]
- Integration tests: [pass/fail]
- Manual testing: [scenarios tested]

## Screenshots (if applicable)
[Add screenshots of plugin UI or configuration]
```

## 🔍 Review Process

### What Reviewers Check

1. **Code Quality**
   - Follows style guidelines
   - Clean, readable code
   - Proper error handling
   - No code smells

2. **Security**
   - No hardcoded credentials
   - Input validation
   - Proper permission usage
   - No known vulnerabilities

3. **Testing**
   - Sufficient test coverage
   - Tests actually test the code
   - Edge cases covered

4. **Documentation**
   - Clear README
   - Complete manifest.json
   - Code comments where needed
   - Configuration documented

5. **Performance**
   - No obvious performance issues
   - Resource limits enforced
   - Efficient algorithms

### Automated Checks (CI/CD)

All PRs must pass:
- ✅ Linting (pylint/clippy)
- ✅ Tests (pytest/cargo test)
- ✅ Security scan (Trivy)
- ✅ Dependency check (Dependabot)
- ✅ Checksum generation

### Review Timeline

- **Initial review**: Within 3 business days
- **Follow-up reviews**: Within 2 business days
- **Merge decision**: After 2 approvals from maintainers

### After Merge

1. PR merged to `develop` branch
2. Automated tests run
3. Staged for next release
4. Released to `main` with version tag
5. Checksum auto-generated
6. Available in Plugin Manager

## 🏷️ Versioning

Follow Semantic Versioning (MAJOR.MINOR.PATCH):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes

Update manifest.json version for each release.

## 📞 Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open an Issue with `bug` label
- **Feature Requests**: Open an Issue with `enhancement` label
- **Discord**: Join our [Discord server](https://discord.gg/your-server)

## 🎖️ Recognition

Contributors will be:
- Listed in plugin manifest (`author` field)
- Credited in release notes
- Added to CONTRIBUTORS.md
- Featured in monthly community updates

Thank you for contributing to make CyberSheppard and SentinelCore better! 🚀
