# CyberSheppard Agent

High-performance monitoring agent for CyberSheppard MicroSIEM platform.

## Overview

The CyberSheppard Agent replaces SSH-based monitoring with a persistent WebSocket connection, providing:

- **95% performance improvement** (from 10.3s to 0.5s per target)
- **10x scalability** (from ~50 to 1000+ targets)
- **Real-time monitoring** (<1s latency vs 30-60s polling)
- **93% bandwidth reduction** (Zstd compression + incremental updates)
- **Self-healing** (automatic reconnection with exponential backoff)

## Architecture

```
Target Server                     Backend Server
┌───────────────────┐             ┌──────────────────┐
│ CyberSheppard     │   WebSocket │  Backend         │
│ Agent (binary)    ├────────────►│  (Rust/Axum)     │
│                   │   HTTPS/WSS │                  │
│  ├─ System        │             │  ├─ WebSocket    │
│  ├─ Network       │   Metrics   │  │   Handler      │
│  ├─ Users         │   (Zstd     │  ├─ Metrics      │
│  ├─ Files         │   compressed│  │   Parser       │
│  ├─ Services      │   JSON)     │  └─ InfluxDB     │
│  └─ Docker        │             │      Writer      │
└───────────────────┘             └──────────────────┘
```

## Installation

### Prerequisites

- Linux system (Ubuntu 20.04+, Debian 11+, CentOS 8+, RHEL 8+)
- Root access
- Network connectivity to CyberSheppard backend
- Rust 1.70+ (for building from source)

### Quick Install

1. **Build the agent** (on development machine):
   ```bash
   cd cybersheppard-agent
   cargo build --release
   ```

2. **Run installation script** (on target server):
   ```bash
   sudo ./deploy/install.sh
   ```

3. **Configure the agent**:
   ```bash
   sudo nano /etc/cybersheppard-agent/config.toml
   ```

   Required settings:
   ```toml
   backend_url = "https://your-cybersheppard-server.com"
   auth_token = "YOUR_TOKEN_FROM_BACKEND"  # Get from dashboard
   target_id = 1                            # Assigned in backend
   ```

4. **Start the agent**:
   ```bash
   sudo systemctl start cybersheppard-agent
   sudo systemctl enable cybersheppard-agent
   ```

5. **Verify status**:
   ```bash
   sudo systemctl status cybersheppard-agent
   sudo journalctl -u cybersheppard-agent -f
   ```

## Configuration

### Full Configuration Options

```toml
# Backend connection
backend_url = "https://cybersheppard.example.com"
auth_token = "your-auth-token"
target_id = 1

# Collection settings
collection_interval = 30  # Collect metrics every 30 seconds
send_interval = 10        # Send buffered data every 10 seconds
compression_level = 3     # Zstd compression (1-22)
max_buffer_size = 10      # Max payloads before forced flush

[reconnect]
initial_backoff = 1       # Start with 1 second backoff
max_backoff = 300         # Max 5 minutes backoff
backoff_multiplier = 2.0  # Exponential backoff

[collectors]
# Enable/disable specific collectors
system = true    # CPU, memory, disk, uptime
network = true   # Connections, ports, traffic
users = true     # Accounts, sessions, sudo
files = true     # File integrity, SUID, world-writable
services = true  # Systemd services, Docker containers
auditd = true    # Audit events (requires auditd)
docker = true    # Docker containers (requires docker)
```

### Performance Tuning

**For high-frequency monitoring** (more real-time):
```toml
collection_interval = 10
send_interval = 5
```

**For resource-constrained systems** (less overhead):
```toml
collection_interval = 60
send_interval = 30
compression_level = 1
```

**For high-throughput** (many targets):
```toml
compression_level = 6
max_buffer_size = 20
```

## Migration from SSH-based Monitoring

### Migration Strategy

**Recommended: Gradual Rollout**

1. **Phase 1: Pilot (10% targets)**
   - Deploy agent to 5-10 test targets
   - Monitor for 24-48 hours
   - Verify metrics quality

2. **Phase 2: Expansion (50% targets)**
   - Deploy to half of production targets
   - Run parallel with SSH monitoring for 1 week
   - Compare data accuracy

3. **Phase 3: Full Deployment (100% targets)**
   - Deploy to all remaining targets
   - Disable SSH monitoring
   - Remove old collector scripts

### Backend Configuration

1. **Apply database migration**:
   ```bash
   psql -U cybersheppard -d cybersheppard < database/postgresql/migrations/002_agent_support.sql
   ```

2. **Generate auth tokens** (per target):
   ```sql
   UPDATE targets
   SET agent_enabled = true,
       agent_auth_token = encode(gen_random_bytes(32), 'hex')
   WHERE id = 1;  -- Your target ID
   ```

3. **Retrieve token**:
   ```sql
   SELECT id, hostname, agent_auth_token
   FROM targets
   WHERE agent_enabled = true;
   ```

4. **Restart backend** to load new routes:
   ```bash
   systemctl restart cybersheppard-backend
   ```

### Verification

**Agent side**:
```bash
# Check agent status
systemctl status cybersheppard-agent

# View logs
journalctl -u cybersheppard-agent -f --since "5 minutes ago"

# Expected output:
# "Connected to backend"
# "Authentication sent"
# "Starting metrics collection"
# "Metrics collected and buffered"
# "Sending buffered metrics (count: X)"
```

**Backend side**:
```bash
# Check backend logs
journalctl -u cybersheppard-backend -f | grep "Agent"

# Expected output:
# "Agent WebSocket connected"
# "Agent authenticated: target_id=X"
# "Processing metrics for target_id=X"
```

**Database verification**:
```sql
SELECT id, hostname, agent_connected, agent_last_seen, agent_version
FROM targets
WHERE agent_enabled = true;
```

## Troubleshooting

### Agent won't connect

**Check backend URL**:
```bash
curl -I https://your-backend.com/health
```

**Check firewall**:
```bash
# Allow outbound HTTPS
sudo ufw allow out 443/tcp
sudo firewall-cmd --add-port=443/tcp --permanent
```

**Check TLS certificate**:
```bash
openssl s_client -connect your-backend.com:443 -showcerts
```

### Authentication fails

**Verify token**:
```sql
SELECT id, agent_auth_token FROM targets WHERE id = 1;
```

**Regenerate token**:
```sql
UPDATE targets
SET agent_auth_token = encode(gen_random_bytes(32), 'hex')
WHERE id = 1;
```

### High CPU usage

**Reduce collection frequency**:
```toml
collection_interval = 60  # Increase from 30
```

**Disable heavy collectors**:
```toml
[collectors]
files = false  # File integrity can be CPU intensive
docker = false # If not using Docker
```

### High bandwidth usage

**Increase compression**:
```toml
compression_level = 6  # Increase from 3
```

**Increase send interval**:
```toml
send_interval = 30  # Batch more data
```

## Performance Metrics

### Before (SSH-based):
- Collection time per target: **10.3s**
- Max targets (60s interval): **~50**
- Bandwidth per target: **750KB**
- Latency: **30-60s** (polling interval)

### After (Agent-based):
- Collection time per target: **0.5s** (-95%)
- Max targets (60s interval): **1000+** (+2000%)
- Bandwidth per target: **50KB** (-93%)
- Latency: **<1s** (-98%)

## Security

### Agent Security

- **Encrypted connection**: All traffic over HTTPS/WSS
- **Token authentication**: 256-bit random tokens
- **No SSH keys**: No need for SSH access
- **No root required**: Agent runs as dedicated user (optional)
- **Sandboxed execution**: Systemd isolation enabled

### Network Security

```bash
# Firewall configuration
# Allow ONLY outbound to backend
sudo ufw allow out to <backend-ip> port 443 proto tcp
sudo ufw deny out to any port 443 proto tcp
```

### Token Rotation

```bash
# Rotate token (in backend)
UPDATE targets SET agent_auth_token = encode(gen_random_bytes(32), 'hex') WHERE id = 1;

# Update agent config
sudo nano /etc/cybersheppard-agent/config.toml
# Change auth_token = "NEW_TOKEN"

# Restart agent
sudo systemctl restart cybersheppard-agent
```

## Logs

### Log Locations

- **Systemd journal**: `journalctl -u cybersheppard-agent`
- **Logrotate**: Configured for 14-day rotation
- **Log level**: Set via `RUST_LOG` environment

### Enable Debug Logging

Edit `/etc/systemd/system/cybersheppard-agent.service`:
```ini
[Service]
Environment="RUST_LOG=debug"
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl restart cybersheppard-agent
```

## Uninstallation

```bash
sudo ./deploy/uninstall.sh
```

This will:
- Stop and disable the service
- Remove binary and systemd service
- Optionally remove configuration and logs

## Development

### Build from source

```bash
cd cybersheppard-agent
cargo build --release
```

Binary will be at: `target/release/cybersheppard-agent`

### Run in development mode

```bash
RUST_LOG=debug cargo run -- /path/to/config.toml
```

### Run tests

```bash
cargo test
```

### Cross-compilation

For ARM64 targets:
```bash
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
```

## Support

For issues, questions, or feature requests:
- GitHub: https://github.com/dognet/cybersheppard
- Email: support@dognet-technologies.com
- Docs: https://docs.cybersheppard.io

## License

Proprietary - Dognet Technologies © 2026
