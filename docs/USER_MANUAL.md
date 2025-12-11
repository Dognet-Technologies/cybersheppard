# CyberSheppard (MicroSIEM) - User Manual

## 📚 Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Dashboard Overview](#dashboard-overview)
4. [Managing Targets](#managing-targets)
5. [Hardening Servers](#hardening-servers)
6. [Monitoring & Compliance](#monitoring--compliance)
7. [Viewing Violations](#viewing-violations)
8. [Notifications](#notifications)
9. [Integrations](#integrations)
10. [User Management](#user-management)
11. [Reporting](#reporting)
12. [FAQ](#faq)

---

## 🎯 Introduction

**CyberSheppard (MicroSIEM)** is a Linux hardening and behavioral compliance monitoring system designed for security-conscious organizations.

### What CyberSheppard Does

- **Automated Hardening**: Apply security configurations to Linux servers
- **Continuous Monitoring**: Track system metrics, logs, and security events
- **Compliance Validation**: Verify configurations match security baselines
- **Real-time Alerts**: Get notified when thresholds are exceeded
- **Drift Detection**: Detect when configurations change from baseline

### Key Features

✅ SSH hardening and monitoring
✅ Auditd configuration and event tracking
✅ Sysctl security parameters
✅ Real-time metric streaming via WebSocket
✅ Email, Slack, and Discord notifications
✅ Integration with SentinelCore and FireDog
✅ Role-based access control (Admin, Operator, Viewer)

---

## 🚀 Getting Started

### First Login

1. Navigate to `https://your-cybersheppard-server`
2. Enter your username and password
3. Complete the setup wizard (first-time only)

### User Roles

- **Admin**: Full access to all features, user management
- **Operator**: Can manage targets, view reports, apply hardening
- **Viewer**: Read-only access to dashboards and reports

---

## 📊 Dashboard Overview

The main dashboard provides an at-a-glance view of your security posture.

### Widgets

#### System Status
- **Total Targets**: Number of monitored servers
- **Online Targets**: Servers currently reporting data
- **Active Violations**: Current compliance violations
- **Overall Score**: Aggregate compliance score (0-100)

#### Recent Violations
Real-time list of compliance violations with severity indicators:
- 🔴 **Critical**: Immediate action required
- 🟠 **High**: Address within 24 hours
- 🟡 **Medium**: Address within 7 days
- 🔵 **Low**: Monitor and plan remediation

#### Target Health
Visual representation of target server status:
- **Green**: Fully compliant
- **Yellow**: Minor issues
- **Red**: Critical violations detected

#### Real-time Metrics
Live graphs showing:
- CPU usage across targets
- Memory utilization
- Network traffic
- Failed login attempts
- Sudo command execution

---

## 🖥️ Managing Targets

### Adding a New Target

1. Click **"Targets"** in the sidebar
2. Click **"Add Target"**
3. Fill in the form:
   - **Hostname**: Server hostname
   - **IP Address**: Server IP
   - **Description**: Optional description
   - **SSH Connection**:
     - Username
     - Authentication method (Key or Password)
     - SSH key or password
4. Click **"Test Connection"**
5. If successful, click **"Add Target"**

### Target Details

Click on any target to view:

- **Overview**: Status, last seen, compliance score
- **Metrics**: CPU, memory, disk, network graphs
- **Logs**: Recent system logs and security events
- **Violations**: Active and historical violations
- **Hardening History**: Applied hardening models
- **Configuration**: Current SSH, auditd, sysctl settings

### Editing Targets

1. Navigate to target details
2. Click **"Edit"**
3. Modify settings
4. Click **"Save Changes"**

### Deleting Targets

1. Navigate to target details
2. Click **"Delete"**
3. Confirm deletion
4. **Note**: This removes the target from monitoring but does not undo hardening

---

## 🔒 Hardening Servers

### What is Server Hardening?

Server hardening applies security configurations to reduce attack surface:
- SSH configuration (disable root login, enforce key auth)
- Auditd rules (monitor file changes, command execution)
- Sysctl parameters (network security, kernel hardening)
- Firewall rules
- Package updates

### Available Hardening Models

#### Base Models (Recommended for most environments)
- **ssh_hardening_base**: Secure SSH configuration
- **auditd_base**: Essential audit rules
- **sysctl_base**: Basic kernel security parameters

#### Severo Models (Maximum security, may break compatibility)
- **ssh_hardening_severo**: Strictest SSH settings
- **auditd_severo**: Comprehensive audit logging
- **sysctl_severo**: Maximum kernel hardening

### Applying Hardening

1. Navigate to target details
2. Click **"Hardening"** tab
3. Select a hardening model
4. Click **"Preview Changes"** to see what will be modified
5. Review the changes carefully
6. Click **"Apply Hardening"**
7. Wait for completion (typically 30-60 seconds)

### Dry Run Mode

Always test hardening in dry-run mode first:

1. Enable **"Dry Run"** toggle
2. Click **"Apply Hardening"**
3. Review the simulated changes
4. If satisfied, disable dry-run and apply

### Backup and Rollback

CyberSheppard automatically backs up configurations before hardening:

- Backups stored in `/var/backups/cybersheppard/` on target
- Rollback available via **"Hardening History"** → **"Rollback"**

---

## 📈 Monitoring & Compliance

### Understanding Compliance Rules

Compliance rules define acceptable thresholds for metrics:

**Example**:
- **Metric**: `failed_logins`
- **Threshold**: 50
- **Operator**: greater_than
- **Severity**: high
- **Action**: Alert if failed login attempts exceed 50 in 1 hour

### Viewing Compliance Rules

1. Navigate to **"Compliance"** → **"Rules"**
2. View all active rules
3. Filter by severity, category, or target

### Creating Custom Rules

1. Click **"Compliance"** → **"Rules"** → **"New Rule"**
2. Fill in:
   - **Rule Name**: Descriptive name
   - **Metric**: Choose from available metrics
   - **Threshold**: Numeric threshold value
   - **Comparison**: greater_than, less_than, equals
   - **Severity**: critical, high, medium, low
   - **Alert**: Enable/disable notifications
3. Click **"Create Rule"**

### Editing Rules

1. Navigate to rule details
2. Click **"Edit"**
3. Modify settings
4. Click **"Save"**

### Disabling Rules

1. Navigate to rule details
2. Toggle **"Enabled"** to OFF
3. Rule will no longer generate violations

---

## 🚨 Viewing Violations

### Violations List

Navigate to **"Violations"** to see:

- All active violations
- Severity indicators
- Target hostname
- Metric name
- Current value vs threshold
- Time detected

### Violation Details

Click on any violation to view:

- **Timeline**: When violation started
- **Metric Graph**: Historical data leading to violation
- **Context**: Related logs and events
- **Remediation**: Suggested actions

### Acknowledging Violations

1. Open violation details
2. Click **"Acknowledge"**
3. Add a comment (optional)
4. Violation marked as acknowledged

### Resolving Violations

Violations auto-resolve when metric returns to normal.

To manually resolve:
1. Open violation details
2. Click **"Resolve"**
3. Add resolution notes
4. Violation closed

---

## 🔔 Notifications

### Configuring Notifications

Navigate to **"Settings"** → **"Notifications"**

#### Email Notifications

1. Enable **"Email Notifications"**
2. Configure SMTP:
   - SMTP Host (e.g., smtp.gmail.com)
   - SMTP Port (587 for TLS, 465 for SSL)
   - Username
   - Password
   - From Email
3. Add recipient emails
4. Click **"Test Email"** to verify
5. Click **"Save"**

#### Slack Notifications

1. Enable **"Slack Notifications"**
2. Create a Slack Incoming Webhook:
   - Go to https://api.slack.com/messaging/webhooks
   - Create new webhook for your channel
   - Copy webhook URL
3. Paste webhook URL in CyberSheppard
4. Click **"Test Slack"**
5. Click **"Save"**

#### Discord Notifications

1. Enable **"Discord Notifications"**
2. Create a Discord Webhook:
   - Open Discord channel settings
   - Go to **Integrations** → **Webhooks**
   - Create new webhook
   - Copy webhook URL
3. Paste webhook URL in CyberSheppard
4. Click **"Test Discord"**
5. Click **"Save"**

### Notification Rules

Configure when notifications are sent:

- **All Violations**: Send for every violation
- **Critical & High Only**: Only critical and high severity
- **Critical Only**: Only critical violations
- **Aggregated**: Send daily summary

---

## 🔗 Integrations

### SentinelCore Integration

**SentinelCore** provides vulnerability scanning.

1. Navigate to **"Integrations"** → **"SentinelCore"**
2. Enable integration
3. Configure:
   - API Endpoint: `https://sentinel.example.com/api`
   - API Key: (from SentinelCore)
   - Sync Interval: How often to sync (default: 1 hour)
4. Click **"Test Connection"**
5. Click **"Save"**

**What it does**:
- Syncs vulnerability data to CyberSheppard
- Correlates vulnerabilities with hardening status
- Shows vulnerable packages per target

### FireDog Integration

**FireDog** provides firewall management and threat intelligence.

1. Navigate to **"Integrations"** → **"FireDog"**
2. Enable integration
3. Configure:
   - API Endpoint: `https://firedog.example.com/api`
   - API Key: (from FireDog)
   - Sync Interval: Default 30 minutes
4. Click **"Test Connection"**
5. Click **"Save"**

**What it does**:
- Syncs firewall rules
- Imports threat intelligence feeds
- Blocks malicious IPs automatically

---

## 👥 User Management

### Adding Users (Admin only)

1. Navigate to **"Settings"** → **"Users"**
2. Click **"Add User"**
3. Fill in:
   - Username
   - Email
   - Password (must be 12+ characters)
   - Role (Admin, Operator, Viewer)
4. Click **"Create User"**
5. User receives email with credentials

### Editing Users

1. Navigate to user list
2. Click on username
3. Modify:
   - Email
   - Role
   - Active status
4. Click **"Save"**

### Resetting Passwords

As admin:
1. Navigate to user details
2. Click **"Reset Password"**
3. New password generated and emailed to user

As user:
1. Click **"Forgot Password"** on login page
2. Enter email
3. Check email for reset link

### Deleting Users

1. Navigate to user details
2. Click **"Delete User"**
3. Confirm deletion
4. User immediately logged out and disabled

---

## 📑 Reporting

### Available Reports

#### Compliance Report
- Overall compliance score
- Violations by severity
- Top violating targets
- Compliance trends over time

#### Hardening Report
- Hardening coverage (% of targets hardened)
- Hardening status per target
- Drift detection summary
- Validation results

#### Security Summary
- Failed login attempts
- Sudo command execution
- Privilege escalations
- File integrity violations

### Generating Reports

1. Navigate to **"Reports"**
2. Select report type
3. Choose date range
4. Select targets (or "All")
5. Click **"Generate Report"**
6. Download as PDF, CSV, or JSON

### Scheduled Reports

1. Navigate to **"Reports"** → **"Scheduled"**
2. Click **"New Schedule"**
3. Configure:
   - Report type
   - Frequency (daily, weekly, monthly)
   - Recipients
4. Click **"Create Schedule"**

---

## ❓ FAQ

### Q: How often do collectors send data?
**A**: Collectors send data every 5 minutes by default (configurable).

### Q: What happens if a collector goes offline?
**A**: The target is marked as offline after 15 minutes of no data. No new violations are generated while offline.

### Q: Can I undo hardening?
**A**: Yes, use the **"Rollback"** feature in Hardening History to restore previous configurations.

### Q: How long is data retained?
**A**:
- Metrics: 90 days (InfluxDB)
- Logs: 30 days (PostgreSQL)
- Violations: Indefinitely (PostgreSQL)

### Q: Can I monitor Windows servers?
**A**: No, CyberSheppard currently only supports Linux targets.

### Q: What Linux distributions are supported?
**A**: Ubuntu 20.04+, Debian 11+, RHEL 8+, Rocky Linux 8+, CentOS 8+

### Q: Is there a mobile app?
**A**: Not yet. The web interface is mobile-responsive.

### Q: How do I upgrade CyberSheppard?
**A**: See [Installation Guide - Upgrading](./INSTALLATION_GUIDE.md#upgrading)

### Q: Can I use custom hardening models?
**A**: Yes, place YAML files in `hardening-models/custom/` and they'll appear in the UI.

### Q: How do I backup CyberSheppard data?
**A**: Backup PostgreSQL and InfluxDB databases regularly:
```bash
docker-compose exec postgres pg_dump -U cybersheppard cybersheppard > backup.sql
docker-compose exec influxdb influx backup /backup
```

---

## 📞 Support

- **Documentation**: https://docs.cybersheppard.io
- **Community Forum**: https://community.cybersheppard.io
- **Email**: support@cybersheppard.io
- **GitHub Issues**: https://github.com/Dognet-Technologies/cybersheppard/issues

---

## 📝 Next Steps

- Read the [Admin Guide](./ADMIN_GUIDE.md)
- Learn about [Hardening Models](./HARDENING_MODELS.md)
- Configure [Integrations](./INTEGRATION_SPEC.md)
- Review [API Documentation](./openapi.yaml)
