 # Hardening Models - README

## 📁 Directory Structure

This directory contains pre-configured hardening models for different system roles and compliance standards.

```
models/
├── README.md                    # This file
├── service/
│   └──never_stop
│   └──never_start
├── base/                        # Basic hardening level
│   ├── web_generic/
│   ├── web_nis2/
│   ├── web_pci/
│   ├── database_generic/
│   └── generic/
│   └── ...
├── severo/                      # Strict hardening level
│   ├── web_generic/
│   ├── web_nis2/
│   └── generic/
│   └── ...
└── custom/                      # User-created models
    └── ...
```

---

## 🎯 Model Types

### By Level
- **base**: Lighter hardening, maintains more flexibility
- **severo**: Strict hardening, maximum security

### By Role
- **web**: Web servers (nginx, apache)
- **database**: Database servers (postgresql, mysql)
- **dns**: DNS servers (bind, unbound)
- **gateway**: Network gateways/routers

### By Compliance
- **generic**: No specific compliance requirements
- **nis2**: NIS2 Directive compliance
- **pci**: PCI-DSS compliance
- **iso27001**: ISO 27001 compliance

---

## 📝 File Naming Convention

Configuration files use **dot notation** to represent target paths:

```
Target Path              →  Model Filename
────────────────────────────────────────────────────
/etc/ssh/sshd_config     →  etc.ssh.sshd_config
/etc/sysctl.d/99-hardening.conf  →  etc.sysctl.d.99-hardening.conf
/etc/audit/rules.d/audit.rules   →  etc.audit.rules.d.audit.rules
/etc/iptables/rules.v4   →  etc.iptables.rules.v4
/etc/sudoers.d/microsiem →  etc.sudoers.d.microsiem
```

**Rule**: Replace all `/` with `.` and remove the leading `/`

---

## 🔨 Creating a New Model

### Step 1: Create Directory

```bash
mkdir -p models/severo/web_custom
cd models/severo/web_custom
```

### Step 2: Add Configuration Files

Create files using dot notation:

```bash
# SSH hardening
cat > etc.ssh.sshd_config <<'EOF'
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
EOF

# Kernel parameters
cat > etc.sysctl.d.99-hardening.conf <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
kernel.dmesg_restrict = 1
EOF

# Firewall rules
cat > etc.iptables.rules.v4 <<'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
COMMIT
EOF

# Sudo permissions
cat > etc.sudoers.d.microsiem <<'EOF'
microsiem ALL=(root) NOPASSWD: /usr/bin/systemctl status *
microsiem ALL=(root) NOPASSWD: /usr/sbin/netstat
microsiem ALL=(ALL) !ALL
EOF
```

### Step 3: Add Metadata (Optional but Recommended)

```bash
cat > model.json <<'EOF'
{
  "name": "web_custom",
  "version": "1.0.0",
  "description": "Custom web server hardening",
  "role": "web",
  "compliance": "custom",
  "level": "severo",
  "author": "Your Name",
  "created_at": "2025-10-30",
  "supported_os": ["debian11", "debian12", "ubuntu22.04"],
  
  "services_to_enable": ["nginx", "auditd"],
  "services_to_disable": ["apache2", "telnet", "ftp"],
  
  "packages_to_install": ["fail2ban"],
  "packages_to_remove": ["telnetd"],
  
  "requires_reboot": false
}
EOF
```

### Step 4: Test on Non-Production Machine

**CRITICAL**: Always test on a non-production machine first!

```bash
# Apply to test machine
python apply_hardening.py --model severo/web_custom --target test-vm-01

# Verify system is stable
ssh microsiem@test-vm-01 'systemctl status'

# Check SSH still works
ssh microsiem@test-vm-01 'echo "SSH OK"'

# Rollback if needed
python rollback_hardening.py --target test-vm-01 --backup 20251030_103045
```

---

## ✅ Best Practices

### 1. Start from Existing Model
Don't start from scratch - copy an existing similar model:

```bash
cp -r models/severo/web_generic models/custom/my_web
cd models/custom/my_web
# Modify files as needed
```

### 2. Always Include These Files

Minimum required files for any model:
- `etc.ssh.sshd_config` - SSH hardening
- `etc.sysctl.d.99-hardening.conf` - Kernel parameters
- `etc.iptables.rules.v4` - Firewall rules
- `etc.sudoers.d.microsiem` - MicroSIEM user permissions

### 3. Test Incrementally

Apply changes incrementally:
1. Test SSH config alone
2. Add sysctl parameters
3. Add firewall rules
4. Add remaining configs

### 4. Document Everything

Add comments in configuration files:

```conf
# MicroSIEM Hardening - NIS2 Compliance
# Applied: 2025-10-30
# Author: Security Team
# 
# This configuration enforces:
# - Disabled root login
# - Key-based authentication only
# - Rate limiting for brute force protection

Protocol 2
PermitRootLogin no
```

### 5. Version Control

Use Git to track changes:

```bash
git add models/custom/my_web/
git commit -m "Add custom web server hardening model"
git tag -a v1.0.0 -m "Release version 1.0.0 of my_web model"
```

---

## 🔍 Common Configuration Files

### SSH Hardening (`etc.ssh.sshd_config`)

```conf
Protocol 2
Port 22
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers microsiem
```

### Kernel Parameters (`etc.sysctl.d.99-hardening.conf`)

```conf
# Network security
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0

# Kernel security
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
```

### Firewall Rules (`etc.iptables.rules.v4`)

```conf
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Allow loopback
-A INPUT -i lo -j ACCEPT

# Allow established connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from MicroSIEM server only
-A INPUT -p tcp -s 192.168.1.5 --dport 22 -j ACCEPT

# Allow HTTP/HTTPS (web servers)
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# Rate limit SSH
-A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
-A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

# Log dropped packets
-A INPUT -j LOG --log-prefix "iptables-dropped: "

COMMIT
```

### Audit Rules (`etc.audit.rules.d.audit.rules`)

```conf
# MicroSIEM Audit Rules

# Delete all previous rules
-D

# Buffer size
-b 8192

# Failure mode (0=silent 1=printk 2=panic)
-f 1

# Monitor authentication
-w /var/log/auth.log -p wa -k auth
-w /var/log/faillog -p wa -k logins
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity

# Monitor system configuration changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/sudoers -p wa -k sudoers
-w /etc/iptables/ -p wa -k iptables

# Monitor privileged commands
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k sudo_commands
-a always,exit -F arch=b64 -S execve -F path=/bin/su -k su_commands

# Make rules immutable (requires reboot to change)
-e 2
```

### Sudoers (`etc.sudoers.d.microsiem`)

```conf
# MicroSIEM monitoring user
# Created: 2025-10-30
# Purpose: Minimal permissions for system monitoring

# Allow specific read-only commands
microsiem ALL=(root) NOPASSWD: /usr/bin/systemctl status *
microsiem ALL=(root) NOPASSWD: /usr/sbin/netstat
microsiem ALL=(root) NOPASSWD: /usr/bin/ss
microsiem ALL=(root) NOPASSWD: /usr/bin/lsof
microsiem ALL=(root) NOPASSWD: /usr/bin/find /etc -type f
microsiem ALL=(root) NOPASSWD: /usr/bin/apt list --upgradable
microsiem ALL=(root) NOPASSWD: /usr/sbin/auditctl -l

# Explicitly deny everything else
microsiem ALL=(ALL) !ALL

# Log all sudo commands
Defaults:microsiem log_output
Defaults:microsiem!/usr/bin/sudoreplay !log_output
```
### Service (`never_stop`)

```conf
# MicroSIEM sevice ALWAIS enabled/started
# Created: 2025-10-30
# Purpose: This servicies are critical and MUST be started

ssh
logrotate
cron
```
### Service (`never_start`)

```conf
# MicroSIEM sevice ALWAIS disabled/stopped
# Created: 2025-10-30
# Purpose: This servicies are useless and MUST be stopped anyways

avahi
ntp
```
---

## 🔒 Security Considerations

### 1. SSH Configuration
- **Always** keep SSH accessible for MicroSIEM
- **Never** disable PubkeyAuthentication
- Test SSH after changes before closing session

### 2. Firewall Rules
- **Always** allow SSH from MicroSIEM server IP
- Consider allowing ICMP for connectivity testing
- Block all unnecessary ports

### 3. Audit Rules
- Monitor critical files and directories
- Log privileged command execution
- Balance verbosity vs performance

### 4. Service Management
- Only disable services you're certain are unnecessary
- Check dependencies before disabling
- Test service startup after hardening

### 5. File Permissions
- Verify ownership of config files (usually root:root)
- Check permissions (644 for most configs, 600 for sensitive)
- Don't break existing applications

---

## 🚨 Troubleshooting

### SSH Locked Out
If you lock yourself out via SSH:

1. Access via console/VNC
2. Restore backup:
   ```bash
   sudo cp /etc/ssh/sshd_config.backup.* /etc/ssh/sshd_config
   sudo systemctl restart sshd
   ```

### Services Won't Start
Check logs:
```bash
sudo journalctl -u service_name -n 50
sudo systemctl status service_name
```

### Firewall Blocking Traffic
Temporarily disable to test:
```bash
sudo iptables -P INPUT ACCEPT
sudo iptables -F
# Test connectivity
# Then restore proper rules
```

### Rollback Everything
```bash
# Restore all backups from timestamp
BACKUP_TIME="20251030_103045"
for file in /etc/**/*.backup.$BACKUP_TIME; do
    sudo cp "$file" "${file%.backup.$BACKUP_TIME}"
done

# Restart services
sudo systemctl restart sshd
sudo systemctl restart networking
```

---

## 📚 Resources

### Hardening Guides
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks/
- NIST Guidelines: https://www.nist.gov/cyberframework
- ANSSI Hardening Guide: https://www.ssi.gouv.fr/

### Compliance Standards
- NIS2 Directive: https://www.enisa.europa.eu/
- PCI-DSS: https://www.pcisecuritystandards.org/
- ISO 27001: https://www.iso.org/isoiec-27001-information-security.html

### Tools
- Lynis: System auditing tool
- OpenSCAP: Security compliance tool
- Ansible Hardening: Automation playbooks

---

## 🤝 Contributing

When adding new models:

1. Test thoroughly on non-production systems
2. Document all changes in model.json
3. Include comments in configuration files
4. Update this README if adding new patterns
5. Submit for review before production use

---

**Last Updated**: 2025-10-30  
**Maintained By**: MicroSIEM Team
