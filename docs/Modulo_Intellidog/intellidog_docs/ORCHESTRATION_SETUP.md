# Orchestration Setup Guide

## Overview

This guide explains how to configure the **Orchestration** settings on Firedog, Sentinel Core, and CyberSheppard to enable inter-tool communication and database replication for Intellidog.

**Prerequisites**:
- Firedog, Sentinel Core, and CyberSheppard installed and operational
- Network connectivity between all three VMs
- Admin access to all three systems

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Tool Orchestration                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Firedog (192.168.1.50)                                     │
│  ├─ API Key: fdog_abc123xyz                                 │
│  ├─ Knows: CyberSheppard IP + API key                       │
│  └─ Knows: Sentinel IP + API key                            │
│                                                              │
│  Sentinel Core (192.168.1.51)                               │
│  ├─ API Key: sent_ghi789rst                                 │
│  ├─ Knows: CyberSheppard IP + API key                       │
│  └─ Knows: Firedog IP + API key                             │
│                                                              │
│  CyberSheppard (192.168.1.100)                              │
│  ├─ API Key: cyber_def456uvw                                │
│  ├─ Knows: Firedog IP + API key                             │
│  └─ Knows: Sentinel IP + API key                            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Key Concept**: Each tool generates its own API key and shares it with the others. This creates a trusted network for orchestration and replication.

---

## Step 1: Configure Firedog

### 1.1 Access Orchestration Settings

```
Firedog UI → Settings → Orchestration
```

### 1.2 Generate Firedog API Key

```
[Section: API Key Management]

┌──────────────────────────────────────────────────┐
│ Firedog API Key                                  │
├──────────────────────────────────────────────────┤
│ Current API Key: **********************          │
│                                                  │
│ [Generate New API Key]  [Show]  [Copy]          │
└──────────────────────────────────────────────────┘
```

**Actions**:
1. Click **"Generate New API Key"**
2. API key generated: `fdog_abc123xyz789...` (32+ characters)
3. Click **"Copy"** to clipboard
4. **Save this key** - you'll need it for CyberSheppard and Sentinel

**⚠️ Important**: 
- This key is shown only once
- Store it securely (password manager recommended)
- You'll enter this key on CyberSheppard and Sentinel

### 1.3 Configure CyberSheppard Connection

```
[Section: CyberSheppard Integration]

┌──────────────────────────────────────────────────┐
│ CyberSheppard Configuration                      │
├──────────────────────────────────────────────────┤
│ IP Address: [192.168.1.100        ]              │
│ Port:       [8000                 ]              │
│ API Key:    [************************]           │
│                                                  │
│ [Test Connection]  [Save]                        │
└──────────────────────────────────────────────────┘
```

**Actions**:
1. Enter CyberSheppard IP address (e.g., `192.168.1.100`)
2. Enter CyberSheppard API key (you'll get this from CyberSheppard in Step 3)
3. Click **"Test Connection"**
   - ✅ Success: "Connected to CyberSheppard successfully"
   - ❌ Failure: Check IP, port, and API key
4. Click **"Save"**

### 1.4 Configure Sentinel Connection

```
[Section: Sentinel Core Integration]

┌──────────────────────────────────────────────────┐
│ Sentinel Core Configuration                      │
├──────────────────────────────────────────────────┤
│ IP Address: [192.168.1.51         ]              │
│ Port:       [8000                 ]              │
│ API Key:    [************************]           │
│                                                  │
│ [Test Connection]  [Save]                        │
└──────────────────────────────────────────────────┘
```

**Actions**:
1. Enter Sentinel IP address (e.g., `192.168.1.51`)
2. Enter Sentinel API key (you'll get this from Sentinel in Step 2)
3. Click **"Test Connection"**
4. Click **"Save"**

**Final State on Firedog**:
```
✅ Firedog API Key: fdog_abc123xyz (generated)
✅ CyberSheppard: 192.168.1.100 (configured)
✅ Sentinel: 192.168.1.51 (configured)
```

---

## Step 2: Configure Sentinel Core

### 2.1 Access Orchestration Settings

```
Sentinel UI → Settings → Orchestration
```

### 2.2 Generate Sentinel API Key

```
[Section: API Key Management]

┌──────────────────────────────────────────────────┐
│ Sentinel API Key                                 │
├──────────────────────────────────────────────────┤
│ Current API Key: **********************          │
│                                                  │
│ [Generate New API Key]  [Show]  [Copy]          │
└──────────────────────────────────────────────────┘
```

**Actions**:
1. Click **"Generate New API Key"**
2. API key generated: `sent_ghi789rst012...`
3. Click **"Copy"** to clipboard
4. **Save this key** - you'll need it for CyberSheppard and Firedog

### 2.3 Configure CyberSheppard Connection

```
[Section: CyberSheppard Integration]

IP Address: 192.168.1.100
API Key: <paste CyberSheppard API key>

[Test Connection]  [Save]
```

### 2.4 Configure Firedog Connection

```
[Section: Firedog Integration]

IP Address: 192.168.1.50
API Key: <paste Firedog API key from Step 1.2>

[Test Connection]  [Save]
```

**Final State on Sentinel**:
```
✅ Sentinel API Key: sent_ghi789rst (generated)
✅ CyberSheppard: 192.168.1.100 (configured)
✅ Firedog: 192.168.1.50 (configured)
```

---

## Step 3: Configure CyberSheppard

### 3.1 Access Orchestration Settings

```
CyberSheppard UI → Settings → Orchestration
```

### 3.2 Generate CyberSheppard API Key

```
[Section: API Key Management]

┌──────────────────────────────────────────────────┐
│ CyberSheppard API Key                            │
├──────────────────────────────────────────────────┤
│ Current API Key: **********************          │
│                                                  │
│ [Generate New API Key]  [Show]  [Copy]          │
└──────────────────────────────────────────────────┘
```

**Actions**:
1. Click **"Generate New API Key"**
2. API key generated: `cyber_def456uvw345...`
3. Click **"Copy"** to clipboard
4. **Save this key** - you'll need it for Firedog and Sentinel

**⚠️ Go Back to Firedog and Sentinel**:
- Return to Firedog (Step 1.3) and enter this API key
- Return to Sentinel (Step 2.3) and enter this API key

### 3.3 Configure Firedog Connection

```
[Section: Firedog Integration]

IP Address: 192.168.1.50
API Key: <paste Firedog API key from Step 1.2>

[Test Connection]  [Save]
```

### 3.4 Configure Sentinel Connection

```
[Section: Sentinel Core Integration]

IP Address: 192.168.1.51
API Key: <paste Sentinel API key from Step 2.2>

[Test Connection]  [Save]
```

**Final State on CyberSheppard**:
```
✅ CyberSheppard API Key: cyber_def456uvw (generated)
✅ Firedog: 192.168.1.50 (configured)
✅ Sentinel: 192.168.1.51 (configured)
```

---

## Verification Checklist

After completing all three configurations, verify:

### On Firedog
- [ ] API key generated and saved
- [ ] CyberSheppard connection: ✅ Test successful
- [ ] Sentinel connection: ✅ Test successful

### On Sentinel
- [ ] API key generated and saved
- [ ] CyberSheppard connection: ✅ Test successful
- [ ] Firedog connection: ✅ Test successful

### On CyberSheppard
- [ ] API key generated and saved
- [ ] Firedog connection: ✅ Test successful
- [ ] Sentinel connection: ✅ Test successful

### Network Connectivity Test

From CyberSheppard, verify you can reach both tools:

```bash
# Test Firedog
curl http://192.168.1.50:8000/health

# Test Sentinel
curl http://192.168.1.51:8000/health
```

Both should return `200 OK`.

---

## Security Considerations

### API Key Storage

API keys are stored **encrypted** in the database:

```sql
-- Example: system_integrations table
SELECT service_name, base_url, is_active 
FROM system_integrations;

-- API keys are encrypted, never shown in plaintext
```

**Encryption Method**: Fernet (symmetric encryption with key from `.env`)

```python
# backend/app/services/integration_service.py
from cryptography.fernet import Fernet

cipher = Fernet(settings.ENCRYPTION_KEY.encode())
encrypted_key = cipher.encrypt(api_key.encode()).decode()
```

### API Key Rotation

**When to rotate**:
- Every 90 days (recommended)
- After suspected compromise
- After team member changes

**How to rotate**:
1. Generate new API key on source tool
2. Update API key on connected tools
3. Old key is automatically invalidated

**Example** (rotating Firedog key):
```
1. Firedog → Generate new API key
2. CyberSheppard → Update Firedog API key
3. Sentinel → Update Firedog API key
4. Firedog → Old key no longer works
```

### Network Security

**Firewall Rules** (recommended):

```bash
# On Firedog (192.168.1.50)
# Allow only CyberSheppard and Sentinel
iptables -A INPUT -p tcp -s 192.168.1.100 --dport 8000 -j ACCEPT  # CyberSheppard
iptables -A INPUT -p tcp -s 192.168.1.51 --dport 8000 -j ACCEPT   # Sentinel
iptables -A INPUT -p tcp --dport 8000 -j DROP  # Block all others

# On Sentinel (192.168.1.51)
iptables -A INPUT -p tcp -s 192.168.1.100 --dport 8000 -j ACCEPT  # CyberSheppard
iptables -A INPUT -p tcp -s 192.168.1.50 --dport 8000 -j ACCEPT   # Firedog
iptables -A INPUT -p tcp --dport 8000 -j DROP

# On CyberSheppard (192.168.1.100)
iptables -A INPUT -p tcp -s 192.168.1.50 --dport 8000 -j ACCEPT   # Firedog
iptables -A INPUT -p tcp -s 192.168.1.51 --dport 8000 -j ACCEPT   # Sentinel
iptables -A INPUT -p tcp --dport 8000 -j DROP
```

### PostgreSQL Replication Security

The **CyberSheppard API key** is used as the password for the `intellirep` PostgreSQL user:

```sql
-- On Firedog PostgreSQL
CREATE USER intellirep WITH REPLICATION PASSWORD 'cyber_def456uvw';

-- On Sentinel PostgreSQL
CREATE USER intellirep WITH REPLICATION PASSWORD 'cyber_def456uvw';
```

**Why this design?**:
- Single source of truth (CyberSheppard API key)
- No additional password to manage
- Automatic rotation when CyberSheppard key changes

---

## Troubleshooting

### Connection Test Fails

**Error**: `❌ Cannot connect to CyberSheppard`

**Checks**:
1. Verify IP address is correct
2. Verify port is correct (default: 8000)
3. Test network connectivity:
   ```bash
   ping 192.168.1.100
   telnet 192.168.1.100 8000
   ```
4. Check firewall rules on target
5. Verify target service is running:
   ```bash
   systemctl status cybersheppard
   ```

### Authentication Failed

**Error**: `❌ Invalid API key`

**Checks**:
1. Verify API key was copied correctly (no extra spaces)
2. Regenerate API key if lost
3. Check logs on target system:
   ```bash
   tail -f /var/log/cybersheppard/api.log
   ```

### API Key Not Showing

**Issue**: After generating API key, it shows `****`

**Solution**: This is expected behavior for security. The key is shown only once during generation. If you didn't copy it:
1. Generate a new API key
2. Update all connected tools with the new key

---

## Next Steps

After completing orchestration setup:

1. ✅ **Install Replication Plugins**
   - See: `REPLICATION_PLUGINS.md`
   
2. ✅ **Activate Intellidog Module**
   - See: `INTELLIDOG_MODULE.md`

3. ✅ **Verify Replication Status**
   - See: `DATABASE_ARCHITECTURE.md`

---

## Summary

**What You've Configured**:
- ✅ Each tool has its own API key
- ✅ Each tool knows the IP and API key of the other tools
- ✅ Secure, encrypted API key storage
- ✅ Network connectivity verified

**What Happens Next**:
- Replication plugins use these settings to configure PostgreSQL
- Intellidog uses these API keys for REST API calls
- Database replication flows automatically

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-12-31  
**Author**: Dognet Technologies
