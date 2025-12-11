# CyberSheppard - Quick Start Guide

Get CyberSheppard up and running in 15 minutes! ⚡

---

## 🚀 Installation (5 minutes)

### Prerequisites

- Linux server (Ubuntu 22.04 recommended)
- Docker & Docker Compose installed
- 8GB RAM, 4 CPU cores, 100GB disk minimum

### Install

```bash
# 1. Clone repository
git clone https://github.com/Dognet-Technologies/cybersheppard.git
cd cybersheppard

# 2. Copy and configure environment
cp deploy/.env.production.example .env
nano .env  # Set DATABASE_URL password, JWT_SECRET, INFLUXDB_TOKEN

# 3. Generate secrets (run 3 times for different values)
openssl rand -base64 48

# 4. Run setup
sudo chmod +x deploy/setup-production.sh
sudo ./deploy/setup-production.sh

# 5. Start services
docker-compose up -d

# 6. Verify
docker-compose ps  # All services should be "Up"
```

---

## 👤 Initial Setup (3 minutes)

### Create Admin User

```bash
docker-compose exec backend-rust cargo run --bin create-admin -- \
  --username admin \
  --email admin@example.com \
  --password SecurePassword123!
```

### Access Web Interface

1. Open browser: `https://your-server-ip`
2. Login with admin credentials
3. Skip the setup wizard for now (or configure notifications)

---

## 🖥️ Add Your First Target (5 minutes)

### On CyberSheppard UI

1. Click **"Targets"** → **"Add Target"**
2. Fill in:
   - Hostname: `web-01`
   - IP Address: `192.168.1.100`
   - Description: `Production web server`
3. SSH Connection:
   - Username: `root` (or sudo user)
   - Authentication: Select **"SSH Key"**
   - Upload your SSH private key
4. Click **"Test Connection"** → Should show ✅ Success
5. Click **"Add Target"**

### Install Collector on Target

```bash
# On your target server (192.168.1.100)
sudo mkdir -p /opt/cybersheppard-collector
cd /opt/cybersheppard-collector

# Download collector scripts (replace with your CyberSheppard server IP)
scp user@cybersheppard-server:/opt/cybersheppard/collectors/* .

# Configure
sudo nano config.env
```

Add:
```env
CYBERSHEPPARD_API_URL=https://your-cybersheppard-server
CYBERSHEPPARD_API_KEY=your_api_key_from_ui  # Get from UI: Settings → API Keys
TARGET_ID=1
```

Install systemd service:
```bash
sudo cp cybersheppard-collector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cybersheppard-collector
sudo systemctl start cybersheppard-collector

# Verify
sudo systemctl status cybersheppard-collector
```

Back in the CyberSheppard UI, you should see data flowing within 5 minutes! 📊

---

## 🔒 Apply Hardening (2 minutes)

1. Go to **"Targets"** → Click on `web-01`
2. Click **"Hardening"** tab
3. Select **"ssh_hardening_base"** model
4. Toggle **"Dry Run"** ON (safe first run)
5. Click **"Apply Hardening"**
6. Review changes → Look good?
7. Toggle **"Dry Run"** OFF
8. Click **"Apply Hardening"** again
9. Wait 30-60 seconds for completion ✅

Your server is now hardened! 🛡️

---

## ✅ Verify Everything Works

### Check Dashboard

1. Go to **"Dashboard"**
2. You should see:
   - Total Targets: 1
   - Online Targets: 1
   - Real-time metrics graphs

### Check Compliance

1. Go to **"Compliance"** → **"Rules"**
2. View pre-configured rules
3. Go to **"Violations"**
4. Should be empty (or minor violations if any)

---

## 🔔 Setup Notifications (Optional, 2 minutes)

### Email (Recommended)

1. Go to **"Settings"** → **"Notifications"**
2. Enable **"Email Notifications"**
3. Configure SMTP:
   - Host: `smtp.gmail.com` (or your SMTP server)
   - Port: `587`
   - Username: `your-email@gmail.com`
   - Password: (use App Password for Gmail)
   - From Email: `noreply@cybersheppard.example.com`
4. Add recipients: `["admin@example.com"]`
5. Click **"Test Email"** → Check your inbox
6. Click **"Save"**

### Slack (Quick)

1. Go to https://api.slack.com/messaging/webhooks
2. Create webhook for your channel
3. Copy webhook URL
4. In CyberSheppard: **Settings** → **Notifications** → **Slack**
5. Enable and paste webhook URL
6. Click **"Test Slack"** → Check your Slack channel
7. Click **"Save"**

---

## 🎉 You're Done!

CyberSheppard is now monitoring your server and will alert you of any compliance violations.

---

## 📚 Next Steps

- **Add more targets**: Repeat "Add Target" steps
- **Create custom compliance rules**: Go to Compliance → Rules → New Rule
- **Explore hardening models**: Check out `hardening-models/` directory
- **Setup integrations**: Connect SentinelCore or FireDog
- **Read full docs**:
  - [User Manual](./USER_MANUAL.md)
  - [Admin Guide](./ADMIN_GUIDE.md)
  - [Hardening Models](./HARDENING_MODELS.md)

---

## 🆘 Troubleshooting

### Target shows "Offline"

```bash
# On target server
sudo systemctl status cybersheppard-collector
sudo journalctl -u cybersheppard-collector -f

# Test API connectivity
curl -k https://your-cybersheppard-server/api/health
```

### No data in dashboard

Wait 5 minutes for first data collection. Check:
```bash
# On CyberSheppard server
docker-compose logs -f backend-rust
```

### Services won't start

```bash
# Check all services
docker-compose ps

# View logs
docker-compose logs -f

# Restart
docker-compose restart
```

---

## 📞 Get Help

- **Docs**: https://docs.cybersheppard.io
- **GitHub**: https://github.com/Dognet-Technologies/cybersheppard/issues
- **Email**: support@cybersheppard.io

---

**Happy hardening! 🛡️**
