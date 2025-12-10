# CyberSheppard - Target Monitoring Scripts

Bash scripts per il monitoring di sistemi Linux usando **solo comandi nativi** (auditd, netstat, lsof, pidof, ps, etc).

## 📋 Collectors Disponibili

### 1. **system_metrics.sh** - Metriche di Sistema
Raccoglie metriche di sistema usando comandi nativi:
- **CPU**: top, uptime, nproc
- **Memoria**: /proc/meminfo
- **Disco**: df
- **Rete**: /sys/class/net/*/statistics

**Output JSON**: CPU usage, load average, memoria, swap, filesystem, interfacce di rete

### 2. **auditd_collector.sh** - Log Auditd
Raccoglie eventi da auditd usando ausearch e aureport:
- **File Access**: Eventi PATH
- **Syscalls**: Eventi SYSCALL
- **Autenticazione**: USER_AUTH, USER_LOGIN
- **Esecuzione Programmi**: EXECVE
- **Statistiche Audit**: auditctl -s

**Requisito**: auditd deve essere installato e configurato con le regole appropriate

### 3. **sudo_collector.sh** - Log Sudo
Raccoglie comandi sudo eseguiti:
- Supporta **journalctl** (systemd)
- Supporta **/var/log/auth.log** (Debian/Ubuntu)
- Supporta **/var/log/secure** (RHEL/CentOS)
- Statistiche: totale comandi, tentativi falliti, utenti unici

**Output JSON**: Lista comandi sudo con user, comando, pwd, timestamp

### 4. **network_monitor.sh** - Monitoring Rete
Monitora connessioni di rete e porte:
- **Porte in ascolto**: ss o netstat
- **Connessioni attive**: socket ESTABLISHED
- **File aperti**: lsof -i
- **Statistiche**: connessioni per stato, IP unici

**Comandi usati**: ss, netstat, lsof

### 5. **process_monitor.sh** - Monitoring Processi
Monitora processi in esecuzione:
- **Top CPU**: Top 10 processi per utilizzo CPU
- **Top Memoria**: Top 10 processi per utilizzo RAM
- **Statistiche**: totale, running, sleeping, zombie, stopped
- **Servizi Critici**: sshd, cron, rsyslog, auditd (con pidof)

**Comandi usati**: ps, pidof, /proc

## 🚀 Installazione

### Installazione Automatica
```bash
# Su ogni target Linux
sudo ./install.sh \
  --api-url http://cybersheppard-backend:8080 \
  --api-key "your-api-key" \
  --target-id 1
```

Lo script di installazione:
1. Crea directory `/opt/cybersheppard`
2. Copia tutti i collectors
3. Crea configurazione in `/etc/cybersheppard/config.conf`
4. Crea servizio systemd `cybersheppard-collector`
5. Abilita e avvia il servizio

### Installazione Manuale
```bash
# Crea directories
sudo mkdir -p /opt/cybersheppard/collectors
sudo mkdir -p /etc/cybersheppard
sudo mkdir -p /var/log/cybersheppard

# Copia scripts
sudo cp cybersheppard-collector.sh /opt/cybersheppard/
sudo cp collectors/*.sh /opt/cybersheppard/collectors/
sudo chmod +x /opt/cybersheppard/*.sh
sudo chmod +x /opt/cybersheppard/collectors/*.sh

# Configura
sudo cp config/cybersheppard.conf.example /etc/cybersheppard/config.conf
sudo nano /etc/cybersheppard/config.conf  # Modifica con i tuoi parametri
```

## ⚙️ Configurazione

File: `/etc/cybersheppard/config.conf`

```bash
# Backend API
CYBERSHEPPARD_API_URL="http://backend:8080"
CYBERSHEPPARD_API_KEY="your-api-key"
CYBERSHEPPARD_TARGET_ID="1"

# Intervallo raccolta (secondi)
INTERVAL=30

# Verbose logging
VERBOSE=false
```

## 🎯 Utilizzo

### Come Servizio Systemd
```bash
# Status
sudo systemctl status cybersheppard-collector

# Start/Stop
sudo systemctl start cybersheppard-collector
sudo systemctl stop cybersheppard-collector

# Restart
sudo systemctl restart cybersheppard-collector

# Logs
sudo journalctl -u cybersheppard-collector -f
```

### Esecuzione Manuale
```bash
# Esecuzione singola (oneshot)
/opt/cybersheppard/cybersheppard-collector.sh --oneshot --verbose

# Loop continuo
/opt/cybersheppard/cybersheppard-collector.sh --interval 30 --verbose

# Test singolo collector
/opt/cybersheppard/collectors/system_metrics.sh
/opt/cybersheppard/collectors/auditd_collector.sh
```

## 📊 Formato Output

Tutti i collectors producono output in formato JSON:

```json
{
  "target_id": "1",
  "timestamp": "2025-11-30T15:00:00Z",
  "data": {
    "system_metrics": {
      "type": "system_metrics",
      "hostname": "target-server",
      "metrics": {
        "cpu": { "user": 5.2, "system": 2.1, "load1": 0.5 },
        "memory": { "total": 16777216, "used": 8388608, "used_percent": 50.0 },
        "disk": { "filesystems": [...] },
        "network": { "interfaces": [...] }
      }
    },
    "auditd": { ... },
    "sudo": { ... },
    "network": { ... },
    "processes": { ... }
  }
}
```

## 🔒 Requisiti Auditd

Per il monitoring completo via auditd, le regole devono essere configurate. Esempi:

```bash
# File system monitoring
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers

# Network monitoring
-a always,exit -F arch=b64 -S socket -S connect -S bind -k network

# Process execution
-a always,exit -F arch=b64 -S execve -k exec

# Apply rules
sudo auditctl -R /etc/audit/rules.d/cybersheppard.rules
```

Queste regole vengono applicate automaticamente tramite i modelli di hardening di CyberSheppard.

## 📝 Note Tecniche

### Comandi Nativi Utilizzati
- `top`, `uptime`, `nproc` - CPU metrics
- `/proc/meminfo` - Memoria
- `df` - Disk usage
- `/sys/class/net` - Network interfaces
- `ausearch`, `aureport`, `auditctl` - Auditd
- `journalctl` - Systemd logs
- `ss`, `netstat` - Network connections
- `lsof` - Open files
- `ps`, `pidof` - Processes
- `grep`, `awk`, `sed` - Text processing

### Compatibilità
- ✅ Debian/Ubuntu (apt, auth.log)
- ✅ RHEL/CentOS/Rocky (yum/dnf, secure)
- ✅ Systemd e SysVinit
- ✅ IPv4 e IPv6

### Performance
- **Overhead minimo**: ~1-2% CPU durante la raccolta
- **Memoria**: <10MB
- **Intervallo consigliato**: 30-60 secondi

## 🐛 Troubleshooting

### Servizio non si avvia
```bash
# Check logs
sudo journalctl -u cybersheppard-collector -n 50

# Check permissions
ls -l /opt/cybersheppard/
ls -l /etc/cybersheppard/

# Test manuale
sudo /opt/cybersheppard/cybersheppard-collector.sh --oneshot --verbose
```

### Auditd non raccoglie dati
```bash
# Verifica auditd è attivo
sudo systemctl status auditd

# Verifica regole
sudo auditctl -l

# Test ausearch
sudo ausearch -ts recent
```

### Dati non arrivano al backend
```bash
# Test connessione
curl -I http://backend:8080/health

# Check backup files (retry automatico)
ls -lh /var/log/cybersheppard/failed_*.json

# Test invio manuale
curl -X POST \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d @/var/log/cybersheppard/failed_xxx.json \
  http://backend:8080/api/monitoring/data
```

## 📚 Vedi Anche

- [Hardening Models](../hardening-models/) - Template di configurazione
- [Backend API](../backend-rust/README.md) - API Rust Axum
- [Django Hardening](../backend-django/README.md) - Engine di hardening
