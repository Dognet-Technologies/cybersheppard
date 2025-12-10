# MicroSIEM (CyberSheppard) - Code Reuse Map

## 📋 Indice

1. [Overview](#overview)
2. [Codice Riusabile da Sentinel Core](#codice-riusabile-da-sentinel-core)
3. [Codice Riusabile da FireDog](#codice-riusabile-da-firedog)
4. [Componenti da Creare Ex-Novo](#componenti-da-creare-ex-novo)
5. [Strategia di Integrazione](#strategia-di-integrazione)
6. [Mapping File per File](#mapping-file-per-file)

---

## Overview

**Obiettivo**: Massimizzare il riuso di codice esistente da **Sentinel Core** e **FireDog** per accelerare lo sviluppo di **MicroSIEM** ed evitare duplicazioni.

### Principi Guida

1. ✅ **Riusa tutto il possibile** - Non riscrivere codice già funzionante
2. ✅ **Adatta solo dove necessario** - Cambia solo per integrazione con Rust backend
3. ✅ **Mantieni la logica business** - Preserva algoritmi e validazioni esistenti
4. ✅ **Integra via API** - Sentinel Core e FireDog rimangono sistemi separati
5. ✅ **Estrai librerie comuni** - Crea package condivisi per SSH, logging, etc.

---

## Codice Riusabile da Sentinel Core

### 1. API Client (per integrazione)

**File**: Sentinel Core API endpoints (da README.md)

**Riusabile per MicroSIEM**: ✅ 100% via chiamate HTTP

```python
# microsiem/integrations/sentinel_client.py
import requests
from typing import List, Dict, Optional

class SentinelCoreClient:
    """Client per integrazione con Sentinel Core"""
    
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url  # es: http://sentinel-core:8080
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        })
    
    def get_vulnerabilities(self, 
                           severity: Optional[str] = None,
                           asset: Optional[str] = None,
                           limit: int = 100) -> List[Dict]:
        """
        Recupera vulnerabilità da Sentinel Core
        
        GET /api/vulnerabilities/?severity={severity}&asset={asset}&limit={limit}
        """
        params = {'limit': limit}
        if severity:
            params['severity'] = severity
        if asset:
            params['asset'] = asset
        
        response = self.session.get(
            f"{self.base_url}/api/vulnerabilities/",
            params=params,
            timeout=30
        )
        response.raise_for_status()
        return response.json()['results']
    
    def get_vulnerability_by_id(self, vuln_id: int) -> Dict:
        """GET /api/vulnerabilities/{id}/"""
        response = self.session.get(
            f"{self.base_url}/api/vulnerabilities/{vuln_id}/",
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    
    def get_assets(self) -> List[Dict]:
        """GET /api/assets/"""
        response = self.session.get(
            f"{self.base_url}/api/assets/",
            timeout=30
        )
        response.raise_for_status()
        return response.json()['results']
    
    def get_asset_vulnerabilities(self, asset_id: int) -> List[Dict]:
        """GET /api/assets/{id}/vulnerabilities/"""
        response = self.session.get(
            f"{self.base_url}/api/assets/{asset_id}/vulnerabilities/",
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    
    def search_cve(self, cve_id: str) -> Dict:
        """GET /api/vulnerabilities/search/?cve={cve_id}"""
        response = self.session.get(
            f"{self.base_url}/api/vulnerabilities/search/",
            params={'cve': cve_id},
            timeout=30
        )
        response.raise_for_status()
        return response.json()
```

**Endpoints Sentinel Core da Usare**:

| Endpoint | Metodo | Descrizione | Uso in MicroSIEM |
|----------|--------|-------------|------------------|
| `/api/vulnerabilities/` | GET | Lista vulnerabilità | Dashboard correlazioni |
| `/api/vulnerabilities/{id}/` | GET | Dettaglio vulnerabilità | Alert dettagliati |
| `/api/assets/` | GET | Lista asset | Mapping asset ↔ target |
| `/api/assets/{id}/vulnerabilities/` | GET | Vuln per asset | Report sicurezza target |
| `/api/scans/` | GET | Lista scan | Storico scansioni |
| `/api/metrics/` | GET | Metriche sistema | Dashboard integrazioni |

**Database**: NON accedere direttamente al DB Sentinel Core, solo via API

---

### 2. Modelli Dati (per InfluxDB mapping)

**Riusabile**: ✅ Schema concettuale delle vulnerabilità

```python
# microsiem/integrations/sentinel_models.py
from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime

@dataclass
class SentinelVulnerability:
    """Modello per vulnerabilità da Sentinel Core"""
    id: int
    cve_id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score: float
    epss_score: Optional[float]
    asset_id: int
    asset_name: str
    detected_at: datetime
    remediation: Optional[str]
    
    def to_influxdb_point(self, target_ip: str):
        """Converte in punto InfluxDB per correlazioni"""
        return {
            'measurement': 'sentinel_vulnerabilities',
            'tags': {
                'cve_id': self.cve_id,
                'severity': self.severity,
                'asset_name': self.asset_name,
                'target_ip': target_ip
            },
            'fields': {
                'cvss_score': self.cvss_score,
                'epss_score': self.epss_score or 0.0,
                'title': self.title,
                'description': self.description
            },
            'time': self.detected_at
        }
```

---

## Codice Riusabile da FireDog

### 1. SSH Manager (Paramiko) - 🔥 RIUSO TOTALE

**File**: `backend/api/ssh_manager.py`

**Riusabile per MicroSIEM**: ✅ 95% - Adattare solo per integrazione con Rust

```python
# microsiem/hardening_engine/ssh_manager.py
# COPIA DIRETTA da FireDog con modifiche minime

import paramiko
import os
from pathlib import Path
from scp import SCPClient
from typing import Optional, Tuple, Dict
import logging

logger = logging.getLogger(__name__)

class SSHManager:
    """
    Gestione connessioni SSH ai target
    RIUSATO DA FIREDOG - Modificato per MicroSIEM
    """

    def __init__(self, target_ip: str, ssh_port: int = 22, 
                 username: str = "microcyber", timeout: int = 30):
        self.target_ip = target_ip
        self.ssh_port = ssh_port
        self.username = username
        self.timeout = timeout
        self.client = None
        self.scp_client = None

    def connect(self, private_key_path: str) -> bool:
        """Connessione SSH al target"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Carica chiave privata Ed25519
            private_key = paramiko.Ed25519Key.from_private_key_file(
                private_key_path
            )

            self.client.connect(
                hostname=self.target_ip,
                port=self.ssh_port,
                username=self.username,
                pkey=private_key,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
            )

            logger.info(f"SSH connected to {self.target_ip}")
            return True

        except Exception as e:
            logger.error(f"SSH connection failed to {self.target_ip}: {e}")
            return False

    def disconnect(self):
        """Chiudi connessione"""
        if self.scp_client:
            self.scp_client.close()
        if self.client:
            self.client.close()
        logger.info(f"SSH disconnected from {self.target_ip}")

    def execute_command(self, command: str) -> Tuple[int, str, str]:
        """Esegui comando remoto"""
        if not self.client:
            raise Exception("Not connected")

        try:
            stdin, stdout, stderr = self.client.exec_command(
                command, timeout=self.timeout
            )
            exit_code = stdout.channel.recv_exit_status()

            stdout_str = stdout.read().decode("utf-8")
            stderr_str = stderr.read().decode("utf-8")

            return exit_code, stdout_str, stderr_str

        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload file via SCP"""
        if not self.client:
            raise Exception("Not connected")

        try:
            if not self.scp_client:
                self.scp_client = SCPClient(self.client.get_transport())

            self.scp_client.put(local_path, remote_path)
            logger.info(f"Uploaded {local_path} to {self.target_ip}:{remote_path}")
            return True

        except Exception as e:
            logger.error(f"Upload failed: {e}")
            return False

    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download file via SCP"""
        if not self.client:
            raise Exception("Not connected")

        try:
            if not self.scp_client:
                self.scp_client = SCPClient(self.client.get_transport())

            self.scp_client.get(remote_path, local_path)
            logger.info(f"Downloaded {remote_path} from {self.target_ip}")
            return True

        except Exception as e:
            logger.error(f"Download failed: {e}")
            return False

    def upload_directory(self, local_dir: str, remote_dir: str) -> bool:
        """Upload intera directory"""
        if not self.client:
            raise Exception("Not connected")

        try:
            if not self.scp_client:
                self.scp_client = SCPClient(self.client.get_transport())

            self.scp_client.put(local_dir, remote_dir, recursive=True)
            logger.info(f"Uploaded directory {local_dir} to {self.target_ip}:{remote_dir}")
            return True

        except Exception as e:
            logger.error(f"Directory upload failed: {e}")
            return False

    def __enter__(self):
        """Context manager enter"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
```

**Modifiche necessarie**:
- ✅ Rimuovi dipendenze da Django models
- ✅ Passa parametri esplicitamente invece di `target` object
- ✅ Adatta logging per Python standard (non Django)
- ✅ Aggiungi metodi per hardening specifici (upload modelli, apply configs)

---

### 2. FireDog API Client (per integrazione threats)

**File**: FireDog API endpoints (estratti da views.py e urls.py)

**Riusabile per MicroSIEM**: ✅ 100% via chiamate HTTP

```python
# microsiem/integrations/firedog_client.py
import requests
from typing import List, Dict, Optional
from datetime import datetime, timedelta

class FireDogClient:
    """Client per integrazione con FireDog Central"""
    
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url  # es: http://firedog:8000
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        })
    
    def get_threats(self, 
                    target_hostname: Optional[str] = None,
                    severity: Optional[str] = None,
                    hours: int = 24,
                    limit: int = 100) -> List[Dict]:
        """
        Recupera minacce da FireDog
        
        GET /api/threats/?target={hostname}&classification={severity}&limit={limit}
        """
        params = {'limit': limit}
        if target_hostname:
            params['target__hostname'] = target_hostname
        if severity:
            params['classification'] = severity
        
        response = self.session.get(
            f"{self.base_url}/api/threats/",
            params=params,
            timeout=30
        )
        response.raise_for_status()
        return response.json()['results']
    
    def get_threat_summary(self, target_id: int, hours: int = 24) -> Dict:
        """
        GET /api/targets/{id}/threats/summary/?hours={hours}
        """
        response = self.session.get(
            f"{self.base_url}/api/targets/{target_id}/threats/summary/",
            params={'hours': hours},
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    
    def get_target_statistics(self, target_id: int) -> Dict:
        """GET /api/targets/{id}/stats/latest/"""
        response = self.session.get(
            f"{self.base_url}/api/targets/{target_id}/stats/latest/",
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    
    def get_targets(self) -> List[Dict]:
        """GET /api/targets/"""
        response = self.session.get(
            f"{self.base_url}/api/targets/",
            timeout=30
        )
        response.raise_for_status()
        return response.json()['results']
```

**Endpoints FireDog da Usare**:

| Endpoint | Metodo | Descrizione | Uso in MicroSIEM |
|----------|--------|-------------|------------------|
| `/api/threats/` | GET | Lista minacce | Dashboard correlazioni |
| `/api/targets/{id}/threats/summary/` | GET | Summary threats | Alert aggregati |
| `/api/targets/{id}/stats/latest/` | GET | Statistics firewall | Monitoring rete |
| `/api/targets/` | GET | Lista target gestiti | Sincronizzazione |
| `/api/rules/` | GET | Regole firewall | Audit configurazioni |

---

### 3. Modelli FireDog (per InfluxDB)

```python
# microsiem/integrations/firedog_models.py
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class FireDogThreat:
    """Modello per minacce da FireDog"""
    id: int
    target_hostname: str
    target_ip: str
    source_ip: str
    threat_type: str  # PORT_SCAN, SYN_FLOOD, BRUTE_FORCE, etc.
    classification: str  # CRITICAL, HIGH, MEDIUM, LOW
    score: int  # 0-100
    details: str
    detected_at: datetime
    acknowledged: bool
    
    def to_influxdb_point(self):
        """Converte in punto InfluxDB per correlazioni"""
        return {
            'measurement': 'firedog_threats',
            'tags': {
                'target_hostname': self.target_hostname,
                'target_ip': self.target_ip,
                'source_ip': self.source_ip,
                'threat_type': self.threat_type,
                'classification': self.classification
            },
            'fields': {
                'score': self.score,
                'details': self.details,
                'acknowledged': self.acknowledged
            },
            'time': self.detected_at
        }

@dataclass
class FireDogStatistics:
    """Statistiche firewall da FireDog"""
    target_hostname: str
    target_ip: str
    input_packets: int
    output_packets: int
    input_dropped: int
    output_dropped: int
    pcap_input_size: int
    pcap_output_size: int
    collected_at: datetime
    
    def to_influxdb_point(self):
        return {
            'measurement': 'firedog_statistics',
            'tags': {
                'target_hostname': self.target_hostname,
                'target_ip': self.target_ip
            },
            'fields': {
                'input_packets': self.input_packets,
                'output_packets': self.output_packets,
                'input_dropped': self.input_dropped,
                'output_dropped': self.output_dropped,
                'input_drop_rate': (self.input_dropped / self.input_packets * 100) if self.input_packets > 0 else 0.0,
                'output_drop_rate': (self.output_dropped / self.output_packets * 100) if self.output_packets > 0 else 0.0,
                'pcap_input_size': self.pcap_input_size,
                'pcap_output_size': self.pcap_output_size
            },
            'time': self.collected_at
        }
```

---

### 4. Settings & Notifications - 🔥 RIUSO PARZIALE

**File**: `backend/settings/models.py`, `views.py`, `serializers.py`

**Riusabile per MicroSIEM**: ✅ 70% - Adattare per Rust backend

**Cosa riusare**:
- ✅ `SystemSettings` model → Convertire in tabella PostgreSQL MicroSIEM
- ✅ `SSHKey` model → **RIUSO TOTALE** (stesso schema)
- ✅ `NotificationConfig` model → **RIUSO TOTALE**
- ✅ `NotificationLog` model → **RIUSO TOTALE**
- ✅ Password encryption logic (Fernet) → Portare in Rust o mantenere in Python service

**Schema SQL da riusare**:

```sql
-- RIUSATO DA FIREDOG (identico)
CREATE TABLE ssh_keys (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    key_type VARCHAR(20) NOT NULL CHECK (key_type IN ('ed25519', 'rsa', 'ecdsa')),
    key_size INTEGER,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,  -- encrypted
    fingerprint VARCHAR(255) UNIQUE NOT NULL,
    scope VARCHAR(20) DEFAULT 'global' CHECK (scope IN ('global', 'group', 'target')),
    scope_value VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    created_by INTEGER REFERENCES users(id),
    is_active BOOLEAN DEFAULT TRUE,
    last_used_at TIMESTAMP
);

CREATE INDEX idx_ssh_keys_scope ON ssh_keys(scope, scope_value);
CREATE INDEX idx_ssh_keys_fingerprint ON ssh_keys(fingerprint);

-- RIUSATO DA FIREDOG (identico)
CREATE TABLE notification_config (
    id INTEGER PRIMARY KEY DEFAULT 1,  -- Singleton
    email_enabled BOOLEAN DEFAULT FALSE,
    email_recipients JSONB DEFAULT '[]',
    smtp_host VARCHAR(255) DEFAULT 'localhost',
    smtp_port INTEGER DEFAULT 587,
    smtp_user VARCHAR(255) DEFAULT 'microcyber',
    smtp_password VARCHAR(500),  -- encrypted
    smtp_use_tls BOOLEAN DEFAULT TRUE,
    smtp_from_email VARCHAR(255) DEFAULT 'microsiem@localhost',
    slack_enabled BOOLEAN DEFAULT FALSE,
    slack_webhook_url VARCHAR(500),
    discord_enabled BOOLEAN DEFAULT FALSE,
    discord_webhook_url VARCHAR(500),
    alert_on_critical_threat BOOLEAN DEFAULT TRUE,
    alert_on_high_threat BOOLEAN DEFAULT TRUE,
    alert_on_target_offline BOOLEAN DEFAULT TRUE,
    target_offline_threshold_minutes INTEGER DEFAULT 5,
    cooldown_minutes INTEGER DEFAULT 60,
    updated_at TIMESTAMP DEFAULT NOW(),
    updated_by INTEGER REFERENCES users(id),
    
    CONSTRAINT ensure_singleton CHECK (id = 1)
);

-- RIUSATO DA FIREDOG (identico)
CREATE TABLE notification_logs (
    id SERIAL PRIMARY KEY,
    notification_type VARCHAR(20) CHECK (notification_type IN ('email', 'slack', 'discord')),
    alert_type VARCHAR(50),
    target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    recipient VARCHAR(500),
    message TEXT,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    sent_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_notification_logs_alert_type ON notification_logs(alert_type, sent_at);
CREATE INDEX idx_notification_logs_target ON notification_logs(target_id, sent_at);
```

**Codice Python da riusare** (notification sender):

```python
# microsiem/notifications/sender.py
# RIUSATO DA FIREDOG - Backend notification logic

import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)

class NotificationSender:
    """
    Gestore invio notifiche
    RIUSATO DA FIREDOG
    """
    
    def __init__(self, config: Dict):
        """
        config: NotificationConfig da database
        """
        self.config = config
    
    def send_email(self, subject: str, body: str, 
                   recipients: Optional[list] = None) -> bool:
        """Invia email tramite SMTP"""
        
        if not self.config.get('email_enabled'):
            logger.warning("Email notifications disabled")
            return False
        
        recipients = recipients or self.config.get('email_recipients', [])
        
        if not recipients:
            logger.error("No email recipients configured")
            return False
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.config['smtp_from_email']
            msg['To'] = ', '.join(recipients)
            
            # Plain text
            text_part = MIMEText(body, 'plain')
            msg.attach(text_part)
            
            # HTML version (optional)
            html_body = f"<html><body><pre>{body}</pre></body></html>"
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
            
            # Connect and send
            smtp_host = self.config['smtp_host']
            smtp_port = self.config['smtp_port']
            smtp_user = self.config['smtp_user']
            smtp_password = self._decrypt_smtp_password(
                self.config['smtp_password']
            )
            
            if self.config.get('smtp_use_tls'):
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
                server.starttls()
            else:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
            
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            
            server.sendmail(
                self.config['smtp_from_email'],
                recipients,
                msg.as_string()
            )
            server.quit()
            
            logger.info(f"Email sent to {recipients}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    def send_slack(self, message: str, webhook_url: Optional[str] = None) -> bool:
        """Invia notifica Slack"""
        
        if not self.config.get('slack_enabled'):
            logger.warning("Slack notifications disabled")
            return False
        
        webhook_url = webhook_url or self.config.get('slack_webhook_url')
        
        if not webhook_url:
            logger.error("Slack webhook URL not configured")
            return False
        
        try:
            payload = {
                'text': message,
                'username': 'MicroSIEM',
                'icon_emoji': ':shield:'
            }
            
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            
            logger.info("Slack notification sent")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False
    
    def send_discord(self, message: str, webhook_url: Optional[str] = None) -> bool:
        """Invia notifica Discord"""
        
        if not self.config.get('discord_enabled'):
            logger.warning("Discord notifications disabled")
            return False
        
        webhook_url = webhook_url or self.config.get('discord_webhook_url')
        
        if not webhook_url:
            logger.error("Discord webhook URL not configured")
            return False
        
        try:
            payload = {
                'content': message,
                'username': 'MicroSIEM'
            }
            
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            
            logger.info("Discord notification sent")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Discord notification: {e}")
            return False
    
    def _decrypt_smtp_password(self, encrypted_password: str) -> str:
        """Decripta password SMTP (Fernet)"""
        if not encrypted_password or not encrypted_password.startswith('gAAAAAB'):
            return encrypted_password
        
        try:
            from cryptography.fernet import Fernet
            # Usa chiave derivata da SECRET_KEY (da config Rust)
            # TODO: Implementare key derivation
            cipher = Fernet(self._get_encryption_key())
            decrypted = cipher.decrypt(encrypted_password.encode())
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt SMTP password: {e}")
            return ''
    
    def _get_encryption_key(self) -> bytes:
        """Ottiene chiave encryption da configurazione"""
        # TODO: Implementare recupero da Rust backend config
        # Per ora placeholder
        from base64 import urlsafe_b64encode
        key = b'placeholder_secret_key_32bytes!'
        return urlsafe_b64encode(key)
```

---

### 5. WebSocket Log Streaming - 🔥 RIUSO CONCETTUALE

**File**: `backend/firedog/consumers.py`

**Riusabile per MicroSIEM**: ✅ 50% - Logica riusabile, implementazione da adattare

**Cosa riusare**:
- ✅ Pattern di streaming log real-time
- ✅ Autenticazione JWT via query string
- ✅ Logica di tail file e streaming incrementale
- ❌ Channels (specifico Django) → Usare WebSocket Axum in Rust

**Logica da portare in Rust**:

```rust
// microsiem/backend/src/websocket/log_stream.rs
// ISPIRATO DA FIREDOG consumers.py

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
};
use futures::{sink::SinkExt, stream::StreamExt};
use std::path::PathBuf;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use tokio::time::{sleep, Duration};
use serde::Deserialize;

#[derive(Deserialize)]
struct WsQuery {
    token: String,
}

pub async fn log_stream_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    State(app_state): State<AppState>,
) -> impl IntoResponse {
    // Valida JWT token
    match validate_jwt(&query.token) {
        Ok(user_id) => {
            ws.on_upgrade(move |socket| handle_log_stream(socket, app_state))
        }
        Err(_) => {
            // Reject connection
            ws.on_failed_upgrade(|_| async {})
        }
    }
}

async fn handle_log_stream(mut socket: WebSocket, state: AppState) {
    // Send welcome message
    let _ = socket.send(Message::Text(
        serde_json::json!({
            "type": "connection",
            "message": "Connected to log stream"
        }).to_string()
    )).await;
    
    // Log files to monitor
    let log_files = vec![
        ("application", PathBuf::from("/var/log/microsiem/application.log")),
        ("hardening", PathBuf::from("/var/log/microsiem/hardening.log")),
        ("monitoring", PathBuf::from("/var/log/microsiem/monitoring.log")),
    ];
    
    // Track file positions
    let mut file_positions: HashMap<String, u64> = HashMap::new();
    for (source, path) in &log_files {
        if let Ok(file) = File::open(path) {
            if let Ok(metadata) = file.metadata() {
                file_positions.insert(source.to_string(), metadata.len());
            }
        }
    }
    
    // Streaming loop
    loop {
        // Check for client commands
        if let Some(Ok(msg)) = socket.recv().await {
            match msg {
                Message::Text(text) => {
                    if let Ok(cmd) = serde_json::from_str::<Value>(&text) {
                        if cmd["command"] == "pause" {
                            // Pause streaming
                            continue;
                        }
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        
        // Read new lines from each log file
        for (source, path) in &log_files {
            if let Some(pos) = file_positions.get_mut(source) {
                if let Ok(mut file) = File::open(path) {
                    let _ = file.seek(SeekFrom::Start(*pos));
                    let reader = BufReader::new(file);
                    
                    for line in reader.lines() {
                        if let Ok(line_content) = line {
                            let msg = serde_json::json!({
                                "type": "log",
                                "source": source,
                                "message": line_content,
                                "timestamp": chrono::Utc::now().to_rfc3339()
                            });
                            
                            if socket.send(Message::Text(msg.to_string())).await.is_err() {
                                return; // Client disconnected
                            }
                        }
                    }
                    
                    // Update position
                    if let Ok(metadata) = file.metadata() {
                        *pos = metadata.len();
                    }
                }
            }
        }
        
        // Wait before next check
        sleep(Duration::from_millis(500)).await;
    }
}
```

---

## Componenti da Creare Ex-Novo

### 1. Rust Backend API (Axum)

**File**: `microsiem/backend/src/**/*.rs`

**Nuovo al 100%** - Nessun codice riusabile da Sentinel/FireDog

- ✅ API REST con Axum
- ✅ JWT authentication + refresh tokens
- ✅ CSRF protection (Synchronizer Token Pattern)
- ✅ Rate limiting
- ✅ PostgreSQL queries (sqlx)
- ✅ InfluxDB writer
- ✅ WebSocket handlers

---

### 2. Hardening Models & Applier

**File**: `microsiem/hardening_engine/`

**Parzialmente nuovo** - Riusa SSH logic da FireDog

- ✅ Model loader (read file-based models)
- ✅ Model validator
- ✅ Model applier (via SSH) → **RIUSA SSHManager da FireDog**
- ✅ Rollback manager
- ✅ Integrity checker (SHA512)

---

### 3. Monitoring Scripts (Bash on targets)

**File**: `microsiem/target_scripts/`

**Nuovo al 100%** - Specifico per MicroSIEM

- ✅ `monitoring.sh` orchestrator
- ✅ `collectors/auditd.sh`
- ✅ `collectors/sudolog.sh`
- ✅ `collectors/syscalls.sh`
- ✅ `collectors/connections.sh`
- ✅ `collectors/users.sh`
- ✅ `aggregate_json.py`

---

### 4. Frontend React + TypeScript

**File**: `microsiem/frontend/src/**/*.tsx`

**Nuovo al 100%** - Nessun componente riusabile direttamente

Ma **ISPIRATI** da FireDog per:
- ✅ Layout generale
- ✅ Dashboard structure
- ✅ Settings page pattern
- ✅ Notification configuration UI
- ✅ SSH key management UI

---

## Strategia di Integrazione

### Flusso Generale

```
┌──────────────────────────────────────────────────────────┐
│  MicroSIEM (Rust + Axum Backend)                         │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  ┌─────────────────────────────────────────────┐         │
│  │  REST API (Rust/Axum)                       │         │
│  │  - /api/auth/*, /api/targets/*, etc.       │         │
│  └───────────┬─────────────────────────────────┘         │
│              │                                            │
│  ┌───────────▼──────────────┐ ┌───────────────────────┐ │
│  │ PostgreSQL               │ │ InfluxDB              │ │
│  │ (metadata, users, etc.)  │ │ (time-series, logs)   │ │
│  └──────────────────────────┘ └───────────────────────┘ │
│                                                           │
│  ┌───────────────────────────────────────────────┐       │
│  │  Python Hardening Engine (Flask micro-API)   │       │
│  │  → RIUSA SSHManager da FireDog               │       │
│  │  → RIUSA NotificationSender da FireDog       │       │
│  └────┬──────────────────────────────────────────┘       │
│       │ SSH (Ed25519)                                    │
│       ▼                                                  │
│  ┌─────────────────────────────┐                        │
│  │  Target Systems             │                        │
│  │  → Hardening scripts        │                        │
│  │  → Monitoring scripts (NEW) │                        │
│  └─────────────────────────────┘                        │
│                                                           │
│  ┌────────────────────────────────────────────────┐      │
│  │  Integration Clients (Python)                  │      │
│  │  → SentinelCoreClient (HTTP API calls)        │      │
│  │  → FireDogClient (HTTP API calls)             │      │
│  └────┬───────────────────────────────────────────┘      │
│       │                                                  │
│       ├──► Sentinel Core (Port 8080, PostgreSQL)        │
│       └──► FireDog Central (Port 8000, PostgreSQL)      │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

### Punti di Integrazione

1. **Rust Backend ↔ Python Hardening Engine**
   - Comunicazione: HTTP (Flask micro-API su porta locale, es. 5001)
   - Endpoints Python:
     - `POST /apply_hardening` (target_id, model_id)
     - `POST /upload_file` (target_id, local_path, remote_path)
     - `POST /execute_command` (target_id, command)
     - `GET /check_connection` (target_id)

2. **Rust Backend ↔ Sentinel Core**
   - Comunicazione: HTTP REST API
   - Autenticazione: API Key in `X-API-Key` header
   - Rate limiting: 1000 req/hour

3. **Rust Backend ↔ FireDog**
   - Comunicazione: HTTP REST API
   - Autenticazione: API Key in `X-API-Key` header
   - Rate limiting: 1000 req/hour

4. **Python Hardening Engine ↔ Targets**
   - Comunicazione: SSH (Paramiko)
   - Autenticazione: Ed25519 keys
   - Protocol: SCP per file transfer

---

## Mapping File per File

### Codice da FireDog → MicroSIEM

| File FireDog | Riuso | Destinazione MicroSIEM | Note |
|--------------|-------|------------------------|------|
| `backend/api/ssh_manager.py` | ✅ 95% | `hardening_engine/ssh_manager.py` | Rimuovi Django deps |
| `backend/settings/models.py` (SSHKey, NotificationConfig) | ✅ 100% | Schema PostgreSQL MicroSIEM | Stesso schema |
| `backend/settings/views.py` (notification logic) | ✅ 70% | `notifications/sender.py` | Adatta per Rust backend |
| `backend/firedog/consumers.py` | ✅ 50% | `backend/src/websocket/log_stream.rs` | Porta logica in Rust |
| `firedog-package/firewall-manager.py` | ❌ 0% | N/A | Resta su target FireDog |
| `firedog-package/traffic-analyzer.py` | ❌ 0% | N/A | Resta su target FireDog |

### Codice da Sentinel Core → MicroSIEM

| Componente Sentinel | Riuso | Destinazione MicroSIEM | Note |
|---------------------|-------|------------------------|------|
| API endpoints | ✅ 100% | `integrations/sentinel_client.py` | HTTP client |
| Database schema | ❌ 0% | N/A | Non accedere al DB direttamente |
| Vulnerability models | ✅ 50% | `integrations/sentinel_models.py` | Schema concettuale |

### Codice Nuovo per MicroSIEM

| Componente | Linguaggio | File | Priorità |
|------------|-----------|------|----------|
| REST API Backend | Rust | `backend/src/api/**/*.rs` | P0 |
| JWT Auth + CSRF | Rust | `backend/src/middleware/**/*.rs` | P0 |
| Hardening Models Loader | Python | `hardening_engine/model_loader.py` | P0 |
| Hardening Applier | Python | `hardening_engine/applier.py` | P0 |
| Monitoring Scripts | Bash | `target_scripts/monitoring.sh` | P0 |
| Auditd Collector | Bash | `target_scripts/collectors/auditd.sh` | P0 |
| Sudolog Collector | Bash | `target_scripts/collectors/sudolog.sh` | P0 |
| Frontend Dashboard | React/TS | `frontend/src/components/**/*.tsx` | P1 |
| Integration Service | Rust | `backend/src/services/integration_service.rs` | P1 |
| InfluxDB Correlator | Rust | `backend/src/services/correlator.rs` | P2 |

---

## Summary Riuso vs Nuovo

### Percentuali Riuso Codice

| Area | Riuso | Nuovo | Fonte |
|------|-------|-------|-------|
| **SSH Management** | 95% | 5% | FireDog |
| **Notification System** | 80% | 20% | FireDog |
| **Settings Management** | 70% | 30% | FireDog |
| **WebSocket Streaming** | 40% | 60% | FireDog (concept) |
| **Integrations APIs** | 100% | 0% | HTTP calls |
| **Backend REST API** | 0% | 100% | Nuovo Rust |
| **Hardening Engine** | 30% | 70% | Nuovo Python |
| **Monitoring Scripts** | 0% | 100% | Nuovo Bash |
| **Frontend** | 20% | 80% | Nuovo React/TS |

**TOTALE STIMATO**: 
- ✅ **~35% codice riusabile** (SSH, notifications, settings, integrations)
- ❌ **~65% codice nuovo** (Rust backend, hardening, monitoring, frontend)

---

## Conclusioni

### Vantaggi del Riuso

1. ✅ **SSH Manager maturo e testato** (Paramiko da FireDog)
2. ✅ **Notification system completo** (email/Slack/Discord già implementato)
3. ✅ **Settings management UI pattern** (FireDog ha già fatto il lavoro)
4. ✅ **Integrazione via HTTP** (no bisogno di accesso diretto a DB esterni)
5. ✅ **SSH key management** (schema e logica già definiti)

### Aree da Sviluppare Ex-Novo

1. ❌ **Backend Rust completo** (API, auth, middleware, DB access)
2. ❌ **Hardening models system** (file-based, validator, applier)
3. ❌ **Monitoring scripts** (auditd, sudolog, syscalls collectors)
4. ❌ **Frontend dashboard** (React/TS components)
5. ❌ **Correlation engine** (InfluxDB queries per correlazioni)

### Prossimi Passi

1. Estrarre `ssh_manager.py` da FireDog e adattare per MicroSIEM
2. Estrarre `notification_sender.py` e models da FireDog
3. Creare client HTTP per Sentinel Core e FireDog
4. Sviluppare backend Rust con focus su priorità (hardening → monitoring)
5. Implementare monitoring scripts bash per target

---

**Versione**: 1.0.0  
**Data**: 2025-11-28  
**Autore**: Development Team
