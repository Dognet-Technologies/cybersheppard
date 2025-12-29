# 🚀 CyberSheppard - Guida Avvio Rapido

## Prerequisiti
- PostgreSQL in esecuzione (porta 5432)
- InfluxDB in esecuzione (porta 8086)
- Rust toolchain installato
- Node.js + npm installati

---

## 🗄️ Setup Database (PRIMA VOLTA)

### 1. Installa PostgreSQL e InfluxDB (se non già installati)

```bash
# Linux Mint / Ubuntu / Debian
sudo apt update
sudo apt install postgresql postgresql-contrib influxdb2
```

### 2. Crea database e utente PostgreSQL

```bash
# Avvia PostgreSQL (se non già in esecuzione)
sudo systemctl start postgresql
sudo systemctl enable postgresql  # Avvio automatico al boot

# Crea database e utente
sudo -u postgres psql -c "CREATE DATABASE cybersheppard;"
sudo -u postgres psql -c "CREATE USER cybersheppard WITH PASSWORD 'your_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE cybersheppard TO cybersheppard;"

# Verifica
sudo -u postgres psql -c "\l" | grep cybersheppard
```

### 3. Avvia InfluxDB

```bash
# Avvia InfluxDB
sudo systemctl start influxdb
sudo systemctl enable influxdb  # Avvio automatico al boot

# Verifica che sia in esecuzione
curl http://localhost:8086/health
```

### 4. Configura .env
```bash
# Copia e modifica con le credenziali scelte sopra
cp .env.example .env
nano .env  # Modifica POSTGRES_PASSWORD, INFLUXDB_TOKEN, ecc.
```

### 5. Applica migrazioni PostgreSQL

**IMPORTANTE:** Se hai già un database con migrazioni vecchie, ricrealo da zero:
```bash
# Drop e ricrea database (ATTENZIONE: cancella tutti i dati!)
sudo -u postgres psql -c "DROP DATABASE IF EXISTS cybersheppard;"
sudo -u postgres psql -c "CREATE DATABASE cybersheppard;"
sudo -u postgres psql -c "ALTER DATABASE cybersheppard OWNER TO vlnman;"
sudo -u postgres psql cybersheppard -c "GRANT ALL ON SCHEMA public TO vlnman;"
```

Poi applica le migrazioni:
```bash
cd database/postgresql
./apply_migrations.sh
cd ../..
```

### 6. Prepara SQLx (solo prima volta)
```bash
cd backend-rust
cargo sqlx prepare
cd ..
```

### 7. Configura InfluxDB (prima volta)
```bash
# Apri http://localhost:8086 nel browser
# Crea organizzazione: "cybersheppard"
# Crea bucket: "metrics", "logs", "correlations"
# Copia il token generato in .env (INFLUXDB_TOKEN)
```

---

## ▶️ Avvio Sviluppo

### 1. Backend Rust (API principale)
```bash
cd backend-rust
cargo run
# In ascolto su http://localhost:8080
```

### 2. Frontend React
```bash
cd frontend-react
npm install    # Solo prima volta
npm run dev
# In ascolto su http://localhost:5173
```

### 3. Backend Django (Hardening Engine - OPZIONALE)
```bash
cd backend-django
# Crea virtualenv se non esiste
python -m venv venv
source venv/bin/activate  # Linux/Mac
# oppure: venv\Scripts\activate  # Windows

pip install -r requirements.txt  # Solo prima volta
python manage.py migrate         # Solo prima volta
python manage.py runserver 8001
# In ascolto su http://localhost:8001
```

---

## 🧪 Test Rapido

1. Apri browser su http://localhost:5173
2. Registra primo utente (sarà admin automaticamente)
3. Login con le credenziali

---

## 🔧 Comandi Utili

### Rust
```bash
cargo build              # Compila
cargo run                # Compila + avvia
cargo test               # Test
cargo clean              # Pulisci build
```

### Frontend
```bash
npm run dev              # Sviluppo
npm run build            # Build produzione
npm run preview          # Preview build
```

### Database
```bash
# Reset completo DB (ATTENZIONE: cancella tutto!)
cd database/postgresql
psql -U cybersheppard -d postgres -c "DROP DATABASE IF EXISTS cybersheppard;"
psql -U cybersheppard -d postgres -c "CREATE DATABASE cybersheppard;"
./apply_migrations.sh
```

---

## 📝 Note

- Il backend Rust DEVE essere avviato prima del frontend
- Il primo utente registrato diventa automaticamente admin
- Le credenziali DB sono in `.env` (copia da `.env.example`)
- InfluxDB serve per le metriche/logs in tempo reale
- Django backend è opzionale, serve solo per hardening automation

---

## 🐛 Troubleshooting

### "Connection refused" su PostgreSQL
```bash
# Verifica che PostgreSQL sia in esecuzione
sudo systemctl status postgresql
# oppure
pg_isready
```

### "sqlx prepare failed" su Rust
```bash
cd backend-rust
# Assicurati che DB sia up e migrazioni applicate
cargo sqlx prepare --database-url "postgresql://user:pass@localhost/cybersheppard"
```

### "Port already in use"
```bash
# Trova processo sulla porta 8080
lsof -i :8080
# Termina processo
kill -9 <PID>
```
