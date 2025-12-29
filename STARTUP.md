# 🚀 CyberSheppard - Guida Avvio Rapido

## Prerequisiti
- PostgreSQL in esecuzione (porta 5432)
- InfluxDB in esecuzione (porta 8086)
- Rust toolchain installato
- Node.js + npm installati

---

## 🗄️ Setup Database (PRIMA VOLTA)

```bash
# 1. Copia e configura .env
cp .env.example .env
# Modifica .env con le tue credenziali DB

# 2. Applica migrazioni PostgreSQL
cd database/postgresql
./apply_migrations.sh
cd ../..

# 3. Prepara SQLx (solo prima volta)
cd backend-rust
cargo sqlx prepare
cd ..
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
