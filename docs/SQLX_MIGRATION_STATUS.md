# SQLx Migration Status

## ✅ Completato

1. **Feature SQLx aggiunte** - bigdecimal e ipnetwork
2. **Directory migrations creata** - symlink a database/postgresql/migrations
3. **Schema aggiornato** con colonne mancanti:
   - `targets.is_active`
   - `refresh_tokens.token`
   - `csrf_tokens.token`
   - `compliance_violations.alert_generated`
   - `compliance_violations.alert_id`

4. **Correzioni codice**:
   - `hardening.rs`: Query SSH info ora usa JOIN con ssh_keys
   - `websocket.rs`: Query audit_logs usa resource_type invece di resource
   - `auth.rs`: Fix Option<bool> unwrap per is_active

## ⚠️ Problemi Rimanenti (~ 90 errori)

### 1. Token vs Token_Hash
Il codice cerca colonna `token` ma lo schema ha `token_hash`.
**Soluzione**: Le colonne `token` sono state aggiunte per compatibilità.

### 2. Tipi NUMERIC e INET
Molti campi NUMERIC ritornano `Option<()>` invece di valori corretti.
**Causa**: Problema di type mapping SQLx con bigdecimal.
**Fix necessario**: Verificare che bigdecimal sia correttamente configurato.

### 3. Option<T> Mismatches
Molti campi sono `Option<T>` nel DB ma usati come `T` nel codice.
**Fix necessario**: Aggiungere `.unwrap_or()` o `.unwrap_or_default()`.

### 4. Nomi Colonne
- `compliance_frameworks.framework_name` → usare `name` o `display_name`
- `alerts.message` → usare `description`
- Vari altri alias necessari

## 📋 Prossimi Passi

### Step 1: Ricrea Database
```bash
# IMPORTANTE: Lo schema è stato aggiornato
sudo -u postgres psql
DROP DATABASE cybersheppard;
CREATE DATABASE cybersheppard OWNER vlnman;
\q

# Applica migrazione aggiornata
psql -U vlnman -d cybersheppard -f database/postgresql/migrations/001_complete_schema.sql
```

### Step 2: Testa SQLx Prepare
```bash
cd backend-rust
cargo sqlx prepare 2>&1 | tee sqlx_errors.log
```

### Step 3: Risolvi Errori Rimanenti
Consulta il log degli errori e sistema:
- Type mismatches (Option<T>)
- Alias colonne mancanti
- Problemi bigdecimal/ipnetwork

## 📝 Note
- Features bigdecimal/ipnetwork **sono state aggiunte** a Cargo.toml
- Alcuni problemi richiedono modifiche manuali al codice
- Lo schema consolidato include tutte le tabelle necessarie
