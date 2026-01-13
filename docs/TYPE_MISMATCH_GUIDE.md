# Guida alla Risoluzione dei Type Mismatch

## Situazione Attuale: 59 Errori Rimanenti

Dopo aver risolto i problemi di schema e configurazione, rimangono **59 errori** di compilazione, principalmente dovuti a **type mismatches** tra i modelli Rust e i tipi del database PostgreSQL.

## Categorie di Problemi

### 1. BigDecimal vs f32/f64 (~ 35 errori)

**Problema**: PostgreSQL usa `NUMERIC` per campi decimali, SQLx li mappa a `BigDecimal`, ma i modelli Rust usano `f32`.

**Campi Interessati**:
- `cvss_score`, `epss_score` (vulnerability scores)
- `score`, `threat_score` (threat/correlation scores)
- `compliance_score`
- `correlation_confidence`
- `duration` (in integration_sync_log)

**Soluzioni Possibili**:

#### Opzione A: Cambiare Modelli per Usare BigDecimal
```rust
use bigdecimal::BigDecimal;

struct SecurityCorrelation {
    vulnerability_cvss: Option<BigDecimal>,  // era f32
    threat_score: BigDecimal,                 // era f32  
    correlation_confidence: Option<BigDecimal>, // era f32
    // ...
}
```

Poi convertire quando serve:
```rust
let score_f32: f32 = correlation.threat_score
    .to_string()
    .parse()
    .unwrap_or(0.0);
```

#### Opzione B: Type Override nelle Query
```rust
sqlx::query!(
    r#"
    SELECT 
        cvss_score as "cvss_score: f32",
        threat_score as "threat_score: f32"
    FROM ...
    "#
)
```

**NOTA**: Opzione B richiede modificare TUTTE le query, mentre Opzione A centralizza il cambiamento.

### 2. IpNetwork vs String (~ 10 errori)

**Problema**: PostgreSQL `INET` viene mappato a `IpNetwork`, ma il codice usa `String`.

**Campi Interessati**:
- `source_ip`, `destination_ip` in firedog_threats
- Vari ip_address fields

**Soluzione Raccomandata**: Usare IpNetwork nei modelli
```rust
use ipnetwork::IpNetwork;

struct FiredogThreat {
    source_ip: IpNetwork,      // era String
    destination_ip: IpNetwork, // era String
    // ...
}
```

Convertire quando serve display:
```rust
let ip_str = threat.source_ip.to_string();
```

### 3. Option<bool> vs bool (~ 8 errori)

**Problema**: Campi `enabled`, `is_active` sono `Option<bool>` nel DB ma `bool` nei modelli.

**Campi Interessati**:
- `IntegrationConfig.enabled` (is_enabled nel DB)
- `ComplianceFramework.enabled`
- `AlertRule.enabled`

**Soluzione**: Modificare i modelli per usare Option<bool> o aggiungere ! nella query:

```rust
// Opzione A: Cambiare modello
struct IntegrationConfig {
    enabled: Option<bool>,  // era bool
}

// Uso: enabled.unwrap_or(false)
```

```rust
// Opzione B: Query override
sqlx::query_as!(
    IntegrationConfig,
    r#"
    SELECT 
        service_name,
        COALESCE(is_enabled, false) as "enabled!"
    FROM integrations_config
    "#
)
```

### 4. Option<T> vs T Generici (~ 6 errori)

**Campi Interessati**:
- `String` vs `Option<String>` (correlation_type, risk_level, etc.)
- `i32` vs `Option<i32>` (vari ID fields)
- `DateTime<Utc>` vs `Option<DateTime<Utc>>` (timestamp fields)

**Soluzione**: Usare `!` suffix nelle query per campi NOT NULL:

```rust
sqlx::query!(
    r#"
    SELECT 
        id as "id!",
        name as "name!",
        created_at as "created_at!"
    FROM table
    "#
)
```

## Piano di Azione Raccomandato

### Step 1: Modifica Modelli Principali (1-2 ore)

File da modificare:
1. `src/services/correlation_engine.rs` - SecurityCorrelation
2. `src/services/integrations.rs` - IntegrationConfig, SentinelVulnerability, FiredogThreat
3. `src/services/compliance_engine.rs` - ComplianceFramework, ComplianceAssessment
4. `src/services/alerting.rs` - AlertRule

Cambiamenti tipo:
- `f32` → `BigDecimal` per score fields
- `String` → `IpNetwork` per IP fields  
- `bool` → `Option<bool>` per enabled fields

### Step 2: Aggiungi Helper per Conversioni

Crea `src/utils/conversions.rs`:
```rust
use bigdecimal::BigDecimal;
use ipnetwork::IpNetwork;

pub trait BigDecimalExt {
    fn to_f32(&self) -> f32;
    fn to_f64(&self) -> f64;
}

impl BigDecimalExt for BigDecimal {
    fn to_f32(&self) -> f32 {
        self.to_string().parse().unwrap_or(0.0)
    }
    
    fn to_f64(&self) -> f64 {
        self.to_string().parse().unwrap_or(0.0)
    }
}

impl BigDecimalExt for Option<BigDecimal> {
    fn to_f32(&self) -> f32 {
        self.as_ref()
            .map(|d| d.to_f32())
            .unwrap_or(0.0)
    }
}

pub trait IpNetworkExt {
    fn to_string_addr(&self) -> String;
}

impl IpNetworkExt for IpNetwork {
    fn to_string_addr(&self) -> String {
        self.ip().to_string()
    }
}
```

### Step 3: Fix Errori Restanti

Dopo le modifiche ai modelli, ricompila:
```bash
cargo sqlx prepare 2>&1 | tee sqlx_errors_v2.log
```

Risolvi gli errori rimanenti uno per uno.

### Step 4: Alternative Rapida (Se Step 1-3 Troppo Lunghi)

Se non vuoi modificare i modelli ora, usa `SQLX_OFFLINE=true`:

```bash
# Nel .env
SQLX_OFFLINE=true

# Compila senza verifiche DB
cargo build
```

**NOTA**: Questo maschera i problemi ma permette di compilare. Gli errori di tipo si manifesteranno a runtime!

## Errori Specifici da Risolvere

### Errore: private_key_path does not exist
✅ **RISOLTO**: Colonna aggiunta a ssh_keys

### Errore: framework_name does not exist  
✅ **RISOLTO**: Colonna aggiunta a compliance_frameworks

### Errore: message does not exist (alerts)
✅ **RISOLTO**: Colonna aggiunta a alerts table

### Errore: frameworks_assessed does not exist
✅ **RISOLTO**: Colonna aggiunta a compliance_assessments

### Errori BigDecimal/IpNetwork
❌ **DA FARE**: Modificare modelli o query (vedi sopra)

### Errori Option<bool>
❌ **DA FARE**: Aggiungere Option o usare COALESCE

## Comandi Utili

```bash
# Conta errori per tipo
grep "^error\[" sqlx_errors.log | sort | uniq -c

# Lista files con più errori
grep "^error.*-->" sqlx_errors.log | awk '{print $3}' | cut -d: -f1 | sort | uniq -c | sort -rn

# Test compilazione specifica
cargo check --message-format=short 2>&1 | grep error

# Ricrea DB con schema aggiornato
sudo -u postgres psql -c "DROP DATABASE IF EXISTS cybersheppard;"
sudo -u postgres psql -c "CREATE DATABASE cybersheppard OWNER vlnman;"
psql -U vlnman -d cybersheppard -f database/postgresql/migrations/001_complete_schema.sql
```

## Risorse

- [SQLx Type Override Docs](https://docs.rs/sqlx/latest/sqlx/macro.query.html#type-overrides)
- [BigDecimal Crate](https://docs.rs/bigdecimal/latest/bigdecimal/)
- [IpNetwork Crate](https://docs.rs/ipnetwork/latest/ipnetwork/)

## Conclusione

Il progetto richiede allineamento significativo tra schema DB e modelli Rust. Le feature SQLx (bigdecimal, ipnetwork) sono state aggiunte, ma i modelli devono essere aggiornati per usare questi tipi correttamente.

**Tempo Stimato**: 2-4 ore per fix completo, oppure 30 minuti per workaround SQLX_OFFLINE.
