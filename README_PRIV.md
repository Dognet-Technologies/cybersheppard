# MicroSIEM - Documentation Index

## 📚 Project Documentation

Questa è la documentazione standardizzata del progetto **MicroSIEM**. La struttura è stata progettata per permettere lo sviluppo modulare su chat separate, mantenendo coerenza e standard comuni.

---

## 🗂️ Struttura Documentazione

### 1. **PROJECT_SPEC.md** - Specifiche di Progetto
**Usa questo documento per:**
- Comprendere l'obiettivo generale del progetto
- Conoscere lo stack tecnologico (Flask+FastAPI, React+TypeScript, InfluxDB, JSON)
- Capire l'architettura ad alto livello
- Vedere la struttura delle directory
- Comprendere i moduli core (Hardening, Monitoring, Checking, Alerting)
- Conoscere i ruoli utente e permessi
- Vedere il roadmap di sviluppo

**Quando referenziarlo in una chat:**
> "Sto lavorando sul frontend. Ho letto PROJECT_SPEC.md e so che usiamo React+TypeScript con TanStack Query. Voglio implementare..."

---

### 2. **ARCHITECTURE.md** - Architettura Dettagliata
**Usa questo documento per:**
- Capire il flusso dei dati tra componenti
- Vedere i diagrammi di architettura
- Comprendere la comunicazione frontend-backend-database-target
- Conoscere la struttura dei moduli backend
- Vedere gli schemi database (PostgreSQL, InfluxDB)
- Capire il sistema di monitoring e collection
- Conoscere la strategia di deployment (Docker)

**Quando referenziarlo in una chat:**
> "Sto implementando il modulo di monitoring. Secondo ARCHITECTURE.md, il flusso è: target esegue cron → genera JSON → server fa SCP → parse → write to InfluxDB. Voglio implementare..."

---

### 3. **API_CONTRACT.md** - Contratto API
**Usa questo documento per:**
- Conoscere tutti gli endpoint disponibili
- Vedere esempi di request/response
- Capire gli schemi JSON
- Implementare chiamate API nel frontend
- Creare nuovi endpoint nel backend
- Vedere gli eventi WebSocket
- Conoscere i codici di errore standard

**Quando referenziarlo in una chat:**
> "Sto creando il componente per aggiungere macchine. Secondo API_CONTRACT.md, devo fare POST /api/machines con questi campi: hostname, ip_address, role, compliance_standard. Il response include suggested_models. Ecco il mio componente..."

---

### 4. **SECURITY.md** - Requisiti di Sicurezza
**Usa questo documento per:**
- Implementare controlli di sicurezza OWASP
- Vedere esempi di codice sicuro
- Evitare vulnerabilità comuni (SQL injection, XSS, CSRF)
- Implementare autenticazione e autorizzazione
- Configurare logging e monitoring
- Vedere le best practices di sicurezza

**Quando referenziarlo in una chat:**
> "Sto implementando il login. Secondo SECURITY.md, devo usare bcrypt con work factor 12, implementare rate limiting (5 tentativi/minuto), e account lockout dopo 5 tentativi. Ecco il mio codice..."

---

## 🎯 Come Usare Questa Documentazione

### Scenario 1: Chat Separata per Frontend
```
[Nuova Chat]
Tu: "Sto lavorando sul frontend di MicroSIEM. Ho caricato PROJECT_SPEC.md, 
ARCHITECTURE.md e API_CONTRACT.md. Voglio implementare la pagina di gestione 
macchine con le seguenti funzionalità..."

Claude: [Userà le info dai documenti per aiutarti nel contesto corretto]
```

### Scenario 2: Chat Separata per Backend
```
[Nuova Chat]
Tu: "Sto lavorando sul backend di MicroSIEM. Ho caricato PROJECT_SPEC.md, 
ARCHITECTURE.md, API_CONTRACT.md e SECURITY.md. Voglio implementare il 
servizio SSH che si connette ai target e applica l'hardening..."

Claude: [Userà le info dai documenti per aiutarti]
```

### Scenario 3: Chat Separata per Moduli Specifici
```
[Nuova Chat]
Tu: "Sto lavorando sul modulo di Hardening di MicroSIEM. Ho caricato 
PROJECT_SPEC.md e ARCHITECTURE.md. Secondo le specifiche, il modulo deve 
validare i modelli, calcolare hash SHA512, e applicare configurazioni via SSH..."

Claude: [Ti aiuta con il contesto specifico del modulo]
```

### Scenario 4: Unire il Lavoro da Chat Diverse
```
Chat Frontend: componenti React completati
Chat Backend: API endpoints completati
Chat Database: schemi e migrations completati
Chat Security: controlli di sicurezza implementati

→ Unisci tutto seguendo la struttura in PROJECT_SPEC.md/directory
→ Testa l'integrazione seguendo ARCHITECTURE.md/data flow
→ Verifica sicurezza seguendo SECURITY.md/checklist
```

---

## 📋 Decisioni Tecniche Chiave

### Stack Tecnologico Definitivo
```yaml
Frontend:
  framework: React 18+
  language: TypeScript 5+
  state: TanStack Query
  http: Axios
  charts: Recharts

Backend:
  frameworks: Flask + FastAPI
  language: Python 3.11+
  ssh: Paramiko
  validation: Pydantic

Database:
  metadata: PostgreSQL 15+
  timeseries: InfluxDB 2.x

Infrastructure:
  webserver: Nginx
  container: Docker + Docker Compose
  os: Debian/Ubuntu

Data Format:
  exchange: JSON (standard unico)

Security:
  auth: JWT
  ssh_keys: Ed25519
  password: bcrypt
  https: TLS 1.3
```

### Perché JSON (non CSV o YAML)
- ✅ Nativo per InfluxDB (API REST)
- ✅ Parsing veloce in Python
- ✅ Supporta strutture nested
- ✅ Standard de-facto per API
- ✅ Debugging più facile

### Perché Flask + FastAPI (non solo uno)
- **Flask**: Auth, admin, operazioni tradizionali
- **FastAPI**: API REST, WebSocket, async operations, docs auto-generate

### Perché InfluxDB (non solo PostgreSQL)
- Time-series ottimizzato
- Retention policies automatiche
- Query veloci su grandi volumi
- Downsampling nativo

---

## 🔄 Workflow di Sviluppo Consigliato

### Fase 1: Setup Iniziale
1. Leggi tutti i documenti per avere overview completo
2. Setup ambiente di sviluppo locale
3. Crea struttura directory come in PROJECT_SPEC.md

### Fase 2: Sviluppo Modulare (Chat Separate)

**Chat 1 - Database Schema**
- Carica: PROJECT_SPEC.md, ARCHITECTURE.md
- Task: Implementa schemi PostgreSQL e InfluxDB
- Output: `database/postgresql/schema.sql`, `database/influxdb/schema.flux`

**Chat 2 - Backend Core**
- Carica: PROJECT_SPEC.md, ARCHITECTURE.md, API_CONTRACT.md, SECURITY.md
- Task: Implementa auth, database connections, base API
- Output: `backend/app/` core files

**Chat 3 - Frontend Core**
- Carica: PROJECT_SPEC.md, ARCHITECTURE.md, API_CONTRACT.md
- Task: Implementa auth UI, routing, layout
- Output: `frontend/src/` core files

**Chat 4 - Modulo Hardening**
- Carica: PROJECT_SPEC.md, ARCHITECTURE.md, SECURITY.md
- Task: Implementa hardening service, model validation
- Output: `modules/hardening/`, API endpoints hardening
- **Nota**: I modelli sono file di configurazione reali in `modules/hardening/models/`
  - Usa naming convention: `etc.ssh.sshd_config` → `/etc/ssh/sshd_config`
  - Ogni modello è una directory (es: `web_nis2/`) con i file di config
  - Vedi PROJECT_SPEC.md sezione "Hardening Models Structure"

**Chat 5 - Modulo Monitoring**
- Carica: PROJECT_SPEC.md, ARCHITECTURE.md
- Task: Implementa data collection, parsing, storage
- Output: `modules/monitoring/`, `target-scripts/`

**Chat 6 - Modulo Checking**
- Carica: PROJECT_SPEC.md, ARCHITECTURE.md
- Task: Implementa compliance checks, security checks
- Output: `modules/checking/`

**Chat 7 - Modulo Alerting**
- Carica: PROJECT_SPEC.md, SECURITY.md
- Task: Implementa email, webhook alerts
- Output: `modules/alerting/`

**Chat 8 - Frontend Dashboard**
- Carica: PROJECT_SPEC.md, ARCHITECTURE.md, API_CONTRACT.md
- Task: Implementa dashboard, charts, real-time updates
- Output: `frontend/src/components/dashboard/`

**Chat 9 - Frontend Machines**
- Carica: PROJECT_SPEC.md, API_CONTRACT.md
- Task: Implementa gestione macchine UI
- Output: `frontend/src/components/machines/`

**Chat 10 - Testing & Security**
- Carica: SECURITY.md, PROJECT_SPEC.md
- Task: Implementa test suite, security checks
- Output: `tests/`, security audit

### Fase 3: Integrazione
1. Unisci tutto il codice seguendo struttura PROJECT_SPEC.md
2. Testa integrazione seguendo flussi in ARCHITECTURE.md
3. Verifica API contract con API_CONTRACT.md
4. Audit sicurezza con SECURITY.md

### Fase 4: Deployment
1. Crea Docker images
2. Setup docker-compose
3. Configure Nginx
4. Deploy e test

---

## 🎨 Convenzioni di Codice

### Python (Backend)
```python
# Naming conventions
- Classes: PascalCase (UserService, MachineModel)
- Functions: snake_case (get_machines, apply_hardening)
- Constants: UPPER_SNAKE_CASE (MAX_RETRIES, API_VERSION)
- Private: _leading_underscore (_validate_token)

# Imports order
1. Standard library
2. Third-party packages
3. Local imports

# Type hints sempre
def get_machine(machine_id: int) -> Machine:
    pass

# Docstrings per funzioni pubbliche
def apply_hardening(machine_id: int, model_id: int) -> dict:
    """
    Apply hardening model to target machine.
    
    Args:
        machine_id: ID of target machine
        model_id: ID of hardening model to apply
        
    Returns:
        dict: Result with success status and details
        
    Raises:
        MachineNotFoundError: If machine doesn't exist
        ModelNotFoundError: If model doesn't exist
    """
```

### TypeScript (Frontend)
```typescript
// Naming conventions
- Interfaces: PascalCase with I prefix (IMachine, IUser)
- Types: PascalCase (Machine, ApiResponse)
- Components: PascalCase (MachineList, LoginForm)
- Functions: camelCase (getMachines, handleSubmit)
- Constants: UPPER_SNAKE_CASE (API_BASE_URL)

// File naming
- Components: PascalCase.tsx (MachineList.tsx)
- Hooks: camelCase.ts (useMachines.ts)
- Utils: camelCase.ts (validators.ts)
- Types: camelCase.types.ts (machine.types.ts)

// Always export types
export interface IMachine {
  id: number;
  hostname: string;
  ip_address: string;
  role: string;
}

// Props interface for components
interface MachineCardProps {
  machine: IMachine;
  onDelete: (id: number) => void;
}
```

### SQL (Database)
```sql
-- Table names: lowercase, plural
machines, users, hardening_models

-- Column names: snake_case
created_at, ip_address, last_seen

-- Always include timestamps
created_at TIMESTAMP DEFAULT NOW()
updated_at TIMESTAMP DEFAULT NOW()

-- Foreign keys explicit
CONSTRAINT fk_machine_user 
  FOREIGN KEY (user_id) REFERENCES users(id)
```

---

## ✅ Checklist Finale

Prima di considerare un modulo completo:

### Backend
- [ ] Tutti gli endpoint in API_CONTRACT.md implementati
- [ ] Input validation con Pydantic
- [ ] Error handling appropriato
- [ ] Logging configurato
- [ ] Test unitari scritti
- [ ] Controlli sicurezza OWASP implementati
- [ ] Documentazione API aggiornata

### Frontend
- [ ] Tutti i componenti UI completati
- [ ] Chiamate API corrette secondo API_CONTRACT.md
- [ ] Error handling e loading states
- [ ] TypeScript strict mode senza errori
- [ ] Responsive design
- [ ] Accessibilità (a11y) considerata

### Moduli
- [ ] Interfaccia chiara e documentata
- [ ] Testato isolatamente
- [ ] Integrato con il sistema
- [ ] Performance accettabile
- [ ] Logging appropriato
- [ ] Error handling robusto

### Security
- [ ] OWASP Top 10 mitigations implementate
- [ ] Input validation ovunque
- [ ] Output encoding
- [ ] Authentication e authorization
- [ ] Audit logging
- [ ] Security headers configurati

---

## 📞 Come Chiedere Aiuto in Chat

### ✅ BUONO
```
"Sto lavorando sul modulo di monitoring di MicroSIEM. Ho caricato 
PROJECT_SPEC.md e ARCHITECTURE.md. Secondo le specifiche, devo 
implementare il parser JSON che legge i file da /tmp/microsiem_*.json 
e scrive su InfluxDB. Il formato JSON è definito in PROJECT_SPEC.md 
pagina X. Ho scritto questo codice [codice], ma ho questo problema..."
```

### ❌ CATTIVO
```
"Come faccio a parsare JSON in Python?"
```

### ✅ BUONO
```
"Sto implementando l'endpoint POST /api/machines secondo API_CONTRACT.md.
La richiesta deve validare hostname con regex RFC 1123. Ho implementato 
questo validator Pydantic [codice], ma vorrei anche verificare che 
l'hostname non esista già nel database. Come posso..."
```

### ❌ CATTIVO
```
"Come faccio un endpoint Flask?"
```

---

## 🚀 Prossimi Passi

1. **Ora**: Hai la documentazione completa
2. **Prossimo**: Decidi da quale modulo iniziare
3. **Poi**: Apri una chat dedicata a quel modulo
4. **Infine**: Carica i documenti pertinenti e inizia a sviluppare

**Ricorda**: La documentazione è viva. Quando fai modifiche significative, 
aggiorna i documenti per mantenere la coerenza tra le chat.

---

## 📚 Risorse Aggiuntive

### Per Frontend
- React Docs: https://react.dev
- TypeScript Docs: https://www.typescriptlang.org/docs/
- TanStack Query: https://tanstack.com/query/latest
- Recharts: https://recharts.org

### Per Backend
- Flask: https://flask.palletsprojects.com/
- FastAPI: https://fastapi.tiangolo.com/
- Pydantic: https://docs.pydantic.dev/
- Paramiko: https://www.paramiko.org/

### Per Database
- PostgreSQL: https://www.postgresql.org/docs/
- InfluxDB: https://docs.influxdata.com/
- SQLAlchemy: https://www.sqlalchemy.org/

### Per Security
- OWASP: https://owasp.org/
- NIST: https://www.nist.gov/cyberframework

---

**Buon lavoro con MicroSIEM! 🚀**

**Versione Documentazione**: 1.0.0  
**Ultimo Aggiornamento**: 2025-10-30
