# CyberSheppard - User Roles & Permissions

## Overview

CyberSheppard utilizza un sistema di ruoli semplificato con **3 ruoli** per mantenere la gestione degli accessi chiara e intuitiva.

## Ruoli

### 1. Admin (Amministratore)

**Accesso completo al sistema**

Può gestire:
- ✅ Tutti gli utenti e i ruoli
- ✅ Tutte le impostazioni di sistema
- ✅ Installazione/rimozione plugin
- ✅ Tutte le configurazioni
- ✅ Tutti i dati e report
- ✅ Log di audit completi

**Casi d'uso:**
- System administrator
- Security architect
- DevOps/Infrastructure team

### 2. Team Leader

**Gestione del team e delle risorse**

Può gestire:
- ✅ Membri del proprio team
- ✅ Target e asset del team
- ✅ Scan e vulnerability assessment
- ✅ Alert e notifiche del team
- ✅ Report del team
- ✅ Configurazione plugin (non installazione)
- ✅ Integrazioni e connettori
- ✅ API keys del team
- ✅ Log di audit del team
- ❌ Impostazioni di sistema
- ❌ Installazione/rimozione plugin

**Casi d'uso:**
- Team security leader
- SOC manager
- Senior security analyst

### 3. User (Utente)

**Accesso operativo base**

Può:
- ✅ Visualizzare dashboard
- ✅ Visualizzare target e asset
- ✅ Eseguire scan
- ✅ Visualizzare vulnerabilità
- ✅ Visualizzare alert
- ✅ Generare report personali
- ✅ Gestire proprie API keys
- ✅ Modificare impostazioni personali
- ❌ Creare/modificare/eliminare risorse
- ❌ Gestire utenti
- ❌ Accedere a impostazioni di sistema
- ❌ Gestire plugin

**Casi d'uso:**
- Security analyst
- Junior analyst
- External consultant (read-only)

## Matrice Completa dei Permessi

| Funzionalità | Admin | Team Leader | User |
|--------------|-------|-------------|------|
| **Dashboard** |
| Visualizzare | ✅ | ✅ | ✅ |
| Personalizzare | ✅ | ✅ | ✅ |
| **Targets/Assets** |
| Visualizzare | ✅ | ✅ | ✅ |
| Creare | ✅ | ✅ | ❌ |
| Modificare | ✅ | ✅ (team) | ❌ |
| Eliminare | ✅ | ✅ (team) | ❌ |
| **Scan** |
| Visualizzare | ✅ | ✅ | ✅ |
| Eseguire | ✅ | ✅ | ✅ |
| Schedulare | ✅ | ✅ | ❌ |
| Modificare | ✅ | ✅ (team) | ❌ |
| Eliminare | ✅ | ✅ (team) | ❌ |
| **Vulnerabilità** |
| Visualizzare | ✅ | ✅ | ✅ |
| Modificare stato | ✅ | ✅ (team) | ❌ |
| Assegnare | ✅ | ✅ (team) | ❌ |
| **Alert** |
| Visualizzare | ✅ | ✅ | ✅ |
| Creare regole | ✅ | ✅ | ❌ |
| Modificare regole | ✅ | ✅ (team) | ❌ |
| Eliminare regole | ✅ | ✅ (team) | ❌ |
| **Report** |
| Visualizzare propri | ✅ | ✅ | ✅ |
| Visualizzare team | ✅ | ✅ | ❌ |
| Visualizzare tutti | ✅ | ❌ | ❌ |
| Generare | ✅ | ✅ | ✅ |
| Schedulare | ✅ | ✅ | ❌ |
| **Plugin** |
| Visualizzare | ✅ | ✅ | ✅ |
| Installare | ✅ | ❌ | ❌ |
| Rimuovere | ✅ | ❌ | ❌ |
| Configurare | ✅ | ✅ | ❌ |
| Abilitare/Disabilitare | ✅ | ✅ | ❌ |
| **Integrazioni** |
| Visualizzare | ✅ | ✅ | ✅ |
| Creare | ✅ | ✅ | ❌ |
| Configurare | ✅ | ✅ | ❌ |
| Eliminare | ✅ | ✅ | ❌ |
| **Impostazioni Sistema** |
| Visualizzare | ✅ | ❌ | ❌ |
| Modificare | ✅ | ❌ | ❌ |
| **Impostazioni Utente** |
| Proprie | ✅ | ✅ | ✅ |
| Team | ✅ | ✅ | ❌ |
| Tutti | ✅ | ❌ | ❌ |
| **User Management** |
| Visualizzare tutti | ✅ | ❌ | ❌ |
| Visualizzare team | ✅ | ✅ | ❌ |
| Creare utenti | ✅ | ✅ (team) | ❌ |
| Modificare utenti | ✅ | ✅ (team) | ❌ |
| Eliminare utenti | ✅ | ✅ (team) | ❌ |
| Cambiare ruoli | ✅ | ❌ | ❌ |
| **API Keys** |
| Proprie | ✅ | ✅ | ✅ |
| Team | ✅ | ✅ | ❌ |
| Tutte | ✅ | ❌ | ❌ |
| **Audit Logs** |
| Visualizzare propri | ✅ | ✅ | ❌ |
| Visualizzare team | ✅ | ✅ | ❌ |
| Visualizzare tutti | ✅ | ❌ | ❌ |

## Gestione Team

### Assegnazione Team

Gli utenti possono essere assegnati a un team tramite `team_id`:

```sql
-- Assegna utente a team
UPDATE users SET team_id = 1 WHERE id = 5;

-- Assegna team leader come manager
UPDATE users SET managed_by = 3 WHERE id = 5;
```

### Gerarchie Team

```
Admin (ID: 1)
├─ Team Leader (ID: 2, team_id: 1)
│  ├─ User (ID: 4, team_id: 1, managed_by: 2)
│  └─ User (ID: 5, team_id: 1, managed_by: 2)
└─ Team Leader (ID: 3, team_id: 2)
   ├─ User (ID: 6, team_id: 2, managed_by: 3)
   └─ User (ID: 7, team_id: 2, managed_by: 3)
```

### Query Team

```sql
-- Visualizza gerarchia team
SELECT * FROM user_hierarchy WHERE team_id = 1;

-- Ottieni membri team di un team leader
SELECT * FROM users WHERE managed_by = 2;

-- Conta utenti per team
SELECT team_id, COUNT(*) as members
FROM users
WHERE team_id IS NOT NULL
GROUP BY team_id;
```

## Implementazione Backend

### Check Permessi (Rust)

```rust
use crate::middleware::permissions::Permissions;

// Richiede admin
if !Permissions::is_admin(&auth_user) {
    return Err(StatusCode::FORBIDDEN);
}

// Richiede admin o team leader
if !Permissions::is_admin_or_team_leader(&auth_user) {
    return Err(StatusCode::FORBIDDEN);
}

// Check permessi specifici
if !Permissions::can_manage_plugins(&auth_user) {
    return Err(StatusCode::FORBIDDEN);
}
```

### Middleware

```rust
use crate::middleware::permissions::{require_admin, require_admin_or_team_leader};

// Route solo admin
.route("/settings/system", get(get_system_settings))
.layer(middleware::from_fn(require_admin))

// Route admin o team leader
.route("/users", get(list_users))
.layer(middleware::from_fn(require_admin_or_team_leader))
```

## Implementazione Frontend

### Check Permessi (TypeScript)

```typescript
import { Permissions, usePermissions } from '@/utils/permissions';

// In un componente
function PluginManager() {
  const { user } = useAuth();
  const permissions = usePermissions(user.role);

  return (
    <div>
      {permissions.canManagePlugins && (
        <button onClick={installPlugin}>Install Plugin</button>
      )}

      {permissions.canConfigurePlugins && (
        <button onClick={configurePlugin}>Configure</button>
      )}

      {permissions.canViewPlugins && (
        <PluginList />
      )}
    </div>
  );
}
```

### Protected Routes

```typescript
import { withPermission, Permissions } from '@/utils/permissions';

// Component protetto - solo admin
const SettingsPage = withPermission(
  SettingsComponent,
  (role) => Permissions.canManageSystemSettings(role)
);

// Component protetto - admin o team leader
const UserManagementPage = withPermission(
  UserManagementComponent,
  (role) => Permissions.canManageUsers(role)
);
```

### Conditional Rendering

```typescript
{user.role === 'admin' && (
  <AdminPanel />
)}

{(user.role === 'admin' || user.role === 'teamLeader') && (
  <TeamManagementPanel />
)}
```

## Best Practices

### 1. Principle of Least Privilege
Assegna sempre il ruolo minimo necessario per le responsabilità dell'utente.

### 2. Team Organization
Organizza utenti in team per semplificare la gestione dei permessi.

### 3. Regular Audits
Rivedi periodicamente i ruoli e i permessi degli utenti.

### 4. Separation of Duties
Admin non dovrebbe eseguire operazioni quotidiane - crea team leader per questo.

### 5. API Key Security
- Admin: chiavi master per integrazione sistema
- Team Leader: chiavi per integrazioni team
- User: chiavi per script personali

## Esempi d'uso

### Scenario 1: SOC Team

```
Admin (Security Director)
├─ Team Leader (SOC Manager)
│  ├─ User (Senior Analyst)
│  ├─ User (Junior Analyst)
│  └─ User (Analyst)
└─ Team Leader (Incident Response Lead)
   ├─ User (IR Analyst)
   └─ User (Forensics Analyst)
```

### Scenario 2: Multi-Team Organization

```
Admin (CISO)
├─ Team Leader (Infrastructure Security)
│  └─ Users (Infrastructure team)
├─ Team Leader (Application Security)
│  └─ Users (AppSec team)
└─ Team Leader (Compliance)
   └─ Users (Compliance team)
```

## Migration da Sistemi Precedenti

Se hai un sistema con più ruoli, la migration è automatica:

```sql
-- Migration automatica (già in 009_simplify_roles.sql)
admin/administrator/root        → admin
manager/supervisor/lead         → teamLeader
analyst/operator/viewer/user    → user
```

## FAQ

**Q: Posso avere più di 3 ruoli?**
A: No, il sistema è progettato per semplicità con 3 ruoli. Usa team_id per organizzazione granulare.

**Q: Un user può vedere dati di altri user?**
A: No, user vede solo i propri dati. Team leader vede dati del team.

**Q: Posso avere più team leader?**
A: Sì, ogni team può avere il proprio team leader.

**Q: Admin può delegare permessi?**
A: Sì, creando team leader per gestione autonoma del team.

---

**Ultima revisione:** 2025-12-29
**Versione schema:** 009_simplify_roles.sql
