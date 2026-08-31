# CyberSheppard — Development Status

**Data assessment**: 2026-08-31
**Branch**: develop/v0.0.2
**Versione**: backend-rust 0.1.0 · frontend 1.0.0

> ⚠️ **Nota storica**: la precedente versione di questo documento (28 dic 2025) stimava
> il completamento al ~45%. Da allora, sul branch `develop/v0.0.2`, quasi tutto il backlog
> P0/P1 delle Fasi 1–6 è stato implementato, più feature fuori dal piano originale (RBAC,
> plugin system, agent support, analytics avanzata). Questo documento riflette lo stato reale.

---

## 📊 Executive Summary

Lo scaffolding e l'implementazione di **tutte le fasi core (1–6)** del piano esistono e sono
compilanti: **entrambi i build** (backend Rust e frontend React) sono verdi su `develop/v0.0.2`.

La verifica end-to-end (Fase 7) è stata eseguita: build backend+frontend verdi, migrazioni
applicate da zero su DB pulito, e le suite di test ora **compilano ed eseguono** (47 test
backend, 21 test frontend). Sono state inoltre aggiunte tre capacità di integrazione della
suite — **collegamento dell'agent `dog_agent`**, **server MCP** e **HTTPS** (vedi sezione
"Integrazione suite"). Il lavoro residuo è ampliare la copertura e consolidare il deployment.

**Completamento stimato**: **~75–85% "on paper"** — da confermare con verifica funzionale.

### Metriche reali del codice

| Componente        | LOC     | File | Test |
|-------------------|---------|------|------|
| Backend Rust      | ~20.000 | 62   | **47 test** (4 file integrazione + moduli `#[cfg(test)]`) ✅ |
| Backend Django    | ~2.960  | 11   | — |
| Frontend React    | ~8.600  | 40 (17 pagine) | **21 test** (Vitest + RTL: Permissions, Button, Badge) ✅ |
| Target collectors | 9 script bash | — | — |
| Hardening models/templates | 11 YAML | — | — |
| Migrazioni SQL    | 14      | —    | — |

---

## ✅ Stato per fase del piano

### Fase 1 — Backend Hardening ✅ Implementato
- **Django hardening engine** completo: `applier/{applier,backup,rollback}.py`,
  `models_loader/{loader,validator}.py`, `ssh/manager.py`.
- **Rust**: `services/hardening_executor.rs`, API `hardening.rs`.
- Da verificare: apply/rollback su target reale end-to-end.

### Fase 2 — Monitoring ✅ Implementato
- **Rust**: `collector.rs`, `event_collector.rs`, `influxdb_writer.rs`, `scheduler.rs`.
- API: `monitoring.rs`, `auditd.rs`, `security_events.rs`.
- **Collectors** (tutti e 9 presenti): auditd, network, process, sudo, system_metrics,
  **files, packages, users, services** (i 4 "mancanti" di dicembre ora esistono).
- **Ingest agent funzionante** (vedi "Integrazione suite"): `dog_agent` invia metriche via
  WebSocket → decompressione zstd → snapshot JSONB su PostgreSQL. Verificato end-to-end.
- Da verificare: setup buckets/retention InfluxDB, mapping fine metriche agent → measurement
  InfluxDB tipizzate (ora snapshot JSONB lossless in `agent_metric_snapshots`).

### Fase 3 — Frontend Core ✅ Implementato
- `Login.tsx`, `Layout.tsx`, `Dashboard.tsx`, `Targets.tsx` + UI kit (`components/ui`).
- Test: framework **Vitest + React Testing Library** (`happy-dom`) con 21 test iniziali
  (RBAC `Permissions`, `Button`, `Badge/SeverityBadge/StatusBadge`). Copertura da ampliare.

### Fase 4 — Hardening UI ✅ Implementato
- `Hardening.tsx`, `HardeningTemplates.tsx`, `ApplyHardeningModal.tsx`.

### Fase 5 — Integrations & Correlation ✅ Implementato
- **Rust**: `integration_sync.rs`, `correlation_engine.rs`, `alerting.rs`, `notification.rs`.
- API: `integrations.rs`. Pagine: `Integrations.tsx`, `SecurityCorrelations.tsx`.

### Fase 6 — Compliance & Alerts ✅ Implementato
- **Rust**: `compliance_engine.rs`, `compliance_scanner.rs`, API `compliance*.rs`.
- Pagine: `ComplianceDashboard/Controls/Frameworks.tsx`, `Alerts.tsx`, `Violations.tsx`.
- Da verificare: generazione report PDF, delta report.

### Fase 7 — Testing & QA ✅ Verifica eseguita (copertura da ampliare)
- **Build**: backend Rust (bin + lib) e frontend (`tsc && vite build`) verdi.
- **Backend test**: 41 test verdi. Nota: la suite non compilava (crate solo-binary); risolto
  estraendo `src/lib.rs` (moduli + `AppState`), così `tests/` importa gli internals.
- **Frontend test**: 21 test verdi (Vitest + RTL, `happy-dom`) — framework introdotto da zero.
- **Migrazioni**: 12/12 applicate da zero su DB pulito (69 tabelle, admin seed); dev DB locale
  ricreato per risolvere il drift dei checksum.
- **Cleanup**: warning backend 129 → 33 (`cargo fix`); i 33 residui sono dead-code da valutare.
- CI: CodeQL SAST, cargo-deny, dependency-review, SHA-pinning delle action.
- Da fare: alzare la copertura (pagine, servizi), test Django, E2E.

### Fase 8 — Deploy & Docs ⚠️ Parziale (approccio cambiato)
- **No Docker**: deploy via **systemd + nginx** (`deploy/`): `setup-production.sh`,
  `nginx/cybersheppard.conf`, unit `cybersheppard-{rust,django}.service`,
  `.env.production.example`.
- Da verificare: procedura di setup completa su host pulito.

---

## ➕ Oltre il piano originale (feature aggiunte)

- **RBAC** per ruoli con estrattori role-gated (migrazione 011).
- **Plugin system**: `services/plugin_manager.rs`, API `plugins.rs`, `Plugins.tsx` (migrazione 010).
- **Agent support**: `services/agent_registry.rs`, API `agents.rs` (migrazione 002).
- **Analytics avanzata**: `bayesian_network.rs`, `anomaly_detection.rs`,
  `lateral_movement_predictor.rs`, `graph_analytics.rs`, `baseline_calculator.rs`
  (migrazione 008).
- **Frontend extra**: `AuditEvents.tsx`, `EventDetails.tsx`, `Monitoring.tsx`.

---

## 🔗 Integrazione suite (SentinelCore · FireDog · CyberSheppard)

Tre capacità aggiunte per coerenza con gli altri prodotti della suite, portando i pattern da
**SentinelCore** (riferimento Rust) dove già esistevano.

### Agent `dog_agent` collegato ✅ (verificato live)
- L'agent Rust esistente (`~/Repos/Progetti/LAVORO/dog_agent`) si connette via WebSocket a
  `/api/agents/ws`, si autentica e invia batch di metriche compresse (zstd+base64).
- Lato server (`api/agents.rs`): implementati **AuthAck** (l'agent lo attende prima di
  inviare), **decompressione zstd reale** (era un placeholder) e **persistenza lossless** in
  `agent_metric_snapshots` (migr. 013, JSONB). 3 unit test + prova end-to-end reale.

### Server MCP ✅ (verificato via curl)
- `POST /api/mcp` — JSON-RPC 2.0 (`initialize`/`ping`/`tools/list`/`tools/call`), portato da
  SentinelCore (`mcp/{protocol,mod,tools}.rs`). 5 tool: `list_targets`, `list_alerts`,
  `get_target_metrics`, `list_compliance_scans`, `acknowledge_alert`.
- **API-key scoped** (migr. 014, `utils::api_key`): chiavi `sk_...` per-utente revocabili con
  scope `read`/`write`; `auth_middleware` le accetta come Bearer (impersona l'utente),
  CSRF-esente. I tool di scrittura richiedono scope `write` (creabile solo da admin).
- **Frontend**: sezione Settings **"MCP Keys"** (distinta dalle integration API keys) per
  creare/revocare le chiavi.

### HTTPS ✅ (codice; verifica finale sul deploy host)
- TLS terminato al reverse-proxy come SentinelCore: `nginx/cybersheppard.conf` ha già redirect
  80→443, HSTS, security headers, CSP con `wss:`, WS upgrade; cert via `setup-production.sh`
  (self-signed + certbot).
- Chiuso il gap: **frontend same-origin** (`API_BASE_URL=''`) e location nginx dedicata per il
  WebSocket dell'agent.

### i18n predisposto
- Infrastruttura **react-i18next** (base inglese, `src/i18n/locales/en/translation.json`).
  Traduzione effettiva verso altre lingue: step successivo.

---

## 🎯 Prossimi passi consigliati

1. **HTTPS end-to-end**: provare `deploy/setup-production.sh` su host/VM (nginx + cert) —
   login via HTTPS, agent su `wss://`, redirect 80→443.
2. **Ampliare la copertura test (Fase 7)**: test pagine/servizi frontend, test Django
   (`hardening_engine`), primi flussi E2E; ridurre i 33 warning dead-code residui.
3. **Ingest metriche**: mapping fine agent `AllMetrics` → measurement InfluxDB tipizzate
   (oltre lo snapshot JSONB) + setup buckets/retention.
4. **i18n**: traduzione effettiva delle stringhe (infrastruttura già pronta, base EN).
5. **Compliance report PDF** e **delta report**: chiudere i "da verificare".
6. **Sicurezza**: le 73 vulnerabilità Dependabot sul default branch (31 high).

---

## 📦 Stack confermato

```yaml
Backend:  Rust + Axum (API)  ·  Python + Django (hardening engine)
Frontend: React 18 + TypeScript + Vite + Tailwind + react-i18next (base EN)
Database: PostgreSQL (sqlx, cache offline .sqlx)  ·  InfluxDB 2.x (time-series)
Agent:    dog_agent (Rust) via WebSocket /api/agents/ws (zstd, API-key)
MCP:      JSON-RPC 2.0 su POST /api/mcp · auth API-key scoped (read/write)
Deploy:   systemd + nginx (bare-metal, TLS al proxy), non Docker
CI:       CodeQL, cargo-deny, dependency-review, release workflow
```

---

**Ultimo aggiornamento**: 2026-08-31 · branch `develop/v0.0.2`
