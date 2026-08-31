# CyberSheppard — Catalogo regole di correlazione eventi

**Scopo**: tracciare in modo "certosino" la scuderia completa delle regole del motore di
correlazione (`backend-rust/src/services/correlation_engine.rs`). Ogni regola trasforma eventi
**grezzi** (`security_events`, molti con `mitre_tactic = NULL`) in **eventi di sicurezza**
(`event_correlations`) taggati con **tattica MITRE ATT&CK** (`attack_stage`) e **tecnica difensiva
D3FEND** mitigante (`correlation_data.mitigating_d3fend`).

**Principio** (vedi `DEVELOPMENT_STATUS` §Integrazione suite): ciò che mappa intrinsecamente su
MITRE è già un evento di sicurezza; il resto nasce grezzo e va **sorvegliato** — queste regole
sono la sorveglianza che eleva per **frequenza**, **sequenza**, **lignaggio di processo**,
**identità**, **rete**, **file**, **geo**.

## Legenda stato
- ✅ implementata e **verificata live**
- 🟢 implementata (build+unit verdi)
- 🟡 parziale / euristica base da rifinire
- 🔲 pianificata, **implementabile ora** (dati già disponibili)
- ⛔ **lacuna**: bloccata da un prerequisito esterno (indicato)

## Dimensioni di correlazione (criteri oltre al tempo)
| Dimensione | Campi (`security_events`) | Note |
|---|---|---|
| Temporale | `timestamp` | finestra/frequenza/sequenza — base di tutte |
| Identità | `user_name`, `user_id`, `event_data->>'auid'` | **auid** = utente di login reale (invariato dopo su/sudo) |
| Lignaggio processo | `process_pid`, `process_ppid`, `process_name`, `process_cmdline` | albero da Laurel — massimo valore |
| Sessione | `event_data->>'ses'` | tutti gli eventi di un login |
| Host/asset | `source_host`, `asset_criticality` | pesatura per criticità |
| Rete | `source_ip`, `destination_ip`, `destination_port`, `protocol`, `bytes_*` | C2/beaconing/exfil |
| File/risorsa | `file_path`, `file_operation` | integrità/persistence/impact |
| Geo | `geo_country`, `geo_city` | impossible travel (⛔ GeoIP) |
| Causalità | `correlation_id`, `parent_event_id`, `sequence_number` | catene esplicite |

---

## Regole

### Già presenti (pre-esistenti)
| # | Regola | Tattica ATT&CK | Dimensione | Metodo | Stato |
|---|---|---|---|---|---|
| R1 | Brute force | credential_access (T1110) | identità+rete, frequenza | ≥N auth fallite stesso utente/host | ✅ (fix: era initial_access) |
| R2 | Lateral movement | lateral_movement (T1021) | host+identità, sequenza | login host A → conn → login host B | 🟢 |
| R3 | Privilege escalation (sudo/su) | privilege_escalation (T1548) | identità, sequenza | utente normale → sudo/su → root | 🟢 |
| R4 | Data exfiltration | exfiltration (T1041) | rete, volume | grandi trasferimenti verso IP esterni | 🟢 |
| R5 | Anomaly cluster | (nessuna fissa) | statistica | cluster di alti anomaly_score | 🟢 |

### Batch 1 — priorità (questo lavoro)
| # | Regola | Tattica ATT&CK | Dimensione | Metodo | Stato |
|---|---|---|---|---|---|
| R6 | **Esecuzione sospetta** (reverse-shell/interprete) | execution (T1059) | lignaggio pid/ppid (1-hop) | exec di `nc`/`bash -i`/`python -c`/`/dev/tcp/` | ✅ |
| R7 | **Privesc attribuita via auid** | privilege_escalation (T1548) | identità (auid vs uid) | uid=0 con auid≠0 (chi ha fatto login davvero) | ✅ |
| R8 | **Correlazione di sessione (ses)** | privilege_escalation | sessione | sessione (ses) con auth fallite E poi eventi uid=0 | ✅ |
| R9 | **Beaconing C2** | command_and_control (T1071) | rete, frequenza | ≥10 conn. verso stesso dest, >5 min | ✅ |

### Batch 2 — estensioni (implementabili ora)
| # | Regola | Tattica ATT&CK | Dimensione | Metodo | Stato |
|---|---|---|---|---|---|
| R10 | Reverse shell | command_and_control (T1071) | processo+rete (**join**) | exec `nc`/`bash -i`//dev/tcp + connect in uscita stesso host (~2 min) | ✅ |
| R11 | Persistenza | persistence (T1547/T1053/T1098) | file | scritture su cron, systemd, `~/.ssh/authorized_keys`, rc.local | ✅ |
| R12 | Accesso a file credenziali | credential_access (T1003) | file | read di `/etc/shadow`, `/etc/sudoers` | ✅ |
| R13 | Discovery burst | discovery (T1082/T1057/T1016) | processo | ≥4 comandi recon distinti (`whoami`,`id`,`uname`,`ss`,`netstat`,`ps`…) | ✅ |
| R14 | Defense evasion | defense_evasion (T1070) | file/processo | tamper audit log, clear `~/.bash_history`, `auditctl -D` | ✅ |
| R15 | Impact / ransomware | impact (T1486/T1490) | file | ≥100 scritture/cancellazioni in <5 min | ✅ |

### Delegato a **Intellidog** (modulo premium esterno)
Queste correlazioni richiedono **intelligence esterna / dati cross-prodotto** e sono competenza del
modulo premium **Intellidog** (Threat Intelligence: feed MISP/OTX/CSV/JSON, IOC matching,
correlazione con firewall FireDog e vulnerabilità SentinelCore — vedi
`docs/Modulo_Intellidog/`). **Non** sono lacune del core CyberSheppard: vanno **delegate**, non
implementate qui.

| Ambito | Cosa | Dove |
|---|---|---|
| Threat-intel / IOC | IP/domini/hash/CVE malevoli noti → detection | Intellidog (feed) |
| Impossible travel / GeoIP | geolocalizzazione + viaggio impossibile | Intellidog (enrichment esterno) |
| Cross-source | correlazione con firewall FireDog / vuln SentinelCore | Intellidog (`firedog_replica`/`sentinel_replica`) |

### Rimane nel core CyberSheppard
| # | Regola | Tattica | Stato |
|---|---|---|---|
| R19 | Deviazione da baseline comportamentale | anomaly | 🟢 code-complete: `anomaly_detection` (z-score vs baseline) + `baseline_calculator` + API `/api/events/{baselines/calculate,anomalies/detect}`. Il **popolamento** dei baseline è operativo (serve storico). |

---

## Lacune / placeholder noti (riepilogo)
> Threat-intel, GeoIP/impossible-travel e correlazione cross-prodotto **non** sono lacune del core:
> sono delegate a **Intellidog** (vedi sopra). L'enrichment geo/IOC su `security_events` arriva da
> lì; il core non integra feed esterni.
- **Mappa MITRE**: le **correlazioni** portano ora tattica + **tecnica** ATT&CK (T-code + nome)
  + D3FEND (`technique_for_pattern`, tutte le 14 regole — mappatura completa a livello di
  tecnica). Il tag **per-evento grezzo** resta volutamente conservativo (solo l'intrinseco);
  la tabella `mitre_attack_map` è la sorgente estendibile per un eventuale caricamento a runtime.
- **D3FEND per-controllo**: `d3fend_for_tactic` mappa tattica→D3FEND generico; il link al
  **controllo compliance specifico** (dal Master Mapping xlsx) è TODO.
- **Process ancestry completa**: usiamo `pid/ppid` diretti; l'albero multi-livello ricostruito da
  Laurel (catena antenati) è sfruttato solo a 1 hop finché non persistiamo la catena.
- **AttackStage**: enum esteso a 13 tattiche (aggiunte defense_evasion, discovery,
  command_and_control, impact). Restano fuori `reconnaissance`(esterna) e `resource_development`.

## Verifica
Ogni regola va provata come R1 (brute force, ✅): iniettare eventi Laurel che formano il pattern →
`POST /api/events/correlations/analyze` → controllare `event_correlations` (tattica + D3FEND).

---
**Ultimo aggiornamento**: 2026-08-31 · branch `develop/v0.0.2-events`
