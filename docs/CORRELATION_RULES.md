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

### Batch 3 — chiusura gap purple-team (2026-09-01)
| # | Regola | Tattica ATT&CK | Dimensione | Metodo | Stato |
|---|---|---|---|---|---|
| R16 | **Root Asset / Credential Discovery** | discovery (T1083) / T1552 | processo (cmdline) | ≥3 ricerche `find`/`ls`/`grep` verso SUID, file di root, chiavi SSH, credenziali | ✅ (colma gap: R13 vedeva solo whoami/id/uname) |
| R17 | **io_uring Audit Evasion** | defense_evasion (T1562) | syscall | uso di `io_uring_setup` da processo non in allowlist (richiede regola audit `-S io_uring_setup`) | ✅ |
| R18 | **Sensor Silence** | defense_evasion (T1562) | server-side | agent connesso + metriche recenti ma `security_events` fermi da >10min (stop auditd/Laurel) | ✅ (richiede `target_id` su security_events, migr. 017) |
| R20 | **Fileless Execution** | execution (T1620) | processo (exe) | `exe` = `/memfd:…` o `(deleted)` — loader in-memory / binario cancellato (richiede audit `execveat`) | ✅ |

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

## Verifica live end-to-end su lab reale (2026-09-01)
Pipeline provata su lab VirtualBox "Laboratorio SentinelSuite": server CyberSheppard
(lab-cybersheppard, deploy systemd+nginx+PostgreSQL) + 2 target reali (lab-client1/2) con
**dog-agent 1.1.1** e **Laurel 0.8.2** come plugin auditd. Scenario d'attacco reale (login
attacker via ssh con auid=1001: brute force, discovery, lettura /etc/shadow, exec sospetta,
privesc) → `event_correlations` popolata via API con **6 tattiche/tecniche ATT&CK + D3FEND**:
R1 brute force `T1110`/D3-MFA, R7 privesc-auid `T1548`/D3-PA, R6 execution `T1059`/D3-PSEP,
R12 credential access `T1003`/D3-MFA, R13 discovery `T1082`, R2 lateral movement `T1021`/D3-NTF.
- **Fix abilitanti** (commit "fix(pipeline)…"): parser `normalize_laurel()` per il formato JSON
  annidato di Laurel 0.8.x (prima ogni evento era `system/unknown` con campi NULL → nessun
  detector scattava); `config.toml` Laurel nel formato 0.8.2; JWT `rust_crypto`; migrazione 016
  (drift schema auth/targets).
- **Nota tuning**: R2 lateral movement è **rumorosa** in ambiente con molti login ssh a
  `127.0.0.1` (li accoppia come "login host A → host B"): da raffinare con esclusione loopback
  / stesso host prima del rilascio.
- **Cattura auid**: le regole execve filtrano `auid>=1000`; i comandi vanno eseguiti in una
  **sessione di login** dell'utente (ssh), non via `su` da root (che eredita auid=0).

## Purple-team: limiti di detection e difese (2026-09-01)
Attacchi reali dal lab (Parrot → target Debian 13, kernel 6.12.105/107) per trovare dove
CyberSheppard fallisce. Sintesi:

| # | Gap trovato | Gravità | Difesa implementata | Stato |
|---|---|---|---|---|
| 1 | **Evasione io_uring**: lettura `/etc/shadow` via `io_uring` → **0 record** auditd/Laurel (bypassa watch inode + auditing syscall); R12 cieco | 🔴 CRITICA | regola audit `-S io_uring_setup -k io_uring` + detector **R17**; hardening opz. `sysctl kernel.io_uring_disabled=2` | ✅ chiuso |
| 2 | **Discovery/credential-search non correlati**: `find -perm -4000`, `find -name id_rsa`, `ls /root`, `grep password`, ping-sweep (T1083/T1552/T1018) catturati ma non elevati | 🟠 ALTA | detector **R16** (Root Asset Discovery) | ✅ chiuso (ping-sweep resta TODO) |
| 3 | **Blind-spot auid≥1000**: execve da root (auid=0) o servizi (auid=unset) → non auditati; attaccante già-root invisibile | 🟠 ALTA | regole audit `-S execve -F euid=0 …auid<1000/unset -k rootexec` | ✅ chiuso |
| 4 | Privesc kernel | 🟢 OK | 6.12.105 patchato, `linux-exploit-suggester` senza CVE noti | n/a |

### Matrice evasione completa (Batterie A/B/C)
Test sistematico dei vettori di evasione più noti contro auditd/Laurel:

| Vettore | Risultato | Difesa |
|---|---|---|
| **io_uring** (read `/etc/shadow`) | 0 record — bypassa watch inode + syscall | R17 + regola `io_uring_setup` |
| **execveat** (loader fileless) | 0 record: la regola copriva solo `execve` | ✅ aggiunto `-S execve,execveat` |
| **memfd_create + execveat** (fileless) | ora catturato, `exe=/memfd:(deleted)` | ✅ R20 |
| **binario cancellato** | catturato, `exe=…(deleted)` | ✅ R20 |
| **loginuid reset** (`/proc/self/loginuid`) | EPERM — immutabile | n/a (già sicuro) |
| **kill processo Laurel** | auditd lo **respawna** subito | resiliente; per stop reale → R18 |
| **stop auditd / disable plugin** (root) | acceca senza lasciare record | ✅ R18 (server-side) |
| **flood backlog audit** | `lost=0` sotto carico moderato | resiliente (backlog 8192, wait 0) |
| **LD_PRELOAD** | **loggato** nell'env (non evade) | opportunità di detection (TODO) |
| **detachment `setsid`/double-fork** (ppid=1) | eventi catturati ma lignaggio spezzato | evasione dell'*attribuzione* (TODO) |
| **read via bash builtin** (file non-watchati) | nessun evento (no execve) | gap intrinseco (non chiudibile senza rumore) |

**Note operative**: la cattura execve richiede sessione di **login** dell'utente (auid), non `su`
da root (eredita auid=0). io_uring_setup e execveat non espongono sempre il contesto completo →
R17/R20 flaggano l'**uso** della tecnica; per l'attribuzione fine (file letto via io_uring, iniezione)
serve **eBPF/LSM**. TODO: rilevatore ping/port-sweep (T1018/T1046), detector LD_PRELOAD (T1574.006),
raffinamento R2 lateral movement (rumorosa sui login loopback), gestione detachment/lignaggio.

---
**Ultimo aggiornamento**: 2026-09-01 · branch `develop/v0.0.2`
