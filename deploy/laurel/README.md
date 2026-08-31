# Laurel — deploy sul target (CyberSheppard)

**Laurel** ([threathunters-io/laurel](https://github.com/threathunters-io/laurel)) gira come
**plugin di auditd sul target monitorato**: legge lo stream degli eventi audit, li **arricchisce**
(process ancestry pid/ppid, risoluzione uid→nomi, argv di execve, container/systemd) e li scrive
come **JSON** (una riga = un evento). Il `dog_agent` legge quel file e lo inoltra al server, dove
diventano `security_events` e alimentano la correlazione MITRE.

## Flusso
```
regole auditd  →  kernel audit  →  Laurel (plugin, enrichment)  →  /var/log/laurel/audit.log (JSON)
                                                                        │
                                              dog_agent (laurel_log_path) inoltra al server
                                                                        ▼
                                        security_events  →  correlation_engine (ATT&CK + D3FEND)
```

## File in questa cartella
| File | Destinazione sul target | Scopo |
|---|---|---|
| `config.toml` | `/etc/laurel/config.toml` | config Laurel (output JSON, enrichment) |
| `plugin-laurel.conf` | `/etc/audit/plugins.d/laurel.conf` | registra Laurel come plugin auditd |
| `../audit/cybersheppard.rules` | `/etc/audit/rules.d/cybersheppard.rules` | regole audit allineate ai detector |
| `install-laurel.sh` | — | installa tutto (eseguire come root) |

## Uso
```bash
sudo deploy/laurel/install-laurel.sh
# poi nella config dell'agent (dog_agent):
#   laurel_log_path = "/var/log/laurel/audit.log"
```

## ⚠️ Da finalizzare (starter)
- **Binario Laurel**: `install-laurel.sh` NON scarica ancora il binario (URL/versione o build da
  confermare — vedi commenti nello script). Config, plugin e regole sono invece pronti.
- **Regole audit**: `cybersheppard.rules` è un set di partenza (il completo è in
  `Esempio_modelli/etc.auditd.audit.rules`). L'auditing di `connect` (rete/beaconing R9) è
  **commentato** perché rumoroso: attivarlo consapevolmente in finalizzazione.
- **authorized_keys per-utente**: aggiungere i watch `/home/*/.ssh` in modo mirato.
- **Chiavi di `config.toml`**: base ragionevole; rifinire sulla versione di Laurel installata.
- L'integrazione è tracciata anche in `docs/DEVELOPMENT_STATUS.md` e `docs/CORRELATION_RULES.md`.
