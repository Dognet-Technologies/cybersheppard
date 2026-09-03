# Regole auditd di CyberSheppard — installazione e personalizzazione

CyberSheppard raccoglie gli eventi di sicurezza tramite **auditd → Laurel → dog-agent**.
Le regole auditd decidono *cosa* viene osservato sull'host. Questa cartella contiene
le regole che alimentano i detector di correlazione (R1–R46).

## File in questa cartella

| File | Ruolo | Ordine di caricamento |
|------|-------|-----------------------|
| `10-cybersheppard-base.rules` | **BASE**: unico `-D` (flush) + settaggi globali (`-b`, `-f`, `--backlog_wait_time`) | **primo** |
| `50-cybersheppard-detect.rules` | **DETECTION**: solo watch/regole (nessun `-D`, nessun settaggio) | dopo la base |

## Installazione

```bash
sudo cp 10-cybersheppard-base.rules 50-cybersheppard-detect.rules /etc/audit/rules.d/
sudo augenrules --load          # concatena i *.rules e li carica
sudo auditctl -l | wc -l        # verifica: le regole sono attive
```

> **Importante — neutralizzare il `-D` di default.** Molte distro installano
> `/etc/audit/rules.d/audit.rules` che inizia con `-D`. Se quel file **carica dopo**
> i nostri (per nome), il suo `-D` **cancella le regole di CyberSheppard**.
> Soluzione: commenta il `-D` e i settaggi globali nel default, lasciando che li
> gestisca solo `10-cybersheppard-base.rules`:
> ```bash
> sudo sed -i -E 's/^(-D|-b |-f |--backlog_wait_time)/#&/' /etc/audit/rules.d/audit.rules
> sudo augenrules --load
> ```

---

## ⚠️ Come `augenrules` combina le regole (leggere prima di personalizzare)

`augenrules` **concatena tutti i `*.rules` in ordine alfabetico di nome file** in un
unico `/etc/audit/audit.rules`, poi `auditctl` li carica **in quell'ordine**. Due
conseguenze fondamentali:

1. **`-D` cancella tutto ciò che è stato caricato PRIMA di sé.** Deve esistere in
   **un solo file, il primo** (`10-cybersheppard-base.rules`). Un secondo `-D` in un
   file che carica dopo azzera silenziosamente CyberSheppard **o** le tue regole,
   a seconda dell'ordine. È l'errore #1.
2. **Per un dato syscall vince la PRIMA regola che matcha.** Quindi una regola
   `-a exit,never` / `-a always,exclude` sopprime gli eventi **solo se viene caricata
   PRIMA** della regola `always,exit` che vorrebbe sopprimere.

I settaggi globali (`-b`, `-f`, `-e`, `--backlog_wait_time`) **non** sono per-regola:
vince **l'ultimo** che viene caricato.

---

## Aggiungere le proprie regole (personalizzazione)

La personalizzazione è supportata e incoraggiata. Segui questo schema e non avrai
sorprese.

### ✅ Cosa fare

- Metti le tue regole in un file che **carica DOPO** quelli di CyberSheppard, es.
  **`/etc/audit/rules.d/70-custom.rules`** (numero > 50). Caricando dopo:
  - le tue regole `always,exit` **aggiungono** copertura;
  - le tue eventuali `never/exclude` **non** possono più sopprimere le regole di
    CyberSheppard (che vengono valutate prima), quindi non ne accecano i detector.
- Tieni **`--backlog_wait_time 0`** (non-bloccante). Con un valore alto (es. 60000)
  se il buffer di audit si riempie i processi si bloccano: su Debian con sshd
  compilato con libaudit questo causa l'**hang di sshd durante il "banner exchange"**.
- Usa `-k` (key) descrittivi e **distinti** dai nostri (`exec`, `privesc`, `credaccess`,
  `identitychange`, `persistence`, `sysconfig`, `logtamper`, `timestomp`, `modules`,
  `io_uring`, `rootexec`, `auditlog`, `auditconfig`, `audittools`). Le tue chiavi
  restano nell'evento (Laurel le propaga) e le vedi in *Threat Detection → Esplora*.
- Valida sempre prima di ricaricare:
  ```bash
  sudo augenrules --check     # verifica sintassi/merge senza applicare
  sudo augenrules --load
  ```

### ❌ Cosa NON fare

- **Non mettere `-D` nel tuo file.** C'è già, in `10-cybersheppard-base.rules`.
- **Non re-impostare i settaggi globali** (`-b`, `-f`) nel tuo file se non vuoi
  cambiarli per tutti: vince l'ultimo caricato.
- **Non usare `-e 2` (immutable)** in un file che non sia l'ultimo in assoluto:
  rende le regole immodificabili e **blocca il caricamento** di tutto ciò che segue.
- **Non sopprimere ciò che serve ai detector.** In particolare evita:
  - `-a always,exclude -F msgtype=CWD` → Laurel perde il campo `cwd` (dettaglio evento).
  - `-a exit,never -F dir=/dev/shm ...` → spegne R30 (esecuzione da `/dev/shm`).
  - `-a exit,never -F subj_type=crond_t` → nasconde la persistenza via cron.
  - qualsiasi `never` su `execve`/`execveat` → cieca gran parte della pipeline.
- **Non duplicare le stesse watch con key diversa** (es. `-w /etc/passwd -k mia_key`
  mentre noi abbiamo `-k identity`): auditd le tiene entrambe e generi **eventi
  doppi** per la stessa modifica.

### Esempio di file utente corretto (`70-custom.rules`)

```
## Regole proprie — nessun -D, nessun settaggio globale, carica dopo CyberSheppard.
## Esempio: audit dei mount e delle modifiche a sysctl (non coperti di default).
-a always,exit -F arch=b64 -S mount -S umount2 -F auid>=1000 -F auid!=unset -k mia_mount
-w /etc/sysctl.conf -p wa -k mia_sysctl
-w /etc/sysctl.d/ -p wa -k mia_sysctl
```

### Ripartire da un set completo (es. Neo23x0)

Vuoi usare una ruleset ampia e matura (es. *Neo23x0/auditd*) come base? Ottimo, ma:

1. **Togli dal quel file** la riga `-D` e i settaggi globali (`-b`, `-f`,
   `--backlog_wait_time`, eventuale `-e`) — li gestisce `10-cybersheppard-base.rules`.
2. Salvalo con un nome che **carichi dopo** (es. `70-neo23x0.rules`).
3. Rimuovi/commenta le sue soppressioni che accecano i detector (vedi lista sopra:
   `/dev/shm`, `CWD`, `crond_t`).
4. `sudo augenrules --check && sudo augenrules --load`.

Così ottieni la **copertura ampia della ruleset esterna** *più* le regole mirate di
CyberSheppard che garantiscono i segnali specifici dei suoi detector (io_uring,
`rootexec`, timestomp, ecc.), senza conflitti di `-D`.
