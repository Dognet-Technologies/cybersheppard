// ============================================================================
// Dizionario centralizzato dei testi di aiuto (tooltip/InfoTip), BILINGUE.
// Ogni voce ha { it, en }: la versione inglese è già predisposta, basta
// completarla/rifinirla. Cambiando LOCALE (o in futuro collegando un vero
// sistema i18n) si commuta tutta l'interfaccia di aiuto da un unico punto.
//
// Uso nei componenti:
//   import { HELP } from '../i18n/help';
//   <InfoTip content={HELP.nav.detection} />
//   <PageHeader ... info={HELP.page.detection} />
// Per i badge dinamici usare le mappe: HELP.severity[sev], HELP.sensor[s], ...
// ============================================================================

export type Locale = 'it' | 'en';

// Lingua attiva dell'interfaccia di aiuto. In futuro: da context/utente.
export const LOCALE: Locale = 'it';

type L = { it: string; en: string };
const t = (e: L): string => e[LOCALE];
// Risolve una mappa { chiave: {it,en} } in { chiave: string } nella lingua attiva.
const tmap = <K extends string>(m: Record<K, L>): Record<K, string> =>
  Object.fromEntries(Object.entries(m).map(([k, v]) => [k, t(v as L)])) as Record<K, string>;

export const HELP = {
  // --- Voci di menu (sidebar) ---------------------------------------------
  nav: {
    dashboard: t({
      it: 'Panoramica generale: conteggi reali di target, violazioni, alert e correlazioni con i grafici di sintesi. Se non ci sono dati, i valori restano a 0.',
      en: 'General overview: real counts of targets, violations, alerts and correlations with summary charts. With no data, values stay at 0.',
    }),
    targets: t({
      it: 'Host monitorati (server e client con agent installato). Da qui li aggiungi, ne vedi lo stato online/offline e gestisci i token di collegamento.',
      en: 'Monitored hosts (servers and clients with the agent installed). Add them, see online/offline status and manage enrollment tokens.',
    }),
    monitoring: t({
      it: 'Stato di monitoraggio dei target in tempo reale. Le serie temporali (CPU/RAM/rete) arriveranno con l’integrazione InfluxDB.',
      en: 'Real-time monitoring status of targets. Time-series metrics (CPU/RAM/network) will arrive with the InfluxDB integration.',
    }),
    hardening: t({
      it: 'Modelli di irrobustimento (hardening) applicabili ai target per allinearne la configurazione alle baseline di sicurezza.',
      en: 'Hardening models you can apply to targets to align their configuration with security baselines.',
    }),
    integrations: t({
      it: 'Stato delle integrazioni con gli altri prodotti della suite (Sentinel, FireDog) e sincronizzazione dei dati.',
      en: 'Status of integrations with the other suite products (Sentinel, FireDog) and data sync.',
    }),
    detection: t({
      it: 'Hub rilevamento minacce: eventi grezzi, correlazioni, copertura MITRE ATT&CK e alert — l’intero flusso SOC in un’unica pagina a schede.',
      en: 'Threat detection hub: raw events, correlations, MITRE ATT&CK coverage and alerts — the whole SOC flow in one tabbed page.',
    }),
    compliance: t({
      it: 'Hub conformità: framework (NIS2, NIST, ISO 27001, MITRE), punteggi e gap, catalogo dei controlli e violazioni di postura.',
      en: 'Compliance hub: frameworks (NIS2, NIST, ISO 27001, MITRE), scores and gaps, controls catalog and posture violations.',
    }),
    settings: t({
      it: 'Configurazione della piattaforma: impostazioni di sistema, chiavi API/MCP, manutenzione del database e account.',
      en: 'Platform configuration: system settings, API/MCP keys, database maintenance and account.',
    }),
    plugins: t({
      it: 'Estensioni installabili da repository esterni per aggiungere sorgenti di raccolta e funzionalità opzionali.',
      en: 'Installable extensions from external repositories to add collection sources and optional features.',
    }),
  },

  // --- Intestazioni di pagina (InfoTip accanto al titolo) ------------------
  page: {
    detection: t({
      it: 'Le schede seguono il flusso di indagine: Tabella (eventi grezzi filtrabili) → Esplora (analisi a faccette) → Correlazioni (pattern d’attacco + copertura ATT&CK) → Alert (triage). La scheda attiva è salvata nell’URL.',
      en: 'Tabs follow the investigation flow: Table (filterable raw events) → Explore (faceted analysis) → Correlations (attack patterns + ATT&CK coverage) → Alerts (triage). The active tab is saved in the URL.',
    }),
    compliance: t({
      it: 'Da qui accedi a Scoring & Gap Analysis, al catalogo dei Controlli e alle Violazioni. Le violazioni sono postura di conformità (config non a norma), diverse dagli alert di minaccia.',
      en: 'From here reach Scoring & Gap Analysis, the Controls catalog and Violations. Violations are compliance posture (non-conforming config), distinct from threat alerts.',
    }),
    monitoring: t({
      it: 'Mostriamo solo dati reali. I grafici delle metriche di sistema restano vuoti finché la raccolta serie temporali (InfluxDB) non è attiva lato backend.',
      en: 'We show real data only. System-metric charts stay empty until time-series collection (InfluxDB) is enabled on the backend.',
    }),
    violations: t({
      it: 'Scostamenti rilevati dal motore di conformità rispetto alle soglie/configurazioni attese sui target. Puoi prenderli in carico (acknowledge) o risolverli con una nota.',
      en: 'Deviations detected by the compliance engine against expected thresholds/configuration on targets. You can acknowledge or resolve them with a note.',
    }),
    complianceControls: t({
      it: 'Catalogo dei 113 controlli suddivisi per macroarea, con mappatura multi-framework (NIS2/NIST/ISO/MITRE) e supporto per sistema operativo/piattaforma.',
      en: 'Catalog of the 113 controls grouped by macro-area, with multi-framework mapping (NIS2/NIST/ISO/MITRE) and per-OS/platform support.',
    }),
    complianceDashboard: t({
      it: 'Punteggio di conformità per framework e per target, con evidenza dei gap critici e ad alta priorità da colmare.',
      en: 'Compliance score by framework and by target, highlighting critical and high-priority gaps to close.',
    }),
    dashboard: t({
      it: 'Panoramica sintetica della postura di sicurezza. Tutti i valori sono reali: se non ci sono dati restano a 0 e i grafici vuoti (nessun dato simulato).',
      en: 'Concise overview of your security posture. All values are real: with no data they stay at 0 and charts stay empty (no simulated data).',
    }),
    targets: t({
      it: 'Host monitorati con agent installato. Aggiungi/rimuovi target, verifica lo stato online/offline e gestisci i token di collegamento.',
      en: 'Monitored hosts with the agent installed. Add/remove targets, check online/offline status and manage enrollment tokens.',
    }),
    hardening: t({
      it: 'Modelli di irrobustimento applicabili ai target. Applicando un modello, le sue regole vengono eseguite sull’host per allineare la configurazione alla baseline.',
      en: 'Hardening models you can apply to targets. Applying a model runs its rules on the host to align configuration with the baseline.',
    }),
    hardeningTemplates: t({
      it: 'Template YAML di hardening pronti all’uso, con framework coperti, sistemi operativi supportati, tempo stimato e supporto al rollback.',
      en: 'Ready-to-use YAML hardening templates, with covered frameworks, supported OSes, estimated time and rollback support.',
    }),
    integrations: t({
      it: 'Collegamenti con gli altri prodotti della suite (Sentinel, FireDog): stato della connessione e sincronizzazione manuale dei dati.',
      en: 'Links to the other suite products (Sentinel, FireDog): connection status and manual data sync.',
    }),
    eventDetails: t({
      it: 'Analisi completa di un singolo evento: processo, identità, file/rete, ancestry, mappatura MITRE e log grezzo. Da qui puoi aggiornarne lo stato.',
      en: 'Full analysis of a single event: process, identity, file/network, ancestry, MITRE mapping and raw log. You can update its status here.',
    }),
  },

  // --- Schede dell’hub Threat Detection -----------------------------------
  detectionTabs: {
    table: t({
      it: 'Eventi di sicurezza in tabella, con filtri per target, severità, categoria e stato. Clicca “Details” per l’analisi completa di un evento.',
      en: 'Security events in a table, filterable by target, severity, category and status. Click “Details” for a full event analysis.',
    }),
    explore: t({
      it: 'Esplorazione a faccette dei log arricchiti (auditd/Laurel + eBPF): affina per host/utente/categoria/tattica/sensore e apri un evento per vedere processo, identità, ancestry e JSON grezzo.',
      en: 'Faceted exploration of enriched logs (auditd/Laurel + eBPF): refine by host/user/category/tactic/sensor and open an event to see process, identity, ancestry and raw JSON.',
    }),
    correlations: t({
      it: 'Pattern d’attacco correlati dagli eventi, con mappatura MITRE ATT&CK/D3FEND. Usa il toggle per vedere la Lista dettagliata o la Matrice di copertura.',
      en: 'Attack patterns correlated from events, mapped to MITRE ATT&CK/D3FEND. Use the toggle to switch between the detailed List and the coverage Matrix.',
    }),
    alerts: t({
      it: 'Alert di sicurezza da triare: prendili in carico (acknowledge) e poi risolvili. Riguardano attività di minaccia, non la conformità.',
      en: 'Security alerts to triage: acknowledge then resolve. They concern threat activity, not compliance.',
    }),
    modeList: t({
      it: 'Vista Lista: tabella dettagliata delle correlazioni con severità, tecnica, sensore, entità coinvolte e risk score.',
      en: 'List view: detailed table of correlations with severity, technique, sensor, involved entities and risk score.',
    }),
    modeMatrix: t({
      it: 'Vista Matrice: la kill-chain MITRE ATT&CK con le tecniche che i detector coprono. Le celle colorate sono rilevate di recente; quelle tratteggiate sono coperte ma senza detection. Clicca una cella per filtrare la Lista.',
      en: 'Matrix view: the MITRE ATT&CK kill-chain with the techniques detectors cover. Colored cells were detected recently; dashed cells are covered but with no detection. Click a cell to filter the List.',
    }),
  },

  // --- Badge / concetti ricorrenti (mappe dinamiche) ----------------------
  severity: tmap({
    critical: { it: 'Critica: impatto grave e/o attacco molto probabile — intervento immediato.', en: 'Critical: severe impact and/or highly likely attack — act immediately.' },
    high: { it: 'Alta: rischio rilevante — da gestire con priorità.', en: 'High: significant risk — handle with priority.' },
    medium: { it: 'Media: rischio moderato — da valutare.', en: 'Medium: moderate risk — to be assessed.' },
    low: { it: 'Bassa: rischio minimo o informativo.', en: 'Low: minimal or informational risk.' },
    info: { it: 'Informativo: nessun rischio diretto.', en: 'Informational: no direct risk.' },
  }),
  status: tmap({
    new: { it: 'Nuovo: non ancora preso in carico.', en: 'New: not yet triaged.' },
    active: { it: 'Attivo: in corso, da gestire.', en: 'Active: ongoing, to be handled.' },
    acknowledged: { it: 'Preso in carico: un operatore lo sta gestendo.', en: 'Acknowledged: an operator is handling it.' },
    investigating: { it: 'In indagine: analisi in corso.', en: 'Investigating: analysis in progress.' },
    resolved: { it: 'Risolto: chiuso, nessuna azione ulteriore.', en: 'Resolved: closed, no further action.' },
    online: { it: 'Online: l’host comunica con il server.', en: 'Online: the host is communicating with the server.' },
    offline: { it: 'Offline: nessun contatto recente dall’host.', en: 'Offline: no recent contact from the host.' },
    false_positive: { it: 'Falso positivo: rilevazione non reale.', en: 'False positive: not a real detection.' },
  }),
  sensor: tmap({
    ebpf: { it: 'Rilevato dal sensore eBPF nel kernel: resistente a tecniche di evasione come io_uring o lo spoofing dell’auid.', en: 'Detected by the in-kernel eBPF sensor: resistant to evasion such as io_uring or auid spoofing.' },
    auditd: { it: 'Rilevato tramite auditd/Laurel (log di audit dello spazio utente).', en: 'Detected via auditd/Laurel (user-space audit logs).' },
  }),

  // --- Etichette/concetti singoli -----------------------------------------
  concept: {
    mitreTactic: t({
      it: 'Tattica MITRE ATT&CK: il “perché” di un passo d’attacco (obiettivo dell’avversario nella kill-chain).',
      en: 'MITRE ATT&CK tactic: the “why” of an attack step (the adversary’s goal in the kill-chain).',
    }),
    mitreTechnique: t({
      it: 'Tecnica MITRE ATT&CK: il “come” — il metodo concreto usato per raggiungere la tattica.',
      en: 'MITRE ATT&CK technique: the “how” — the concrete method used to achieve the tactic.',
    }),
    d3fend: t({
      it: 'MITRE D3FEND: contromisura difensiva che mitiga la tecnica osservata.',
      en: 'MITRE D3FEND: defensive countermeasure that mitigates the observed technique.',
    }),
    riskScore: t({
      it: 'Punteggio di rischio 0–100 calcolato dal motore di correlazione (severità × confidenza × contesto).',
      en: 'Risk score 0–100 computed by the correlation engine (severity × confidence × context).',
    }),
    confidence: t({
      it: 'Confidenza della correlazione: quanto il motore è sicuro che il pattern sia reale.',
      en: 'Correlation confidence: how sure the engine is that the pattern is real.',
    }),
    complianceScore: t({
      it: 'Percentuale di controlli conformi sul totale applicabile per quel framework/target.',
      en: 'Percentage of compliant controls over the total applicable for that framework/target.',
    }),
  },

  // --- Threat Detection › scheda Tabella (eventi) --------------------------
  eventsTable: {
    statTotal: t({ it: 'Numero totale di eventi di sicurezza raccolti nelle ultime 24 ore.', en: 'Total security events collected in the last 24 hours.' }),
    statCritical: t({ it: 'Eventi di severità critica nelle ultime 24h.', en: 'Critical-severity events in the last 24h.' }),
    statHigh: t({ it: 'Eventi di severità alta nelle ultime 24h.', en: 'High-severity events in the last 24h.' }),
    statNew: t({ it: 'Eventi non ancora presi in carico da un operatore.', en: 'Events not yet triaged by an operator.' }),
    colSeverity: t({ it: 'Gravità stimata dell’evento (critica/alta/media/bassa).', en: 'Estimated event severity (critical/high/medium/low).' }),
    colCategory: t({ it: 'Categoria dell’evento (es. reverse shell, escalation privilegi, accesso a file sensibili).', en: 'Event category (e.g. reverse shell, privilege escalation, sensitive file access).' }),
    colHost: t({ it: 'Host di origine dell’evento (hostname e indirizzo IP).', en: 'Source host of the event (hostname and IP address).' }),
    colEvent: t({ it: 'Descrizione dell’evento; se presente, syscall e comando coinvolti.', en: 'Event description; syscall and command involved when available.' }),
    colTime: t({ it: 'Data e ora di raccolta dell’evento.', en: 'Date and time the event was collected.' }),
    colCorrelations: t({ it: 'Correlazioni incrociate con FireDog/Sentinel ed eventi correlati aggiuntivi.', en: 'Cross-correlations with FireDog/Sentinel and additional related events.' }),
    colStatus: t({ it: 'Stato di gestione dell’evento (nuovo / in indagine / risolto / falso positivo).', en: 'Handling status of the event (new / investigating / resolved / false positive).' }),
    colActions: t({ it: 'Apri il dettaglio completo dell’evento.', en: 'Open the full event detail.' }),
    colMitre: t({ it: 'Tecnica MITRE ATT&CK associata all’evento, se mappata.', en: 'MITRE ATT&CK technique associated with the event, if mapped.' }),
    colSensor: t({ it: 'Sorgente della rilevazione: sensore eBPF (kernel) o canale auditd/Laurel.', en: 'Detection source: eBPF sensor (kernel) or auditd/Laurel channel.' }),
    rowHint: t({ it: 'Clicca una riga per aprire il dettaglio completo dell’evento.', en: 'Click a row to open the full event detail.' }),
    filterHost: t({ it: 'Filtra per host di origine.', en: 'Filter by source host.' }),
    filterTarget: t({ it: 'Filtra per host di origine.', en: 'Filter by source host.' }),
    filterSeverity: t({ it: 'Filtra per gravità.', en: 'Filter by severity.' }),
    filterCategory: t({ it: 'Filtra per categoria di evento.', en: 'Filter by event category.' }),
    filterStatus: t({ it: 'Filtra per stato di gestione.', en: 'Filter by handling status.' }),
  },

  // --- Threat Detection › scheda Correlazioni (Lista) ----------------------
  correlations: {
    statTotal: t({ it: 'Correlazioni corrispondenti ai filtri correnti.', en: 'Correlations matching the current filters.' }),
    statCritical: t({ it: 'Correlazioni di severità critica.', en: 'Critical-severity correlations.' }),
    statHigh: t({ it: 'Correlazioni di severità alta.', en: 'High-severity correlations.' }),
    statActive: t({ it: 'Correlazioni ancora attive (non risolte).', en: 'Correlations still active (unresolved).' }),
    colSeverity: t({ it: 'Gravità complessiva del pattern d’attacco correlato.', en: 'Overall severity of the correlated attack pattern.' }),
    colPattern: t({ it: 'Nome/tipo del pattern d’attacco riconosciuto dal motore di correlazione.', en: 'Name/type of the attack pattern recognized by the correlation engine.' }),
    colMitre: t({ it: 'Tattica e tecnica MITRE ATT&CK e, se disponibile, la contromisura D3FEND mitigante.', en: 'MITRE ATT&CK tactic and technique and, when available, the mitigating D3FEND countermeasure.' }),
    colSensor: t({ it: 'Sorgente della rilevazione: sensore eBPF (kernel) o canale auditd/Laurel.', en: 'Detection source: eBPF sensor (kernel) or auditd/Laurel channel.' }),
    colEntities: t({ it: 'Host e utenti coinvolti nella correlazione.', en: 'Hosts and users involved in the correlation.' }),
    colRisk: t({ it: 'Punteggio di rischio 0–100 e numero di eventi che compongono la correlazione.', en: 'Risk score 0–100 and number of events composing the correlation.' }),
    colConfidence: t({ it: 'Confidenza del motore sulla realtà del pattern (0–100%).', en: 'Engine confidence that the pattern is real (0–100%).' }),
    colDetected: t({ it: 'Data e ora del primo rilevamento della correlazione.', en: 'Date and time the correlation was first detected.' }),
    colStatus: t({ it: 'Stato della correlazione (attiva / in indagine / risolta).', en: 'Correlation status (active / investigating / resolved).' }),
    filterTactic: t({ it: 'Filtra per tattica MITRE ATT&CK.', en: 'Filter by MITRE ATT&CK tactic.' }),
    filterSeverity: t({ it: 'Filtra per gravità.', en: 'Filter by severity.' }),
    filterSensor: t({ it: 'Filtra per sorgente di rilevazione (eBPF o auditd).', en: 'Filter by detection source (eBPF or auditd).' }),
  },

  // --- Threat Detection › scheda Alert -------------------------------------
  alerts: {
    statTotal: t({ it: 'Numero totale di alert corrispondenti ai filtri.', en: 'Total alerts matching the filters.' }),
    statNew: t({ it: 'Alert nuovi, non ancora presi in carico.', en: 'New alerts, not yet triaged.' }),
    statAck: t({ it: 'Alert presi in carico ma non ancora risolti.', en: 'Acknowledged but not yet resolved alerts.' }),
    statResolved: t({ it: 'Alert risolti e chiusi.', en: 'Resolved and closed alerts.' }),
    colSeverity: t({ it: 'Gravità dell’alert.', en: 'Alert severity.' }),
    colAlert: t({ it: 'Titolo e messaggio descrittivo dell’alert.', en: 'Alert title and descriptive message.' }),
    colType: t({ it: 'Tipo/regola che ha generato l’alert.', en: 'Type/rule that generated the alert.' }),
    colCreated: t({ it: 'Data e ora di creazione dell’alert.', en: 'Alert creation date and time.' }),
    colStatus: t({ it: 'Stato dell’alert (nuovo / preso in carico / risolto).', en: 'Alert status (new / acknowledged / resolved).' }),
    filterSeverity: t({ it: 'Filtra per gravità.', en: 'Filter by severity.' }),
    filterStatus: t({ it: 'Filtra per stato.', en: 'Filter by status.' }),
  },

  // --- Compliance (frameworks) --------------------------------------------
  compliance: {
    statActiveFrameworks: t({ it: 'Numero di framework di conformità attualmente abilitati.', en: 'Number of currently enabled compliance frameworks.' }),
    statAvgScore: t({ it: 'Punteggio medio di conformità su tutti i framework valutati.', en: 'Average compliance score across all assessed frameworks.' }),
    statTargetsAssessed: t({ it: 'Numero di target che hanno almeno una valutazione di conformità.', en: 'Number of targets with at least one compliance assessment.' }),
    statViolations: t({ it: 'Totale violazioni critiche e ad alta gravità sui target.', en: 'Total critical and high-severity violations across targets.' }),
  },

  // --- Violations ----------------------------------------------------------
  violations: {
    colSeverity: t({ it: 'Gravità della violazione di conformità.', en: 'Compliance violation severity.' }),
    colMetric: t({ it: 'Metrica/controllo violato e relativa descrizione.', en: 'Violated metric/control and its description.' }),
    colTarget: t({ it: 'Host su cui è stata rilevata la violazione.', en: 'Host where the violation was detected.' }),
  },

  // --- Threat Detection › scheda Esplora (faccette) -----------------------
  exploreFacet: tmap({
    source_host: { it: 'Filtra gli eventi per host di origine.', en: 'Filter events by source host.' },
    event_category: { it: 'Filtra per categoria di evento (es. persistenza, escalation).', en: 'Filter by event category (e.g. persistence, escalation).' },
    event_type: { it: 'Filtra per tipo specifico di evento/syscall.', en: 'Filter by the specific event/syscall type.' },
    user_name: { it: 'Filtra per utente che ha generato l’evento.', en: 'Filter by the user that generated the event.' },
    mitre_tactic: { it: 'Filtra per tattica MITRE ATT&CK associata.', en: 'Filter by the associated MITRE ATT&CK tactic.' },
    sensor: { it: 'Filtra per sorgente: sensore eBPF (kernel) o auditd/Laurel.', en: 'Filter by source: eBPF sensor (kernel) or auditd/Laurel.' },
  }),

  // --- Dashboard -----------------------------------------------------------
  dashboard: {
    statTotal: t({ it: 'Numero totale di target registrati sulla piattaforma.', en: 'Total number of targets registered on the platform.' }),
    statOnline: t({ it: 'Target attualmente online (in comunicazione col server).', en: 'Targets currently online (communicating with the server).' }),
    statViolations: t({ it: 'Violazioni di conformità ancora aperte (stato “nuovo”).', en: 'Compliance violations still open (status “new”).' }),
    statAlerts: t({ it: 'Alert di sicurezza attualmente attivi.', en: 'Security alerts currently active.' }),
  },

  // --- Monitoring ----------------------------------------------------------
  monitoring: {
    statTotal: t({ it: 'Numero totale di target registrati.', en: 'Total number of registered targets.' }),
    statOnline: t({ it: 'Target che comunicano regolarmente col server.', en: 'Targets communicating regularly with the server.' }),
    statOffline: t({ it: 'Target senza contatto recente.', en: 'Targets with no recent contact.' }),
    statLastData: t({ it: 'Timestamp del dato di monitoraggio più recente ricevuto.', en: 'Timestamp of the most recent monitoring data received.' }),
  },

  // --- Remediation (per tattica) — CyberSheppard è monitoraggio: l'azione è
  // creare regole sugli altri tool della suite, non "risolvere" qui. ---------
  remediation: tmap({
    initial_access: { it: 'Rivedi l’esposizione dei servizi e le regole in ingresso su FireDog (iptables).', en: 'Review service exposure and inbound FireDog (iptables) rules.' },
    execution: { it: 'Esecuzione sospetta: valuta una regola FireDog per bloccare binario/porta e applica un template di hardening al target.', en: 'Suspicious execution: consider a FireDog rule to block the binary/port and apply a hardening template to the target.' },
    persistence: { it: 'Rimuovi il meccanismo di persistenza (cron/unit/autostart) sull’host e verificane l’integrità.', en: 'Remove the persistence mechanism (cron/unit/autostart) on the host and verify its integrity.' },
    privilege_escalation: { it: 'Verifica binari SUID e policy sudo; applica un template di hardening al target.', en: 'Check SUID binaries and sudo policy; apply a hardening template to the target.' },
    defense_evasion: { it: 'Verifica integrità di audit/Laurel e dei sensori sull’host (possibile tentativo di evasione).', en: 'Verify audit/Laurel and sensor integrity on the host (possible evasion attempt).' },
    credential_access: { it: 'Ruota le credenziali potenzialmente esposte e irrigidisci i permessi dei file sensibili.', en: 'Rotate potentially exposed credentials and tighten sensitive-file permissions.' },
    discovery: { it: 'Attività ricognitiva: monitora l’host. Connessioni da/verso asset non presenti nell’inventario SentinelCore sono sospette.', en: 'Recon activity: monitor the host. Connections to/from assets not in the SentinelCore inventory are suspicious.' },
    lateral_movement: { it: 'Restringi gli accessi tra host con regole FireDog; verifica che gli asset coinvolti siano nell’inventario SentinelCore.', en: 'Restrict host-to-host access with FireDog rules; check the involved assets are in the SentinelCore inventory.' },
    command_and_control: { it: 'Blocca l’IP/destinazione C2 con una regola FireDog (iptables) sull’host.', en: 'Block the C2 IP/destination with a FireDog (iptables) rule on the host.' },
    exfiltration: { it: 'Blocca la destinazione con una regola FireDog e verifica i volumi di traffico in uscita.', en: 'Block the destination with a FireDog rule and check outbound traffic volumes.' },
    impact: { it: 'Isola l’host (regola FireDog) e verifica backup e integrità dei dati.', en: 'Isolate the host (FireDog rule) and verify backups and data integrity.' },
  }),

  // --- Etichette UI raggruppamento / colonne dinamiche ---------------------
  ui: {
    colRemediation: t({ it: 'Rimedio', en: 'Remediation' }),
    colRemediationInfo: t({
      it: 'Azione consigliata sugli altri tool della suite (es. FireDog/iptables, hardening, inventario SentinelCore). CyberSheppard monitora e segnala: la mitigazione avviene lì.',
      en: 'Suggested action on the other suite tools (e.g. FireDog/iptables, hardening, SentinelCore inventory). CyberSheppard monitors and reports: mitigation happens there.',
    }),
    occurrences: t({ it: 'occorrenze', en: 'occurrences' }),
    firstSeen: t({ it: 'prima vista', en: 'first seen' }),
    lastSeen: t({ it: 'ultima vista', en: 'last seen' }),
    showOccurrences: t({ it: 'Mostra le occorrenze', en: 'Show occurrences' }),
    hideOccurrences: t({ it: 'Nascondi le occorrenze', en: 'Hide occurrences' }),
    groupWindowLabel: t({ it: 'Raggruppa correlazioni ripetute', en: 'Group repeated correlations' }),
    groupWindowHelp: t({
      it: 'Raccoglie le occorrenze ripetute della stessa correlazione entro la finestra scelta, mostrando un contatore ×N e lo storico nel dettaglio. “Off” = elenco piatto di ogni singola occorrenza.',
      en: 'Collapses repeated occurrences of the same correlation within the chosen window, showing an ×N counter and the history in the detail. “Off” = flat list of every single occurrence.',
    }),
    groupOff: t({ it: 'Off — storico piatto', en: 'Off — flat history' }),
    countLabel: t({ it: 'occorrenze raggruppate entro la finestra scelta', en: 'occurrences grouped within the chosen window' }),
    remediationDefault: t({ it: 'Valuta una regola di blocco/hardening sugli strumenti della suite (FireDog, SentinelCore).', en: 'Consider a block/hardening rule on the suite tools (FireDog, SentinelCore).' }),
  },
};
