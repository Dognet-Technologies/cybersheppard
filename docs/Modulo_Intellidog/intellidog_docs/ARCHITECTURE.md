# Intellidog - Architecture Documentation

**Version**: 1.0.0  
**Last Updated**: 2025-01-15  
**Author**: Dognet Technologies  
**Status**: Production-Ready Specification

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Architecture](#system-architecture)
3. [Component Architecture](#component-architecture)
4. [Data Architecture](#data-architecture)
5. [Integration Architecture](#integration-architecture)
6. [Security Architecture](#security-architecture)
7. [Performance & Scalability](#performance--scalability)
8. [Deployment Architecture](#deployment-architecture)
9. [Monitoring & Observability](#monitoring--observability)

---

## Executive Summary

### What is Intellidog?

Intellidog is a premium threat intelligence module for MicroSIEM that transforms reactive security monitoring into proactive threat hunting. Unlike standalone threat intelligence platforms, Intellidog is deeply integrated with the existing MicroSIEM ecosystem, leveraging:

- **Real-time data correlation** with Firedog (firewall management)
- **Vulnerability context** from Sentinel Core (vulnerability management)
- **Operational logs** from MicroSIEM monitoring agents

### Core Capabilities

```
┌─────────────────────────────────────────────────────────────────┐
│ INTELLIDOG CORE CAPABILITIES                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│ 1. THREAT INTELLIGENCE AGGREGATION                              │
│    └─ Multi-source IoC feeds (MISP, OTX, AbuseIPDB)             │
│    └─ 500k+ indicators (IP, domain, hash, URL)                  │
│    └─ Real-time updates (webhook + scheduled sync)              │
│                                                                  │
│ 2. EXPLOIT DETECTION ENGINE                                     │
│    └─ Multi-layer correlation (IoC + Behavioral + Network)      │
│    └─ Confidence scoring (0-100%)                               │
│    └─ Attack timeline reconstruction                            │
│                                                                  │
│ 3. VIRTUAL PATCHING                                             │
│    └─ Automated mitigation (when official patch unavailable)    │
│    └─ Firedog integration (iptables/ModSecurity rules)          │
│    └─ Testing mode → Block mode lifecycle                       │
│                                                                  │
│ 4. THREAT HUNTING                                               │
│    └─ Sigma rule library (100+ detection rules)                 │
│    └─ Custom query builder                                      │
│    └─ Historical IoC search (90-day retention)                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Key Differentiators

| Traditional Threat Intel | Intellidog |
|--------------------------|------------|
| Standalone platform | Integrated module |
| API-only data access | Local replica (PostgreSQL) |
| IoC lists (passive) | Active correlation + detection |
| Manual remediation | Automated virtual patching |
| Separate tools/UX | Unified MicroSIEM interface |

---

## System Architecture

### High-Level Overview

```
┌────────────────────────────────────────────────────────────────────────┐
│                         INTELLIDOG ECOSYSTEM                           │
└────────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────────────────┐
                    │   External Threat Intel     │
                    │   Feeds (Internet)          │
                    ├─────────────────────────────┤
                    │ • MISP (Community)          │
                    │ • AlienVault OTX            │
                    │ • AbuseIPDB                 │
                    │ • Shodan (Premium)          │
                    │ • VirusTotal (Premium)      │
                    └──────────┬──────────────────┘
                               │ HTTPS/API
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                       INTELLIDOG MODULE                              │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │ BACKEND (Python/FastAPI)                                   │    │
│  ├────────────────────────────────────────────────────────────┤    │
│  │                                                             │    │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐   │    │
│  │  │ Feed Sync   │  │ Correlation  │  │ Virtual Patch   │   │    │
│  │  │ Service     │  │ Engine       │  │ Service         │   │    │
│  │  └─────────────┘  └──────────────┘  └─────────────────┘   │    │
│  │                                                             │    │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐   │    │
│  │  │ Threat      │  │ License      │  │ API Layer       │   │    │
│  │  │ Hunting     │  │ Validator    │  │ (FastAPI)       │   │    │
│  │  └─────────────┘  └──────────────┘  └─────────────────┘   │    │
│  │                                                             │    │
│  └─────────────────────┬───────────────────────────────────────┘    │
│                        │                                            │
│  ┌─────────────────────▼───────────────────────────────────────┐    │
│  │ DATA LAYER                                                   │    │
│  ├──────────────────────────────────────────────────────────────┤    │
│  │                                                              │    │
│  │  PostgreSQL (Relational)       InfluxDB (Time-Series)       │    │
│  │  ├─ intellidog schema           ├─ Detections metrics       │    │
│  │  ├─ firedog_replica             ├─ Vpatch effectiveness     │    │
│  │  └─ sentinel_replica            └─ Feed sync metrics        │    │
│  │                                                              │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │ FRONTEND (React/TypeScript)                                │    │
│  ├────────────────────────────────────────────────────────────┤    │
│  │                                                             │    │
│  │  • Threat Intel Dashboard    • Detection Management        │    │
│  │  • Virtual Patch Manager     • Threat Hunting UI           │    │
│  │  • Feed Configuration        • Real-time Alerts (WS)       │    │
│  │                                                             │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
                               │
                               │ Integration
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    DOGNET ECOSYSTEM                                  │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │
│  │   MicroSIEM     │  │    Firedog      │  │  Sentinel Core  │    │
│  │   (Base)        │  │   (Firewall)    │  │   (Vuln Mgmt)   │    │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘    │
│           │                    │                     │             │
│           │  PostgreSQL        │  PostgreSQL         │  PostgreSQL │
│           │  Replication       │  Replication        │             │
│           │                    │                     │             │
│           └────────────────────┴─────────────────────┘             │
│                                │                                    │
│                                ▼                                    │
│                    Intellidog Subscriber DB                         │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Architecture Principles

1. **Modularity**: Intellidog is a self-contained module that extends MicroSIEM without modifying core codebase
2. **Integration-First**: Deep integration with Firedog and Sentinel Core via database replication (not API polling)
3. **Performance**: Local data access (replicated tables) ensures <5ms query times
4. **Scalability**: Hybrid PostgreSQL (relational) + InfluxDB (time-series) for optimal performance
5. **Security**: GPG-signed licensing, AES-256 encrypted API keys, read-only database replicas

---

## Component Architecture

### Backend Components

#### 1. Feed Synchronization Service

**Responsibility**: Manage threat intelligence feed updates

```
┌─────────────────────────────────────────────────────────────┐
│ Feed Synchronization Architecture                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Feed Manager (Orchestrator)                          │   │
│  └───────┬──────────────────────────────────────────────┘   │
│          │                                                   │
│          ├──► MISP Feed Connector                           │
│          │    ├─ Sync Interval: 4 hours                     │
│          │    ├─ Method: Webhook + Scheduled                │
│          │    └─ Volume: ~500k IoC                          │
│          │                                                   │
│          ├──► AlienVault OTX Connector                      │
│          │    ├─ Sync Interval: 1 hour                      │
│          │    ├─ Method: REST API                           │
│          │    └─ Volume: ~2M IoC                            │
│          │                                                   │
│          └──► AbuseIPDB Connector                           │
│               ├─ Sync: On-demand (query)                    │
│               ├─ Method: REST API                           │
│               └─ Cache TTL: 24 hours                        │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ IoC Processing Pipeline                              │   │
│  ├──────────────────────────────────────────────────────┤   │
│  │                                                       │   │
│  │  1. Deduplication (SHA256 hash of IoC value)         │   │
│  │  2. Normalization (IP, domain, hash formatting)      │   │
│  │  3. Enrichment (merge data from multiple feeds)      │   │
│  │  4. Confidence Aggregation (weighted average)        │   │
│  │  5. Storage (PostgreSQL + InfluxDB metrics)          │   │
│  │                                                       │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Key Classes**:
- `BaseFeed` (abstract): Common interface for all feeds
- `MISPFeed`: MISP-specific connector
- `OTXFeed`: AlienVault OTX connector
- `AbuseIPDBFeed`: AbuseIPDB connector
- `FeedManager`: Orchestrator for sync scheduling
- `IoCSanitizer`: Normalization and validation

**Data Flow**:
1. Celery periodic task triggers `FeedManager.sync_all()`
2. Feed connectors fetch new IoC from external APIs
3. IoC processed through deduplication pipeline
4. Stored in `intellidog_iocs` table
5. Metrics written to InfluxDB (`feed_sync_metrics`)

---

#### 2. Correlation Engine

**Responsibility**: Detect active exploitation of vulnerabilities

```
┌─────────────────────────────────────────────────────────────┐
│ Exploit Detection - Multi-Layer Correlation                 │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  INPUT SOURCES:                                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │ MicroSIEM  │  │  Firedog   │  │  Sentinel  │            │
│  │ Logs       │  │  Firewall  │  │  Core CVE  │            │
│  └──────┬─────┘  └──────┬─────┘  └──────┬─────┘            │
│         │               │               │                   │
│         └───────────────┴───────────────┘                   │
│                         │                                    │
│                         ▼                                    │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ CORRELATION LAYERS                                    │   │
│  ├──────────────────────────────────────────────────────┤   │
│  │                                                       │   │
│  │ Layer 1: IoC Matching (25% weight)                   │   │
│  │ ├─ Match IP addresses in logs with threat intel      │   │
│  │ ├─ Match domains in DNS queries                      │   │
│  │ └─ Match file hashes in file system events           │   │
│  │                                                       │   │
│  │ Layer 2: Behavioral Analysis (30% weight)            │   │
│  │ ├─ Syscall anomalies (web server spawning shell)     │   │
│  │ ├─ Process tree anomalies (unexpected parent/child)  │   │
│  │ └─ File system anomalies (suspicious file creation)  │   │
│  │                                                       │   │
│  │ Layer 3: Network Analysis (25% weight)               │   │
│  │ ├─ C2 beaconing patterns (periodic connections)      │   │
│  │ ├─ Outbound connections to non-whitelisted IPs       │   │
│  │ └─ Data exfiltration patterns (volume anomalies)     │   │
│  │                                                       │   │
│  │ Layer 4: Pattern Matching (20% weight)               │   │
│  │ ├─ Known exploit signatures (from CVE database)      │   │
│  │ ├─ Attack patterns (MITRE ATT&CK techniques)         │   │
│  │ └─ Sigma rule matches                                │   │
│  │                                                       │   │
│  └───────────────────────┬───────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ CONFIDENCE SCORING                                    │   │
│  ├──────────────────────────────────────────────────────┤   │
│  │                                                       │   │
│  │ Score = (L1 * 0.25) + (L2 * 0.30) + (L3 * 0.25)     │   │
│  │         + (L4 * 0.20)                                │   │
│  │                                                       │   │
│  │ Classification:                                       │   │
│  │   0-30%  → LOW (Monitor)                             │   │
│  │   30-70% → MEDIUM (Investigate)                      │   │
│  │   70-90% → HIGH (Urgent remediation)                 │   │
│  │   90-100% → CONFIRMED (Incident response)            │   │
│  │                                                       │   │
│  └───────────────────────┬───────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ ATTACK RECONSTRUCTION                                 │   │
│  ├──────────────────────────────────────────────────────┤   │
│  │                                                       │   │
│  │ • Timeline assembly (chronological event ordering)    │   │
│  │ • Kill chain mapping (reconnaissance → exfiltration) │   │
│  │ • MITRE ATT&CK attribution (tactics & techniques)    │   │
│  │ • Evidence collection (logs, IoC, anomalies)         │   │
│  │ • Recommendation generation (remediation steps)      │   │
│  │                                                       │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Key Classes**:
- `IoCSentinelCoreMatcher`: Correlate IoC with CVE from Sentinel Core
- `BehavioralAnalyzer`: Detect syscall/process anomalies
- `NetworkAnalyzer`: Identify C2 communication patterns
- `ConfidenceScorer`: Calculate detection confidence
- `AttackReconstructor`: Build attack timeline

**Example Query** (using replicated data):
```sql
-- Find machines with CVE that has active exploit attempts
SELECT 
    d.machine_id,
    d.hostname,
    d.cve_id,
    v.cvss_score,
    v.epss_score,
    d.confidence,
    COUNT(d.ioc_matches) as ioc_match_count
FROM intellidog_detections d
JOIN sentinel_replica.vulnerabilities v 
    ON d.cve_id = v.cve_id
WHERE d.confidence >= 70
  AND v.exploit_available = true
GROUP BY d.machine_id, d.hostname, d.cve_id, v.cvss_score, v.epss_score, d.confidence
ORDER BY v.cvss_score DESC, d.confidence DESC;
```

**Performance**: <50ms for full correlation analysis (thanks to local replica data)

---

#### 3. Virtual Patching Service

**Responsibility**: Automated mitigation when official patches unavailable

```
┌─────────────────────────────────────────────────────────────┐
│ Virtual Patching Lifecycle                                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  PHASE 1: DETECTION                                          │
│  ┌────────────────────────────────────────────────────┐     │
│  │ Intellidog detects exploited CVE                   │     │
│  │ No official patch available (EOL software)         │     │
│  │ Asset exposed to Internet (high risk)              │     │
│  └────────────────┬───────────────────────────────────┘     │
│                   ▼                                          │
│  PHASE 2: RULE GENERATION                                    │
│  ┌────────────────────────────────────────────────────┐     │
│  │ VirtualPatchGenerator analyzes:                    │     │
│  │ ├─ CVE details (NVD, vendor advisory)              │     │
│  │ ├─ Exploit PoC (identify attack pattern)           │     │
│  │ └─ Asset config (Apache, ModSecurity available?)   │     │
│  │                                                     │     │
│  │ Generated rules (multiple layers):                 │     │
│  │ ├─ Network: iptables (block exploit traffic)       │     │
│  │ ├─ Application: ModSecurity WAF (HTTP-aware)       │     │
│  │ └─ System: AppArmor profile (defense-in-depth)     │     │
│  └────────────────┬───────────────────────────────────┘     │
│                   ▼                                          │
│  PHASE 3: TESTING (48 hours)                                 │
│  ┌────────────────────────────────────────────────────┐     │
│  │ Deploy in ALERT-ONLY mode                          │     │
│  │ ├─ Rules log but don't block                       │     │
│  │ ├─ Monitor false positive rate                     │     │
│  │ └─ Verify legitimate traffic unaffected            │     │
│  │                                                     │     │
│  │ Metrics collected:                                 │     │
│  │ ├─ Exploit attempts matched: 47                    │     │
│  │ ├─ False positives: 2 (0.4%)                       │     │
│  │ └─ Decision: Activate (FP rate < 5%)               │     │
│  └────────────────┬───────────────────────────────────┘     │
│                   ▼                                          │
│  PHASE 4: ACTIVATION                                         │
│  ┌────────────────────────────────────────────────────┐     │
│  │ Switch to BLOCK mode                               │     │
│  │ ├─ Update Firedog rules via API                    │     │
│  │ ├─ Apply to target machine                         │     │
│  │ └─ Notify SOC team                                 │     │
│  └────────────────┬───────────────────────────────────┘     │
│                   ▼                                          │
│  PHASE 5: MONITORING                                         │
│  ┌────────────────────────────────────────────────────┐     │
│  │ Continuous validation:                             │     │
│  │ ├─ Count exploit attempts blocked (daily)          │     │
│  │ ├─ Monitor false positive rate                     │     │
│  │ ├─ Alert if bypass detected (new variant)          │     │
│  │ └─ Check: Is official patch available?             │     │
│  └────────────────┬───────────────────────────────────┘     │
│                   ▼                                          │
│  PHASE 6: DECOMMISSIONING                                    │
│  ┌────────────────────────────────────────────────────┐     │
│  │ When official patch applied:                       │     │
│  │ ├─ Verify vulnerability resolved (re-scan)         │     │
│  │ ├─ Remove virtual patch rules from Firedog         │     │
│  │ └─ Archive metrics (14 days protected)             │     │
│  └────────────────────────────────────────────────────┘     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Firedog Integration**:
```python
# Example: Deploy virtual patch via Firedog API
firedog_client = FiredogClient(
    base_url=settings.FIREDOG_API_URL,
    api_key=decrypt_api_key(settings.FIREDOG_API_KEY_ENCRYPTED)
)

# Create iptables rule (alert mode)
alert_rule = """
iptables -A INPUT -p tcp --dport 80 \
  -m string --algo bm --string "/../" \
  -j LOG --log-prefix "VPATCH-ALERT-CVE-2021-41773: "
"""

firedog_rule = firedog_client.create_rule(
    machine_id=machine_id,
    rule_data={
        'cve_id': 'CVE-2021-41773',
        'iptables_command': alert_rule,
        'enabled': True
    }
)

# Store virtual patch record
vpatch = VirtualPatch(
    machine_id=machine_id,
    cve_id='CVE-2021-41773',
    patch_type='iptables',
    patch_rules=alert_rule,
    status='testing',
    mode='alert',
    firedog_rule_id=firedog_rule['id']
)
db.session.add(vpatch)
db.session.commit()
```

**Key Classes**:
- `VirtualPatchGenerator`: Generate iptables/ModSecurity rules
- `RuleValidator`: Syntax check and conflict detection
- `PatchLifecycleManager`: Orchestrate testing → activation → decommission
- `FiredogClient`: API wrapper for Firedog integration

---

#### 4. Threat Hunting Service

**Responsibility**: Proactive search for indicators of compromise

```
┌─────────────────────────────────────────────────────────────┐
│ Threat Hunting Architecture                                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Sigma Rule Engine                                    │   │
│  ├──────────────────────────────────────────────────────┤   │
│  │                                                       │   │
│  │ Sigma YAML → Query Translation                       │   │
│  │                                                       │   │
│  │ Input:                                                │   │
│  │   title: Suspicious PowerShell Execution             │   │
│  │   detection:                                          │   │
│  │     selection:                                        │   │
│  │       type: 'EXECVE'                                  │   │
│  │       a0|contains: 'powershell'                       │   │
│  │                                                       │   │
│  │ Output (SQL):                                         │   │
│  │   SELECT * FROM logs                                  │   │
│  │   WHERE type = 'EXECVE'                               │   │
│  │     AND a0 LIKE '%powershell%'                        │   │
│  │                                                       │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Custom Query Builder                                  │   │
│  ├──────────────────────────────────────────────────────┤   │
│  │                                                       │   │
│  │ UI-based query construction:                          │   │
│  │                                                       │   │
│  │ [Field: source_ip]                                    │   │
│  │ [Operator: reputation_score_gt]                       │   │
│  │ [Value: 80]                                           │   │
│  │ [Source: AbuseIPDB]                                   │   │
│  │                                                       │   │
│  │ Generated query:                                      │   │
│  │   Find all SSH login attempts from IPs with           │   │
│  │   AbuseIPDB score > 80 in last 30 days                │   │
│  │                                                       │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Historical IoC Search                                 │   │
│  ├──────────────────────────────────────────────────────┤   │
│  │                                                       │   │
│  │ Scenario: New IoC published today                     │   │
│  │ Action: Search 90-day log retention                   │   │
│  │                                                       │   │
│  │ Example:                                              │   │
│  │   IoC: 203.0.113.50 (malicious IP)                   │   │
│  │   Search: MicroSIEM logs (past 90 days)               │   │
│  │   Result:                                             │   │
│  │     - 2024-11-20: First seen (DNS query)              │   │
│  │     - 2024-12-05: SSH brute force attempt             │   │
│  │     - 2025-01-10: Apache exploit attempt              │   │
│  │                                                       │   │
│  │ Conclusion: Compromised 3 months ago (unknown)        │   │
│  │                                                       │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Sigma Rule Library**:
- **100+ pre-loaded rules** (from Sigma HQ GitHub)
- **Categories**: Persistence, Privilege Escalation, Defense Evasion, Lateral Movement, etc.
- **MITRE ATT&CK mapping**: Each rule tagged with tactics/techniques

**Key Classes**:
- `SigmaEngine`: Parse and execute Sigma rules
- `QueryBuilder`: Visual query construction
- `CampaignManager`: Orchestrate multi-query hunting campaigns
- `HistoricalSearch`: Search IoC in archived logs

---

### Frontend Components

#### Component Hierarchy

```
IntellidogModule
│
├── Pages
│   ├── ThreatIntelPage
│   │   └── Components
│   │       ├── ThreatIntelDashboard (overview metrics)
│   │       ├── IoCSummary (feed breakdown)
│   │       └── TopThreats (most active threat actors)
│   │
│   ├── DetectionsPage
│   │   └── Components
│   │       ├── ExploitDetectionTable (filterable list)
│   │       ├── DetectionDetailModal (evidence, timeline)
│   │       └── ConfidenceChart (score distribution)
│   │
│   ├── VirtualPatchesPage
│   │   └── Components
│   │       ├── VirtualPatchManager (active patches list)
│   │       ├── VPatchCreationWizard (step-by-step creation)
│   │       └── EffectivenessMetrics (blocks, false positives)
│   │
│   └── HuntingPage
│       └── Components
│           ├── HuntingQueryBuilder (visual builder)
│           ├── SavedQueriesList (library)
│           ├── CampaignManager (multi-query campaigns)
│           └── ResultsVisualization (timeline, graphs)
│
├── Services
│   ├── intellidog.api.ts (REST API client)
│   ├── intellidog.websocket.ts (real-time updates)
│   └── intellidog.helpers.ts (utility functions)
│
└── Types
    ├── ioc.types.ts
    ├── detection.types.ts
    ├── vpatch.types.ts
    └── hunting.types.ts
```

#### Real-Time Updates (WebSocket)

```typescript
// WebSocket events subscription
const ws = new IntellidogWebSocket();

ws.on('detection.new', (detection) => {
  // New exploit detection
  showNotification({
    severity: detection.severity,
    title: `Exploit Detected: ${detection.cve_id}`,
    message: `Confidence: ${detection.confidence}%`,
    action: () => navigate(`/detections/${detection.id}`)
  });
});

ws.on('vpatch.deployed', (vpatch) => {
  // Virtual patch deployed
  updateVirtualPatchList();
});

ws.on('feed.sync.completed', (feed) => {
  // Feed sync finished
  updateIoCCount(feed.name, feed.new_iocs);
});
```

---

## Data Architecture

### Database Strategy: Hybrid Approach

**Why Hybrid?**

| Data Type | Storage | Reason |
|-----------|---------|--------|
| IoC database | PostgreSQL | Relational queries, ACID, complex joins |
| CVE metadata | PostgreSQL (replica) | Join with detections, foreign keys |
| Firewall rules | PostgreSQL (replica) | Relational integrity with vpatches |
| Detection metadata | PostgreSQL | Audit trail, filtering, search |
| Detection time-series | InfluxDB | Trending, dashboards, aggregations |
| Vpatch metrics | InfluxDB | Performance tracking over time |
| Feed sync metrics | InfluxDB | Monitoring, alerting |

### PostgreSQL Schema

#### Native Tables (intellidog schema)

**Key Tables**:
1. `intellidog_iocs` - Indicators of Compromise
2. `intellidog_detections` - Exploit detection events
3. `intellidog_virtual_patches` - Virtual patch records
4. `intellidog_feeds` - Feed configuration and status
5. `intellidog_hunting_queries` - Saved threat hunting queries
6. `intellidog_sigma_rules` - Sigma detection rule library
7. `intellidog_license` - License management
8. `system_integrations` - API keys (encrypted)

**Indexes** (performance-critical):
```sql
-- Fast IoC lookup
CREATE INDEX idx_iocs_type_value_hash 
ON intellidog_iocs(ioc_type, ioc_value_hash);

-- Fast detection filtering
CREATE INDEX idx_detections_confidence 
ON intellidog_detections(confidence) 
WHERE confidence >= 70;

-- Time-based queries
CREATE INDEX idx_detections_detected_at 
ON intellidog_detections(detected_at DESC);
```

#### Replicated Schemas (read-only)

**firedog_replica**:
- `firewall_rules` - Active firewall rules
- `machines` - Managed machines
- `rule_stats` - Rule effectiveness metrics
- `rule_logs` - Firewall logs

**sentinel_replica**:
- `vulnerabilities` - Detected vulnerabilities
- `cves` - CVE database
- `machines` - Scanned machines
- `scan_results` - Scan history
- `cve_exploits` - Exploit availability
- `epss_scores` - EPSS prediction scores

**Replication Setup**:
```sql
-- On Firedog database
CREATE PUBLICATION firedog_to_intellidog FOR TABLE
    firewall_rules,
    machines,
    rule_stats;

-- On Intellidog database
CREATE SUBSCRIPTION firedog_sub
    CONNECTION 'host=firedog-db port=5432 dbname=firedog user=firedog_replication password=***'
    PUBLICATION firedog_to_intellidog
    WITH (copy_data = true, synchronous_commit = off);
```

**Replication Lag Monitoring**:
```sql
SELECT 
    subname,
    NOW() - latest_end_time AS replication_lag
FROM pg_stat_subscription
WHERE subname IN ('firedog_sub', 'sentinel_sub');

-- Expected: < 1 second
-- Warning: > 5 seconds
-- Critical: > 30 seconds
```

### InfluxDB Schema

#### Measurements

**1. intellidog_detections** (time-series)
```
Tags (indexed):
  - machine_id
  - hostname
  - cve_id
  - severity (low/medium/high/critical)
  - status (open/investigating/resolved)

Fields (values):
  - confidence (int, 0-100)
  - ioc_count (int)
  - behavioral_anomaly_count (int)
  - network_anomaly_count (int)

Retention: 90 days
```

**2. vpatch_effectiveness** (metrics)
```
Tags:
  - vpatch_id
  - machine_id
  - cve_id
  - mode (alert/block)

Fields:
  - exploits_blocked (int)
  - false_positives (int)
  - packets_matched (int)
  - bytes_blocked (int)

Retention: 365 days
```

**3. feed_sync_metrics** (monitoring)
```
Tags:
  - feed_name (misp/otx/abuseipdb)
  - status (success/failed)

Fields:
  - ioc_count (int)
  - sync_duration_ms (int)
  - errors (int)
  - new_iocs (int)
  - updated_iocs (int)

Retention: 30 days
```

#### Query Examples

**Detection Trend (Last 7 Days)**:
```flux
from(bucket: "intellidog")
  |> range(start: -7d)
  |> filter(fn: (r) => r._measurement == "intellidog_detections")
  |> filter(fn: (r) => r.severity == "critical")
  |> aggregateWindow(every: 1h, fn: count)
  |> yield(name: "critical_detections_hourly")
```

**Virtual Patch Effectiveness**:
```flux
from(bucket: "intellidog")
  |> range(start: -30d)
  |> filter(fn: (r) => r._measurement == "vpatch_effectiveness")
  |> filter(fn: (r) => r._field == "exploits_blocked")
  |> sum()
```

---

## Integration Architecture

### 1. MicroSIEM Integration

**Integration Points**:
- **Shared Authentication**: JWT tokens from MicroSIEM
- **Unified UI**: Intellidog pages in MicroSIEM navigation
- **Log Access**: Query MicroSIEM log database for correlation
- **Alerting**: Intellidog detections → MicroSIEM alert system

**Data Flow**:
```
MicroSIEM Logs → Intellidog Correlation → Detection → MicroSIEM Alert
```

### 2. Firedog Integration

**Integration Method**: PostgreSQL Logical Replication + REST API

**Replication** (read access):
- Purpose: Query firewall rules, machine status
- Lag: <1 second (asynchronous)
- Tables: `firewall_rules`, `machines`, `rule_stats`

**REST API** (write access):
- Purpose: Deploy virtual patch rules
- Endpoints:
  - `POST /api/v1/rules` (create rule)
  - `PUT /api/v1/rules/{id}` (update rule)
  - `DELETE /api/v1/rules/{id}` (remove rule)
  - `POST /api/v1/rules/apply` (apply to target)

**Authentication**: API key stored encrypted in `system_integrations` table

**Example**:
```python
# Read: Query replicated data (local, fast)
firewall_rules = db.session.query(FiredogReplica.FirewallRule)\
    .filter(FiredogReplica.FirewallRule.machine_id == machine_id)\
    .all()

# Write: Deploy virtual patch via API (remote)
firedog_api.create_rule(
    machine_id=machine_id,
    rule_data={'iptables_command': '...', 'description': 'Virtual Patch CVE-2024-1234'}
)
```

### 3. Sentinel Core Integration

**Integration Method**: PostgreSQL Logical Replication

**Replicated Data**:
- `vulnerabilities` - Detected CVEs on machines
- `cves` - CVE metadata (CVSS, EPSS, exploit availability)
- `scan_results` - Scan history

**Use Cases**:
- **CVE Context**: Enrich detections with CVSS/EPSS scores
- **Exploit Availability**: Prioritize CVEs with public exploits
- **Correlation**: Match IoC with vulnerable machines

**Example Query**:
```sql
-- Find machines with exploitable CVEs that have active attacks
SELECT 
    m.hostname,
    v.cve_id,
    v.cvss_score,
    v.epss_score,
    d.confidence AS detection_confidence,
    d.ioc_matches
FROM sentinel_replica.vulnerabilities v
JOIN sentinel_replica.machines m ON v.machine_id = m.id
LEFT JOIN intellidog_detections d ON v.cve_id = d.cve_id AND v.machine_id = d.machine_id
WHERE v.exploit_available = true
  AND d.confidence >= 70
ORDER BY v.cvss_score DESC;
```

### 4. External Threat Intel Feeds

**Feed Architecture**:

```
┌──────────────────────────────────────────────────────────┐
│ External Feeds (Internet)                                │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  MISP                AlienVault OTX       AbuseIPDB      │
│  ├─ REST API        ├─ REST API          ├─ REST API    │
│  ├─ Webhook         ├─ Pulses            ├─ Queries     │
│  └─ Community feeds └─ Subscriptions     └─ Cache 24h   │
│                                                           │
└──────────────┬────────────────────────────────────────────┘
               │ HTTPS (API calls)
               ▼
┌──────────────────────────────────────────────────────────┐
│ Intellidog Feed Connectors                               │
│                                                           │
│  ┌──────────────────────────────────────────────────┐    │
│  │ Feed Manager (Celery Periodic Tasks)             │    │
│  ├──────────────────────────────────────────────────┤    │
│  │                                                   │    │
│  │  • MISP: Sync every 4 hours + webhook            │    │
│  │  • OTX: Sync every 1 hour                        │    │
│  │  • AbuseIPDB: On-demand queries (cached)         │    │
│  │                                                   │    │
│  └──────────────────────────────────────────────────┘    │
│                                                           │
└──────────────┬────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────┐
│ intellidog_iocs (PostgreSQL)                             │
│                                                           │
│  Deduplicated, normalized, enriched IoC database         │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

**API Key Management**:
```sql
-- API keys stored encrypted
INSERT INTO system_integrations (integration_name, api_url, api_key_encrypted)
VALUES (
    'misp',
    'https://misp.example.com',
    pgp_sym_encrypt('misp_api_key_xyz', current_setting('app.encryption_key'))
);

-- Retrieve and decrypt
SELECT 
    integration_name,
    api_url,
    pgp_sym_decrypt(api_key_encrypted, current_setting('app.encryption_key')) as api_key
FROM system_integrations
WHERE integration_name = 'misp';
```

---

## Security Architecture

### 1. Licensing System (GPG Signature)

**License File Structure**:
```
-----BEGIN INTELLIDOG LICENSE-----
eyJjdXN0b21lcl9uYW1lIjogIkFjbWUgQ29ycCIsICJleHBpcmVzX2F0IjogIjIwMjYtMDEtMTUifQ==
-----END INTELLIDOG LICENSE-----
-----BEGIN PGP SIGNATURE-----
iQIzBAABCAAdFiEE...
-----END PGP SIGNATURE-----
```

**Validation Process**:
```python
class LicenseValidator:
    DOGNET_PUBLIC_KEY = """..."""  # Embedded in code
    
    def validate_license(self):
        # 1. Verify GPG signature
        verified = gpg.verify_file('LICENSE')
        if not verified.valid:
            return {'valid': False, 'error': 'Invalid signature'}
        
        # 2. Decode license data
        license_data = json.loads(base64.b64decode(license_b64))
        
        # 3. Check expiration
        if datetime.utcnow() > datetime.fromisoformat(license_data['expires_at']):
            return {'valid': False, 'error': 'License expired'}
        
        # 4. Check machine limit
        if current_machine_count > license_data['max_machines']:
            return {'valid': False, 'error': 'Machine limit exceeded'}
        
        return {'valid': True, 'expires_at': license_data['expires_at']}
```

**License Check Points**:
- **Module bootstrap**: Validate on Intellidog service start
- **Daily check**: Celery task verifies license still valid
- **API calls**: Middleware checks license before processing

### 2. API Key Encryption

**Storage**: PostgreSQL `system_integrations` table  
**Encryption**: AES-256 via `pgcrypto` extension  
**Master Key**: Environment variable (not committed to git)

```sql
-- Encrypt API key before storage
INSERT INTO system_integrations (integration_name, api_key_encrypted)
VALUES (
    'firedog',
    pgp_sym_encrypt('firedog_api_key_abc123', current_setting('app.encryption_key'))
);

-- Decrypt for use
SELECT pgp_sym_decrypt(api_key_encrypted, current_setting('app.encryption_key'))
FROM system_integrations
WHERE integration_name = 'firedog';
```

**Master Key Rotation**:
```bash
# Generate new encryption key
openssl rand -base64 32 > /secure/path/new_encryption_key

# Re-encrypt all API keys with new key
psql -d microsiem -c "UPDATE system_integrations SET api_key_encrypted = pgp_sym_encrypt(pgp_sym_decrypt(api_key_encrypted, 'old_key'), 'new_key');"

# Update environment variable
export APP_ENCRYPTION_KEY=$(cat /secure/path/new_encryption_key)
```

### 3. Database Replication Security

**Authentication**: Dedicated replication user (limited privileges)

```sql
-- On Firedog database
CREATE ROLE firedog_replication WITH REPLICATION LOGIN PASSWORD 'strong_random_password';
GRANT SELECT ON TABLE firewall_rules, machines, rule_stats TO firedog_replication;
-- No INSERT/UPDATE/DELETE privileges
```

**Network Security**: `pg_hba.conf` restricts replication connections

```
# Only allow replication from Intellidog IP
host    replication     firedog_replication     192.168.1.100/32        scram-sha-256
host    firedog         firedog_replication     192.168.1.100/32        scram-sha-256
```

**Encryption**: SSL/TLS for replication traffic (PostgreSQL native)

```sql
-- On Intellidog subscription
CREATE SUBSCRIPTION firedog_sub
    CONNECTION 'host=firedog-db sslmode=require ...'
    PUBLICATION firedog_to_intellidog;
```

### 4. Input Validation & Sanitization

**SQL Injection Prevention**:
- Parameterized queries (SQLAlchemy ORM)
- No raw SQL from user input

**XSS Prevention**:
- React auto-escapes variables
- DOMPurify for rich text fields

**API Input Validation**:
```python
from pydantic import BaseModel, validator, constr

class CreateVirtualPatchRequest(BaseModel):
    machine_id: int
    cve_id: constr(regex=r'^CVE-\d{4}-\d{4,7}$')  # CVE format validation
    mode: Literal['alert', 'block']
    
    @validator('machine_id')
    def validate_machine_exists(cls, v):
        if not db.session.get(Machine, v):
            raise ValueError('Machine not found')
        return v
```

### 5. Audit Logging

**All Security-Relevant Actions Logged**:
```sql
CREATE TABLE intellidog_audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INTEGER,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT NOW()
);

-- Example: Log virtual patch deployment
INSERT INTO intellidog_audit_logs (user_id, action, resource_type, resource_id, details)
VALUES (
    1,
    'vpatch_deployed',
    'virtual_patch',
    123,
    jsonb_build_object('cve_id', 'CVE-2024-1234', 'machine_id', 5, 'mode', 'alert')
);
```

---

## Performance & Scalability

### Performance Targets

| Metric | Target | Critical Threshold |
|--------|--------|--------------------|
| API response time (p95) | <200ms | >500ms |
| IoC lookup query | <5ms | >50ms |
| Correlation analysis | <50ms | >200ms |
| Feed sync (MISP 100k IoC) | <5 minutes | >15 minutes |
| Database replication lag | <1 second | >5 seconds |
| Dashboard load time | <2 seconds | >5 seconds |

### Scalability Considerations

#### 1. Database Scaling

**PostgreSQL**:
- **Current capacity**: 100k IoC, 10k detections/day
- **Horizontal scaling**: Read replicas for reporting queries
- **Vertical scaling**: Up to 32 CPU cores, 128GB RAM

**InfluxDB**:
- **Current capacity**: 1M metrics/hour
- **Retention policies**: Automatic downsampling (1h → 1d → 1w aggregates)
- **Horizontal scaling**: InfluxDB Enterprise clustering

#### 2. Background Task Scaling (Celery)

**Worker Pools**:
```python
# Separate queues for different task priorities
CELERY_ROUTES = {
    'intellidog.tasks.feed_sync': {'queue': 'feed_sync'},
    'intellidog.tasks.correlation': {'queue': 'correlation'},
    'intellidog.tasks.hunting': {'queue': 'hunting'},
}

# Scale workers per queue
celery -A intellidog worker -Q feed_sync -c 4       # 4 workers
celery -A intellidog worker -Q correlation -c 8     # 8 workers (CPU-intensive)
celery -A intellidog worker -Q hunting -c 2         # 2 workers
```

#### 3. Caching Strategy

**Redis Cache**:
```python
# Cache frequently accessed IoC lookups
@cache.memoize(timeout=3600)  # 1 hour TTL
def get_ioc_by_value(ioc_value: str) -> Optional[IoC]:
    return db.session.query(IoC)\
        .filter(IoC.ioc_value_hash == hashlib.sha256(ioc_value.encode()).hexdigest())\
        .first()

# Cache AbuseIPDB queries (avoid API rate limits)
@cache.memoize(timeout=86400)  # 24 hour TTL
def get_abuseipdb_reputation(ip: str) -> dict:
    return abuseipdb_api.check(ip)
```

#### 4. Query Optimization

**Indexes** (already covered in Data Architecture)

**Materialized Views** (for expensive aggregations):
```sql
-- Pre-compute top threat actors (refresh hourly)
CREATE MATERIALIZED VIEW top_threat_actors AS
SELECT 
    source_ip,
    COUNT(*) as total_attempts,
    COUNT(DISTINCT machine_id) as machines_targeted,
    MAX(detected_at) as last_seen
FROM intellidog_detections
WHERE detected_at >= NOW() - INTERVAL '7 days'
GROUP BY source_ip
ORDER BY total_attempts DESC
LIMIT 100;

CREATE UNIQUE INDEX ON top_threat_actors(source_ip);

-- Refresh via Celery task
REFRESH MATERIALIZED VIEW CONCURRENTLY top_threat_actors;
```

---

## Deployment Architecture

### Deployment Topology

```
┌────────────────────────────────────────────────────────────┐
│ PRODUCTION DEPLOYMENT                                      │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Application Servers (Docker Swarm / Kubernetes)      │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │                                                       │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │  │
│  │  │ MicroSIEM   │  │ Intellidog  │  │ Intellidog  │  │  │
│  │  │ (Frontend)  │  │ Backend #1  │  │ Backend #2  │  │  │
│  │  │ Nginx       │  │ Gunicorn    │  │ Gunicorn    │  │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │  │
│  │                                                       │  │
│  │  Load Balancer (HAProxy / Nginx)                     │  │
│  │  ├─ Round-robin backend instances                    │  │
│  │  └─ WebSocket sticky sessions                        │  │
│  │                                                       │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Worker Servers                                        │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │                                                       │  │
│  │  Celery Workers (3 instances)                        │  │
│  │  ├─ feed_sync queue (2 workers)                      │  │
│  │  ├─ correlation queue (4 workers)                    │  │
│  │  └─ hunting queue (2 workers)                        │  │
│  │                                                       │  │
│  │  Celery Beat (scheduler)                             │  │
│  │  └─ Periodic tasks (feed sync, license check)        │  │
│  │                                                       │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Database Tier                                         │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │                                                       │  │
│  │  PostgreSQL (Primary + Read Replica)                 │  │
│  │  ├─ Primary: Write + Read                            │  │
│  │  └─ Replica: Read-only (reporting, dashboards)       │  │
│  │                                                       │  │
│  │  InfluxDB (Single node / Clustered)                  │  │
│  │  └─ Time-series metrics                              │  │
│  │                                                       │  │
│  │  Redis (Master + Sentinel)                           │  │
│  │  ├─ Celery broker                                    │  │
│  │  ├─ Cache layer                                      │  │
│  │  └─ Session storage                                  │  │
│  │                                                       │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
└────────────────────────────────────────────────────────────┘

        │                                  │
        │ PostgreSQL Replication           │
        ▼                                  ▼
┌──────────────┐                  ┌──────────────┐
│   Firedog    │                  │ Sentinel Core│
│   Database   │                  │   Database   │
└──────────────┘                  └──────────────┘
```

### Deployment Steps

**1. Prerequisites**:
- MicroSIEM Base installed and operational
- PostgreSQL 12+ (with `pgcrypto` extension)
- InfluxDB 2.x
- Redis 6+
- Python 3.9+
- Node.js 18+

**2. Database Replication Setup**:
```bash
# Install replication plugins
cd /opt/firedog/plugins
./plugin-manager install firedog-replication-plugin
./firedog-replication-plugin/scripts/install.sh

cd /opt/sentinel/plugins
./plugin-manager install sentinelcore-replication-plugin
./sentinelcore-replication-plugin/scripts/install.sh

cd /opt/microsiem/plugins
./plugin-manager install cybersheppard-replication-plugin
./cybersheppard-replication-plugin/scripts/configure_subscription.py
```

**3. Intellidog Module Installation**:
```bash
# Install Intellidog module
cd /opt/microsiem/modules
git clone https://github.com/dognet-tech/intellidog.git
cd intellidog

# Backend setup
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Database migrations
alembic upgrade head

# Frontend build
cd frontend
npm install
npm run build

# Copy built assets to MicroSIEM static directory
cp -r dist/* /opt/microsiem/frontend/static/intellidog/
```

**4. Configuration**:
```bash
# Add Intellidog environment variables to MicroSIEM .env
cat >> /opt/microsiem/.env <<EOF

# Intellidog Configuration
INTELLIDOG_ENABLED=true
INTELLIDOG_MISP_ENABLED=true
INTELLIDOG_MISP_URL=https://misp.example.com
INTELLIDOG_MISP_API_KEY=your_misp_key
INTELLIDOG_OTX_ENABLED=true
INTELLIDOG_OTX_API_KEY=your_otx_key
INTELLIDOG_ABUSEIPDB_ENABLED=true
INTELLIDOG_ABUSEIPDB_API_KEY=your_abuseipdb_key
APP_ENCRYPTION_KEY=$(openssl rand -base64 32)
EOF
```

**5. License Activation**:
```bash
# Copy license file to module directory
cp /path/to/LICENSE_YourCompany_20250115.txt /opt/microsiem/modules/intellidog/LICENSE

# Validate license
cd /opt/microsiem/modules/intellidog
python scripts/license_check.py

# Expected output:
# ✅ License valid
# Customer: Your Company
# Expires: 2026-01-15
# Max machines: 50
```

**6. Service Start**:
```bash
# Start Intellidog backend
systemctl start intellidog-api
systemctl start intellidog-workers
systemctl start intellidog-beat

# Verify services running
systemctl status intellidog-api
systemctl status intellidog-workers
systemctl status intellidog-beat
```

**7. Verification**:
```bash
# Test replication
cd /opt/microsiem/modules/intellidog
./scripts/test_replication.py

# Test API
curl -H "Authorization: Bearer $JWT_TOKEN" \
     http://localhost:8000/api/intellidog/feeds

# Expected: List of configured feeds
```

---

## Monitoring & Observability

### Metrics Collection

**1. Application Metrics** (Prometheus format)

```python
from prometheus_client import Counter, Histogram, Gauge

# Feed sync metrics
feed_sync_total = Counter('intellidog_feed_sync_total', 'Total feed syncs', ['feed_name', 'status'])
feed_sync_duration = Histogram('intellidog_feed_sync_duration_seconds', 'Feed sync duration', ['feed_name'])
ioc_count = Gauge('intellidog_ioc_count', 'Total IoC count', ['feed_name'])

# Detection metrics
detections_total = Counter('intellidog_detections_total', 'Total detections', ['severity', 'confidence_level'])
correlation_duration = Histogram('intellidog_correlation_duration_seconds', 'Correlation engine duration')

# Virtual patch metrics
vpatch_active = Gauge('intellidog_vpatch_active', 'Active virtual patches')
vpatch_blocks = Counter('intellidog_vpatch_blocks_total', 'Exploit blocks', ['cve_id'])
```

**2. Database Monitoring**

```sql
-- PostgreSQL replication lag
SELECT 
    application_name,
    client_addr,
    state,
    sync_state,
    EXTRACT(EPOCH FROM (NOW() - replay_lag)) as lag_seconds
FROM pg_stat_replication;

-- Table sizes
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as total_size
FROM pg_tables
WHERE schemaname IN ('intellidog', 'firedog_replica', 'sentinel_replica')
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

**3. InfluxDB Monitoring**

```flux
// Query performance
from(bucket: "_monitoring")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "query")
  |> aggregateWindow(every: 5m, fn: mean)
```

### Alerting Rules

**Prometheus Alerts**:
```yaml
groups:
  - name: intellidog
    rules:
      - alert: FeedSyncFailed
        expr: increase(intellidog_feed_sync_total{status="failed"}[1h]) > 3
        for: 5m
        annotations:
          summary: "Feed sync failing repeatedly"
          
      - alert: HighConfidenceDetection
        expr: intellidog_detections_total{confidence_level="confirmed"} > 0
        for: 1m
        annotations:
          summary: "Confirmed exploit detected"
          severity: critical
          
      - alert: ReplicationLagHigh
        expr: pg_replication_lag_seconds > 5
        for: 5m
        annotations:
          summary: "Database replication lag > 5 seconds"
```

### Logging

**Structured Logging** (JSON format):
```python
import structlog

logger = structlog.get_logger()

logger.info(
    "feed_sync_completed",
    feed_name="misp",
    ioc_count=45230,
    duration_seconds=120,
    new_iocs=342,
    updated_iocs=89
)

# Output:
# {"event": "feed_sync_completed", "feed_name": "misp", "ioc_count": 45230, "duration_seconds": 120, "new_iocs": 342, "updated_iocs": 89, "timestamp": "2025-01-15T10:30:00Z"}
```

**Log Aggregation**: Forward to MicroSIEM logging stack (Loki, Elasticsearch, etc.)

---

## Appendices

### A. Glossary

- **IoC**: Indicator of Compromise (malicious IP, domain, hash, etc.)
- **CVE**: Common Vulnerabilities and Exposures identifier
- **CVSS**: Common Vulnerability Scoring System (0-10 severity)
- **EPSS**: Exploit Prediction Scoring System (0-100% likelihood)
- **C2**: Command & Control (attacker infrastructure)
- **MISP**: Malware Information Sharing Platform
- **OTX**: AlienVault Open Threat Exchange
- **Sigma**: Generic signature format for SIEM rules
- **Virtual Patching**: Temporary mitigation (firewall rules) when official patch unavailable

### B. References

- [PostgreSQL Logical Replication Docs](https://www.postgresql.org/docs/current/logical-replication.html)
- [InfluxDB Best Practices](https://docs.influxdata.com/influxdb/v2.0/write-data/best-practices/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

### C. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2025-01-15 | Dognet Technologies | Initial production-ready specification |

---

**End of Architecture Documentation**
