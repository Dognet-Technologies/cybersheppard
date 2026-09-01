// ============================================================================
// ATT&CK Coverage Matrix — copertura detection sulla kill-chain MITRE ATT&CK.
// Aggrega le correlazioni (attack_stage + tecnica) e le proietta sul catalogo
// dei detector ("scuderia" R1–R24): mostra cosa è rilevato di recente, la
// severità e i buchi di copertura.
// ============================================================================

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Crosshair, Activity, ShieldCheck, AlertTriangle } from 'lucide-react';
import api from '../services/api';
import { PageHeader, StatsGrid, StatCard, Select } from '../components/ui';

type Sev = 'critical' | 'high' | 'medium' | 'low';

// Tattiche in ordine kill-chain (id = attack_stage lato backend).
const TACTICS: { id: string; name: string }[] = [
  { id: 'initial_access', name: 'Initial Access' },
  { id: 'execution', name: 'Execution' },
  { id: 'persistence', name: 'Persistence' },
  { id: 'privilege_escalation', name: 'Privilege Escalation' },
  { id: 'defense_evasion', name: 'Defense Evasion' },
  { id: 'credential_access', name: 'Credential Access' },
  { id: 'discovery', name: 'Discovery' },
  { id: 'lateral_movement', name: 'Lateral Movement' },
  { id: 'command_and_control', name: 'Command & Control' },
  { id: 'exfiltration', name: 'Exfiltration' },
  { id: 'impact', name: 'Impact' },
];

// Catalogo "scuderia": tecniche che i detector R1–R24 possono emettere per tattica.
const CAPABILITY: Record<string, { t: string; name: string }[]> = {
  initial_access: [{ t: 'T1078', name: 'Valid Accounts' }],
  execution: [
    { t: 'T1059', name: 'Command & Scripting Interpreter' },
    { t: 'T1620', name: 'Reflective Code Loading' },
  ],
  persistence: [{ t: 'T1547', name: 'Boot/Logon Autostart' }],
  privilege_escalation: [{ t: 'T1548', name: 'Abuse Elevation Control' }],
  defense_evasion: [
    { t: 'T1070', name: 'Indicator Removal' },
    { t: 'T1562', name: 'Impair Defenses' },
    { t: 'T1055', name: 'Process Injection' },
    { t: 'T1574.006', name: 'Dynamic Linker Hijack' },
  ],
  credential_access: [
    { t: 'T1110', name: 'Brute Force' },
    { t: 'T1003', name: 'OS Credential Dumping' },
  ],
  discovery: [
    { t: 'T1082', name: 'System Information Discovery' },
    { t: 'T1083', name: 'File & Directory Discovery' },
    { t: 'T1046', name: 'Network Service Discovery' },
  ],
  lateral_movement: [{ t: 'T1021', name: 'Remote Services' }],
  command_and_control: [{ t: 'T1071', name: 'Application Layer Protocol' }],
  exfiltration: [{ t: 'T1041', name: 'Exfiltration Over C2' }],
  impact: [{ t: 'T1486', name: 'Data Encrypted for Impact' }],
};

const SEV_RANK: Record<Sev, number> = { critical: 4, high: 3, medium: 2, low: 1 };

// Stile cella per severità (rilevata) vs capace-ma-non-rilevata.
const SEV_CELL: Record<Sev, string> = {
  critical: 'bg-red-600 text-white border-red-700 shadow-sm',
  high: 'bg-orange-500 text-white border-orange-600 shadow-sm',
  medium: 'bg-amber-400 text-amber-950 border-amber-500 shadow-sm',
  low: 'bg-sky-400 text-sky-950 border-sky-500',
};
const IDLE_CELL =
  'bg-slate-50 text-slate-400 border-dashed border-slate-300 hover:border-slate-400';

export default function AttackMatrix() {
  const navigate = useNavigate();
  const [hours, setHours] = useState(24);

  const { data: response, isLoading } = useQuery({
    queryKey: ['attack-matrix', hours],
    queryFn: () => api.getSecurityCorrelations({ hours, limit: 500 }),
    refetchInterval: 30000,
  });

  const correlations: any[] = response?.data || [];

  // Aggrega per tecnica: { count, maxSev, tactic }
  const byTechnique = useMemo(() => {
    const map = new Map<string, { count: number; sev: Sev; tactic: string }>();
    for (const c of correlations) {
      const tech: string | undefined = c.correlation_data?.mitre_technique;
      const tactic: string | undefined = c.attack_stage;
      if (!tech || !tactic) continue;
      const sev = (c.severity || 'low') as Sev;
      const key = `${tactic}::${tech}`;
      const cur = map.get(key);
      if (!cur) map.set(key, { count: 1, sev, tactic });
      else {
        cur.count += 1;
        if (SEV_RANK[sev] > SEV_RANK[cur.sev]) cur.sev = sev;
      }
    }
    return map;
  }, [correlations]);

  const stats = useMemo(() => {
    const tacticsHit = new Set<string>();
    const techsHit = new Set<string>();
    let critical = 0;
    for (const c of correlations) {
      if (c.attack_stage) tacticsHit.add(c.attack_stage);
      if (c.correlation_data?.mitre_technique) techsHit.add(c.correlation_data.mitre_technique);
      if (c.severity === 'critical') critical += 1;
    }
    return {
      tacticsCovered: tacticsHit.size,
      techniques: techsHit.size,
      total: correlations.length,
      critical,
    };
  }, [correlations]);

  return (
    <div>
      <PageHeader
        title="MITRE ATT&CK — Copertura Detection"
        subtitle="La kill-chain proiettata sulla scuderia dei detector: cosa è rilevato, con quale severità, e dove restano i buchi"
        icon={<Crosshair className="w-6 h-6" />}
        actions={
          <div className="w-40">
            <Select
              value={String(hours)}
              onChange={(e: any) => setHours(Number(e.target.value))}
            >
              <option value="1">Ultima ora</option>
              <option value="24">Ultime 24h</option>
              <option value="168">Ultimi 7 giorni</option>
            </Select>
          </div>
        }
      />

      <StatsGrid columns={4} className="mb-6">
        <StatCard title="Tattiche coperte" value={`${stats.tacticsCovered}/${TACTICS.length}`} icon={<ShieldCheck className="w-6 h-6" />} variant="info" />
        <StatCard title="Tecniche rilevate" value={stats.techniques} icon={<Crosshair className="w-6 h-6" />} variant="info" />
        <StatCard title="Detection nel periodo" value={stats.total} icon={<Activity className="w-6 h-6" />} variant="warning" />
        <StatCard title="Critiche" value={stats.critical} icon={<AlertTriangle className="w-6 h-6" />} variant="danger" />
      </StatsGrid>

      {/* Legenda */}
      <div className="flex flex-wrap items-center gap-4 mb-4 text-xs text-slate-600">
        <span className="font-semibold text-slate-700">Severità rilevata:</span>
        {(['critical', 'high', 'medium', 'low'] as Sev[]).map((s) => (
          <span key={s} className="inline-flex items-center gap-1.5">
            <span className={`w-3 h-3 rounded ${SEV_CELL[s].split(' ')[0]}`} />
            {s}
          </span>
        ))}
        <span className="inline-flex items-center gap-1.5">
          <span className="w-3 h-3 rounded border border-dashed border-slate-300 bg-slate-50" />
          coperta ma non rilevata
        </span>
      </div>

      {/* Matrice: colonne = tattiche (kill-chain), celle = tecniche */}
      <div className="overflow-x-auto pb-4">
        <div className="flex gap-3 min-w-max">
          {TACTICS.map((tactic) => {
            const caps = CAPABILITY[tactic.id] || [];
            const detectedInTactic = caps.filter((c) =>
              byTechnique.has(`${tactic.id}::${c.t}`),
            ).length;
            return (
              <div key={tactic.id} className="w-52 flex-shrink-0">
                <div className="mb-2 px-1">
                  <div className="text-[13px] font-semibold text-slate-800 leading-tight">
                    {tactic.name}
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono">
                    {detectedInTactic}/{caps.length} attive
                  </div>
                  <div className="h-0.5 mt-1 rounded-full bg-gradient-to-r from-blue-500 to-blue-500/0" />
                </div>
                <div className="space-y-2">
                  {caps.length === 0 && (
                    <div className="text-[11px] text-slate-300 italic px-1">—</div>
                  )}
                  {caps.map((cap) => {
                    const hit = byTechnique.get(`${tactic.id}::${cap.t}`);
                    const cls = hit ? SEV_CELL[hit.sev] : IDLE_CELL;
                    return (
                      <button
                        key={cap.t}
                        onClick={() =>
                          navigate(
                            `/correlations?technique=${encodeURIComponent(cap.t)}&tactic=${tactic.id}`,
                          )
                        }
                        className={`w-full text-left rounded-lg border px-3 py-2 transition-all hover:-translate-y-0.5 hover:shadow-md ${cls}`}
                        title={
                          hit
                            ? `${cap.t} · ${hit.count} detection · ${hit.sev}`
                            : `${cap.t} · nessuna detection nel periodo`
                        }
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-[11px] font-bold">{cap.t}</span>
                          {hit && (
                            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-black/20">
                              {hit.count}
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] leading-tight mt-0.5 opacity-90">
                          {cap.name}
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {isLoading && (
        <div className="text-sm text-slate-400 mt-4">Caricamento correlazioni…</div>
      )}
    </div>
  );
}
