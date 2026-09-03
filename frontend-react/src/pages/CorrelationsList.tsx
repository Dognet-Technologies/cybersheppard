// ============================================================================
// Correlazioni — vista "Lista". Pattern d'attacco correlati dagli eventi, con
// mappatura MITRE ATT&CK/D3FEND. CyberSheppard è MONITORAGGIO: non c'è triage
// (niente acknowledge/resolve); l'azione consigliata è una "remediation" verso
// gli altri tool della suite (FireDog/iptables, hardening, inventario).
//
// Le correlazioni sono una HISTORY degli accadimenti: le occorrenze ripetute
// della stessa correlazione vengono RAGGRUPPATE a livello di vista (contatore
// ×N) entro la finestra scelta in Settings; il dettaglio elenca ogni occorrenza.
// ============================================================================

import { Fragment, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import { AlertTriangle, CheckCircle, Activity, Cpu, X, ChevronRight, ChevronDown } from 'lucide-react';
import { fmtTs } from '../utils/datetime';
import { Badge, StatsGrid, StatCard, EmptyState, Select, InfoTip } from '../components/ui';
import { HELP } from '../i18n/help';
import { getGroupWindowMin } from '../utils/prefs';

function sensorOf(row: any): 'ebpf' | 'auditd' {
  return row?.correlation_data?.sensor === 'ebpf' ? 'ebpf' : 'auditd';
}

const TACTIC_OPTIONS = [
  'initial_access', 'execution', 'persistence', 'privilege_escalation',
  'stealth', 'defense_impairment', 'credential_access', 'discovery',
  'lateral_movement', 'collection', 'command_and_control', 'exfiltration', 'impact',
];

const SEV_VARIANT: Record<string, 'danger' | 'warning' | 'info' | 'default'> = {
  critical: 'danger', high: 'warning', medium: 'info', low: 'default',
};

// Firma di una correlazione: raggruppa le occorrenze dello stesso pattern.
function signatureOf(c: any): string {
  return [
    c.correlation_type,
    c.attack_stage,
    c.correlation_data?.mitre_technique,
    (c.involved_hosts || []).join(','),
    (c.involved_users || []).join(','),
  ].join('|');
}

const tsOf = (c: any): number => new Date(c.last_event_time || c.created_at).getTime();

interface Group {
  key: string;
  rep: any;        // occorrenza rappresentativa (più recente del gruppo)
  items: any[];    // tutte le occorrenze del gruppo
}

// Raggruppa per firma spezzando quando il gap tra occorrenze supera la finestra.
function buildGroups(correlations: any[], windowMin: number): Group[] {
  if (windowMin === 0) {
    return correlations
      .slice()
      .sort((a, b) => tsOf(b) - tsOf(a))
      .map((c) => ({ key: c.id, rep: c, items: [c] }));
  }
  const bySig = new Map<string, any[]>();
  for (const c of correlations) {
    const s = signatureOf(c);
    if (!bySig.has(s)) bySig.set(s, []);
    bySig.get(s)!.push(c);
  }
  const out: Group[] = [];
  const windowMs = windowMin * 60000;
  for (const [sig, items] of bySig) {
    items.sort((a, b) => tsOf(a) - tsOf(b));
    let bucket: any[] = [];
    let lastT = 0;
    const flush = () => {
      if (bucket.length) {
        const rep = bucket[bucket.length - 1];
        out.push({ key: `${sig}@${rep.id}`, rep, items: [...bucket] });
      }
    };
    for (const c of items) {
      const t = tsOf(c);
      if (bucket.length && t - lastT > windowMs) {
        flush();
        bucket = [];
      }
      bucket.push(c);
      lastT = t;
    }
    flush();
  }
  return out.sort((a, b) => tsOf(b.rep) - tsOf(a.rep));
}

export default function CorrelationsList() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const [tactic, setTactic] = useState<string>(searchParams.get('tactic') || 'all');
  const [severity, setSeverity] = useState<string>('all');
  const [sensor, setSensor] = useState<string>('all');
  const technique = searchParams.get('technique') || '';
  const windowMin = getGroupWindowMin();

  const { data: response, isLoading } = useQuery({
    queryKey: ['security-correlations'],
    queryFn: () => api.getSecurityCorrelations({ hours: 24, limit: 500 }),
    refetchInterval: 30000,
  });

  const allCorrelations = response?.data || [];

  const correlations = useMemo(() => {
    return allCorrelations.filter((c: any) => {
      if (tactic !== 'all' && c.attack_stage !== tactic) return false;
      if (severity !== 'all' && c.severity !== severity) return false;
      if (sensor !== 'all' && sensorOf(c) !== sensor) return false;
      if (technique && c.correlation_data?.mitre_technique !== technique) return false;
      return true;
    });
  }, [allCorrelations, tactic, severity, sensor, technique]);

  const groups = useMemo(() => buildGroups(correlations, windowMin), [correlations, windowMin]);

  const clearTechnique = () => {
    const p = new URLSearchParams(searchParams);
    p.delete('technique');
    setSearchParams(p, { replace: true });
  };

  const stats = {
    total: correlations.length,
    critical: correlations.filter((c: any) => c.severity === 'critical').length,
    high: correlations.filter((c: any) => c.severity === 'high').length,
    groups: groups.length,
  };

  return (
    <div>
      <StatsGrid columns={4} className="mb-6">
        <StatCard title="Total Correlations" value={stats.total} icon={<Activity className="w-6 h-6" />} variant="info" info={HELP.correlations.statTotal} />
        <StatCard title="Critical" value={stats.critical} icon={<AlertTriangle className="w-6 h-6" />} variant="danger" info={HELP.correlations.statCritical} />
        <StatCard title="High Severity" value={stats.high} icon={<AlertTriangle className="w-6 h-6" />} variant="warning" info={HELP.correlations.statHigh} />
        <StatCard title="Gruppi" value={stats.groups} icon={<CheckCircle className="w-6 h-6" />} variant="default" info={HELP.ui.countLabel} />
      </StatsGrid>

      {/* Barra filtri */}
      <div className="flex flex-wrap items-end gap-3 mb-4 p-3 bg-white rounded-lg border border-slate-200">
        <div className="w-52">
          <label className="text-xs font-medium text-slate-500 mb-1 flex items-center gap-1">Tattica ATT&amp;CK <InfoTip content={HELP.correlations.filterTactic} /></label>
          <Select value={tactic} onChange={(e: any) => setTactic(e.target.value)}>
            <option value="all">Tutte le tattiche</option>
            {TACTIC_OPTIONS.map((t) => (<option key={t} value={t}>{t.replace(/_/g, ' ')}</option>))}
          </Select>
        </div>
        <div className="w-40">
          <label className="text-xs font-medium text-slate-500 mb-1 flex items-center gap-1">Severità <InfoTip content={HELP.correlations.filterSeverity} /></label>
          <Select value={severity} onChange={(e: any) => setSeverity(e.target.value)}>
            <option value="all">Tutte</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </Select>
        </div>
        <div className="w-40">
          <label className="text-xs font-medium text-slate-500 mb-1 flex items-center gap-1">Sensore <InfoTip content={HELP.correlations.filterSensor} /></label>
          <Select value={sensor} onChange={(e: any) => setSensor(e.target.value)}>
            <option value="all">Tutti</option>
            <option value="ebpf">eBPF (kernel)</option>
            <option value="auditd">auditd / Laurel</option>
          </Select>
        </div>
        {technique && (
          <button onClick={clearTechnique} className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-orange-50 text-orange-700 border border-orange-200 hover:bg-orange-100" title="Rimuovi il filtro per tecnica">
            Tecnica: {technique} <X className="w-3 h-3" />
          </button>
        )}
        <div className="ml-auto text-sm text-slate-500 self-center">
          {groups.length} gruppi · {correlations.length} occorrenze
          {windowMin > 0 ? ` (finestra ${windowMin}m)` : ' (storico piatto)'}
        </div>
      </div>

      {groups.length === 0 && !isLoading ? (
        <EmptyState icon={<CheckCircle className="w-8 h-8" />} title="Nessuna correlazione" description="Il motore di correlazione non ha rilevato pattern sospetti nella finestra selezionata." />
      ) : (
        <div className="bg-white rounded-lg border border-slate-200 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 text-slate-500 text-[11px] uppercase tracking-wide">
                <tr>
                  <th className="px-3 py-2 w-8"></th>
                  <th className="text-left px-3 py-2 font-medium">Severità</th>
                  <th className="text-left px-3 py-2 font-medium">Pattern / MITRE</th>
                  <th className="text-left px-3 py-2 font-medium">Sensore</th>
                  <th className="text-left px-3 py-2 font-medium">Host</th>
                  <th className="text-left px-3 py-2 font-medium">Risk</th>
                  <th className="text-left px-3 py-2 font-medium">Ultima</th>
                  <th className="text-left px-3 py-2 font-medium">×N</th>
                  <th className="text-left px-3 py-2 font-medium">
                    <span className="inline-flex items-center gap-1">{HELP.ui.colRemediation} <InfoTip content={HELP.ui.colRemediationInfo} /></span>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {groups.map((g) => {
                  const c = g.rep;
                  const tech = c.correlation_data?.mitre_technique;
                  const techName = c.correlation_data?.mitre_technique_name;
                  const d3 = c.correlation_data?.mitigating_d3fend;
                  const remediation = (HELP.remediation as Record<string, string>)[c.attack_stage] || '';
                  const isOpen = !!expanded[g.key];
                  const multi = g.items.length > 1;
                  return (
                    <Fragment key={g.key}>
                      <tr
                        className={`hover:bg-blue-50/40 ${multi ? 'cursor-pointer' : ''}`}
                        onClick={() => multi && setExpanded((s) => ({ ...s, [g.key]: !s[g.key] }))}
                      >
                        <td className="px-3 py-2 text-slate-400">
                          {multi ? (isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />) : null}
                        </td>
                        <td className="px-3 py-2"><Badge variant={SEV_VARIANT[c.severity] || 'default'}>{(c.severity || '—').toUpperCase()}</Badge></td>
                        <td className="px-3 py-2">
                          <div className="font-medium text-gray-900">{c.pattern_name || c.correlation_type?.replace(/_/g, ' ')}</div>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {c.attack_stage && <span className="inline-flex px-1.5 py-0.5 rounded text-[10px] bg-red-50 text-red-700 border border-red-200">{c.attack_stage.replace(/_/g, ' ')}</span>}
                            {tech && <span className="inline-flex px-1.5 py-0.5 rounded text-[10px] font-mono bg-orange-50 text-orange-700 border border-orange-200" title={techName}>{tech}</span>}
                            {d3 && <span className="inline-flex px-1.5 py-0.5 rounded text-[10px] bg-green-50 text-green-700 border border-green-200">D3FEND {d3}</span>}
                          </div>
                        </td>
                        <td className="px-3 py-2">
                          {sensorOf(c) === 'ebpf'
                            ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-violet-50 text-violet-700 border border-violet-200"><Cpu className="w-3 h-3" /> eBPF</span>
                            : <span className="inline-flex px-2 py-0.5 rounded text-xs bg-slate-50 text-slate-600 border border-slate-200">auditd</span>}
                        </td>
                        <td className="px-3 py-2 text-slate-600">{(c.involved_hosts || []).slice(0, 2).join(', ') || '—'}</td>
                        <td className="px-3 py-2 text-slate-700 font-mono text-xs">{c.risk_score ? Number(c.risk_score).toFixed(0) : '—'}/100</td>
                        <td className="px-3 py-2 text-slate-500 text-xs whitespace-nowrap">{fmtTs(c.last_event_time, 'dd/MM HH:mm')}</td>
                        <td className="px-3 py-2">
                          {multi
                            ? <span className="inline-flex items-center justify-center min-w-[2rem] px-2 py-0.5 rounded-full text-xs font-bold bg-blue-600 text-white">×{g.items.length}</span>
                            : <span className="text-slate-400 text-xs">1</span>}
                        </td>
                        <td className="px-3 py-2 text-xs text-slate-600 max-w-xs">{remediation}</td>
                      </tr>
                      {isOpen && multi && (
                        <tr>
                          <td></td>
                          <td colSpan={8} className="px-3 py-2 bg-slate-50">
                            <div className="text-[11px] font-semibold text-slate-500 uppercase mb-1">{HELP.ui.occurrences} ({g.items.length})</div>
                            <div className="space-y-1">
                              {g.items.slice().sort((a, b) => tsOf(b) - tsOf(a)).map((o) => (
                                <div key={o.id} className="flex items-center gap-3 text-xs text-slate-600 font-mono">
                                  <span className="text-slate-400">{fmtTs(o.last_event_time, 'dd/MM/yyyy HH:mm:ss')}</span>
                                  <span>risk {o.risk_score ? Number(o.risk_score).toFixed(0) : '—'}</span>
                                  <span>{o.event_count ?? 0} eventi</span>
                                  <span className="truncate">{(o.involved_users || []).join(', ')}</span>
                                </div>
                              ))}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
