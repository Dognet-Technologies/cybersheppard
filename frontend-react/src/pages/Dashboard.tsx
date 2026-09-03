// ============================================================================
// Dashboard - Main overview page (solo dati reali; 0/empty se assenti).
// Card e grafici azionabili: cliccando si naviga al contesto (Threat Detection,
// Compliance, MITRE) — la Dashboard è un punto di partenza per l'indagine.
// ============================================================================

import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import { Server, AlertTriangle, CheckCircle, Activity, Shield, Zap, ExternalLink } from 'lucide-react';
import {
  BarChart, Bar, PieChart, Pie, Cell, AreaChart, Area,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import { PageHeader, StatsGrid, StatCard, Card, CardHeader, EmptyState } from '../components/ui';
import { HELP } from '../i18n/help';
import { fmtTs } from '../utils/datetime';

// Placeholder quando un grafico non ha dati (invece di renderizzare vuoto/mock).
function NoData({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center h-[260px] text-sm text-slate-400">{label}</div>
  );
}

// URL della pagina ufficiale MITRE ATT&CK per una tecnica (gestisce le sotto-tecniche).
function mitreTechniqueUrl(tid?: string): string | undefined {
  if (!tid) return undefined;
  const [base, sub] = tid.trim().toUpperCase().split('.');
  return `https://attack.mitre.org/techniques/${base}${sub ? `/${sub}` : ''}/`;
}

const TOOLTIP_STYLE = { backgroundColor: '#fff', border: '1px solid #e5e7eb', borderRadius: '8px', fontSize: 12 };

export default function Dashboard() {
  const navigate = useNavigate();

  const { data: targets } = useQuery({ queryKey: ['targets'], queryFn: () => api.getTargets(), refetchInterval: 30000 });
  const { data: violations } = useQuery({ queryKey: ['violations'], queryFn: () => api.getViolations({ status: 'new' }) });
  // Stessa fonte alert di Threat Detection (getActiveAlerts/api/alerts/active dà 500).
  const { data: alerts } = useQuery({ queryKey: ['dash-alerts'], queryFn: () => api.getAlerts('all', 'all'), refetchInterval: 30000 });
  const { data: correlationsResp } = useQuery({
    queryKey: ['dash-correlations'],
    queryFn: () => api.getSecurityCorrelations({ hours: 24, limit: 1000 }),
    refetchInterval: 30000,
  });
  const { data: frameworkSummary } = useQuery({ queryKey: ['framework-summary'], queryFn: () => api.getFrameworkSummary() });

  const targetList: any[] = Array.isArray(targets) ? targets : [];
  const correlations: any[] = correlationsResp?.data || [];
  const alertList: any[] = Array.isArray(alerts) ? alerts : (alerts?.data || alerts?.alerts || []);
  const summary: any[] = Array.isArray(frameworkSummary) ? frameworkSummary : [];

  const stats = {
    total: targetList.length,
    online: targetList.filter((t) => t.status === 'online').length,
    offline: targetList.filter((t) => t.status === 'offline').length,
    violations: violations?.total || 0,
    critical: violations?.summary?.critical || 0,
    high: violations?.summary?.high || 0,
    medium: violations?.summary?.medium || 0,
    low: violations?.summary?.low || 0,
    alerts: alertList.length,
  };

  // Violazioni per severità (reali)
  const severityData = [
    { name: 'Critical', value: stats.critical, color: '#ef4444' },
    { name: 'High', value: stats.high, color: '#f97316' },
    { name: 'Medium', value: stats.medium, color: '#eab308' },
    { name: 'Low', value: stats.low, color: '#64748b' },
  ].filter((d) => d.value > 0);
  const severityTotal = severityData.reduce((s, d) => s + d.value, 0);

  // Correlazioni per tattica ATT&CK (id conservato per il deep-link)
  const correlationsByTactic = useMemo(() => {
    const m = new Map<string, number>();
    for (const c of correlations) {
      const id = c.attack_stage || 'unknown';
      m.set(id, (m.get(id) || 0) + 1);
    }
    return [...m.entries()]
      .map(([id, count]) => ({ id, tactic: id.replace(/_/g, ' '), count }))
      .sort((a, b) => b.count - a.count);
  }, [correlations]);

  // Correlazioni per ora nelle ultime 24h (time-series, ora locale)
  const correlationsByHour = useMemo(() => {
    const now = Date.now();
    const arr = Array.from({ length: 24 }, (_, i) => {
      const d = new Date(now - (23 - i) * 3600000);
      return { h: `${String(d.getHours()).padStart(2, '0')}:00`, correlazioni: 0 };
    });
    for (const c of correlations) {
      const diffH = Math.floor((now - new Date(c.created_at).getTime()) / 3600000);
      if (diffH >= 0 && diffH < 24) arr[23 - diffH].correlazioni += 1;
    }
    return arr;
  }, [correlations]);

  // Compliance per framework (reale; 0 se nessun assessment)
  const complianceData = useMemo(
    () =>
      summary
        .map((s: any) => ({ framework: s.framework_name || s.code || `#${s.framework_id}`, score: Math.round(s.avg_compliance_score || 0) }))
        .filter((d: any) => d.framework)
        .slice(0, 8),
    [summary],
  );
  const complianceHasScores = complianceData.some((d: any) => d.score > 0);
  const complianceColor = (s: number) => (s >= 80 ? '#22c55e' : s >= 60 ? '#eab308' : '#ef4444');

  const recentActivity = useMemo(
    () => [...correlations].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()).slice(0, 6),
    [correlations],
  );

  const goTactic = (id?: string) => id && navigate(`/detection?view=correlations&mode=list&tactic=${id}`);
  const goTechnique = (t?: string) => t && navigate(`/detection?view=correlations&mode=list&technique=${encodeURIComponent(t)}`);
  const goHost = (h?: string) => h && navigate(`/detection?view=table&host=${encodeURIComponent(h)}`);

  return (
    <div>
      <PageHeader title="Dashboard" subtitle="Panoramica dell'infrastruttura di sicurezza" icon={<Activity className="w-6 h-6" />} info={HELP.page.dashboard} />

      {/* Stats reali — cliccabili per andare al contesto */}
      <StatsGrid columns={4} className="mb-8">
        <button className="text-left" onClick={() => navigate('/targets')}>
          <StatCard title="Target totali" value={stats.total} icon={<Server className="w-6 h-6" />} variant="info" info={HELP.dashboard.statTotal} />
        </button>
        <button className="text-left" onClick={() => navigate('/targets')}>
          <StatCard title="Target online" value={stats.online} icon={<CheckCircle className="w-6 h-6" />} variant="success" info={HELP.dashboard.statOnline} />
        </button>
        <button className="text-left" onClick={() => navigate('/compliance/violations')}>
          <StatCard title="Violazioni attive" value={stats.violations} icon={<AlertTriangle className="w-6 h-6" />} variant={stats.violations > 10 ? 'danger' : 'warning'} info={HELP.dashboard.statViolations} />
        </button>
        <button className="text-left" onClick={() => navigate('/detection?view=alerts')}>
          <StatCard title="Alert attivi" value={stats.alerts} icon={<Shield className="w-6 h-6" />} variant={stats.alerts > 5 ? 'warning' : 'default'} info={HELP.dashboard.statAlerts} />
        </button>
      </StatsGrid>

      {/* Riga 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <Card>
          <CardHeader title="Correlazioni per tattica ATT&CK" subtitle="Ultime 24h · clicca una barra per aprire la tattica" />
          {correlationsByTactic.length === 0 ? (
            <NoData label="Nessuna correlazione nelle ultime 24h" />
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={correlationsByTactic} layout="vertical" margin={{ left: 30, right: 16, top: 8, bottom: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#eef2f7" />
                <XAxis type="number" stroke="#94a3b8" allowDecimals={false} tick={{ fontSize: 11 }}
                  label={{ value: 'N. correlazioni', position: 'insideBottom', offset: -8, fontSize: 11, fill: '#64748b' }} />
                <YAxis type="category" dataKey="tactic" stroke="#94a3b8" width={130} tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: '#f1f5f9' }} />
                <Bar dataKey="count" name="Correlazioni" radius={[0, 6, 6, 0]} cursor="pointer"
                  onClick={(d: any) => goTactic(d?.id ?? d?.payload?.id)}>
                  {correlationsByTactic.map((_, i) => (<Cell key={i} fill={['#2563eb', '#7c3aed', '#0891b2', '#db2777', '#ea580c', '#16a34a'][i % 6]} />))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card>
          <CardHeader title="Violazioni per severità" subtitle="Distribuzione attuale" />
          {severityTotal === 0 ? (
            <NoData label="Nessuna violazione" />
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie data={severityData} cx="50%" cy="50%" innerRadius={55} outerRadius={90} paddingAngle={2} dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`} labelLine={false}>
                  {severityData.map((e, i) => (<Cell key={i} fill={e.color} />))}
                </Pie>
                <Legend verticalAlign="bottom" height={24} iconType="circle" wrapperStyle={{ fontSize: 12 }} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      {/* Riga 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <Card>
          <CardHeader title="Correlazioni nel tempo" subtitle="Per ora, ultime 24h" />
          {correlations.length === 0 ? (
            <NoData label="Nessuna correlazione nelle ultime 24h" />
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <AreaChart data={correlationsByHour} margin={{ left: 8, right: 16, top: 8, bottom: 20 }}>
                <defs>
                  <linearGradient id="gradCorr" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#2563eb" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#2563eb" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#eef2f7" />
                <XAxis dataKey="h" stroke="#94a3b8" tick={{ fontSize: 10 }} interval={2}
                  label={{ value: 'Ora (locale)', position: 'insideBottom', offset: -8, fontSize: 11, fill: '#64748b' }} />
                <YAxis stroke="#94a3b8" allowDecimals={false} tick={{ fontSize: 11 }} width={32} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend verticalAlign="top" height={22} iconType="plainline" wrapperStyle={{ fontSize: 12 }} />
                <Area type="monotone" dataKey="correlazioni" name="Correlazioni" stroke="#2563eb" strokeWidth={1.5} fill="url(#gradCorr)" dot={false} activeDot={{ r: 3 }} />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card>
          <CardHeader title="Compliance per framework" subtitle="Punteggio medio (0 senza assessment)" />
          {complianceData.length === 0 || !complianceHasScores ? (
            <NoData label="Nessun assessment di compliance eseguito" />
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={complianceData} margin={{ left: 8, right: 16, top: 8, bottom: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#eef2f7" />
                <XAxis dataKey="framework" stroke="#94a3b8" tick={{ fontSize: 10 }} />
                <YAxis stroke="#94a3b8" domain={[0, 100]} tick={{ fontSize: 11 }} width={32}
                  label={{ value: 'Punteggio %', angle: -90, position: 'insideLeft', fontSize: 11, fill: '#64748b' }} />
                <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: '#f1f5f9' }} />
                <Legend verticalAlign="top" height={22} iconType="circle" wrapperStyle={{ fontSize: 12 }} />
                <Bar dataKey="score" name="Punteggio conformità" radius={[6, 6, 0, 0]}>
                  {complianceData.map((d: any, i: number) => (<Cell key={i} fill={complianceColor(d.score)} />))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      {/* Attività recente (reale) — dettagli azionabili */}
      <Card>
        <CardHeader title="Attività recente" subtitle="Ultime correlazioni di sicurezza · clicca tecnica/host/pattern per approfondire" />
        {recentActivity.length === 0 ? (
          <EmptyState icon={<CheckCircle className="w-8 h-8" />} title="Nessuna attività recente" description="Non sono state rilevate correlazioni di sicurezza di recente" />
        ) : (
          <div className="space-y-4">
            {recentActivity.map((c) => {
              const tech = c.correlation_data?.mitre_technique as string | undefined;
              const host = (c.involved_hosts || [])[0] as string | undefined;
              const mitre = mitreTechniqueUrl(tech);
              return (
                <div key={c.id} className="flex items-start space-x-4 pb-4 border-b border-gray-100 last:border-0 last:pb-0">
                  <div className="flex-shrink-0 w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center">
                    <Zap className={`w-5 h-5 ${c.severity === 'critical' ? 'text-red-600' : c.severity === 'high' ? 'text-orange-600' : 'text-blue-600'}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 flex items-center gap-2 flex-wrap">
                      {/* Pattern → tutte le occorrenze di quella tecnica */}
                      <button onClick={() => goTechnique(tech)} disabled={!tech}
                        className={tech ? 'hover:text-blue-700 hover:underline' : 'cursor-default'}>
                        {c.pattern_name || c.correlation_type}
                      </button>
                      {/* Tecnica → pagina ufficiale MITRE */}
                      {tech && mitre && (
                        <a href={mitre} target="_blank" rel="noreferrer" title="Apri su MITRE ATT&CK"
                          className="inline-flex items-center gap-0.5 text-xs font-mono text-orange-700 hover:underline">
                          {tech} <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </p>
                    <p className="text-sm text-gray-500 truncate">
                      {(c.attack_stage || '').replace(/_/g, ' ')}
                      {host && (
                        <>
                          {' · '}
                          <button onClick={() => goHost(host)} className="text-slate-600 hover:text-blue-700 hover:underline">
                            {host}
                          </button>
                        </>
                      )}
                    </p>
                  </div>
                  <span className="text-xs text-gray-400 flex-shrink-0">{c.created_at ? fmtTs(c.created_at, 'HH:mm') : ''}</span>
                </div>
              );
            })}
          </div>
        )}
      </Card>
    </div>
  );
}
