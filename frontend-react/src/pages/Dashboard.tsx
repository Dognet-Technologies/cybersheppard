// ============================================================================
// Dashboard - Main overview page (solo dati reali; 0/empty se assenti)
// ============================================================================

import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import api from '../services/api';
import {
  Server,
  AlertTriangle,
  CheckCircle,
  Activity,
  Shield,
  Zap,
} from 'lucide-react';
import { fmtTs } from '../utils/datetime';
import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { PageHeader, StatsGrid, StatCard, Card, CardHeader, EmptyState } from '../components/ui';
import { HELP } from '../i18n/help';

// Placeholder quando un grafico non ha dati (invece di renderizzare vuoto/mock).
function NoData({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center h-[250px] text-sm text-slate-400">
      {label}
    </div>
  );
}

export default function Dashboard() {
  const { data: targets } = useQuery({ queryKey: ['targets'], queryFn: () => api.getTargets(), refetchInterval: 30000 });
  const { data: violations } = useQuery({ queryKey: ['violations'], queryFn: () => api.getViolations({ status: 'new' }) });
  const { data: alerts } = useQuery({ queryKey: ['alerts', 'active'], queryFn: () => api.getActiveAlerts() });
  const { data: correlationsResp } = useQuery({
    queryKey: ['dash-correlations'],
    queryFn: () => api.getSecurityCorrelations({ hours: 24, limit: 200 }),
    refetchInterval: 30000,
  });
  const { data: frameworkSummary } = useQuery({
    queryKey: ['framework-summary'],
    queryFn: () => api.getFrameworkSummary(),
  });

  const targetList: any[] = Array.isArray(targets) ? targets : [];
  const correlations: any[] = correlationsResp?.data || [];
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
    alerts: Array.isArray(alerts) ? alerts.length : 0,
  };

  // Violazioni per severità (reali)
  const severityData = [
    { name: 'Critical', value: stats.critical, color: '#ef4444' },
    { name: 'High', value: stats.high, color: '#f97316' },
    { name: 'Medium', value: stats.medium, color: '#eab308' },
    { name: 'Low', value: stats.low, color: '#64748b' },
  ];
  const severityTotal = severityData.reduce((s, d) => s + d.value, 0);

  // Stato target (reale)
  const targetStatusData = [
    { name: 'Online', value: stats.online, color: '#22c55e' },
    { name: 'Offline', value: stats.offline, color: '#ef4444' },
  ];

  // Correlazioni per tattica ATT&CK (reali, ultime 24h)
  const correlationsByTactic = useMemo(() => {
    const m = new Map<string, number>();
    for (const c of correlations) {
      const t = (c.attack_stage || 'unknown').replace(/_/g, ' ');
      m.set(t, (m.get(t) || 0) + 1);
    }
    return [...m.entries()].map(([tactic, count]) => ({ tactic, count })).sort((a, b) => b.count - a.count);
  }, [correlations]);

  // Compliance per framework (reale, dal summary; 0 se nessun assessment)
  const complianceData = useMemo(
    () =>
      summary
        .map((s: any) => ({
          framework: s.framework_name || s.code || `#${s.framework_id}`,
          score: Math.round(s.avg_compliance_score || 0),
        }))
        .filter((d: any) => d.framework)
        .slice(0, 8),
    [summary],
  );
  const complianceHasScores = complianceData.some((d: any) => d.score > 0);

  // Attività recente (reale: ultime correlazioni)
  const recentActivity = useMemo(
    () =>
      [...correlations]
        .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
        .slice(0, 6),
    [correlations],
  );

  return (
    <div>
      <PageHeader title="Dashboard" subtitle="Panoramica dell'infrastruttura di sicurezza" icon={<Activity className="w-6 h-6" />} info={HELP.page.dashboard} />

      {/* Stats reali */}
      <StatsGrid columns={4} className="mb-8">
        <StatCard title="Target totali" value={stats.total} icon={<Server className="w-6 h-6" />} variant="info" info={HELP.dashboard.statTotal} />
        <StatCard title="Target online" value={stats.online} icon={<CheckCircle className="w-6 h-6" />} variant="success" info={HELP.dashboard.statOnline} />
        <StatCard title="Violazioni attive" value={stats.violations} icon={<AlertTriangle className="w-6 h-6" />} variant={stats.violations > 10 ? 'danger' : 'warning'} info={HELP.dashboard.statViolations} />
        <StatCard title="Alert attivi" value={stats.alerts} icon={<Shield className="w-6 h-6" />} variant={stats.alerts > 5 ? 'warning' : 'default'} info={HELP.dashboard.statAlerts} />
      </StatsGrid>

      {/* Riga 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <Card>
          <CardHeader title="Correlazioni per tattica ATT&CK" subtitle="Ultime 24h" />
          {correlationsByTactic.length === 0 ? (
            <NoData label="Nessuna correlazione nelle ultime 24h" />
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={correlationsByTactic} layout="vertical" margin={{ left: 40 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis type="number" stroke="#6b7280" allowDecimals={false} />
                <YAxis type="category" dataKey="tactic" stroke="#6b7280" width={120} tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ backgroundColor: '#fff', border: '1px solid #e5e7eb', borderRadius: '8px' }} />
                <Bar dataKey="count" fill="#3b82f6" radius={[0, 6, 6, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card>
          <CardHeader title="Violazioni per severità" subtitle="Distribuzione attuale" />
          {severityTotal === 0 ? (
            <NoData label="Nessuna violazione" />
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={severityData.filter((d) => d.value > 0)} cx="50%" cy="50%" labelLine={false} label={({ name, value }) => `${name}: ${value}`} outerRadius={80} dataKey="value">
                  {severityData.filter((d) => d.value > 0).map((entry, i) => (<Cell key={i} fill={entry.color} />))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      {/* Riga 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <Card>
          <CardHeader title="Stato target" subtitle="Disponibilità attuale" />
          {stats.total === 0 ? (
            <NoData label="Nessun target" />
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={targetStatusData.filter((d) => d.value > 0)} cx="50%" cy="50%" labelLine={false} label={({ name, value }) => `${name}: ${value}`} outerRadius={80} dataKey="value">
                  {targetStatusData.filter((d) => d.value > 0).map((entry, i) => (<Cell key={i} fill={entry.color} />))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card>
          <CardHeader title="Compliance per framework" subtitle="Punteggio medio (0 senza assessment)" />
          {complianceData.length === 0 || !complianceHasScores ? (
            <NoData label="Nessun assessment di compliance eseguito" />
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={complianceData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis dataKey="framework" stroke="#6b7280" tick={{ fontSize: 10 }} />
                <YAxis stroke="#6b7280" domain={[0, 100]} />
                <Tooltip contentStyle={{ backgroundColor: '#fff', border: '1px solid #e5e7eb', borderRadius: '8px' }} />
                <Bar dataKey="score" fill="#3b82f6" radius={[8, 8, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      {/* Attività recente (reale) */}
      <Card>
        <CardHeader title="Attività recente" subtitle="Ultime correlazioni di sicurezza" />
        {recentActivity.length === 0 ? (
          <EmptyState icon={<CheckCircle className="w-8 h-8" />} title="Nessuna attività recente" description="Non sono state rilevate correlazioni di sicurezza di recente" />
        ) : (
          <div className="space-y-4">
            {recentActivity.map((c) => (
              <div key={c.id} className="flex items-start space-x-4 pb-4 border-b border-gray-100 last:border-0 last:pb-0">
                <div className="flex-shrink-0 w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center">
                  <Zap className={`w-5 h-5 ${c.severity === 'critical' ? 'text-red-600' : c.severity === 'high' ? 'text-orange-600' : 'text-blue-600'}`} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900">
                    {c.pattern_name || c.correlation_type}
                    {c.correlation_data?.mitre_technique && <span className="ml-2 text-xs font-mono text-orange-700">{c.correlation_data.mitre_technique}</span>}
                  </p>
                  <p className="text-sm text-gray-500 truncate">
                    {(c.attack_stage || '').replace(/_/g, ' ')}
                    {c.involved_hosts?.length ? ` · ${c.involved_hosts.slice(0, 2).join(', ')}` : ''}
                  </p>
                </div>
                <span className="text-xs text-gray-400 flex-shrink-0">{c.created_at ? fmtTs(c.created_at, 'HH:mm') : ''}</span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
