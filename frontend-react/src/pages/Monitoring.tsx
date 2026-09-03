// ============================================================================
// Monitoring Page - Stato dei target in tempo reale.
// NOTA: le serie temporali (CPU/RAM/rete) richiedono la raccolta metriche via
// InfluxDB, non ancora attiva lato backend (/api/monitoring/metrics è uno stub).
// Finché non c'è una sorgente reale NON mostriamo grafici mock: solo dati reali
// (stato target) e placeholder espliciti al posto dei grafici.
// ============================================================================

import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import { Activity, Cpu, HardDrive, Network, Info, Server, ShieldCheck, ShieldAlert, ShieldX } from 'lucide-react';
import { PageHeader, Card, CardHeader, StatsGrid, StatCard, Badge, InfoTip } from '../components/ui';
import { HELP } from '../i18n/help';

// Mappa stato sensore → etichetta/badge/icona/tooltip.
const SENSOR_UI: Record<string, { label: string; variant: 'success' | 'warning' | 'danger' | 'default'; icon: JSX.Element; info: string }> = {
  healthy: { label: 'Attivo', variant: 'success', icon: <ShieldCheck className="w-4 h-4 text-green-600" />, info: HELP.monitoring.sensorHealthy },
  sensor_stale: { label: 'Fermo', variant: 'danger', icon: <ShieldAlert className="w-4 h-4 text-red-600" />, info: HELP.monitoring.sensorStale },
  agent_offline: { label: 'Agente offline', variant: 'default', icon: <ShieldX className="w-4 h-4 text-slate-400" />, info: HELP.monitoring.sensorAgentOffline },
};

function SensorPanel() {
  const { data } = useQuery({
    queryKey: ['sensor-status'],
    queryFn: () => api.getSensorStatus(),
    refetchInterval: 15000,
  });
  const sensors: any[] = data?.data || [];

  return (
    <Card className="mb-6">
      <CardHeader
        title="Stato sensori (auditd/Laurel)"
        subtitle="Il sensore di sicurezza su ogni host: se è fermo, riavvialo sull’host"
        action={<InfoTip content={HELP.monitoring.sensorInfo} />}
      />
      {sensors.length === 0 ? (
        <p className="text-sm text-slate-400 py-4">Nessun target.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-slate-500 text-[11px] uppercase tracking-wide">
              <tr>
                <th className="text-left px-3 py-2 font-medium">Host</th>
                <th className="text-left px-3 py-2 font-medium">Sensore</th>
                <th className="text-left px-3 py-2 font-medium">Ultimo evento</th>
                <th className="text-left px-3 py-2 font-medium">Eventi/5min</th>
                <th className="text-left px-3 py-2 font-medium">Azione</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {sensors.map((s) => {
                const ui = SENSOR_UI[s.status] || SENSOR_UI.agent_offline;
                return (
                  <tr key={s.target_id} className="hover:bg-slate-50/60">
                    <td className="px-3 py-2">
                      <div className="font-medium text-gray-900">{s.hostname}</div>
                      <div className="text-xs text-gray-500">{s.ip}</div>
                    </td>
                    <td className="px-3 py-2">
                      <span className="inline-flex items-center gap-1.5">
                        {ui.icon}
                        <Badge variant={ui.variant}>{ui.label}</Badge>
                        <InfoTip content={ui.info} />
                      </span>
                    </td>
                    <td className="px-3 py-2 text-slate-600 text-xs">
                      {s.last_event_at ? new Date(s.last_event_at).toLocaleString() : '—'}
                      {s.event_minutes_ago != null && (
                        <span className="text-slate-400"> ({s.event_minutes_ago}m fa)</span>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono text-slate-700">{s.events_5m ?? 0}</td>
                    <td className="px-3 py-2">
                      {s.status !== 'healthy' ? (
                        <span className="inline-flex items-center gap-1 text-xs text-slate-600">
                          <code className="font-mono bg-slate-100 px-1.5 py-0.5 rounded">sudo systemctl restart auditd</code>
                          <InfoTip content={HELP.monitoring.sensorRestart} />
                        </span>
                      ) : (
                        <span className="text-xs text-slate-400">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

// Placeholder al posto di un grafico privo di sorgente dati reale.
function MetricsUnavailable() {
  return (
    <div className="flex flex-col items-center justify-center h-[250px] text-center px-6">
      <Cpu className="w-8 h-8 text-slate-300 mb-2" />
      <p className="text-sm font-medium text-slate-500">Metriche non disponibili</p>
      <p className="text-xs text-slate-400 mt-1">
        La raccolta serie temporali (InfluxDB) non è ancora attiva.
      </p>
    </div>
  );
}

export default function Monitoring() {
  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: () => api.getTargets(),
    refetchInterval: 30000,
  });

  const targetList: any[] = Array.isArray(targets) ? targets : [];
  const total = targetList.length;
  const onlineTargets = targetList.filter((t) => t.status === 'online').length;
  const offlineTargets = total - onlineTargets;
  const lastSeen = targetList
    .map((t) => t.last_monitoring_at || t.last_seen)
    .filter(Boolean)
    .sort()
    .pop();

  return (
    <div>
      <PageHeader
        title="Real-time Monitoring"
        subtitle={`${onlineTargets} target${onlineTargets !== 1 ? 's' : ''} online`}
        icon={<Activity className="w-6 h-6" />}
        info={HELP.page.monitoring}
        actions={
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-green-500 animate-pulse" />
            <Badge variant="success">Live updates</Badge>
          </div>
        }
      />

      {/* Avviso: metriche time-series non ancora disponibili */}
      <div className="flex items-start gap-3 mb-6 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3">
        <Info className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
        <div className="text-sm text-amber-800">
          <span className="font-medium">Metriche di sistema in arrivo.</span>{' '}
          La raccolta di CPU, memoria e traffico di rete richiede l'integrazione InfluxDB
          lato backend (endpoint <code className="font-mono text-xs">/api/monitoring/metrics</code> ancora
          non implementato). Fino ad allora i grafici restano vuoti: nessun dato simulato.
        </div>
      </div>

      {/* Stat reali derivate dai target */}
      <StatsGrid columns={4} className="mb-6">
        <StatCard
          title="Target totali"
          value={total}
          icon={<Server className="w-6 h-6" />}
          variant="info"
          info={HELP.monitoring.statTotal}
        />
        <StatCard
          title="Online"
          value={onlineTargets}
          icon={<Activity className="w-6 h-6" />}
          variant="success"
          info={HELP.monitoring.statOnline}
        />
        <StatCard
          title="Offline"
          value={offlineTargets}
          icon={<Network className="w-6 h-6" />}
          variant={offlineTargets > 0 ? 'danger' : 'default'}
          info={HELP.monitoring.statOffline}
        />
        <StatCard
          title="Ultimo dato"
          value={lastSeen ? new Date(lastSeen).toLocaleString() : 'Mai'}
          icon={<HardDrive className="w-6 h-6" />}
          variant="default"
          info={HELP.monitoring.statLastData}
        />
      </StatsGrid>

      {/* Stato del sensore di sicurezza (auditd/Laurel) per target */}
      <SensorPanel />

      {/* Charts (placeholder finché non c'è una sorgente reale) + stato target */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader title="CPU Usage" subtitle="Utilizzo processore (serie temporale)" />
          <MetricsUnavailable />
        </Card>

        <Card>
          <CardHeader title="Memory Usage" subtitle="Utilizzo RAM (serie temporale)" />
          <MetricsUnavailable />
        </Card>

        <Card>
          <CardHeader title="Network Traffic" subtitle="Traffico in/out (serie temporale)" />
          <MetricsUnavailable />
        </Card>

        {/* Target Status List — dati reali */}
        <Card>
          <CardHeader title="Target Status" subtitle="Stato di monitoraggio corrente" />
          <div className="space-y-3 max-h-[250px] overflow-y-auto">
            {targetList.length > 0 ? (
              targetList.slice(0, 8).map((target: any) => (
                <div
                  key={target.id}
                  className="flex items-center justify-between py-2 border-b border-gray-100 last:border-b-0"
                >
                  <div>
                    <p className="font-medium text-sm text-gray-900">{target.hostname}</p>
                    <p className="text-xs text-gray-500">{target.ip_address}</p>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        target.status === 'online' ? 'bg-green-500' : 'bg-red-500'
                      }`}
                    ></span>
                    <Badge variant={target.status === 'online' ? 'success' : 'danger'}>
                      {target.status}
                    </Badge>
                  </div>
                </div>
              ))
            ) : (
              <p className="text-gray-500 text-center py-8">No targets available</p>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
