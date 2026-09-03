// ============================================================================
// Events — Table view. Vista tabellare dei security_events (auditd/Laurel + eBPF),
// STESSA sorgente della vista "Esplora": tabella filtrabile con dettaglio nel
// drawer condiviso. Vista "Tabella" dell'hub Threat Detection.
// ============================================================================

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Shield, AlertTriangle, Activity, Cpu } from 'lucide-react';
import api from '../services/api';
import { format } from 'date-fns';
import { tzAbbr } from '../utils/datetime';
import {
  SeverityBadge,
  StatsGrid,
  StatCard,
  InfoTip,
  Select,
} from '../components/ui';
import { HELP } from '../i18n/help';
import EventDrawer from '../components/EventDrawer';

const sensorOf = (e: any): 'ebpf' | 'auditd' => (e?.event_data?.sensor === 'ebpf' ? 'ebpf' : 'auditd');

export default function EventsTableView() {
  const [hours, setHours] = useState(24);
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedHost, setSelectedHost] = useState('all');
  const [selected, setSelected] = useState<any>(null);

  const { data: response, isLoading } = useQuery({
    queryKey: ['events-table', hours],
    queryFn: () => api.getSecurityEvents({ hours, limit: 500 }),
    refetchInterval: 30000,
  });

  const allEvents: any[] = useMemo(() => {
    const d: any = response;
    return d?.data || d?.events || (Array.isArray(d) ? d : []);
  }, [response]);

  const hosts = useMemo(
    () => Array.from(new Set(allEvents.map((e) => e.source_host).filter(Boolean))).sort(),
    [allEvents],
  );
  const categories = useMemo(
    () => Array.from(new Set(allEvents.map((e) => e.event_category).filter(Boolean))).sort(),
    [allEvents],
  );

  const events = useMemo(
    () =>
      allEvents.filter((e) => {
        if (selectedSeverity !== 'all' && e.severity !== selectedSeverity) return false;
        if (selectedCategory !== 'all' && e.event_category !== selectedCategory) return false;
        if (selectedHost !== 'all' && e.source_host !== selectedHost) return false;
        return true;
      }),
    [allEvents, selectedSeverity, selectedCategory, selectedHost],
  );

  const stats = useMemo(() => {
    const by = (s: string) => allEvents.filter((e) => e.severity === s).length;
    return { total: allEvents.length, critical: by('critical'), high: by('high'), medium: by('medium') };
  }, [allEvents]);

  return (
    <div>
      {/* Stats */}
      <StatsGrid columns={4} className="mb-6">
        <StatCard title="Eventi (finestra)" value={stats.total} icon={<Activity className="w-6 h-6" />} variant="info" info={HELP.eventsTable.statTotal} />
        <StatCard title="Critical" value={stats.critical} icon={<AlertTriangle className="w-6 h-6" />} variant="danger" info={HELP.eventsTable.statCritical} />
        <StatCard title="High" value={stats.high} icon={<AlertTriangle className="w-6 h-6" />} variant="warning" info={HELP.eventsTable.statHigh} />
        <StatCard title="Medium" value={stats.medium} icon={<Shield className="w-6 h-6" />} variant="default" info={HELP.severity.medium} />
      </StatsGrid>

      {/* Filtri */}
      <div className="flex flex-wrap items-end gap-4 mb-6">
        <div className="w-40">
          <label className="text-sm font-medium text-gray-700 mb-1 block">Finestra</label>
          <Select value={String(hours)} onChange={(e: any) => setHours(Number(e.target.value))}>
            <option value="1">Ultima ora</option>
            <option value="24">Ultime 24h</option>
            <option value="168">Ultimi 7 giorni</option>
          </Select>
        </div>
        <div className="w-44">
          <label className="text-sm font-medium text-gray-700 mb-1 flex items-center gap-1">Host <InfoTip content={HELP.eventsTable.filterHost} /></label>
          <Select value={selectedHost} onChange={(e: any) => setSelectedHost(e.target.value)}>
            <option value="all">Tutti gli host</option>
            {hosts.map((h) => (<option key={h} value={h}>{h}</option>))}
          </Select>
        </div>
        <div className="w-44">
          <label className="text-sm font-medium text-gray-700 mb-1 flex items-center gap-1">Severità <InfoTip content={HELP.eventsTable.filterSeverity} /></label>
          <Select value={selectedSeverity} onChange={(e: any) => setSelectedSeverity(e.target.value)}>
            <option value="all">Tutte</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </Select>
        </div>
        <div className="w-52">
          <label className="text-sm font-medium text-gray-700 mb-1 flex items-center gap-1">Categoria <InfoTip content={HELP.eventsTable.filterCategory} /></label>
          <Select value={selectedCategory} onChange={(e: any) => setSelectedCategory(e.target.value)}>
            <option value="all">Tutte</option>
            {categories.map((c) => (<option key={c} value={c}>{String(c).replace(/_/g, ' ')}</option>))}
          </Select>
        </div>
      </div>

      {/* Tabella */}
      <div className="bg-white rounded-lg border border-slate-200 overflow-hidden">
        <div className="px-4 py-2 text-xs text-slate-500 border-b border-slate-100 flex items-center justify-between">
          <span>{events.length} eventi</span>
          <span className="flex items-center gap-2"><Activity className="w-4 h-4 animate-pulse text-green-500" /> auto-refresh 30s · {HELP.eventsTable.rowHint}</span>
        </div>
        <div className="overflow-x-auto max-h-[70vh] overflow-y-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-slate-50 text-slate-500 text-[11px] uppercase tracking-wide">
              <tr>
                <th className="text-left px-3 py-2 font-medium">Severità</th>
                <th className="text-left px-3 py-2 font-medium">Ora ({tzAbbr()})</th>
                <th className="text-left px-3 py-2 font-medium">Host</th>
                <th className="text-left px-3 py-2 font-medium">Categoria</th>
                <th className="text-left px-3 py-2 font-medium">Evento</th>
                <th className="text-left px-3 py-2 font-medium"><span className="inline-flex items-center gap-1">MITRE <InfoTip content={HELP.eventsTable.colMitre} /></span></th>
                <th className="px-2 py-2"><span className="inline-flex items-center gap-1">Sensore <InfoTip content={HELP.eventsTable.colSensor} /></span></th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr
                  key={e.id}
                  onClick={() => setSelected(e)}
                  className={`border-t border-slate-50 hover:bg-blue-50/50 cursor-pointer ${selected?.id === e.id ? 'bg-blue-50' : ''}`}
                >
                  <td className="px-3 py-1.5"><SeverityBadge severity={e.severity || 'low'} /></td>
                  <td className="px-3 py-1.5 whitespace-nowrap font-mono text-[12px] text-slate-500">
                    {e.timestamp ? format(new Date(e.timestamp), 'dd/MM HH:mm:ss') : '—'}
                  </td>
                  <td className="px-3 py-1.5 text-slate-600">{e.source_host || '—'}</td>
                  <td className="px-3 py-1.5">
                    <span className="inline-flex px-2 py-0.5 rounded-full text-[11px] bg-purple-100 text-purple-800">{e.event_category || 'unknown'}</span>
                  </td>
                  <td className="px-3 py-1.5 min-w-0">
                    <div className="font-medium text-slate-800 truncate max-w-[360px]">{e.process_cmdline || e.process_name || e.event_type}</div>
                    {e.file_path && <div className="text-[11px] text-slate-400 truncate max-w-[360px]">📄 {e.file_path}</div>}
                  </td>
                  <td className="px-3 py-1.5">
                    {e.mitre_technique
                      ? <span className="inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium bg-orange-50 text-orange-700 border border-orange-200 font-mono">{e.mitre_technique}</span>
                      : <span className="text-slate-300 text-xs">—</span>}
                  </td>
                  <td className="px-2">
                    {sensorOf(e) === 'ebpf' && <Cpu className="w-3.5 h-3.5 text-violet-500" aria-label="eBPF" />}
                  </td>
                </tr>
              ))}
              {events.length === 0 && !isLoading && (
                <tr><td colSpan={7} className="px-4 py-10 text-center text-slate-400">Nessun evento</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selected && <EventDrawer event={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
