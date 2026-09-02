// ============================================================================
// Events — Explorer view. Esploratore log a faccette + drawer di dettaglio.
// Pannelli di faccette (host/utente/categoria/tattica/sensore/tipo) a sinistra,
// tabella eventi al centro, drawer col dettaglio arricchito (processo, identità,
// file/rete, ancestry, JSON grezzo) a destra. Vista "Esplora" della pagina Eventi.
// ============================================================================

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { format } from 'date-fns';
import { X, Cpu, ChevronRight } from 'lucide-react';
import api from '../services/api';
import { Select, Badge } from '../components/ui';

type Facet = 'source_host' | 'user_name' | 'event_category' | 'mitre_tactic' | 'sensor' | 'event_type';

const FACETS: { key: Facet; label: string }[] = [
  { key: 'source_host', label: 'Host' },
  { key: 'event_category', label: 'Categoria' },
  { key: 'event_type', label: 'Tipo evento' },
  { key: 'user_name', label: 'Utente' },
  { key: 'mitre_tactic', label: 'Tattica ATT&CK' },
  { key: 'sensor', label: 'Sensore' },
];

const sensorOf = (e: any): string => (e?.event_data?.sensor === 'ebpf' ? 'ebpf' : 'auditd');
const facetValue = (e: any, f: Facet): string =>
  f === 'sensor' ? sensorOf(e) : (e?.[f] ?? '—');

const sevColor: Record<string, string> = {
  critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-amber-400', low: 'bg-sky-400',
};

export default function EventsExplorerView() {
  const [hours, setHours] = useState(24);
  const [filters, setFilters] = useState<Partial<Record<Facet, string>>>({});
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<any>(null);

  const { data: response, isLoading } = useQuery({
    queryKey: ['event-explorer', hours],
    queryFn: () => api.getSecurityEvents({ hours, limit: 500 }),
    refetchInterval: 30000,
  });

  const allEvents: any[] = useMemo(() => {
    const d: any = response;
    return d?.data || d?.events || (Array.isArray(d) ? d : []);
  }, [response]);

  const events = useMemo(() => {
    const q = search.trim().toLowerCase();
    return allEvents.filter((e) => {
      for (const f of FACETS) {
        const want = filters[f.key];
        if (want && facetValue(e, f.key) !== want) return false;
      }
      if (q) {
        const hay = `${e.process_name} ${e.process_cmdline} ${e.file_path} ${e.user_name} ${e.event_type}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [allEvents, filters, search]);

  // Conteggi faccette calcolati sull'insieme filtrato dalle ALTRE faccette
  const facetCounts = useMemo(() => {
    const res: Record<Facet, Map<string, number>> = {} as any;
    for (const f of FACETS) {
      const others = allEvents.filter((e) =>
        FACETS.every((g) => g.key === f.key || !filters[g.key] || facetValue(e, g.key) === filters[g.key]),
      );
      const m = new Map<string, number>();
      for (const e of others) {
        const v = facetValue(e, f.key);
        m.set(v, (m.get(v) || 0) + 1);
      }
      res[f.key] = m;
    }
    return res;
  }, [allEvents, filters]);

  const toggle = (f: Facet, v: string) =>
    setFilters((cur) => (cur[f] === v ? { ...cur, [f]: undefined } : { ...cur, [f]: v }));

  const activeCount = Object.values(filters).filter(Boolean).length;

  return (
    <div>
      {/* Intervallo temporale */}
      <div className="flex justify-end mb-4">
        <div className="w-40">
          <Select value={String(hours)} onChange={(e: any) => setHours(Number(e.target.value))}>
            <option value="1">Ultima ora</option>
            <option value="24">Ultime 24h</option>
            <option value="168">Ultimi 7 giorni</option>
          </Select>
        </div>
      </div>

      <div className="flex gap-4">
        {/* Faccette */}
        <aside className="w-60 flex-shrink-0 space-y-4">
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Cerca processo/file/utente…"
            className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 focus:border-blue-500 focus:outline-none"
          />
          {activeCount > 0 && (
            <button onClick={() => setFilters({})} className="text-xs text-blue-600 hover:underline">
              Azzera {activeCount} filtri
            </button>
          )}
          {FACETS.map((f) => {
            const counts = facetCounts[f.key];
            const entries = counts ? [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8) : [];
            return (
              <div key={f.key} className="bg-white rounded-lg border border-slate-200 p-3">
                <div className="text-xs font-semibold text-slate-700 mb-2">{f.label}</div>
                <div className="space-y-1">
                  {entries.length === 0 && <div className="text-[11px] text-slate-300">—</div>}
                  {entries.map(([v, n]) => {
                    const active = filters[f.key] === v;
                    return (
                      <button
                        key={v}
                        onClick={() => toggle(f.key, v)}
                        className={`w-full flex items-center justify-between gap-2 px-2 py-1 rounded text-[12px] transition-colors ${
                          active ? 'bg-blue-600 text-white' : 'hover:bg-slate-100 text-slate-700'
                        }`}
                      >
                        <span className="truncate">{v.replace(/_/g, ' ')}</span>
                        <span className={`font-mono ${active ? 'text-blue-100' : 'text-slate-400'}`}>{n}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </aside>

        {/* Tabella eventi */}
        <main className="flex-1 min-w-0">
          <div className="bg-white rounded-lg border border-slate-200 overflow-hidden">
            <div className="px-4 py-2 text-xs text-slate-500 border-b border-slate-100">
              {events.length} eventi {activeCount > 0 || search ? '(filtrati)' : ''}
            </div>
            <div className="overflow-x-auto max-h-[70vh] overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-slate-50 text-slate-500 text-[11px] uppercase tracking-wide">
                  <tr>
                    <th className="text-left px-3 py-2 font-medium">Ora</th>
                    <th className="text-left px-3 py-2 font-medium">Host</th>
                    <th className="text-left px-3 py-2 font-medium">Utente</th>
                    <th className="text-left px-3 py-2 font-medium">Processo</th>
                    <th className="text-left px-3 py-2 font-medium">Categoria</th>
                    <th className="text-left px-3 py-2 font-medium">MITRE</th>
                    <th className="px-2 py-2"></th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr
                      key={e.id}
                      onClick={() => setSelected(e)}
                      className={`border-t border-slate-50 hover:bg-blue-50/50 cursor-pointer ${
                        selected?.id === e.id ? 'bg-blue-50' : ''
                      }`}
                    >
                      <td className="px-3 py-1.5 whitespace-nowrap font-mono text-[12px] text-slate-500">
                        <span className={`inline-block w-1.5 h-1.5 rounded-full mr-1.5 align-middle ${sevColor[e.severity] || 'bg-slate-300'}`} />
                        {e.timestamp ? format(new Date(e.timestamp), 'HH:mm:ss') : '—'}
                      </td>
                      <td className="px-3 py-1.5 text-slate-600">{e.source_host}</td>
                      <td className="px-3 py-1.5 text-slate-600">
                        {e.user_name || '—'}
                        {e.event_data?.auid && e.event_data.auid !== e.event_data.uid && (
                          <span className="text-slate-400"> ·auid {String(e.event_data.auid_name || e.event_data.auid)}</span>
                        )}
                      </td>
                      <td className="px-3 py-1.5 min-w-0">
                        <div className="font-medium text-slate-800 truncate max-w-[280px]">
                          {e.process_cmdline || e.process_name || e.event_type}
                        </div>
                        {e.file_path && <div className="text-[11px] text-slate-400 truncate max-w-[280px]">📄 {e.file_path}</div>}
                      </td>
                      <td className="px-3 py-1.5">
                        <span className="text-[11px] text-slate-500">{e.event_category}</span>
                      </td>
                      <td className="px-3 py-1.5">
                        {e.mitre_technique ? (
                          <span className="inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium bg-orange-50 text-orange-700 border border-orange-200 font-mono">
                            {e.mitre_technique}
                          </span>
                        ) : (
                          <span className="text-slate-300 text-xs">—</span>
                        )}
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
        </main>
      </div>

      {selected && <EventDrawer event={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

// ---------------------------------------------------------------------------
function EventDrawer({ event, onClose }: { event: any; onClose: () => void }) {
  const raw = event.event_data?.laurel_raw;
  const sc = raw?.SYSCALL;
  const spawn = sc?.SPAWNED_BY;
  const [showRaw, setShowRaw] = useState(false);

  const Row = ({ k, v }: { k: string; v: any }) =>
    v === undefined || v === null || v === '' ? null : (
      <div className="flex gap-2 py-1 border-b border-slate-50 text-[13px]">
        <span className="w-32 flex-shrink-0 text-slate-400">{k}</span>
        <span className="text-slate-800 break-all font-mono text-[12px]">{String(v)}</span>
      </div>
    );

  return (
    <>
      <div className="fixed inset-0 bg-black/20 z-40" onClick={onClose} />
      <aside className="fixed right-0 top-0 h-full w-[min(560px,92vw)] bg-white shadow-2xl z-50 flex flex-col">
        <div className="flex items-center justify-between px-5 py-3 border-b border-slate-200">
          <div>
            <div className="text-xs text-slate-400">{event.timestamp && format(new Date(event.timestamp), 'PPpp')}</div>
            <div className="text-lg font-semibold text-slate-800">{event.event_type}</div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-slate-100"><X className="w-5 h-5 text-slate-500" /></button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          {/* Badge */}
          <div className="flex flex-wrap gap-2">
            <Badge variant={event.severity === 'critical' ? 'danger' : event.severity === 'high' ? 'warning' : 'info'}>
              {event.severity?.toUpperCase()}
            </Badge>
            {event.mitre_tactic && (
              <span className="inline-flex px-2 py-0.5 rounded text-xs bg-red-50 text-red-700 border border-red-200">
                ATT&CK: {event.mitre_tactic.replace(/_/g, ' ')}
              </span>
            )}
            {event.mitre_technique && (
              <span className="inline-flex px-2 py-0.5 rounded text-xs bg-orange-50 text-orange-700 border border-orange-200 font-mono">
                {event.mitre_technique}
              </span>
            )}
            {event.event_data?.sensor === 'ebpf' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-violet-50 text-violet-700 border border-violet-200">
                <Cpu className="w-3 h-3" /> eBPF
              </span>
            )}
          </div>

          {/* Processo */}
          <section>
            <h4 className="text-xs font-semibold text-slate-500 uppercase mb-1">Processo</h4>
            <Row k="cmdline" v={event.process_cmdline} />
            <Row k="exe" v={event.process_name} />
            <Row k="pid / ppid" v={`${event.process_pid ?? '—'} / ${event.process_ppid ?? '—'}`} />
            <Row k="syscall" v={event.event_action} />
            <Row k="systemd unit" v={sc?.PID?.systemd_service?.join?.(', ')} />
            <Row k="cwd" v={raw?.CWD?.cwd} />
          </section>

          {/* Ancestry */}
          {spawn && (
            <section>
              <h4 className="text-xs font-semibold text-slate-500 uppercase mb-1">Process ancestry</h4>
              <div className="flex items-center gap-2 text-[13px] bg-slate-50 rounded-lg p-2">
                <span className="font-mono text-slate-700">{spawn.comm || spawn.exe} <span className="text-slate-400">({spawn.pid})</span></span>
                <ChevronRight className="w-4 h-4 text-slate-400" />
                <span className="font-mono text-slate-900 font-medium">{event.process_name?.split('/').pop()} <span className="text-slate-400">({event.process_pid})</span></span>
              </div>
            </section>
          )}

          {/* Identità */}
          <section>
            <h4 className="text-xs font-semibold text-slate-500 uppercase mb-1">Identità</h4>
            <Row k="user (uid)" v={event.user_name} />
            <Row k="auid (login)" v={event.event_data?.auid_name || event.event_data?.auid} />
            <Row k="session" v={event.event_data?.ses} />
          </section>

          {/* File / Rete */}
          {(event.file_path || event.destination_ip) && (
            <section>
              <h4 className="text-xs font-semibold text-slate-500 uppercase mb-1">File / Rete</h4>
              <Row k="file" v={event.file_path} />
              <Row k="operazione" v={event.file_operation} />
              <Row k="dest" v={event.destination_ip ? `${event.destination_ip}:${event.destination_port ?? ''}` : undefined} />
            </section>
          )}

          {/* Raw JSON */}
          <section>
            <button onClick={() => setShowRaw((s) => !s)} className="text-xs font-semibold text-blue-600 hover:underline">
              {showRaw ? '▾' : '▸'} JSON grezzo (Laurel/eBPF)
            </button>
            {showRaw && (
              <pre className="mt-2 text-[11px] bg-slate-900 text-slate-100 rounded-lg p-3 overflow-x-auto max-h-80">
                {JSON.stringify(event.event_data, null, 2)}
              </pre>
            )}
          </section>
        </div>
      </aside>
    </>
  );
}
