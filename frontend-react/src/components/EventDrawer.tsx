// ============================================================================
// EventDrawer — pannello di dettaglio di un evento di sicurezza (security_events).
// Condiviso tra la vista "Tabella" e la vista "Esplora" dell'hub Threat Detection:
// processo, identità, file/rete, ancestry e JSON grezzo (Laurel/eBPF).
// ============================================================================

import { useState } from 'react';
import { X, Cpu, ChevronRight } from 'lucide-react';
import { Badge } from './ui';
import { fmtTs } from '../utils/datetime';

export default function EventDrawer({ event, onClose }: { event: any; onClose: () => void }) {
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
            <div className="text-xs text-slate-400">{event.timestamp && fmtTs(event.timestamp, 'PPpp')}</div>
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
