// ============================================================================
// Threat Detection — hub unificato del dominio "rilevamento minacce".
// Raccoglie in un'unica pagina a schede il flusso SOC:
//   Tabella · Esplora · Correlazioni (Lista/Matrice ATT&CK) · Alert
// La scheda attiva è persistita in ?view=... (condivisibile, resiste al refresh).
// Nota: le violazioni di compliance NON stanno qui — sono postura di conformità
// e vivono sotto /compliance.
// ============================================================================

import { useSearchParams } from 'react-router-dom';
import { Crosshair, Table as TableIcon, FileSearch, Zap, Bell } from 'lucide-react';
import { PageHeader } from '../components/ui';
import EventsTableView from './EventsTableView';
import EventsExplorerView from './EventsExplorerView';
import CorrelationsTab from './CorrelationsTab';
import AlertsView from './AlertsView';

type View = 'table' | 'explore' | 'correlations' | 'alerts';

const TABS: { id: View; label: string; icon: JSX.Element }[] = [
  { id: 'table', label: 'Tabella', icon: <TableIcon className="w-4 h-4" /> },
  { id: 'explore', label: 'Esplora', icon: <FileSearch className="w-4 h-4" /> },
  { id: 'correlations', label: 'Correlazioni', icon: <Zap className="w-4 h-4" /> },
  { id: 'alerts', label: 'Alert', icon: <Bell className="w-4 h-4" /> },
];

const isView = (v: string | null): v is View =>
  v === 'table' || v === 'explore' || v === 'correlations' || v === 'alerts';

export default function ThreatDetection() {
  const [searchParams, setSearchParams] = useSearchParams();
  const raw = searchParams.get('view');
  const view: View = isView(raw) ? raw : 'table';

  const setView = (v: View) => {
    // cambiando scheda ripulisco i parametri specifici della scheda precedente
    const p = new URLSearchParams();
    p.set('view', v);
    setSearchParams(p, { replace: true });
  };

  return (
    <div>
      <PageHeader
        title="Threat Detection"
        subtitle="Eventi, correlazioni, copertura MITRE ATT&CK e alert di sicurezza in un unico flusso"
        icon={<Crosshair className="w-6 h-6" />}
      />

      {/* Tab switcher */}
      <div className="flex gap-1 mb-6 border-b border-slate-200">
        {TABS.map((t) => {
          const active = view === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setView(t.id)}
              className={`flex items-center gap-2 px-4 py-2 text-sm font-medium -mb-px border-b-2 transition-colors ${
                active
                  ? 'border-blue-600 text-blue-700'
                  : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
              }`}
            >
              {t.icon}
              {t.label}
            </button>
          );
        })}
      </div>

      {view === 'table' && <EventsTableView />}
      {view === 'explore' && <EventsExplorerView />}
      {view === 'correlations' && <CorrelationsTab />}
      {view === 'alerts' && <AlertsView />}
    </div>
  );
}
