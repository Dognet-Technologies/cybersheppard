// ============================================================================
// Correlazioni — scheda dell'hub Threat Detection con toggle interno:
//   • Lista   → tabella correlazioni (CorrelationsList)
//   • Matrice → copertura MITRE ATT&CK (AttackMatrixView)
// La modalità è persistita in ?mode=list|matrix (default: list).
// ============================================================================

import { useSearchParams } from 'react-router-dom';
import { List, Grid3x3 } from 'lucide-react';
import CorrelationsList from './CorrelationsList';
import AttackMatrixView from './AttackMatrixView';

type Mode = 'list' | 'matrix';

export default function CorrelationsTab() {
  const [searchParams, setSearchParams] = useSearchParams();
  const mode: Mode = searchParams.get('mode') === 'matrix' ? 'matrix' : 'list';

  const setMode = (m: Mode) => {
    const p = new URLSearchParams(searchParams);
    p.set('mode', m);
    // cambiando modalità azzero il filtro tecnica (valido solo per la Lista)
    if (m === 'matrix') p.delete('technique');
    setSearchParams(p, { replace: true });
  };

  const btn = (m: Mode, label: string, icon: JSX.Element) => {
    const active = mode === m;
    return (
      <button
        onClick={() => setMode(m)}
        className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${
          active ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-600 hover:bg-slate-100'
        }`}
      >
        {icon}
        {label}
      </button>
    );
  };

  return (
    <div>
      <div className="inline-flex gap-1 p-1 mb-4 bg-slate-100 rounded-lg">
        {btn('list', 'Lista', <List className="w-4 h-4" />)}
        {btn('matrix', 'Matrice ATT&CK', <Grid3x3 className="w-4 h-4" />)}
      </div>

      {mode === 'matrix' ? <AttackMatrixView /> : <CorrelationsList />}
    </div>
  );
}
