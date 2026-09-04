// ============================================================================
// PairingModal — avvia una finestra di pairing dell'agent (3 min, stile FireDog)
// e ne mostra lo stato in tempo reale (fase 1: API key, fase 2: identity hash).
// L'agent, avviato sul target entro la finestra con ip/hostname/mac configurati,
// completa il pairing; il server calcola SHA512(ip+hostname+mac) e lo confronta.
// ============================================================================

import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { X, CheckCircle2, Circle, Loader2, AlertTriangle, RefreshCw } from 'lucide-react';
import api from '../services/api';

interface PairingModalProps {
  isOpen: boolean;
  onClose: () => void;
  target: { id: number; hostname: string; ip_address?: string };
}

const WINDOW_SECONDS = 180;

type PairStatus =
  | 'idle'
  | 'pending'
  | 'verifying_hash'
  | 'success'
  | 'failed'
  | 'expired'
  | 'none'
  | 'unknown';

export default function PairingModal({ isOpen, onClose, target }: PairingModalProps) {
  const queryClient = useQueryClient();
  const [started, setStarted] = useState(false);
  const [remaining, setRemaining] = useState(WINDOW_SECONDS);
  const [startError, setStartError] = useState('');
  const expiresAtRef = useRef<number | null>(null);

  const startMutation = useMutation({
    mutationFn: () => api.startPairing(target.id),
    onSuccess: (data: any) => {
      setStartError('');
      setStarted(true);
      const exp = data?.expires_at ? new Date(data.expires_at).getTime() : Date.now() + WINDOW_SECONDS * 1000;
      expiresAtRef.current = exp;
      setRemaining(Math.max(0, Math.round((exp - Date.now()) / 1000)));
    },
    onError: (err: any) => {
      setStartError(err.response?.data?.error || 'Impossibile avviare il pairing');
    },
  });

  // Poll dello stato mentre la finestra è attiva.
  const { data: status } = useQuery({
    queryKey: ['pairing-status', target.id],
    queryFn: () => api.getPairingStatus(target.id),
    enabled: isOpen && started,
    refetchInterval: (query) => {
      const s = (query.state.data as any)?.status;
      return s === 'success' || s === 'failed' || s === 'expired' ? false : 2000;
    },
  });

  const st: PairStatus = (status?.status as PairStatus) || (started ? 'pending' : 'idle');
  const phase1 = !!status?.phase_1_verified;
  const phase2 = !!status?.phase_2_verified;
  const isDone = st === 'success';
  const isFailed = st === 'failed' || st === 'expired';

  // Avvio automatico all'apertura.
  useEffect(() => {
    if (isOpen && !started && !startMutation.isPending) {
      startMutation.mutate();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen]);

  // Countdown finestra.
  useEffect(() => {
    if (!started || isDone || isFailed) return;
    const t = setInterval(() => {
      const exp = expiresAtRef.current;
      if (exp) setRemaining(Math.max(0, Math.round((exp - Date.now()) / 1000)));
    }, 1000);
    return () => clearInterval(t);
  }, [started, isDone, isFailed]);

  // Al successo, aggiorna la lista target (stato online).
  useEffect(() => {
    if (isDone) queryClient.invalidateQueries({ queryKey: ['targets'] });
  }, [isDone, queryClient]);

  // Reset alla chiusura.
  const handleClose = () => {
    setStarted(false);
    setRemaining(WINDOW_SECONDS);
    setStartError('');
    expiresAtRef.current = null;
    queryClient.removeQueries({ queryKey: ['pairing-status', target.id] });
    onClose();
  };

  const retry = () => {
    setStarted(false);
    expiresAtRef.current = null;
    setRemaining(WINDOW_SECONDS);
    startMutation.mutate();
  };

  if (!isOpen) return null;

  const mmss = `${String(Math.floor(remaining / 60)).padStart(2, '0')}:${String(remaining % 60).padStart(2, '0')}`;
  const timedOut = remaining <= 0 && !isDone;
  const effectiveStatus: PairStatus = timedOut && !isFailed ? 'expired' : st;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-lg">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold">Agent pairing — {target.hostname}</h2>
          <button onClick={handleClose} className="text-gray-500 hover:text-gray-700">
            <X className="w-6 h-6" />
          </button>
        </div>

        {startError ? (
          <div className="bg-red-50 text-red-700 px-4 py-3 rounded-lg text-sm flex items-start gap-2">
            <AlertTriangle className="w-5 h-5 shrink-0" />
            <span>{startError}</span>
          </div>
        ) : (
          <>
            {/* Countdown / esito */}
            <div className="text-center py-4">
              {isDone ? (
                <div className="text-green-600">
                  <CheckCircle2 className="w-14 h-14 mx-auto mb-2" />
                  <p className="text-lg font-semibold">Pairing completato</p>
                  {status?.agent_ip && (
                    <p className="text-sm text-gray-500 mt-1 font-mono">
                      {status.agent_hostname} · {status.agent_ip} · {status.agent_mac}
                    </p>
                  )}
                </div>
              ) : effectiveStatus === 'expired' || effectiveStatus === 'failed' ? (
                <div className="text-red-600">
                  <AlertTriangle className="w-14 h-14 mx-auto mb-2" />
                  <p className="text-lg font-semibold">
                    {effectiveStatus === 'expired' ? 'Finestra scaduta' : 'Pairing fallito'}
                  </p>
                  {status?.error_message && (
                    <p className="text-sm text-gray-500 mt-1">{status.error_message}</p>
                  )}
                </div>
              ) : (
                <div>
                  <div className="text-4xl font-mono font-bold text-blue-600 tabular-nums">{mmss}</div>
                  <p className="text-sm text-gray-500 mt-1 flex items-center justify-center gap-1">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    In attesa dell'agent…
                  </p>
                </div>
              )}
            </div>

            {/* Fasi */}
            <div className="space-y-2 border-t pt-4">
              <PhaseRow label="Fase 1 — verifica API key" done={phase1} active={!phase1 && !isFailed} />
              <PhaseRow label="Fase 2 — verifica identità (SHA512 IP+hostname+MAC)" done={phase2} active={phase1 && !phase2 && !isFailed} />
            </div>

            {/* Istruzioni agent */}
            {!isDone && (
              <div className="mt-4 bg-slate-50 border border-slate-200 rounded-lg p-3 text-xs text-slate-600">
                <p className="font-medium text-slate-700 mb-1">Sul target, entro la finestra:</p>
                <p>
                  Configura l'agent con <code className="font-mono">ip</code>, <code className="font-mono">hostname</code> e{' '}
                  <code className="font-mono">mac</code> corrispondenti a questo target e la relativa API key, poi
                  avvia/riavvia il servizio dell'agent (come FireDog).
                </p>
              </div>
            )}
          </>
        )}

        <div className="flex justify-end gap-3 mt-6 pt-4 border-t">
          {(effectiveStatus === 'expired' || effectiveStatus === 'failed' || !!startError) && (
            <button
              onClick={retry}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2"
            >
              <RefreshCw className="w-4 h-4" /> Riprova
            </button>
          )}
          <button onClick={handleClose} className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50">
            {isDone ? 'Chiudi' : 'Annulla'}
          </button>
        </div>
      </div>
    </div>
  );
}

function PhaseRow({ label, done, active }: { label: string; done: boolean; active: boolean }) {
  return (
    <div className="flex items-center gap-2 text-sm">
      {done ? (
        <CheckCircle2 className="w-5 h-5 text-green-500 shrink-0" />
      ) : active ? (
        <Loader2 className="w-5 h-5 text-blue-500 animate-spin shrink-0" />
      ) : (
        <Circle className="w-5 h-5 text-gray-300 shrink-0" />
      )}
      <span className={done ? 'text-gray-800' : active ? 'text-gray-700' : 'text-gray-400'}>{label}</span>
    </div>
  );
}
