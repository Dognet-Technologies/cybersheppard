// ============================================================================
// Tooltip / InfoTip — suggerimenti al passaggio del mouse (e al focus da
// tastiera) per spiegare pagine, metriche, colonne, filtri e badge.
// Accessibile: appare su hover e su focus, con role="tooltip".
// La bolla è renderizzata in un PORTAL su <body> con position:fixed e
// coordinate calcolate dal trigger: così NON viene ritagliata dai contenitori
// con overflow:hidden (es. le tabelle). Nessuna dipendenza esterna.
// I testi vanno dal dizionario bilingue in src/i18n/help.ts.
// ============================================================================

import { ReactNode, useCallback, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import clsx from 'clsx';
import { HelpCircle } from 'lucide-react';

type Side = 'top' | 'bottom' | 'left' | 'right';

interface TooltipProps {
  content?: ReactNode;
  children: ReactNode;
  side?: Side;
  /** Classi extra per la bolla del tooltip. */
  className?: string;
  /** Classi per il wrapper del trigger (es. "block w-full" in una sidebar). */
  wrapperClassName?: string;
}

const GAP = 8;

function computePosition(rect: DOMRect, side: Side) {
  switch (side) {
    case 'bottom':
      return { left: rect.left + rect.width / 2, top: rect.bottom + GAP, transform: 'translate(-50%, 0)' };
    case 'left':
      return { left: rect.left - GAP, top: rect.top + rect.height / 2, transform: 'translate(-100%, -50%)' };
    case 'right':
      return { left: rect.right + GAP, top: rect.top + rect.height / 2, transform: 'translate(0, -50%)' };
    case 'top':
    default:
      return { left: rect.left + rect.width / 2, top: rect.top - GAP, transform: 'translate(-50%, -100%)' };
  }
}

export function Tooltip({ content, children, side = 'top', className, wrapperClassName }: TooltipProps) {
  const triggerRef = useRef<HTMLSpanElement>(null);
  const [pos, setPos] = useState<{ left: number; top: number; transform: string } | null>(null);
  const id = useId();

  const open = useCallback(() => {
    const el = triggerRef.current;
    if (!el) return;
    setPos(computePosition(el.getBoundingClientRect(), side));
  }, [side]);

  const close = useCallback(() => setPos(null), []);

  // Nessun contenuto → renderizza i figli così com'è (nessun wrapper inutile).
  if (content === undefined || content === null || content === '') return <>{children}</>;

  return (
    <span
      ref={triggerRef}
      className={clsx('relative', wrapperClassName || 'inline-flex')}
      onMouseEnter={open}
      onMouseLeave={close}
      onFocus={open}
      onBlur={close}
      aria-describedby={pos ? id : undefined}
    >
      {children}
      {pos &&
        createPortal(
          <span
            id={id}
            role="tooltip"
            style={{ position: 'fixed', left: pos.left, top: pos.top, transform: pos.transform, zIndex: 9999 }}
            className={clsx(
              'pointer-events-none w-max max-w-xs whitespace-normal rounded-lg',
              'bg-slate-900 px-3 py-2 text-left text-xs font-normal leading-relaxed text-slate-100 shadow-xl',
              className,
            )}
          >
            {content}
          </span>,
          document.body,
        )}
    </span>
  );
}

interface InfoTipProps {
  content?: ReactNode;
  side?: Side;
  className?: string;
  /** Etichetta accessibile per lo screen reader (default generico). */
  label?: string;
}

// Piccola icona "?" che mostra una spiegazione. Da mettere accanto a titoli,
// nomi di metriche, intestazioni di colonna, ecc.
export function InfoTip({ content, side = 'top', className, label = 'Maggiori informazioni' }: InfoTipProps) {
  if (content === undefined || content === null || content === '') return null;
  return (
    <Tooltip content={content} side={side}>
      <button
        type="button"
        aria-label={label}
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
        }}
        className={clsx(
          'inline-flex items-center justify-center rounded-full text-slate-400',
          'hover:text-slate-600 focus:text-slate-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400',
          'transition-colors align-middle',
          className,
        )}
      >
        <HelpCircle className="w-3.5 h-3.5" />
      </button>
    </Tooltip>
  );
}
