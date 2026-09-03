// ============================================================================
// Formattazione date/ora nell'ora LOCALE del browser, con etichetta del fuso.
// I timestamp arrivano dal backend in UTC (ISO con 'Z'); qui li mostriamo nel
// fuso di chi guarda e aggiungiamo la sigla del fuso (es. CEST, UTC) per non
// lasciare ambiguità (scelta prodotto: "ora locale, etichettata").
// ============================================================================

import { format } from 'date-fns';

/** Sigla del fuso orario del browser (es. "CEST", "UTC", "GMT+2"). */
export function tzAbbr(d: Date = new Date()): string {
  try {
    const parts = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' }).formatToParts(d);
    return parts.find((p) => p.type === 'timeZoneName')?.value || 'local';
  } catch {
    return 'local';
  }
}

/** Formatta un timestamp in ora locale con sigla del fuso in coda. */
export function fmtTs(ts: string | number | Date | null | undefined, pattern: string): string {
  if (ts === null || ts === undefined || ts === '') return '—';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return '—';
  return `${format(d, pattern)} ${tzAbbr(d)}`;
}
