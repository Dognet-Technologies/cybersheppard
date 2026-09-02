// ============================================================================
// Preferenze UI locali (per-browser). La finestra di raggruppamento delle
// correlazioni ripetute è impostabile dall'utente in Settings; qui la
// leggiamo/scriviamo in localStorage con fallback robusto.
// ============================================================================

const GROUP_WINDOW_KEY = 'cs.corr.groupWindowMin';

// 0 = Off (storico piatto), altrimenti minuti.
export const GROUP_WINDOW_OPTIONS = [0, 10, 15, 30] as const;
export const GROUP_WINDOW_DEFAULT = 15;

export function getGroupWindowMin(): number {
  try {
    const v = localStorage.getItem(GROUP_WINDOW_KEY);
    if (v !== null) {
      const n = parseInt(v, 10);
      if (!Number.isNaN(n) && n >= 0) return n;
    }
  } catch {
    // localStorage non disponibile: usa il default
  }
  return GROUP_WINDOW_DEFAULT;
}

export function setGroupWindowMin(min: number): void {
  try {
    localStorage.setItem(GROUP_WINDOW_KEY, String(min));
  } catch {
    // ignora: preferenza non persistita
  }
}
