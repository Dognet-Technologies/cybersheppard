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

// --- Sidebar: larghezza (px) e stato collassato --------------------------
const SIDEBAR_WIDTH_KEY = 'cs.sidebar.width';
const SIDEBAR_COLLAPSED_KEY = 'cs.sidebar.collapsed';
export const SIDEBAR_MIN = 180;
export const SIDEBAR_MAX = 420;
export const SIDEBAR_DEFAULT = 256;

export function getSidebarWidth(): number {
  try {
    const v = parseInt(localStorage.getItem(SIDEBAR_WIDTH_KEY) ?? '', 10);
    if (!Number.isNaN(v)) return Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, v));
  } catch {
    /* default */
  }
  return SIDEBAR_DEFAULT;
}

export function setSidebarWidth(w: number): void {
  try {
    localStorage.setItem(SIDEBAR_WIDTH_KEY, String(Math.round(w)));
  } catch {
    /* ignora */
  }
}

export function getSidebarCollapsed(): boolean {
  try {
    return localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === '1';
  } catch {
    return false;
  }
}

export function setSidebarCollapsed(v: boolean): void {
  try {
    localStorage.setItem(SIDEBAR_COLLAPSED_KEY, v ? '1' : '0');
  } catch {
    /* ignora */
  }
}
