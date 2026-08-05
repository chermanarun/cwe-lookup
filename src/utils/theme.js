/**
 * Theme management: light/dark with persisted preference and a
 * system-preference fallback for users who have never chosen explicitly.
 *
 * Fallback chain:
 *   1. Explicit user choice stored in localStorage
 *   2. OS/browser `prefers-color-scheme`
 *   3. 'light' (final hard default if storage and media queries are unavailable)
 */

const STORAGE_KEY = 'cwe-lookup-theme';

export function getStoredTheme() {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    return value === 'light' || value === 'dark' ? value : null;
  } catch {
    return null;
  }
}

export function getSystemTheme() {
  try {
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      return 'dark';
    }
  } catch {
    // matchMedia unavailable (very old browser) - fall through to default
  }
  return 'light';
}

export function applyTheme(theme) {
  const resolved = theme === 'dark' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', resolved);
  return resolved;
}

export function getActiveTheme() {
  return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
}

export function setTheme(theme) {
  const resolved = theme === 'dark' ? 'dark' : 'light';
  try {
    localStorage.setItem(STORAGE_KEY, resolved);
  } catch {
    // Storage unavailable (private mode, quota, etc.) - theme still applies for this session
  }
  return applyTheme(resolved);
}

export function toggleTheme() {
  return setTheme(getActiveTheme() === 'dark' ? 'light' : 'dark');
}

/**
 * Initializes the theme. Safe to call multiple times. Also wires a listener
 * so the app follows OS theme changes live, but only while no explicit
 * preference has been saved (otherwise the user's choice always wins).
 */
export function initTheme() {
  const stored = getStoredTheme();
  applyTheme(stored || getSystemTheme());

  try {
    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (!getStoredTheme()) {
          applyTheme(e.matches ? 'dark' : 'light');
        }
      });
    }
  } catch {
    // Listener unsupported - static fallback already applied above
  }

  return getActiveTheme();
}
