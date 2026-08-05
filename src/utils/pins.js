/**
 * "Pinned CWEs" - a small localStorage-backed list letting an engineer
 * bookmark the weaknesses they look up often. Falls back to an in-memory
 * array for the session if localStorage is unavailable (private mode, etc.)
 */
const STORAGE_KEY = 'cwe-lookup-pins';
let memoryFallback = [];
let storageAvailable = true;

function readRaw() {
  if (!storageAvailable) return memoryFallback;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    storageAvailable = false;
    return memoryFallback;
  }
}

function writeRaw(list) {
  if (!storageAvailable) {
    memoryFallback = list;
    return;
  }
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
  } catch {
    storageAvailable = false;
    memoryFallback = list;
  }
}

export function getPinnedCwes() {
  const list = readRaw();
  return Array.isArray(list) ? list : [];
}

export function isPinned(cweId) {
  return getPinnedCwes().includes(cweId);
}

export function togglePin(cweId) {
  const list = getPinnedCwes();
  const next = list.includes(cweId)
    ? list.filter((id) => id !== cweId)
    : [...list, cweId].slice(-8); // keep the pin bar tidy
  writeRaw(next);
  return next;
}
