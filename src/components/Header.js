import { searchCweSuggestions } from '../services/cweService.js';
import { icon, Icons } from '../utils/icons.js';
import { getPinnedCwes } from '../utils/pins.js';

// The app fully re-renders the header on every state change (search, tab
// switch, theme toggle, pin toggle). Tracking the single active
// "click outside" listener here - and removing it before attaching a new
// one - keeps that pattern from leaking a listener per render.
let activeOutsideClickHandler = null;

export function createHeader({ currentCweId, theme, onSearch, onSelectCwe, onToggleTheme }) {
  const container = document.createElement('header');
  container.className = 'hero';

  const pinned = getPinnedCwes();
  const defaults = ['CWE-89', 'CWE-284', 'CWE-79', 'CWE-78'];
  const quickIds = [...new Set([...pinned, ...defaults])].slice(0, 8);

  container.innerHTML = `
    <div class="hero-inner container">
      <div class="hero-top">
        <div class="brand" id="header-logo">
          <div class="brand-mark">${icon(Icons.shield, { size: 20 })}</div>
          <div>
            <div class="brand-title">
              CWE Security Lookup
              <span class="brand-badge">v2.0</span>
            </div>
            <p class="brand-subtitle">Vulnerability intelligence &amp; remediation guide for engineers</p>
          </div>
        </div>
        <div class="hero-actions">
          <button id="theme-toggle-btn" class="theme-toggle" aria-label="Toggle dark mode" title="Toggle color theme">
            ${icon(theme === 'dark' ? Icons.sun : Icons.moon, { size: 17 })}
          </button>
        </div>
      </div>

      <div class="search-bar">
        <span class="search-icon">${icon(Icons.search, { size: 17 })}</span>
        <input
          type="text"
          id="cwe-search-input"
          value="${currentCweId || ''}"
          placeholder="Search a CWE ID (e.g. CWE-89) or keyword..."
          class="search-input"
          autocomplete="off"
        />
        <button id="cwe-search-btn" class="search-submit-btn">Search</button>
        <div id="autocomplete-dropdown" class="autocomplete-dropdown hidden"></div>
      </div>

      <div class="hero-meta-row">
        <span class="hero-meta-label">${pinned.length ? 'Pinned &amp; common:' : 'Common lookups:'}</span>
        <div class="chip-row" id="quick-pills">
          ${quickIds.map((id) => `
            <button type="button" data-cwe="${id}" class="chip${pinned.includes(id) ? ' is-pinned' : ''}">
              ${id}
            </button>
          `).join('')}
        </div>
      </div>

      <div class="hero-banner">
        ${icon(Icons.info, { size: 15 })}
        <span>Backed by the local weakness cache with live <strong>MITRE CWE API</strong> lookups and a synthesized fallback when a record is unavailable.</span>
      </div>
    </div>
  `;

  const input = container.querySelector('#cwe-search-input');
  const searchBtn = container.querySelector('#cwe-search-btn');
  const dropdown = container.querySelector('#autocomplete-dropdown');

  const executeSearch = (val) => {
    dropdown.classList.add('hidden');
    if (val && val.trim()) {
      onSearch(val.trim());
    }
  };

  searchBtn.addEventListener('click', () => executeSearch(input.value));
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') executeSearch(input.value);
  });

  input.addEventListener('input', (e) => {
    const matches = searchCweSuggestions(e.target.value);

    if (matches.length > 0) {
      dropdown.innerHTML = matches.map((m) => `
        <div data-cwe="${m.id}" class="autocomplete-item">
          <div>
            <span class="autocomplete-item-id">${m.id}</span>
            <span class="autocomplete-item-name">${m.name}</span>
          </div>
          <span class="badge badge-neutral">${m.severity}</span>
        </div>
      `).join('');
      dropdown.classList.remove('hidden');

      dropdown.querySelectorAll('.autocomplete-item').forEach((item) => {
        item.addEventListener('click', () => {
          const cweId = item.getAttribute('data-cwe');
          input.value = cweId;
          dropdown.classList.add('hidden');
          onSelectCwe(cweId);
        });
      });
    } else {
      dropdown.classList.add('hidden');
    }
  });

  if (activeOutsideClickHandler) {
    document.removeEventListener('click', activeOutsideClickHandler);
  }
  activeOutsideClickHandler = (e) => {
    if (!container.contains(e.target)) {
      dropdown.classList.add('hidden');
    }
  };
  document.addEventListener('click', activeOutsideClickHandler);

  container.querySelectorAll('#quick-pills .chip').forEach((pill) => {
    pill.addEventListener('click', () => {
      const cweId = pill.getAttribute('data-cwe');
      input.value = cweId;
      onSelectCwe(cweId);
    });
  });

  container.querySelector('#header-logo').addEventListener('click', () => {
    onSelectCwe('CWE-89');
  });

  container.querySelector('#theme-toggle-btn').addEventListener('click', () => {
    onToggleTheme();
  });

  return container;
}
