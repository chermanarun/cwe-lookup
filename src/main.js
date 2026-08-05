import { createHeader } from './components/Header.js';
import { createCweDetailView } from './components/CweDetailView.js';
import { fetchCweDetails, normalizeCweId } from './services/cweService.js';
import { initTheme, toggleTheme } from './utils/theme.js';
import { isPinned, togglePin } from './utils/pins.js';

class AppState {
  constructor() {
    this.currentCweId = 'CWE-89';
    this.selectedLanguage = 'python';
    this.activeTab = 'overview';
    this.cweData = null;
    this.cweSource = 'local';
    this.loading = false;
    this.theme = 'light';
  }

  async setCwe(cweId) {
    this.currentCweId = normalizeCweId(cweId);
    this.loading = true;
    renderApp();

    try {
      const result = await fetchCweDetails(this.currentCweId);
      this.cweData = result.data;
      this.cweSource = result.source;
    } catch (err) {
      console.error('Error fetching CWE details:', err);
    } finally {
      this.loading = false;
      renderApp();
    }
  }

  setLanguage(lang) {
    this.selectedLanguage = lang;
    renderApp();
  }

  setTab(tab) {
    this.activeTab = tab;
    renderApp();
  }

  toggleTheme() {
    this.theme = toggleTheme();
    renderApp();
  }

  togglePin(cweId) {
    togglePin(cweId);
    renderApp();
  }
}

const state = new AppState();

async function init() {
  state.theme = initTheme();
  await state.setCwe('CWE-89');
}

function renderApp() {
  const root = document.getElementById('app');
  if (!root) return;

  root.innerHTML = '';

  // 1. Render Header
  const header = createHeader({
    currentCweId: state.currentCweId,
    theme: state.theme,
    onSearch: (query) => state.setCwe(query),
    onSelectCwe: (cweId) => state.setCwe(cweId),
    onToggleTheme: () => state.toggleTheme()
  });
  root.appendChild(header);

  // 2. Render Main Body
  const main = document.createElement('main');
  main.style.flex = '1';

  if (state.loading) {
    main.innerHTML = `
      <div class="container state-block">
        <div class="spinner"></div>
        <p class="mono" style="font-size:12.5px;">Fetching security intelligence for ${state.currentCweId}...</p>
      </div>
    `;
  } else if (state.cweData) {
    const detailView = createCweDetailView({
      cweData: state.cweData,
      cweSource: state.cweSource,
      selectedLanguage: state.selectedLanguage,
      activeTab: state.activeTab,
      isPinned: isPinned(state.currentCweId),
      onLanguageChange: (lang) => state.setLanguage(lang),
      onTabChange: (tab) => state.setTab(tab),
      onSelectCwe: (cweId) => state.setCwe(cweId),
      onTogglePin: (cweId) => state.togglePin(cweId)
    });
    main.appendChild(detailView);
  }

  root.appendChild(main);

  // 3. Render Footer
  const footer = document.createElement('footer');
  footer.className = 'app-footer';
  footer.innerHTML = `
    <div class="container app-footer-inner">
      <p>CWE Security Lookup &copy; ${new Date().getFullYear()} &bull; Built for security engineers &amp; developers</p>
      <div class="app-footer-tags">
        <span>MITRE API + local cache + synthesized fallback</span>
        <span style="color:var(--accent);">1-click Jira template</span>
      </div>
    </div>
  `;
  root.appendChild(footer);
}

init();
