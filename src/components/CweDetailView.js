import { generateJiraTemplate } from '../services/jiraTemplateGenerator.js';
import { icon, Icons } from '../utils/icons.js';

const LANGUAGES = [
  { key: 'python', label: 'Python' },
  { key: 'javascript', label: 'JS / TS' },
  { key: 'java', label: 'Java' },
  { key: 'go', label: 'Go' },
  { key: 'cpp', label: 'C / C++' },
  { key: 'csharp', label: 'C#' },
  { key: 'php', label: 'PHP' }
];

const TABS = [
  { key: 'overview', label: 'Overview & Impact', icon: Icons.layers },
  { key: 'code', label: 'Vulnerable vs. Fixed', icon: Icons.code },
  { key: 'remediation', label: 'Fix & Testing', icon: Icons.shieldCheck },
  { key: 'checklist', label: 'Checklist', icon: Icons.listChecks },
  { key: 'jira', label: 'Jira Template', icon: Icons.ticketCheck }
];

const SOURCE_META = {
  local: { label: 'Local cache', badge: 'badge-neutral', icon: Icons.database },
  mitre_api: { label: 'MITRE API (live)', badge: 'badge-success', icon: Icons.cloud },
  synthesized: { label: 'Synthesized fallback', badge: 'badge-warning', icon: Icons.wifiOff }
};

export function createCweDetailView({
  cweData,
  cweSource,
  selectedLanguage,
  activeTab,
  isPinned,
  onLanguageChange,
  onTabChange,
  onSelectCwe,
  onTogglePin
}) {
  const container = document.createElement('div');
  container.className = 'container page-body animate-fade-in';

  if (!cweData) {
    container.innerHTML = `
      <div class="card state-block">
        <h3 style="font-size:15px;font-weight:700;">No CWE data found</h3>
        <p class="mt-2" style="font-size:12.5px;">Search for a valid CWE ID (e.g. CWE-89, CWE-284, CWE-79).</p>
      </div>
    `;
    return container;
  }

  const langKey = (selectedLanguage || 'python').toLowerCase();
  const langData = cweData.languages?.[langKey] || cweData.languages?.python || {};
  const currentTab = activeTab || 'overview';
  const jiraTemplateText = generateJiraTemplate(cweData, selectedLanguage);
  const severityBadgeClass = getSeverityBadgeClass(cweData.severity);
  const sourceMeta = SOURCE_META[cweSource] || SOURCE_META.local;

  container.innerHTML = `
    <div class="card card-pad stack" style="margin-bottom:20px;">
      <div style="display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap;">
        <div style="min-width:0;">
          <div class="badge-row" style="margin-bottom:12px;">
            <span class="badge badge-neutral badge-mono">${cweData.id}</span>
            <span class="badge ${severityBadgeClass}">Severity: ${cweData.severity}</span>
            <span class="badge badge-info">${cweData.owaspCategory || 'A01:2021 - Broken Access Control'}</span>
            <span class="badge ${sourceMeta.badge}">${icon(sourceMeta.icon, { size: 11 })} ${sourceMeta.label}</span>
          </div>
          <h1 style="font-size:22px; font-weight:800; letter-spacing:-0.01em; color:var(--text-primary);">
            ${cweData.name}
          </h1>
          <p class="text-mono text-secondary mt-2" style="font-size:12px;">
            CVSS Score: <strong style="color:var(--text-primary);">${cweData.cvssScore || '8.5'}</strong>
          </p>
        </div>
        <div style="display:flex; align-items:flex-start; gap:8px; flex-shrink:0;">
          ${cweData.autoFixAvailable ? `
            <span class="badge badge-solid-success">
              ${icon(Icons.checkCircle, { size: 12 })} Auto-Fix ${cweData.autoFixConfidence || 'Available'}
            </span>
          ` : ''}
          <button id="pin-btn" class="btn btn-icon" aria-label="${isPinned ? 'Unpin this CWE' : 'Pin this CWE'}" title="${isPinned ? 'Unpin' : 'Pin for quick access'}">
            ${icon(isPinned ? Icons.bookmarkCheck : Icons.bookmark, { size: 16 })}
          </button>
        </div>
      </div>

      <div class="attr-row" style="border-top:1px solid var(--border-color); padding-top:16px;">
        <div class="attr-item">
          <span class="attr-item-label">${icon(Icons.shieldAlert, { size: 12 })} Severity</span>
          <span class="attr-item-value">${cweData.severity}</span>
        </div>
        <div class="attr-item">
          <span class="attr-item-label">${icon(Icons.target, { size: 12 })} OWASP</span>
          <span class="attr-item-value">${(cweData.owaspCategory || '').split(' - ')[0] || 'N/A'}</span>
        </div>
        <div class="attr-item">
          <span class="attr-item-label">${icon(Icons.gauge, { size: 12 })} CVSS</span>
          <span class="attr-item-value">${(cweData.cvssScore || '').split(' ')[0] || 'N/A'}</span>
        </div>
        <div class="attr-item">
          <span class="attr-item-label">${icon(Icons.scale, { size: 12 })} Compliance</span>
          <span class="attr-item-value" style="font-weight:600;">${(cweData.complianceImpact || '').split(',')[0] || 'N/A'}</span>
        </div>
      </div>

      <div style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; border-top:1px solid var(--border-color); padding-top:16px;">
        <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
          <span class="text-secondary" style="font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.03em;">
            Target language
          </span>
          <div class="tab-nav" id="lang-selector-group">
            ${renderLanguageButtons(selectedLanguage)}
          </div>
        </div>
        <button id="quick-copy-jira-btn" class="btn btn-primary">
          ${icon(Icons.copy, { size: 13 })} Copy Jira Description
        </button>
      </div>
    </div>

    ${renderMappingNotesBanner(cweData.mappingNotes)}

    <div style="margin: 20px 0;">
      <div class="tab-nav" id="tab-group">
        ${TABS.map((t) => `
          <button data-tab="${t.key}" class="tab-pill${currentTab === t.key ? ' is-active' : ''}">
            ${icon(t.icon, { size: 14 })} ${t.label}
          </button>
        `).join('')}
      </div>
    </div>

    <div id="tab-content">
      ${renderTabContent(currentTab, cweData, langData, selectedLanguage, jiraTemplateText)}
    </div>
  `;

  container.querySelectorAll('#lang-selector-group button').forEach((btn) => {
    btn.addEventListener('click', () => onLanguageChange(btn.getAttribute('data-lang')));
  });

  container.querySelectorAll('#tab-group button').forEach((btn) => {
    btn.addEventListener('click', () => onTabChange(btn.getAttribute('data-tab')));
  });

  container.querySelectorAll('.suggestion-pill').forEach((pill) => {
    pill.addEventListener('click', () => {
      if (onSelectCwe) onSelectCwe(pill.getAttribute('data-cwe'));
    });
  });

  const pinBtn = container.querySelector('#pin-btn');
  if (pinBtn && onTogglePin) {
    pinBtn.addEventListener('click', () => onTogglePin(cweData.id));
  }

  const quickCopyBtn = container.querySelector('#quick-copy-jira-btn');
  if (quickCopyBtn) {
    quickCopyBtn.addEventListener('click', () => copyToClipboard(jiraTemplateText, quickCopyBtn, 'Copy Jira Description'));
  }

  const tabCopyJiraBtn = container.querySelector('#tab-copy-jira-btn');
  if (tabCopyJiraBtn) {
    tabCopyJiraBtn.addEventListener('click', () => copyToClipboard(jiraTemplateText, tabCopyJiraBtn, 'Copy Jira Description'));
  }

  const copyVunCodeBtn = container.querySelector('#copy-vun-code');
  if (copyVunCodeBtn) {
    copyVunCodeBtn.addEventListener('click', () => copyToClipboard(langData.vulnerableCode || '', copyVunCodeBtn, 'Copy Vulnerable Code'));
  }

  const copyFixCodeBtn = container.querySelector('#copy-fix-code');
  if (copyFixCodeBtn) {
    copyFixCodeBtn.addEventListener('click', () => copyToClipboard(langData.fixedCode || '', copyFixCodeBtn, 'Copy Secure Code'));
  }

  return container;
}

function renderMappingNotesBanner(mappingNotes) {
  if (!mappingNotes || !mappingNotes.usage) return '';

  const isDiscouraged = (mappingNotes.usage || '').toLowerCase().includes('discouraged');

  return `
    <div class="alert-banner${isDiscouraged ? '' : ' alert-banner--neutral'}" style="margin-top:20px;">
      <div class="alert-banner-head">
        ${icon(Icons.alertTriangle, { size: 14 })} MITRE Mapping Note: ${mappingNotes.usage}
      </div>
      <p>${mappingNotes.rationale || 'This CWE identifier is a high-level Pillar. Consider mapping to a more specific descendant weakness.'}</p>

      ${mappingNotes.suggestions && mappingNotes.suggestions.length > 0 ? `
        <div class="chip-row" style="margin-top:2px;">
          <span class="text-secondary" style="font-size:11px; font-weight:600;">Suggested descendants:</span>
          ${mappingNotes.suggestions.map((s) => `
            <button data-cwe="${s.id}" class="suggestion-pill badge badge-warning badge-mono" style="cursor:pointer; border-width:1px;">
              ${s.id}: ${s.name}
            </button>
          `).join('')}
        </div>
      ` : ''}
    </div>
  `;
}

function renderLanguageButtons(selectedLang) {
  return LANGUAGES.map((l) => {
    const isSelected = (selectedLang || 'python').toLowerCase() === l.key;
    return `
      <button data-lang="${l.key}" class="tab-pill${isSelected ? ' is-active' : ''}">
        ${l.label}
      </button>
    `;
  }).join('');
}

function getLanguageLabel(langKey) {
  const match = LANGUAGES.find((l) => l.key === (langKey || 'python').toLowerCase());
  return match ? match.label : langKey;
}

function renderTabContent(activeTab, cweData, langData, selectedLanguage, jiraText) {
  switch (activeTab) {
    case 'overview':
      return `
        <div class="grid grid-cols-3">
          <div class="card card-pad stack col-span-2">
            <div>
              <h3 class="section-title">Problem Description</h3>
              <p class="mt-3 leading-relaxed" style="font-size:13.5px;">${cweData.problemDescription}</p>
            </div>

            ${cweData.extendedDescription ? `
              <div>
                <h3 class="section-title">MITRE Extended Specification</h3>
                <p class="mt-3 leading-relaxed text-secondary" style="font-size:12.5px; white-space:pre-wrap;">${cweData.extendedDescription}</p>
              </div>
            ` : ''}

            <div>
              <h3 class="section-title section-title--danger">Attack Impact &amp; Threat Scenario</h3>
              <p class="mt-3 leading-relaxed text-secondary" style="font-size:13px;">${cweData.attackImpact}</p>
            </div>

            ${cweData.observedExamples && cweData.observedExamples.length > 0 ? `
              <div>
                <h3 class="section-title">Real-World Observed CVEs (${cweData.observedExamples.length})</h3>
                <div class="mt-3">
                  ${cweData.observedExamples.map((obs) => `
                    <div class="list-row">
                      <span class="badge badge-warning badge-mono">${obs.cve}</span>
                      <span class="text-secondary" style="font-size:12.5px; margin-left:8px;">${obs.desc}</span>
                    </div>
                  `).join('')}
                </div>
              </div>
            ` : ''}
          </div>

          <div class="stack">
            <div class="card card-pad">
              <h3 class="section-title section-title--warning">Compliance Impact</h3>
              <p class="mt-3 leading-relaxed" style="font-size:12.5px;">${cweData.complianceImpact}</p>
            </div>

            <div class="card card-pad stack-sm">
              <div style="display:flex; justify-content:space-between; padding-bottom:8px; border-bottom:1px solid var(--border-color);">
                <span class="text-secondary" style="font-size:12px;">OWASP Category</span>
                <span style="font-size:12px; font-weight:700;">${cweData.owaspCategory}</span>
              </div>
              <div style="display:flex; justify-content:space-between; padding-bottom:8px; border-bottom:1px solid var(--border-color);">
                <span class="text-secondary" style="font-size:12px;">CVSS Rating</span>
                <span style="font-size:12px; font-weight:700; color:var(--warning-text);">${cweData.cvssScore}</span>
              </div>
              <div style="display:flex; justify-content:space-between;">
                <span class="text-secondary" style="font-size:12px;">Auto-Fix Confidence</span>
                <span style="font-size:12px; font-weight:700; color:var(--success-text);">${cweData.autoFixConfidence}</span>
              </div>
            </div>
          </div>
        </div>
      `;

    case 'code':
      return `
        <div class="stack">
          <div class="grid grid-cols-2">
            <div class="code-panel">
              <div class="code-panel-header">
                <span class="code-panel-title" style="color:var(--danger-text);">
                  ${icon(Icons.xCircle, { size: 13 })} Vulnerable (${getLanguageLabel(selectedLanguage)})
                </span>
                <button id="copy-vun-code" class="btn" style="font-size:11px; padding:5px 10px;">
                  ${icon(Icons.copy, { size: 12 })} Copy
                </button>
              </div>
              <pre class="code-vulnerable">${escapeHtml(langData.vulnerableCode || '// Code example unavailable')}</pre>
            </div>

            <div class="code-panel">
              <div class="code-panel-header">
                <span class="code-panel-title" style="color:var(--success-text);">
                  ${icon(Icons.checkCircle, { size: 13 })} Secure fix (${getLanguageLabel(selectedLanguage)})
                </span>
                <button id="copy-fix-code" class="btn" style="font-size:11px; padding:5px 10px;">
                  ${icon(Icons.copy, { size: 12 })} Copy
                </button>
              </div>
              <pre class="code-fixed">${escapeHtml(langData.fixedCode || '// Secure code example unavailable')}</pre>
            </div>
          </div>

          ${cweData.demonstrativeExamples && cweData.demonstrativeExamples.length > 0 ? `
            <div class="card card-pad stack">
              <h3 class="section-title">MITRE Official Demonstrative Examples (${cweData.demonstrativeExamples.length})</h3>
              ${cweData.demonstrativeExamples.map((demo) => `
                <div class="list-row">
                  <h4 style="font-size:12.5px; font-weight:700;">${demo.title}</h4>
                  <p class="text-muted mt-2" style="font-size:12px;">${demo.description}</p>
                  ${demo.code ? `<pre class="mt-3 mono" style="font-size:12px; padding:12px; background:var(--card-bg-subtle); border-radius:var(--radius-sm); overflow-x:auto;">${escapeHtml(demo.code)}</pre>` : ''}
                </div>
              `).join('')}
            </div>
          ` : ''}
        </div>
      `;

    case 'remediation':
      return `
        <div class="stack">
          <div class="grid grid-cols-2">
            <div class="card card-pad">
              <span class="badge badge-neutral">Primary Fix (${getLanguageLabel(selectedLanguage)})</span>
              <p class="mt-3 leading-relaxed" style="font-size:13.5px; font-weight:500;">
                ${langData.fixMethod1 || 'Implement strict parameterization or input sanitization.'}
              </p>
            </div>
            <div class="card card-pad">
              <span class="badge badge-neutral">Defense-in-Depth (${getLanguageLabel(selectedLanguage)})</span>
              <p class="mt-3 leading-relaxed" style="font-size:13.5px; font-weight:500;">
                ${langData.fixMethod2 || 'Apply input validation allowlists and principle of least privilege.'}
              </p>
            </div>
          </div>

          <div class="card card-pad">
            <h3 class="section-title section-title--success">Testing &amp; Verification Strategy</h3>
            <div class="mono text-secondary mt-3" style="font-size:12px; background:var(--card-bg-subtle); padding:14px; border-radius:var(--radius-sm); white-space:pre-wrap; line-height:1.7;">
              ${cweData.testingMethod || 'Run SAST scanners and DAST payload tests.'}
            </div>
          </div>
        </div>
      `;

    case 'checklist':
      return `
        <div class="card card-pad stack">
          <h3 class="section-title">Developer Remediation Checklist</h3>
          <div class="stack-sm">
            ${(cweData.preventionChecklist || []).map((item) => `
              <label class="checklist-item">
                <input type="checkbox" />
                <span>${item}</span>
              </label>
            `).join('')}
          </div>
        </div>
      `;

    case 'jira':
      return `
        <div class="card card-pad stack">
          <div style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; padding-bottom:14px; border-bottom:1px solid var(--border-color);">
            <div>
              <h3 style="font-size:14px; font-weight:700;">Jira Description Markup</h3>
              <p class="text-secondary mt-2" style="font-size:12px;">Copy and paste this formatted text into a Jira issue description.</p>
            </div>
            <button id="tab-copy-jira-btn" class="btn btn-primary">
              ${icon(Icons.copy, { size: 13 })} Copy Jira Description
            </button>
          </div>
          <textarea readonly class="mono" style="width:100%; height:380px; padding:14px; background:var(--card-bg-subtle); border:1px solid var(--card-border); border-radius:var(--radius-sm); font-size:12px; color:var(--text-primary); line-height:1.6; resize:vertical;">${jiraText}</textarea>
        </div>
      `;

    default:
      return '';
  }
}

function getSeverityBadgeClass(severity) {
  switch ((severity || '').toLowerCase()) {
    case 'critical': return 'badge-danger';
    case 'high': return 'badge-warning';
    case 'medium': return 'badge-info';
    default: return 'badge-neutral';
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function copyToClipboard(text, buttonEl, originalLabel) {
  navigator.clipboard.writeText(text).then(() => {
    const original = buttonEl.innerHTML;
    buttonEl.innerHTML = `${icon(Icons.copyCheck, { size: 12 })} Copied`;
    setTimeout(() => {
      buttonEl.innerHTML = original;
    }, 1800);
  }).catch((err) => {
    console.error('Failed to copy to clipboard:', err);
  });
}
