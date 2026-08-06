/**
 * Generates a beautifully formatted Jira Markdown description template
 * incorporating all 15+ requested vulnerability parameters.
 *
 * @param {object} cweData
 * @param {string} selectedLanguage
 * @param {{id: string, resolvedTo: string, isBestEffort: boolean}|null} alias
 *   Set when the lookup came in via a scanner/internal vulnerability ID
 *   (e.g. "API-EXPOSURE-001") rather than a CWE ID directly - see
 *   src/data/vulnAliases.js. Included so the ticket stays traceable back to
 *   the original finding, not just the CWE it was mapped to.
 */
export function generateJiraTemplate(cweData, selectedLanguage = 'python', alias = null) {
  if (!cweData) return '';

  const langKey = selectedLanguage.toLowerCase();
  const langData = cweData.languages?.[langKey] || cweData.languages?.python || {};
  const langDisplayName = getLanguageDisplayName(selectedLanguage);

  const checklistText = Array.isArray(cweData.preventionChecklist)
    ? cweData.preventionChecklist.map(item => `* [ ] ${item}`).join('\n')
    : '* [ ] Enforce parameterization & input validation';

  const testingText = cweData.testingMethod
    ? cweData.testingMethod.replace(/\\n/g, '\n')
    : '1. SAST Analysis\n2. DAST Payload Injection\n3. Unit Testing';

  const reportedAsRow = alias
    ? `| *Reported As* | *${alias.id}*${alias.isBestEffort ? ' _(best-effort CWE mapping - verify manually)_' : ''} |\n`
    : '';

  return `h1. [SECURITY VULNERABILITY REPORT] ${cweData.id}: ${cweData.name}

|| Parameter || Value ||
${reportedAsRow}| *CWE ID* | *${cweData.id}* |
| *Vulnerability Name* | ${cweData.name} |
| *Category* | ${cweData.category} |
| *OWASP Category* | ${cweData.owaspCategory || 'N/A'} |
| *Severity* | *${cweData.severity.toUpperCase()}* (${cweData.cvssScore || 'N/A'}) |
| *Auto-Fix Available* | ${cweData.autoFixAvailable ? 'YES (' + (cweData.autoFixConfidence || 'Available') + ')' : 'NO'} |
| *Target Language* | *${langDisplayName}* |

----

h2. 1. Problem Description
${cweData.problemDescription}

h2. 2. Attack Impact & Exploitability
*${cweData.attackImpact}*

----

h2. 3. Code Remediation Examples (${langDisplayName})

h3. ❌ Vulnerable Code Example
{code:${getJiraCodeLanguage(selectedLanguage)}}
${langData.vulnerableCode || '// Vulnerable code example unavailable'}
{code}

h3. ✅ Fixed Code Example (Production Ready)
{code:${getJiraCodeLanguage(selectedLanguage)}}
${langData.fixedCode || '// Fixed code example unavailable'}
{code}

----

h2. 4. Fix Methods & Mitigation Strategy
* *Primary Fix Method:* ${langData.fixMethod1 || 'Enforce strict input parameterization.'}
* *Defense-in-Depth Fix Method:* ${langData.fixMethod2 || 'Apply input sanitization and least privilege principles.'}

----

h2. 5. Testing & Verification Method
${testingText}

----

h2. 6. Developer Prevention Checklist
${checklistText}

----

h2. 7. Compliance Impact
*Standard Regulations Affected:*
${cweData.complianceImpact || 'PCI-DSS 4.0, SOC 2, ISO 27001, NIST SP 800-53'}

_Report generated via CWE Intelligence & Remediation Engine._`;
}

function getLanguageDisplayName(langKey) {
  const map = {
    python: 'Python 3',
    javascript: 'JavaScript / TypeScript (Node.js / Web)',
    java: 'Java (JDBC / Spring)',
    go: 'Go (Golang)',
    cpp: 'C / C++',
    csharp: 'C# (.NET)',
    php: 'PHP'
  };
  return map[langKey.toLowerCase()] || langKey;
}

function getJiraCodeLanguage(langKey) {
  const map = {
    python: 'python',
    javascript: 'javascript',
    java: 'java',
    go: 'go',
    cpp: 'cpp',
    csharp: 'csharp',
    php: 'php'
  };
  return map[langKey.toLowerCase()] || 'text';
}
