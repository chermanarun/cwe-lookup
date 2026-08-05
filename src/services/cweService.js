import { cweDatabase } from '../data/cweDatabase.js';

export function normalizeCweId(input) {
  if (!input) return '';
  const trimmed = input.trim().toUpperCase();
  if (trimmed.startsWith('CWE-')) return trimmed;
  const numOnly = trimmed.replace(/[^0-9]/g, '');
  return numOnly ? `CWE-${numOnly}` : trimmed;
}

export async function fetchCweDetails(cweQuery) {
  const normalizedId = normalizeCweId(cweQuery);

  // 1. Check local pre-cached database
  if (cweDatabase[normalizedId]) {
    return { data: cweDatabase[normalizedId], source: 'local' };
  }

  const cweNum = normalizedId.replace('CWE-', '');

  // 2. Fetch from MITRE CWE official API (via Vite proxy / direct endpoint)
  const apiUrls = [
    `/api/mitre/api/v1/cwe/weakness/${cweNum}`,
    `https://cwe-api.mitre.org/api/v1/cwe/weakness/${cweNum}`
  ];

  for (const url of apiUrls) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        const json = await response.json();
        const weakness = json.Weaknesses?.[0] || (json.ID ? json : null);
        if (weakness && weakness.Name) {
          return {
            data: parseMitreApiRecord(normalizedId, weakness),
            source: 'mitre_api'
          };
        }
      }
    } catch (err) {
      console.warn(`MITRE API fetch failed for ${url}:`, err);
    }
  }

  // 3. Fallback synthesis for unknown/unreachable CWE IDs
  return {
    data: createGenericCweRecord(normalizedId),
    source: 'synthesized'
  };
}

export function searchCweSuggestions(query) {
  if (!query || query.trim().length === 0) return [];
  const q = query.trim().toLowerCase();

  const results = [];
  for (const key of Object.keys(cweDatabase)) {
    const item = cweDatabase[key];
    if (
      key.toLowerCase().includes(q) ||
      item.name.toLowerCase().includes(q) ||
      item.category.toLowerCase().includes(q) ||
      item.owaspCategory.toLowerCase().includes(q)
    ) {
      results.push(item);
    }
  }
  return results.slice(0, 6);
}

/**
 * Intelligent parser converting raw MITRE API JSON response into full dashboard record.
 */
function parseMitreApiRecord(cweId, w) {
  const name = w.Name || `Weakness ${cweId}`;
  const desc = w.Description || `Official specification for ${cweId}.`;
  
  // Parse Extended Description
  let extDesc = '';
  if (w.ExtendedDescription) {
    if (typeof w.ExtendedDescription === 'string') {
      extDesc = w.ExtendedDescription;
    } else if (w.ExtendedDescription.Text) {
      extDesc = w.ExtendedDescription.Text;
    } else if (Array.isArray(w.ExtendedDescription)) {
      extDesc = w.ExtendedDescription.map(e => typeof e === 'string' ? e : e.Text || '').join('\n\n');
    }
  }

  const category = w.Abstraction || 'Software Weakness';
  const owaspCat = classifyOwaspCategory(name, desc, category);

  // Parse Demonstrative Examples from MITRE
  const demonstrative = [];
  if (Array.isArray(w.DemonstrativeExamples)) {
    w.DemonstrativeExamples.forEach(demo => {
      if (demo.Entries) {
        let intro = '';
        let code = '';
        let body = '';
        let lang = 'General';

        demo.Entries.forEach(entry => {
          if (entry.IntroText) intro += entry.IntroText + ' ';
          if (entry.ExampleCode) {
            code += entry.ExampleCode + '\n';
            if (entry.Language) lang = entry.Language;
          }
          if (entry.BodyText) body += entry.BodyText + ' ';
        });

        demonstrative.push({
          title: `Demonstrative Example (${lang})`,
          description: (intro + body).trim(),
          code: cleanCodeMarkdown(code),
          language: lang
        });
      }
    });
  }

  // Parse Mitigations
  let fixMethod1 = 'Strict Input & Access Validation: Enforce contextual checks before operation processing.';
  let fixMethod2 = 'Principle of Least Privilege: Compartmentalize system components into safe trust zones.';
  const checklist = [];

  if (Array.isArray(w.PotentialMitigations)) {
    w.PotentialMitigations.forEach((mit, i) => {
      const cleanDesc = (mit.Description || '').replace(/[\n\r]+/g, ' ').trim();
      if (cleanDesc) {
        if (i === 0) fixMethod1 = cleanDesc;
        else if (i === 1) fixMethod2 = cleanDesc;
        checklist.push(cleanDesc);
      }
    });
  }

  if (checklist.length === 0) {
    checklist.push("Enforce strict server-side validation on all inputs.");
    checklist.push("Apply Least Privilege Principle to runtime execution.");
    checklist.push("Sanitize special characters and enforce contextual encoding.");
    checklist.push("Keep software frameworks and dependencies updated.");
  }

  // Parse Observed Examples (CVEs)
  const observed = [];
  if (Array.isArray(w.ObservedExamples)) {
    w.ObservedExamples.forEach(obs => {
      observed.push({
        cve: obs.Reference || obs.CVE || 'CVE Reference',
        desc: obs.Description || ''
      });
    });
  }

  // Parse Mapping Notes & Suggested Specific Descendants
  let mappingNotes = null;
  if (w.MappingNotes) {
    const suggestions = [];
    if (Array.isArray(w.MappingNotes.Suggestions)) {
      w.MappingNotes.Suggestions.forEach(s => {
        suggestions.push({
          id: `CWE-${s.CweID}`,
          name: s.Comment || `CWE-${s.CweID}`
        });
      });
    }

    mappingNotes = {
      usage: w.MappingNotes.Usage || 'ALLOWED',
      rationale: w.MappingNotes.Rationale || '',
      suggestions: suggestions
    };
  }

  return {
    id: cweId,
    name: name,
    category: category,
    owaspCategory: owaspCat,
    severity: determineSeverity(category, w.Abstraction),
    cvssScore: "8.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
    autoFixAvailable: true,
    autoFixConfidence: "Medium (80%)",
    problemDescription: desc,
    extendedDescription: extDesc,
    attackImpact: "Potential unauthorized access, sensitive data exposure, or execution integrity violation.",
    mappingNotes: mappingNotes,
    demonstrativeExamples: demonstrative,
    observedExamples: observed.slice(0, 10),
    languages: generateDistinctLanguageExamples(cweId, name, owaspCat),
    testingMethod: "1. SAST Analysis: Scan codebase for unsafe patterns and unvalidated sinks.\\n2. DAST Verification: Perform boundary fuzzing and authorization checks.\\n3. Code Review: Trace data flow from source to sink.",
    preventionChecklist: checklist,
    complianceImpact: "PCI-DSS 4.0 Req 6.2.4, SOC 2 CC6.1, ISO 27001 A.8.28, NIST SP 800-53 SI-10."
  };
}

function classifyOwaspCategory(name, desc, category) {
  const text = (name + ' ' + desc + ' ' + category).toLowerCase();

  if (text.includes('access control') || text.includes('authorization') || text.includes('privilege') || text.includes('permission') || text.includes('traversal')) {
    return "A01:2021 - Broken Access Control";
  }
  if (text.includes('crypto') || text.includes('encrypt') || text.includes('hash') || text.includes('key') || text.includes('cipher')) {
    return "A02:2021 - Cryptographic Failures";
  }
  if (text.includes('injection') || text.includes('sql') || text.includes('command') || text.includes('xss') || text.includes('scripting')) {
    return "A03:2021 - Injection";
  }
  if (text.includes('design') || text.includes('architecture') || text.includes('trust zone')) {
    return "A04:2021 - Insecure Design";
  }
  if (text.includes('misconfiguration') || text.includes('default') || text.includes('debug')) {
    return "A05:2021 - Security Misconfiguration";
  }
  if (text.includes('outdated') || text.includes('component') || text.includes('third-party') || text.includes('dependency')) {
    return "A06:2021 - Vulnerable and Outdated Components";
  }
  if (text.includes('auth') || text.includes('password') || text.includes('session') || text.includes('credential')) {
    return "A07:2021 - Identification and Authentication Failures";
  }
  if (text.includes('deserialization') || text.includes('integrity') || text.includes('unsigned') || text.includes('pickle')) {
    return "A08:2021 - Software and Data Integrity Failures";
  }
  if (text.includes('logging') || text.includes('monitoring') || text.includes('audit')) {
    return "A09:2021 - Security Logging and Monitoring Failures";
  }
  if (text.includes('ssrf') || text.includes('request forgery') || text.includes('server-side request')) {
    return "A10:2021 - Server-Side Request Forgery";
  }

  return "A01:2021 - Broken Access Control";
}

function determineSeverity(category, abstraction) {
  if (abstraction === 'Pillar' || category === 'Pillar') return 'High';
  return 'High';
}

function cleanCodeMarkdown(code) {
  if (!code) return '';
  return code.replace(/```/g, '').replace(/\t/g, '  ').trim();
}

function createGenericCweRecord(cweId) {
  const name = `Software Security Weakness (${cweId})`;
  const desc = `Detailed specification for ${cweId}. Verify input neutralization, access control boundaries, and data processing routines.`;
  return parseMitreApiRecord(cweId, {
    Name: name,
    Description: desc,
    Abstraction: 'Class'
  });
}

/**
 * Generates distinct, language-native code examples for all 7 programming languages
 * tailored to the specific OWASP category of the weakness.
 */
function generateDistinctLanguageExamples(cweId, name, owaspCat) {
  const isAccessControl = owaspCat.includes('Access Control');
  const isInjection = owaspCat.includes('Injection');

  if (isAccessControl) {
    return {
      python: {
        vulnerableCode: `# VULNERABLE (Python): Endpoint missing authorization verification for ${cweId}
@app.route('/api/resource/<id>', methods=['DELETE'])
def delete_resource(id):
    # Missing permission check for ${cweId}
    db.delete_resource(id)
    return jsonify(success=True)`,
        fixedCode: `# SECURE (Python): Enforcing decorator authorization check
@app.route('/api/resource/<id>', methods=['DELETE'])
@requires_permission('resource:delete')
def delete_resource(id):
    db.delete_resource(id)
    return jsonify(success=True)`,
        fixMethod1: "Decorator Authorization: Apply @requires_permission('admin') on route handler entry points.",
        fixMethod2: "Guaranteed Cleanup: Wrap elevated operations in try/finally blocks to guarantee privilege revocation."
      },
      javascript: {
        vulnerableCode: `// VULNERABLE (Node.js/TS): Admin handler missing role verification for ${cweId}
app.delete('/api/resource/:id', async (req, res) => {
  // Missing RBAC check for ${cweId}
  await db.resource.delete(req.params.id);
  res.json({ success: true });
});`,
        fixedCode: `// SECURE (Node.js/TS): Authorization middleware check
app.delete('/api/resource/:id', authorize('ADMIN'), async (req, res) => {
  await db.resource.delete(req.params.id);
  res.json({ success: true });
});`,
        fixMethod1: "Authorization Middleware: Enforce central authorize('ADMIN') middleware on sensitive API routes.",
        fixMethod2: "CASL / ABAC Policy Engine: Validate user capabilities using Attribute-Based Access Control."
      },
      java: {
        vulnerableCode: `// VULNERABLE (Java/Spring): Controller action missing @PreAuthorize for ${cweId}
@DeleteMapping("/api/resource/{id}")
public ResponseEntity<Void> deleteResource(@PathVariable String id) {
    resourceService.delete(id);
    return ResponseEntity.noContent().build();
}`,
        fixedCode: `// SECURE (Java/Spring): Spring Security @PreAuthorize annotation
@DeleteMapping("/api/resource/{id}")
@PreAuthorize("hasRole('ROLE_ADMIN') and hasPermission(#id, 'Resource', 'delete')")
public ResponseEntity<Void> deleteResource(@PathVariable String id) {
    resourceService.delete(id);
    return ResponseEntity.noContent().build();
}`,
        fixMethod1: "Spring Security @PreAuthorize: Annotate methods with @PreAuthorize(\"hasRole('ADMIN')\").",
        fixMethod2: "Method Security Filters: Enable global method security with strict access rules."
      },
      go: {
        vulnerableCode: `// VULNERABLE (Go): Handler executing without claims validation for ${cweId}
func DeleteResourceHandler(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    db.DeleteResource(r.Context(), id)
    w.WriteHeader(http.StatusOK)
}`,
        fixedCode: `// SECURE (Go): Validate context user claims before execution
func DeleteResourceHandler(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("claims").(*Claims)
    if !ok || !claims.HasPermission("resource:delete") {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    db.DeleteResource(r.Context(), r.URL.Query().Get("id"))
    w.WriteHeader(http.StatusOK)
}`,
        fixMethod1: "Context Scope Validation: Verify r.Context() claims contain required permission scope.",
        fixMethod2: "Open Policy Agent (OPA): Delegate authorization decisions to an OPA policy engine sidecar."
      },
      cpp: {
        vulnerableCode: `// VULNERABLE (C++): Manual seteuid calls without RAII protection for ${cweId}
void performTask() {
    seteuid(0); // Elevate privileges
    doWork();   // If doWork throws exception, process remains root!
    seteuid(getuid());
}`,
        fixedCode: `// SECURE (C++): RAII Privilege Guard ensuring privilege drop
class PrivilegeGuard {
public:
    PrivilegeGuard() { seteuid(0); }
    ~PrivilegeGuard() { seteuid(getuid()); }
};

void performTask() {
    PrivilegeGuard guard;
    doWork();
}`,
        fixMethod1: "RAII Privilege Guard: Enclose elevated privilege blocks in RAII wrappers to guarantee cleanup.",
        fixMethod2: "Linux Capabilities (cap_drop): Drop cap_sys_admin permanent capabilities after startup."
      },
      csharp: {
        vulnerableCode: `// VULNERABLE (C#/.NET): Controller action missing [Authorize] attribute for ${cweId}
[HttpPost]
public IActionResult DeleteResource(string id) {
    _service.Delete(id);
    return Ok();
}`,
        fixedCode: `// SECURE (C#/.NET): ASP.NET Core [Authorize] with Policy
[HttpPost]
[Authorize(Policy = "RequireAdminRole")]
public IActionResult DeleteResource(string id) {
    _service.Delete(id);
    return Ok();
}`,
        fixMethod1: "Policy-Based Authorization: Apply [Authorize(Policy = \"AdminPolicy\")] on actions.",
        fixMethod2: "IAuthorizationService: Use IAuthorizationService.AuthorizeAsync(User, resource, policyName)."
      },
      php: {
        vulnerableCode: `// VULNERABLE (PHP): Action executed without session role check for ${cweId}
if ($_POST['action'] === 'delete_resource') {
    $id = $_POST['id'];
    deleteResource($id);
}`,
        fixedCode: `// SECURE (PHP): Explicit session role check before action execution
if ($_POST['action'] === 'delete_resource') {
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'ADMIN') {
        http_response_code(403);
        die("Access Denied: Admin role required.");
    }
    deleteResource($_POST['id']);
}`,
        fixMethod1: "Session Role Validation: Verify $_SESSION['role'] === 'ADMIN' prior to executing privileged actions.",
        fixMethod2: "Middleware Gateways: Wrap controllers in framework authorization gates (e.g. Laravel Gates)."
      }
    };
  }

  // Default / Injection / General pattern fallback
  return {
    python: {
      vulnerableCode: `# VULNERABLE (Python): Unsanitized input processing for ${cweId}
def process_request(user_input):
    # Dynamic unsafe evaluation of user input
    return eval_operation(user_input)`,
      fixedCode: `# SECURE (Python): Validated & sanitized input handling for ${cweId}
def process_request(user_input):
    if not is_valid_input(user_input):
        raise ValueError("Invalid input format")
    sanitized = sanitize_input(user_input)
    return safe_operation(sanitized)`,
      fixMethod1: "Strict Input Neutralization: Validate format using allowlist schemas.",
      fixMethod2: "Contextual Encoding: Escape special characters prior to processing."
    },
    javascript: {
      vulnerableCode: `// VULNERABLE (JS/TS): Unvalidated input execution for ${cweId}
function handleInput(req, res) {
  const input = req.query.data;
  res.send(executeUnsafe(input));
}`,
      fixedCode: `// SECURE (JS/TS): Schema validation with Zod for ${cweId}
const schema = z.string().alphanumeric();

function handleInput(req, res) {
  const result = schema.safeParse(req.query.data);
  if (!result.success) {
    return res.status(400).json({ error: "Invalid input" });
  }
  res.send(executeSafe(result.data));
}`,
      fixMethod1: "Schema Validation: Use Zod/Joi to validate input data types and formats.",
      fixMethod2: "Context Encoding: Sanitize output using trusted encoding frameworks."
    },
    java: {
      vulnerableCode: `// VULNERABLE (Java): Raw input processing for ${cweId}
public String processData(String input) {
    return engine.eval(input);
}`,
      fixedCode: `// SECURE (Java): Input validation and safe execution for ${cweId}
public String processData(String input) {
    if (!input.matches("^[a-zA-Z0-9_-]+$")) {
        throw new IllegalArgumentException("Invalid input format");
    }
    return engine.safeEval(input);
}`,
      fixMethod1: "Input Allowlisting: Match incoming parameters against regex allowlist patterns.",
      fixMethod2: "Least Privilege Execution: Run task handlers under restricted SecurityManager privileges."
    },
    go: {
      vulnerableCode: `// VULNERABLE (Go): Processing raw string input for ${cweId}
func ProcessHandler(w http.ResponseWriter, r *http.Request) {
    data := r.URL.Query().Get("data")
    out := unsafeOperation(data)
    w.Write([]byte(out))
}`,
      fixedCode: `// SECURE (Go): Validated input handling for ${cweId}
func ProcessHandler(w http.ResponseWriter, r *http.Request) {
    data := r.URL.Query().Get("data")
    if !isValid(data) {
        http.Error(w, "Bad Request", http.StatusBadRequest)
        return
    }
    out := safeOperation(data)
    w.Write([]byte(out))
}`,
      fixMethod1: "Standard Input Validation: Validate HTTP request parameters before passing to business logic.",
      fixMethod2: "Safe Package Wrappers: Use standard library sanitization routines."
    },
    cpp: {
      vulnerableCode: `// VULNERABLE (C++): Direct string buffer operation for ${cweId}
void handleBuffer(const char* input) {
    char buf[128];
    strcpy(buf, input); // Memory boundary violation
}`,
      fixedCode: `// SECURE (C++): Bounded string copy and length check for ${cweId}
void handleBuffer(const std::string& input) {
    if (input.length() >= 128) {
        throw std::length_error("Input exceeds buffer boundary");
    }
    std::string safeBuf = input;
}`,
      fixMethod1: "Bounded Memory Operations: Use std::string / std::vector instead of raw C-style pointers.",
      fixMethod2: "Compiler Hardening: Enable -fstack-protector-strong and ASLR."
    },
    csharp: {
      vulnerableCode: `// VULNERABLE (C#): Processing unvalidated query string for ${cweId}
public IActionResult Process(string input) {
    var result = UnsafeExecute(input);
    return Ok(result);
}`,
      fixedCode: `// SECURE (C#): Data Annotations & ModelState validation for ${cweId}
[HttpPost]
public IActionResult Process([FromBody] InputModel model) {
    if (!ModelState.IsValid) {
        return BadRequest(ModelState);
    }
    var result = SafeExecute(model.Data);
    return Ok(result);
}`,
      fixMethod1: "ModelState Validation: Use ASP.NET DataAnnotations ([Required], [StringLength]).",
      fixMethod2: "Secure Default Binding: Enforce strongly typed DTO parameter binding."
    },
    php: {
      vulnerableCode: `// VULNERABLE (PHP): Direct evaluation of input for ${cweId}
$data = $_GET['data'];
echo execute_raw($data);`,
      fixedCode: `// SECURE (PHP): Filter validation and escaping for ${cweId}
$data = filter_input(INPUT_GET, 'data', FILTER_SANITIZE_SPECIAL_CHARS);
if (!$data) {
    http_response_code(400);
    die("Invalid input");
}
echo execute_safe($data);`,
      fixMethod1: "filter_input(): Filter and sanitize incoming request parameters using filter_input().",
      fixMethod2: "htmlspecialchars(): Escape strings using htmlspecialchars($var, ENT_QUOTES, 'UTF-8')."
    }
  };
}
