export const cweDatabase = {
  "CWE-284": {
    id: "CWE-284",
    name: "Improper Access Control",
    category: "Access Control / Authorization",
    owaspCategory: "A01:2021 - Broken Access Control",
    severity: "High",
    cvssScore: "8.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
    autoFixAvailable: true,
    autoFixConfidence: "Medium (80%)",
    problemDescription: "The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor. Access control involves several protection mechanisms: Authentication (proving identity), Authorization (ensuring actor can access resource), and Accountability (tracking activities). When any mechanism is missing or fails, attackers can gain privileges, read sensitive data, execute commands, or evade detection.",
    extendedDescription: "Specification issues occur when incorrect permissions or ownership are specified (e.g. world-writable password files). Enforcement issues occur when code logic errors prevent proper policy enforcement (e.g. unhandled exceptions leaving elevated privileges active).",
    attackImpact: "Unauthorized privilege escalation, sensitive data exfiltration (PII/source code), unauthorized modification/deletion of system resources, and complete security policy bypass.",
    mappingNotes: {
      usage: "DISCOURAGED (Pillar Abstraction)",
      rationale: "CWE-284 is an extremely high-level Pillar. Its name, 'Improper Access Control', is often misused in low-information vulnerability reports or by active use of the OWASP Top Ten. Consider using specific descendants.",
      suggestions: [
        { id: "CWE-862", name: "Missing Authorization" },
        { id: "CWE-863", name: "Incorrect Authorization" },
        { id: "CWE-732", name: "Incorrect Permission Assignment for Critical Resource" },
        { id: "CWE-306", name: "Missing Authentication" },
        { id: "CWE-1390", name: "Weak Authentication" }
      ]
    },
    demonstrativeExamples: [
      {
        title: "Example 1: Unhandled Exception Lingering in Raised Privilege State (Python)",
        description: "Program raises privileges to create user directory but fails to drop privileges if os.mkdir() throws an exception.",
        code: `def makeNewUserDir(username):
    if invalidUsername(username):
        return False
    try:
        raisePrivileges()
        os.mkdir('/home/' + username)
        lowerPrivileges() # If os.mkdir throws exception, lowerPrivileges is NEVER called!
    except OSError:
        return False
    return True`
      },
      {
        title: "Example 2: Missing Authorization Check in Database Query Handler (PHP)",
        description: "Function executes query carefully avoiding SQL injection, but fails to check if the caller is authorized to view employee records.",
        code: `function runEmployeeQuery($dbName, $name) {
    // Uses prepared statement to avoid CWE-89, but lacks authorization check!
    $stmt = $globalDbHandle->prepare('SELECT * FROM employees WHERE name = :name');
    $stmt->execute(array(':name' => $name));
    return $stmt->fetchAll();
}`
      }
    ],
    observedExamples: [
      { cve: "CVE-2023-26463", desc: "IPSec VPN product incorrect access control leading to expired pointer dereference." },
      { cve: "CVE-2022-24985", desc: "Form hosting site checks authentication for single form only, bypassing multi-form auth." },
      { cve: "CVE-2022-29238", desc: "Collaboration tool fails to enforce directory listing restrictions on direct file requests." },
      { cve: "CVE-2021-21972", desc: "Virtualization platform unauthenticated upload combined with path traversal." }
    ],
    languages: {
      python: {
        vulnerableCode: `# VULNERABLE (Python): Unhandled exception leaves program in elevated privilege state
def create_user_directory(username):
    raise_privileges()
    # If os.mkdir raises OSError, lower_privileges() is NEVER executed!
    os.mkdir(f"/var/user_data/{username}")
    lower_privileges()`,
        fixedCode: `# SECURE (Python): Using Context Manager / try...finally to guarantee privilege reduction
from contextlib import contextmanager

@contextmanager
def elevated_privileges():
    raise_privileges()
    try:
        yield
    finally:
        lower_privileges() # ALWAYS executed regardless of exceptions

def create_user_directory(username):
    with elevated_privileges():
        os.mkdir(f"/var/user_data/{username}")`,
        fixMethod1: "Context Manager Cleanup: Wrap elevated operations in try/finally or @contextmanager to guarantee privilege revocation.",
        fixMethod2: "Flask/FastAPI Decorators: Apply @requires_permission('admin') on route handler entries."
      },
      javascript: {
        vulnerableCode: `// VULNERABLE (Node.js/Express): Admin endpoint missing role/permission check
app.delete('/api/users/:id', async (req, res) => {
  const userId = req.params.id;
  // Missing authorization check: does req.user have admin privileges?
  await db.users.delete(userId);
  res.json({ success: true });
});`,
        fixedCode: `// SECURE (Node.js/Express): Enforce RBAC authorization middleware
function authorize(requiredRole) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== requiredRole) {
      return res.status(403).json({ error: "Forbidden: Insufficient privileges" });
    }
    next();
  };
}

app.delete('/api/users/:id', authorize('ADMIN'), async (req, res) => {
  await db.users.delete(req.params.id);
  res.json({ success: true });
});`,
        fixMethod1: "Authorization Middleware: Enforce central authorize('ADMIN') middleware on sensitive API routes.",
        fixMethod2: "CASL / ABAC Policy Engine: Validate user capabilities using Attribute-Based Access Control."
      },
      java: {
        vulnerableCode: `// VULNERABLE (Java/Spring): Admin method missing security annotations
@DeleteMapping("/api/admin/users/{id}")
public ResponseEntity<Void> deleteUser(@PathVariable String id) {
    // Missing security check: any authenticated user can invoke!
    userService.deleteUser(id);
    return ResponseEntity.noContent().build();
}`,
        fixedCode: `// SECURE (Java/Spring): Method Security via @PreAuthorize
@DeleteMapping("/api/admin/users/{id}")
@PreAuthorize("hasRole('ROLE_ADMIN') and hasPermission(#id, 'User', 'delete')")
public ResponseEntity<Void> deleteUser(@PathVariable String id) {
    userService.deleteUser(id);
    return ResponseEntity.noContent().build();
}`,
        fixMethod1: "Spring Security @PreAuthorize: Annotate methods with @PreAuthorize(\"hasRole('ADMIN')\").",
        fixMethod2: "SecurityContextHolder Verification: Programmatically check SecurityContextHolder.getContext().getAuthentication()."
      },
      go: {
        vulnerableCode: `// VULNERABLE (Go): Handler executing privileged logic without claim verification
func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("id")
    // Missing check: r.Context does not verify admin scope
    db.DeleteUser(r.Context(), userID)
    w.WriteHeader(http.StatusOK)
}`,
        fixedCode: `// SECURE (Go): Verify Context permissions before performing database operations
func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
    userClaims, ok := r.Context().Value("claims").(*Claims)
    if !ok || !userClaims.HasRole("ADMIN") {
        http.Error(w, "Forbidden: Admin privileges required", http.StatusForbidden)
        return
    }
    db.DeleteUser(r.Context(), r.URL.Query().Get("id"))
    w.WriteHeader(http.StatusOK)
}`,
        fixMethod1: "Context Scope Validation: Verify r.Context() claims contain required permission scope.",
        fixMethod2: "Open Policy Agent (OPA): Delegate authorization decisions to an OPA policy engine sidecar."
      },
      cpp: {
        vulnerableCode: `// VULNERABLE (C++): Manual seteuid calls without RAII protection
void performAdminMaintenance() {
    seteuid(0); // Elevate to root
    doFileOperations(); // If doFileOperations throws std::exception, process stays root!
    seteuid(getuid());
}`,
        fixedCode: `// SECURE (C++): RAII Privilege Guard ensuring privilege drop on stack unwinding
class PrivilegeGuard {
public:
    PrivilegeGuard() { seteuid(0); }
    ~PrivilegeGuard() { seteuid(getuid()); } // Destructor ALWAYS runs during exception unwinding
};

void performAdminMaintenance() {
    PrivilegeGuard guard;
    doFileOperations();
}`,
        fixMethod1: "RAII Privilege Guard: Enclose elevated privilege blocks in RAII wrappers to guarantee cleanup.",
        fixMethod2: "Linux Capabilities (cap_drop): Drop cap_sys_admin permanent capabilities after startup."
      },
      csharp: {
        vulnerableCode: `// VULNERABLE (C#/.NET): Controller action missing [Authorize] attribute
[HttpPost]
public IActionResult ResetSystem() {
    // Missing authorization check!
    _systemService.Reset();
    return Ok();
}`,
        fixedCode: `// SECURE (C#/.NET): ASP.NET Core [Authorize] with Policy
[HttpPost]
[Authorize(Policy = "RequireAdminRole")]
public IActionResult ResetSystem() {
    _systemService.Reset();
    return Ok();
}`,
        fixMethod1: "Policy-Based Authorization: Apply [Authorize(Policy = \"AdminPolicy\")] on actions.",
        fixMethod2: "IAuthorizationService: Use IAuthorizationService.AuthorizeAsync(User, resource, policyName)."
      },
      php: {
        vulnerableCode: `// VULNERABLE (PHP): Action executed without session role check
if ($_POST['action'] === 'delete_user') {
    $userId = $_POST['user_id'];
    deleteUser($userId);
}`,
        fixedCode: `// SECURE (PHP): Explicit session role check before action execution
if ($_POST['action'] === 'delete_user') {
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'ADMIN') {
        http_response_code(403);
        die("Access Denied: Admin role required.");
    }
    deleteUser($_POST['user_id']);
}`,
        fixMethod1: "Session Role Validation: Verify $_SESSION['role'] === 'ADMIN' prior to executing privileged actions.",
        fixMethod2: "Middleware Gateways: Wrap controllers in framework authorization gates (e.g. Laravel Gates)."
      }
    },
    testingMethod: "1. SAST Analysis: Scan for un-annotated endpoint handlers missing @PreAuthorize / [Authorize] / requireRole checks.\\n2. DAST Privilege Escalation Tests: Perform Horizontal & Vertical Privilege Escalation attempts using unprivileged tokens.\\n3. Exception Unwind Testing: Trigger errors during elevated ops to verify privilege reduction.",
    preventionChecklist: [
      "Enforce server-side authorization checks on all endpoints and resources.",
      "Ensure privilege elevation is strictly contained using try/finally or RAII wrappers to prevent lingering high-privilege states.",
      "Adopt Principle of Least Privilege: default to deny all access unless explicitly permitted.",
      "Avoid client-side access control decisions; never rely on UI hiding or client toggles.",
      "Log all access control failures for security auditing."
    ],
    complianceImpact: "PCI-DSS 4.0 Requirement 7.1 & 7.2, SOC 2 CC6.1 & CC6.3, ISO 27001 Control A.8.2, NIST SP 800-53 AC-2 & AC-3."
  },
  "CWE-89": {
    id: "CWE-89",
    name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    category: "Injection",
    owaspCategory: "A03:2021 - Injection",
    severity: "Critical",
    cvssScore: "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    autoFixAvailable: true,
    autoFixConfidence: "High (95%)",
    problemDescription: "The application constructs an SQL command using untrusted input from an HTTP request without neutralizing special characters or parameterizing the query. This allows an attacker to manipulate the structure of the SQL query, execute arbitrary database commands, bypass authentication, extract confidential data, or modify database records.",
    attackImpact: "Full Database Compromise: Data exfiltration of PII/credentials, unauthorized database writes/deletions, potential remote code execution via database stored procedures (e.g. xp_cmdshell, SELECT INTO OUTFILE), and complete authentication bypass.",
    languages: {
      python: {
        vulnerableCode: `# VULNERABLE (Python): Direct string interpolation in SQL query
def get_user_profile(user_id):
    cursor = db.cursor()
    query = f"SELECT id, username, email, role FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()`,
        fixedCode: `# SECURE (Python): Parameterized Query using DB-API placeholders
def get_user_profile(user_id):
    cursor = db.cursor()
    query = "SELECT id, username, email, role FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()`,
        fixMethod1: "Parameterized Queries (Prepared Statements): Use database placeholders (%s, ?, :val) so the DB engine compiles query logic separately from user inputs.",
        fixMethod2: "Object-Relational Mapping (ORM): Utilize modern ORMs like SQLAlchemy or Django ORM that enforce parameterization by default."
      },
      javascript: {
        vulnerableCode: `// VULNERABLE (Node.js): String concatenation in SQL query
async function getUserProfile(req, res) {
  const userId = req.query.id;
  const query = "SELECT id, username, email FROM users WHERE id = '" + userId + "'";
  const results = await db.query(query);
  res.json(results.rows);
}`,
        fixedCode: `// SECURE (Node.js): Parameterized Query using parameterized array
async function getUserProfile(req, res) {
  const userId = req.query.id;
  const query = "SELECT id, username, email FROM users WHERE id = $1";
  const results = await db.query(query, [userId]);
  res.json(results.rows);
}`,
        fixMethod1: "Parameterized Queries: Use parameterized query arrays ($1, ?) with pg, mysql2, or sqlite3 drivers.",
        fixMethod2: "Input Type Validation & ORM: Validate input using Zod/Joi schemas and leverage Prisma, Knex, or Sequelize ORM."
      },
      java: {
        vulnerableCode: `// VULNERABLE (Java): Direct string concatenation in Statement
public User getUser(String userId) throws SQLException {
    Statement statement = connection.createStatement();
    String sql = "SELECT * FROM users WHERE user_id = '" + userId + "'";
    ResultSet rs = statement.executeQuery(sql);
    return extractUser(rs);
}`,
        fixedCode: `// SECURE (Java): PreparedStatement with bind variables
public User getUser(String userId) throws SQLException {
    String sql = "SELECT * FROM users WHERE user_id = ?";
    PreparedStatement pstmt = connection.prepareStatement(sql);
    pstmt.setString(1, userId);
    ResultSet rs = pstmt.executeQuery();
    return extractUser(rs);
}`,
        fixMethod1: "PreparedStatement: Always use PreparedStatement in JDBC with placeholder ? setters (setString, setInt).",
        fixMethod2: "JPA / Hibernate Named Parameters: Use Hibernate Criteria API or named parameters (:userId) in JPQL queries."
      },
      go: {
        vulnerableCode: `// VULNERABLE (Go): Sprintf formatting in SQL query
func GetUser(db *sql.DB, userID string) (*User, error) {
    query := fmt.Sprintf("SELECT id, email FROM users WHERE id = '%s'", userID)
    row := db.QueryRow(query)
    var u User
    err := row.Scan(&u.ID, &u.Email)
    return &u, err
}`,
        fixedCode: `// SECURE (Go): Database/sql driver parameterized placeholder
func GetUser(db *sql.DB, userID string) (*User, error) {
    query := "SELECT id, email FROM users WHERE id = $1"
    row := db.QueryRow(query, userID)
    var u User
    err := row.Scan(&u.ID, &u.Email)
    return &u, err
}`,
        fixMethod1: "Parameterized Queries: Always pass arguments as trailing parameters to db.Query() or db.QueryRow().",
        fixMethod2: "GORM / Ent ORM: Use Go ORM frameworks like GORM or Ent which auto-parameterize query conditions."
      },
      cpp: {
        vulnerableCode: `// VULNERABLE (C++): String concatenation with sqlite3_exec
void getUser(sqlite3* db, const std::string& userId) {
    std::string sql = "SELECT name, email FROM users WHERE id = '" + userId + "';";
    char* errMsg = nullptr;
    sqlite3_exec(db, sql.c_str(), callback, 0, &errMsg);
}`,
        fixedCode: `// SECURE (C++): sqlite3_prepare_v2 with sqlite3_bind_text
void getUser(sqlite3* db, const std::string& userId) {
    const char* sql = "SELECT name, email FROM users WHERE id = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, userId.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt) == SQLITE_ROW) {}
        sqlite3_finalize(stmt);
    }
}`,
        fixMethod1: "sqlite3_prepare / bind API: Prepare statement objects and use sqlite3_bind_* calls for all inputs.",
        fixMethod2: "C++ ORM / Abstraction Layer: Use modern C++ SQL libraries like SOCI or ODB with parameter binding."
      },
      csharp: {
        vulnerableCode: `// VULNERABLE (C#): String interpolation in SqlCommand
public User GetUser(string userId) {
    using (var conn = new SqlConnection(connectionString)) {
        conn.Open();
        string sql = $"SELECT Id, Email FROM Users WHERE Id = '{userId}'";
        var cmd = new SqlCommand(sql, conn);
        var reader = cmd.ExecuteReader();
    }
}`,
        fixedCode: `// SECURE (C#): SqlCommand Parameters collection
public User GetUser(string userId) {
    using (var conn = new SqlConnection(connectionString)) {
        conn.Open();
        string sql = "SELECT Id, Email FROM Users WHERE Id = @UserId";
        var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add("@UserId", SqlDbType.VarChar).Value = userId;
        var reader = cmd.ExecuteReader();
    }
}`,
        fixMethod1: "SqlCommand Parameters: Use @Param placeholders and AddWithValue() / SqlDbType bindings.",
        fixMethod2: "Entity Framework Core: Use EF Core LINQ queries (e.g. context.Users.FirstOrDefault(u => u.Id == userId))."
      },
      php: {
        vulnerableCode: `// VULNERABLE (PHP): Direct variable interpolation in query
$userId = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '$userId'";
$result = mysqli_query($conn, $query);`,
        fixedCode: `// SECURE (PHP): PDO Prepared Statements
$userId = $_GET['id'];
$stmt = $pdo->prepare('SELECT id, username, email FROM users WHERE id = :id');
$stmt->execute(['id' => $userId]);
$user = $stmt->fetch();`,
        fixMethod1: "PDO Prepared Statements: Always use PDO::prepare() and execute() with bound arrays or bindParam().",
        fixMethod2: "Doctrine ORM / Eloquent: Leverage Laravel Eloquent or Symfony Doctrine for abstract database interactions."
      }
    },
    testingMethod: "1. SAST Analysis: Scan codebase with Semgrep/SonarQube rules for unparameterized SQL concatenation.\\n2. DAST Automated Scan: Send SQLi payloads (' OR '1'='1, 1; WAITFOR DELAY '0:0:5'--) via OWASP ZAP or Burp Suite.\\n3. Unit Testing: Create automated test cases passing quotes and SQL keywords into user input fields.",
    preventionChecklist: [
      "Mandate parameterization/prepared statements for 100% of database queries.",
      "Enforce strict input validation using allowlists for dynamic table/column names.",
      "Apply Least Privilege Principle to database connection accounts (deny DROP, ALTER, admin procedures).",
      "Disable verbose database error messages in production to avoid info disclosure.",
      "Deploy Web Application Firewall (WAF) SQLi rulesets (ModSecurity / AWS WAF) for defense in depth."
    ],
    complianceImpact: "PCI-DSS 4.0 Requirement 6.2.4 (Prevent Injection Flaws), HIPAA Technical Safeguards (§164.312), SOC 2 CC6.1 & CC6.6, ISO/IEC 27001 Control A.8.28 (Secure Coding), NIST SP 800-53 SI-10."
  },
  "CWE-79": {
    id: "CWE-79",
    name: "Improper Neutralization of Input During Web Page Generation ('Cross-Site Scripting')",
    category: "Injection",
    owaspCategory: "A03:2021 - Injection",
    severity: "High",
    cvssScore: "8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)",
    autoFixAvailable: true,
    autoFixConfidence: "High (90%)",
    problemDescription: "The application places user-supplied input directly into an HTTP response page without sufficient context-aware encoding or sanitization. An attacker can inject malicious HTML tags or JavaScript scripts that execute inside victim users' browsers in the application's domain context.",
    attackImpact: "Session Hijacking (cookie theft), Account Takeover, DOM Manipulation, Credential Phishing via fake inline forms, Keylogging, and unauthorized actions performed on behalf of victim users.",
    languages: {
      python: {
        vulnerableCode: `# VULNERABLE (Python): Rendering unescaped HTML in Flask response
@app.route('/welcome')
def welcome():
    name = request.args.get('name', '')
    return render_template_string(f"<h1>Welcome {name}!</h1>")`,
        fixedCode: `# SECURE (Python): Context-aware HTML escaping using MarkupSafe / Jinja2
from markupsafe import escape

@app.route('/welcome')
def welcome():
    name = request.args.get('name', '')
    safe_name = escape(name)
    return render_template('welcome.html', name=safe_name)`,
        fixMethod1: "Context-Aware HTML Escaping: Escape characters (<, >, &, \", ') into HTML entities before rendering.",
        fixMethod2: "Content Security Policy (CSP): Enforce HTTP CSP headers restricting script execution sources."
      },
      javascript: {
        vulnerableCode: `// VULNERABLE (JS/TS): Direct innerHTML assignment
function displayComment(commentText) {
  document.getElementById('comments').innerHTML = commentText;
}`,
        fixedCode: `// SECURE (JS/TS): Use textContent or DOMPurify
import DOMPurify from 'dompurify';

function displayComment(commentText) {
  document.getElementById('comments').textContent = commentText;
}`,
        fixMethod1: "Safe DOM API: Use textContent / innerText instead of innerHTML / document.write.",
        fixMethod2: "DOMPurify Sanitization: Sanitize rich text inputs using trusted HTML sanitizers."
      },
      java: {
        vulnerableCode: `// VULNERABLE (Java): JSP raw output of parameter
<% String name = request.getParameter("name"); %>
<div>Hello, <%= name %></div>`,
        fixedCode: `// SECURE (Java): JSTL c:out tag
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<div>Hello, <c:out value="\${param.name}" /></div>`,
        fixMethod1: "JSTL c:out & OWASP Java Encoder: Always wrap dynamic attributes and values in context-aware encoders.",
        fixMethod2: "Spring Security CSP Header Filter: Configure Content-Security-Policy headers."
      },
      go: {
        vulnerableCode: `// VULNERABLE (Go): Outputting raw string to http.ResponseWriter
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    fmt.Fprintf(w, "<div>User: %s</div>", name)
}`,
        fixedCode: `// SECURE (Go): html/template with auto-escaping
import "html/template"

func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    tmpl := template.Must(template.New("user").Parse("<div>User: {{.}}</div>"))
    tmpl.Execute(w, name)
}`,
        fixMethod1: "html/template package: Always use Go's standard html/template which contextualizes escaping.",
        fixMethod2: "Sanitization Libraries: Use bluemonday for user-submitted HTML markup."
      },
      cpp: {
        vulnerableCode: `// VULNERABLE (C++): Raw HTML output in CGI / Web server
std::string name = getQueryParam("name");
std::string html = "<h1>Profile: " + name + "</h1>";
sendHttpResponse(html);`,
        fixedCode: `// SECURE (C++): HTML Entity Encoding function
std::string escapeHtml(const std::string& input) {
    std::string output;
    for (char c : input) {
        switch(c) {
            case '<': output += "&lt;"; break;
            case '>': output += "&gt;"; break;
            case '&': output += "&amp;"; break;
            case '"': output += "&quot;"; break;
            case '\'': output += "&#x27;"; break;
            default: output += c;
        }
    }
    return output;
}`,
        fixMethod1: "HTML Encoding Helper: Transform all user inputs into safe HTML entities before stream writing.",
        fixMethod2: "Header hardening: Send Content-Type: text/plain or X-Content-Type-Options: nosniff."
      },
      csharp: {
        vulnerableCode: `// VULNERABLE (C#): ASP.NET Html.Raw helper
public IActionResult UserProfile(string name) {
    ViewBag.Name = name;
    return View();
}`,
        fixedCode: `// SECURE (C#): ASP.NET Razor automatic HTML Encoding
public IActionResult UserProfile(string name) {
    ViewBag.Name = name;
    return View();
}`,
        fixMethod1: "Razor Auto-Escaping: Avoid @Html.Raw() for user input; rely on standard Razor @ string rendering.",
        fixMethod2: "AntiXssEncoder API: Use System.Text.Encodings.Web.HtmlEncoder.Default.Encode()."
      },
      php: {
        vulnerableCode: `// VULNERABLE (PHP): Echoing GET parameter directly
$username = $_GET['user'];
echo "<h2>Welcome, " . $username . "</h2>";`,
        fixedCode: `// SECURE (PHP): htmlspecialchars with ENT_QUOTES and UTF-8
$username = $_GET['user'];
echo "<h2>Welcome, " . htmlspecialchars($username, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . "</h2>";`,
        fixMethod1: "htmlspecialchars(): Escape strings using htmlspecialchars($var, ENT_QUOTES, 'UTF-8').",
        fixMethod2: "HTMLPurifier Library: Filter rich text WYSIWYG input using HTMLPurifier."
      }
    },
    testingMethod: "1. SAST: Check templates for raw output directives (e.g. innerHTML, Html.Raw, v-html, dangerouslySetInnerHTML).\\n2. DAST Payload Injection: Inject script payloads like <script>alert(1)</script>, <svg/onload=alert(1)> and verify browser execution.\\n3. CSP Header Verification: Validate security headers using SecurityHeaders.com.",
    preventionChecklist: [
      "Use context-aware encoding (HTML body, attribute, JavaScript, CSS, URL contexts).",
      "Set HttpOnly and SameSite=Strict/Lax flags on session cookies.",
      "Implement a strong Content Security Policy (CSP): script-src 'self' 'nonce-...' avoiding 'unsafe-inline'.",
      "Avoid raw HTML insertion methods in front-end frameworks (e.g. innerHTML, dangerouslySetInnerHTML).",
      "Sanitize rich text user input using robust libraries like DOMPurify or HTMLPurifier."
    ],
    complianceImpact: "PCI-DSS 4.0 Requirement 6.2.4 (Prevent XSS Flaws), SOC 2 CC6.6 (Boundary Protection), NIST SP 800-53 SI-10, ISO 27001 Control A.8.28."
  }
};
