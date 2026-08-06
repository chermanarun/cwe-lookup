# CWE Intelligence & Remediation Engine
## Overview

**CWE Intelligence & Remediation Engine** is a high-density, classic enterprise Security Operations web application built with **Vite, HTML5, TailwindCSS, and JavaScript**. 

It allows security engineers, developers, and QA teams to input any Common Weakness Enumeration ID (e.g. `CWE-89`, `CWE-284`, `CWE-79`, `CWE-78`), inspect exhaustive security intelligence across **15+ parameters**, toggle between **7 target programming languages**, and instantly copy a **structured Jira issue description template** for immediate developer remediation.

---

## Features

- ** Search & Auto-Complete Engine**: Instant search for any CWE ID or keyword with real-time suggestions and preset quick pills (`CWE-89`, `CWE-284`, `CWE-79`, `CWE-78`).
- ** Dual Intelligence Layer**: Combines a pre-populated offline knowledge base for OWASP Top 10 & CWE Top 25 with a live REST API fetcher connected to official **MITRE CWE API** data (`https://cwe-api.mitre.org`).
- ** 7-Language Remediation**: Production-grade vulnerable vs. fixed code examples and mitigation methods for:
  -  **Python** (Flask/FastAPI decorators, `@contextmanager`, DB-API placeholders)
  -  **JavaScript / TypeScript** (Node.js/Express middleware, `$1` parameter arrays, DOMPurify)
  -  **Java** (Spring Security `@PreAuthorize`, JDBC `PreparedStatement`)
  -  **Go** (Context claims validation, `db.QueryRow` placeholders)
  -  **C / C++** (RAII `PrivilegeGuard` destructors, `sqlite3_prepare_v2`, `posix_spawn`)
  -  **C# (.NET)** (ASP.NET Core `[Authorize(Policy = "...")]`, `SqlCommand.Parameters`)
  -  **PHP** (Session role gates, PDO prepared statements, `htmlspecialchars`)
- ** 1-Click Jira Description Generator**: Copy-pasteable Jira Markdown template including severity badges, problem details, code diffs, fix steps, testing methods, and developer prevention checklists.
- ** Discouraged Pillar Guidance**: Displays warning notes and clickable links to specific descendant weaknesses when querying high-level Pillar CWEs (e.g. `CWE-284` $\rightarrow$ `CWE-862`, `CWE-863`, `CWE-306`).
- ** 15+ Security Parameters**: Includes CVSS 3.1 rating, OWASP Top 10 2021 mapping, Problem Description, Attack Impact, Auto-Fix Confidence, Primary/Defense-in-Depth Fix Methods, SAST/DAST Testing Strategies, Prevention Checklists, and Compliance Impact (PCI-DSS 4.0, HIPAA, SOC 2, ISO 27001, NIST SP 800-53).
- ** Classic Enterprise UI**: Clean, crisp, high-contrast interface designed for security operations and developer productivity without flashy AI neon clutter.

---

##  Quick Start

### Prerequisites
- [Node.js](https://nodejs.org/) (v18.x or higher)
- `npm` or `yarn`

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/cwe-lookup.git

# Navigate into project directory
cd cwe-lookup

# Install dependencies
npm install

# Run local development server
npm run dev
```

Open `http://localhost:3000` in your web browser.

---

## 🛠️ Build for Production

```bash
# Build production bundle
npm run build

# Preview production build locally
npm run preview
```

---

