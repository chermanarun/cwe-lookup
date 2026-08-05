# 🛡️ CWE Intelligence & Remediation Engine

> Instant CWE vulnerability lookup, multi-language security remediation guide, and 1-click Jira description generator for developers and AppSec engineers.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Vite](https://img.shields.io/badge/vite-5.4-purple.svg)
![CWE Top 25](https://img.shields.io/badge/CWE-Top%2025-red.svg)
![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%202021-orange.svg)

---

## 📌 Overview

**CWE Intelligence & Remediation Engine** is a high-density, classic enterprise Security Operations web application built with **Vite, HTML5, TailwindCSS, and JavaScript**. 

It allows security engineers, developers, and QA teams to input any Common Weakness Enumeration ID (e.g. `CWE-89`, `CWE-284`, `CWE-79`, `CWE-78`), inspect exhaustive security intelligence across **15+ parameters**, toggle between **7 target programming languages**, and instantly copy a **structured Jira issue description template** for immediate developer remediation.

---

## ✨ Features

- **🔍 Search & Auto-Complete Engine**: Instant search for any CWE ID or keyword with real-time suggestions and preset quick pills (`CWE-89`, `CWE-284`, `CWE-79`, `CWE-78`).
- **🌐 Dual Intelligence Layer**: Combines a pre-populated offline knowledge base for OWASP Top 10 & CWE Top 25 with a live REST API fetcher connected to official **MITRE CWE API** data (`https://cwe-api.mitre.org`).
- **💻 7-Language Remediation**: Production-grade vulnerable vs. fixed code examples and mitigation methods for:
  - 🐍 **Python** (Flask/FastAPI decorators, `@contextmanager`, DB-API placeholders)
  - 🟨 **JavaScript / TypeScript** (Node.js/Express middleware, `$1` parameter arrays, DOMPurify)
  - ☕ **Java** (Spring Security `@PreAuthorize`, JDBC `PreparedStatement`)
  - 🔷 **Go** (Context claims validation, `db.QueryRow` placeholders)
  - ⚡ **C / C++** (RAII `PrivilegeGuard` destructors, `sqlite3_prepare_v2`, `posix_spawn`)
  - 🟦 **C# (.NET)** (ASP.NET Core `[Authorize(Policy = "...")]`, `SqlCommand.Parameters`)
  - 🐘 **PHP** (Session role gates, PDO prepared statements, `htmlspecialchars`)
- **📋 1-Click Jira Description Generator**: Copy-pasteable Jira Markdown template including severity badges, problem details, code diffs, fix steps, testing methods, and developer prevention checklists.
- **🏷️ Discouraged Pillar Guidance**: Displays warning notes and clickable links to specific descendant weaknesses when querying high-level Pillar CWEs (e.g. `CWE-284` $\rightarrow$ `CWE-862`, `CWE-863`, `CWE-306`).
- **🛡️ 15+ Security Parameters**: Includes CVSS 3.1 rating, OWASP Top 10 2021 mapping, Problem Description, Attack Impact, Auto-Fix Confidence, Primary/Defense-in-Depth Fix Methods, SAST/DAST Testing Strategies, Prevention Checklists, and Compliance Impact (PCI-DSS 4.0, HIPAA, SOC 2, ISO 27001, NIST SP 800-53).
- **🏛️ Classic Enterprise UI**: Clean, crisp, high-contrast interface designed for security operations and developer productivity without flashy AI neon clutter.

---

## 🚀 Quick Start

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

## 📁 Repository Structure

```text
CWE-Lookup/
├── index.html                 # Main HTML entry point with classic typography
├── package.json               # Dependencies and scripts (Vite)
├── vite.config.js             # Vite configuration with MITRE API proxy
├── src/
│   ├── main.js                # State management and application lifecycle
│   ├── style.css              # Classic enterprise styling & syntax highlighting
│   ├── components/
│   │   ├── Header.js          # Navigation bar with search & quick pills
│   │   └── CweDetailView.js   # Main security dashboard & tab views
│   ├── data/
│   │   └── cweDatabase.js     # Multi-language CWE intelligence database
│   └── services/
│       ├── cweService.js      # ID normalization, search & MITRE API parser
│       └── jiraTemplateGenerator.js # Jira Markdown description formatter
└── README.md
```

---

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request to add more CWE definitions, language snippets, or security features.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
