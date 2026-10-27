# OutSystems Factory Analyzer (POC)

A static code analysis and architectural auditing tool for OutSystems enterprise codebases using local XML parsing and LLM intelligence.

---

## 🎯 Executive Summary & Value Proposition

Traditional OutSystems monitoring tools often analyze modules in isolation or rely on runtime telemetry. **OutSystems Factory Analyzer** provides a holistic, offline, cross-module analysis by parsing factory exports (`.oml` / `.xml` representations) locally. 

By combining deterministic AST (Abstract Syntax Tree) parsing with LLM-assisted context evaluation, this tool fills the gap between local AI-assisted development (e.g., Model Context Protocol / MCP agents) and enterprise-wide governance. It acts as a **governance companion** that ensures compliance with OutSystems Architecture Canvas 3.0, identifies hidden cross-application risks, and tracks technical debt without sending sensitive source code to external cloud environments.

---

## 🏛️ The 4 Core Macro Pillars

The Analyzer evaluates your OutSystems ecosystem across four main dimensions:

### 1. Application & Business Overview
* **Portfolio & Dependency Cataloging:** Maps all modules, applications, and extensions, categorizing them into Orchestration, End-User, Core, and Foundation layers.
* **Orphan & Ghost Asset Detection:** Identifies unused applications, unreferenced public actions, and abandoned UI components across the entire factory.
* **Functional Heatmaps:** Translates complex low-code dependency graphs into high-level functional maps for Business Analysts, Product Owners, and Delivery Managers.
* **Cross-App Impact Analysis:** Calculates the blast radius of breaking changes across independent applications before deployment.

### 2. Architecture Assessment (Canvas 3.0)
* **Layering Violation Auditing:** Automatically detects illegal side-way references (End-User to End-User) and upward dependencies (Core to End-User).
* **Circular Dependency Detection:** Highlights complex circular loops (e.g., Module A → B → C → A) that lock release pipelines and increase coupling.
* **Coupling & Cohesion Metrics:** Flag over-utilized core entities and service actions acting as single points of failure.
* **Legacy & Deprecated Pattern Check:** Identifies outdated UI patterns, legacy Web Patterns, and deprecated Forge components.

### 3. Performance Assessment
* **Unindexed Attribute Filters:** Scans Aggregates and Advanced SQL queries filtering or sorting on unindexed database attributes in referenced entities.
* **N+1 Query Detection:** Pinpoints `For Each` loops executing queries sequentially instead of performing bulk/batch operations.
* **ViewState & Payload Optimization:** Detects screens and UI blocks carrying excessive data variables, degrading client-side rendering performance.
* **Dead Code Elimination:** Locates unreferenced Server Actions, Entities, and UI elements to reduce `.oml` size and speed up 1-Click Publish times.

### 4. Security Assessment
* **Unprotected Actions & Endpoints:** Detects public Server Actions, REST/SOAP endpoints, and Screens set to `Anonymous` without explicit Role validation.
* **Sensitive Data Exposure (PII):** Flags entities containing sensitive fields (passwords, tokens, PII) exposed via public APIs or unencrypted parameters.
* **SQL Injection Vulnerabilities:** Audits Advanced SQL nodes for unsafe string concatenations instead of properly parameterized inputs.
* **Role & Governance Drift:** Cross-checks factory permissions against organizational security guidelines to ensure compliance.

---

## 📁 Repository Structure

```text
outsystems-factory-analyzer/
├── CLAUDE.md                  # How to read the code and extend the analysis (for Claude and humans)
├── prompts/
│   ├── NARRATIVE.md           # How executive summaries are written from the findings
│   └── REPORT_*.md            # Original report briefs
├── scripts/
│   ├── run_pipeline.py        # Runs everything below, in order
│   ├── extract_model.py       # XML -> output/model/<Module>.json (one parse, cached)
│   ├── decompile_actions.py   # model -> output/code/<Module>/ readable pseudocode
│   ├── build_index.py         # model -> output/index.json (layers, call graph, dependencies)
│   ├── layers.py              # Architecture Canvas layers and cycle detection
│   ├── checks/                # Rules per pillar -> output/findings/<pillar>.json
│   │   ├── architecture.py  performance.py  security.py  maintainability.py
│   │   └── common.py          # Findings format, shared lookups, secret masking
│   ├── report_html.py         # Shared HTML template
│   ├── generate_reports.py    # findings -> output/<Report>.html
│   └── generate_app_overview.py  # Application & Business Overview (curated purposes + model facts)
├── input/                     # Factory XML/OML exports (not versioned)
└── output/                    # Generated model, pseudocode, findings and reports (not versioned)
```

## ▶️ Usage

```bash
python scripts/run_pipeline.py          # all 5 reports; --force re-parses every XML
```

Reports: `Application_Overview_Report.html`, `Architecture_Report.html`, `Performance_Report.html`,
`Security_Assessment_Report.html`, `Maintainability_Report.html`. Executive summaries live in `output/narrative/`.
