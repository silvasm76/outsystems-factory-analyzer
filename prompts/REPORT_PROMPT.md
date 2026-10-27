# OutSystems Factory Audit & Technical Report Guidelines

## Output Format Requirements
- **Format:** Standalone single-file HTML (`output/Factory_Audit_Report.html`).
- **Styling:** Modern, clean responsive dashboard theme (CSS embedded) with status badges for risks (High/Medium/Low) and styled data tables.
- **Mermaid Integration:** Include the official Mermaid JS script in the `<head>` to automatically render diagrams:
  `<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>`
  `<script>mermaid.initialize({startOnLoad:true});</script>`

---

## Required Report Sections

### 1. Global Architecture & Module Dependency Diagram
- **Visual Diagram:** Generate a detailed visual graph using **Mermaid.js** (`<div class="mermaid"> graph TD ... </div>`) representing:
  - Modules grouped/categorized by layer (End-User, Core Services, Foundation).
  - Explicit directional arrows (`-->`) showing module dependencies (who consumes what).
  - Highlighting cyclic dependencies or layer violations (e.g., Core consuming End-User) in distinct colors.
- **Architecture Overview:** Summary table listing all parsed modules, their identified Architecture Canvas layer, and total public elements exposed.

### 2. Performance & Database Health (Unindexed Queries)
- List all aggregates/queries with filters (`WHERE` clauses) on non-indexed attributes.
- Priority impact score (High, Medium, Low).

### 3. Technical Debt & Dead Code Analysis
- Identify unused Public Server Actions, Entities, or Attributes.

### 4. Cross-Module Impact Analysis
- Critical Core modules with the highest consumption rate across the factory.