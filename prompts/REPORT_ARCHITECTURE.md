# OutSystems Architecture & Dependency Audit Prompt

## Objective
Analyze the XML files in `input/` and generate a detailed HTML report focusing on Architecture Canvas layer compliance, cross-module dependencies, and a visual network graph.

## Output Format Requirements
- **Format:** Standalone single-file HTML (`output/Architecture_Report.html`).
- **Styling:** Dark/Light modern architectural dashboard theme with status badges for layer violations.
- **Mermaid Integration:** Include the Mermaid JS CDN script in `<head>` to render diagrams visually:
  `<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>`
  `<script>mermaid.initialize({startOnLoad:true});</script>`

## Required Sections

### 1. Executive Architecture Summary
- Total modules parsed and layer breakdown (End-User, Core Services, Foundation).

### 2. Global Architecture & Dependency Diagram (Visual)
- Render a detailed **Mermaid.js** graph (`<div class="mermaid"> graph TD ... </div>`):
  - Group modules into subgraph blocks by layer.
  - Directional arrows (`-->`) for module dependencies.
  - Highlight architecture canvas violations in distinct warning colors.

### 3. Architecture Violations & Recommendations
- Table listing side-way or upward dependency violations found in `<Reference>` tags.
- Recommended refactoring steps.