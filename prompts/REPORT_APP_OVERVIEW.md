# OutSystems Application & Business Overview Prompt

## Objective
Analyze the XML files in `input/` and generate a clear, standalone HTML report explaining the overall application purpose, module responsibilities, business features, and inter-application dependencies.

## Output Format Requirements
- **Format:** Standalone single-file HTML (`output/Application_Overview_Report.html`).
- **Styling:** Clean, modern responsive CSS dashboard theme with feature cards, badges, and clean typography.
- **Content Focus:** High-level text and structured HTML tables (no visual diagrams required).

## Required Sections

### 1. Executive Application Summary
- Succinct explanation of the system's overall purpose based on parsed modules, UI screens, and exposed services.

### 2. Module & Feature Catalog
- Table and cards detailing all identified modules:
  - **Module Name & Type:** (End-User, Core, Foundation).
  - **Functional Purpose:** Summary of what the module handles.
  - **Key Business Features:** Core logic, APIs, or user screens provided.

### 3. Inter-Application & Module Dependencies
- Structured HTML table listing dependencies between applications and core services (who consumes what).