# OutSystems Performance & Technical Debt Audit Prompt

## Objective
Analyze the XML files in `input/` to detect potential database bottlenecks, unindexed query filters, heavy operations, and unused code.

## Output Format Requirements
- **Format:** Standalone single-file HTML (`output/Performance_Report.html`).
- **Styling:** Technical audit dashboard theme with color-coded risk badges (High = Red, Medium = Orange, Low = Green) and sortable tables.

## Required Sections

### 1. Performance Health Scorecard
- Overview cards with total unindexed queries found, dead code items, and overall system score.

### 2. Database Health & Unindexed Queries
- Table scanning all Aggregates/Advanced Queries with `WHERE` or `JOIN` conditions filtering on non-indexed attributes (`IsIndexed = False`).
- Columns: `Module`, `Entity`, `Attribute Filtered`, `Query Name`, `Risk Level`.

### 3. Technical Debt & Dead Code
- List unused Public Server Actions, Entities, or Attributes.

### 4. Actionable Remediation Plan
- Prioritized steps for adding DB indexes and optimizing queries.