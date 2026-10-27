# Writing a report's executive summary

Each report (`scripts/generate_reports.py`) opens with `output/narrative/<report>.html` when that file exists.
It is an HTML fragment (no `<html>`/`<body>`), written by Claude from the findings after the checks run.

## Inputs
- `output/findings/<report>.json` — every finding: rule, severity, module, element, evidence, recommendation
  (plus `inventory` for security).
- `output/code/<file>` — the pseudocode of a flow, when a finding needs to be understood before describing it.

## Rules
- Every number and name must come from the findings or the pseudocode. Never estimate or invent.
- Never copy a secret: findings already mask them; refer to the element (e.g. "the LogAPI password"), not the value.
- Structure: a lead paragraph with the rating and counts; "Top priorities" (3 items, grouped by root cause, each with
  the rule ids); "Other notable findings"; "What is already right"; a remediation table (Immediately / 7 days /
  30 days / Next release) mapping actions to rule ids.
- Use the CSS already in the report: `<p class="lead">`, `<h3>`, `<ul>`, `<code>`, `<table class="data">`.
- Regenerate the narrative whenever the findings change, then run `python scripts/generate_reports.py <report>`.
