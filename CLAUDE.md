# OutSystems Factory Analyzer

## Reading OutSystems code: never read input/*.xml directly

The XML exports are huge (up to 70 MB) and key-based. Use the decompiled output instead:

1. `python scripts/extract_model.py` — XML → `output/model/<Module>.json` (names resolved, expressions as text).
   Cached by file size+mtime, so re-running is instant; `--force` to rebuild, `--only A,B` for some modules.
2. `python scripts/decompile_actions.py` — JSON → `output/code/<Module>/` pseudocode:
   - `_module.txt`: references, timers, site properties, entities (attributes, indexes), structures, file index
   - `ServerActions/`, `ClientActions/`, `ServiceAPI/`, ... one `.txt` per action
   - `Screens/`, `Blocks/`: one file per screen/block with its aggregates, data actions and screen actions

To answer "what does action X do": `Grep` for `X.txt` under `output/code/` and read that file.

## Assessment reports

`python scripts/run_pipeline.py` runs everything: extract → decompile → `build_index.py` (`output/index.json`: layers,
call graph, pseudocode path per flow) → `checks/<pillar>.py` (`output/findings/<pillar>.json`) →
`generate_reports.py` (`output/<Report>.html`, shared template in `report_html.py`).

- Findings have one shape (`checks/common.py`): rule, severity (Critical/High/Medium/Low/Info), category, title,
  module, element, file (pseudocode path), evidence, recommendation. Rule ids are listed in each check's docstring.
- Secrets are always masked (`common.mask`). Never print a credential found in the exports.
- The executive summary of each report is `output/narrative/<report>.html`, written from the findings following
  `prompts/NARRATIVE.md`. Rewrite it whenever findings change.
- Done: Security (`checks/security.py`), Maintainability (`checks/maintainability.py`, rules from Indigo's OS11
  guidelines, module score/grade in `findings/maintainability.json` → `modules`). To add a pillar: a `checks/<pillar>.py` with `run(ctx)`, a report function in
  `generate_reports.py`, and both registered in `run_pipeline.py`.

## Pseudocode conventions

- `If cond:` / `Else:` / `Switch` / `ForEach list:` are nested; `continue` = branch back to the loop, `goto` = node reached twice.
- `Aggregate` lists stages: `[name] FROM ...`, `JOIN`, `CALC`, `WHERE`, `GROUP ... BY`, `AGG`.
- `called by:` lists local callers and timers.
- `<unresolved>` = a reference broken in the module itself; `// unreachable:` = nodes not connected to the flow.
- `BuiltinException:%key` = a built-in exception (AllExceptions, DatabaseException...); the export has no names for these.
