# OutSystems Factory Analyzer (POC)

A static code analysis and architectural auditing tool for OutSystems enterprise codebases using XML parsing and LLM intelligence.

## Features
- **Global Architecture Mapping**: Visualizing module relationships across the Four-Layer Canvas.
- **Performance Profiling**: Detecting query filters executing on unindexed database attributes.
- **Dead Code Detection**: Identifying orphaned public actions, unused entities, and unreferenced UI components.
- **Cross-App Impact Analysis**: Evaluating breaking change blast radiuses across independent applications.

## Repository Structure
```text
outsystems-factory-analyzer/
├── .gitignore
├── README.md
├── CLAUDE.md
├── prompts/
│   └── REPORT_PROMPT.md
├── scripts/
│   └── parse_factory.py
├── input/
└── output/