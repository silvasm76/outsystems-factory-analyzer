# Instructions for OutSystems Factory Audit Report Generator

Analyze all OutSystems module XML files provided in the repository and generate a comprehensive technical report saved as `output/Factory_Audit_Report.md`. 

The report must include the following sections:

## 1. Executive Summary & Architecture Overview
- Map all detected applications and modules into the OutSystems Architecture Framework (Four-Layer Canvas / Architecture Canvas).
- Highlight layer violations (e.g., End-User modules bypassing Core services or direct cross-business-domain database access).

## 2. Database Performance Risks (Unindexed Query Filters)
- Identify all Aggregates and Advanced SQL queries that apply filter conditions (`WHERE` clauses) on entity attributes that **lack database indexes**.
- Categorize identified risks by severity (High / Medium) based on entity usage.

## 3. Dead Code & Orphaned Elements
- List all Public Server Actions (`Public = True`) with zero consumer references across the entire factory.
- List unused Entities, Attributes, or UI Blocks that are never referenced in logic or screens.

## 4. Cross-Module Impact & Dependency Analysis
- Identify the most tightly coupled modules in the factory.
- Map high-risk dependencies where breaking changes would impact the largest number of consuming applications.

## 5. Technical Debt & Maintainability Heatmap
- Identify screens with excessive widget nesting or complex UI trees.
- Highlight Server Actions with high cyclomatic complexity or excessive node counts.