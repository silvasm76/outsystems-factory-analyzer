# OutSystems Factory Security Assessment Report

---

## Executive Summary

| Document Metadata | Details |
| :--- | :--- |
| **Target Infrastructure** | OutSystems Factory (Development & Production Environments) |
| **Assessment Type** | Code & Architecture Security Audit |
| **Report Date** | October 2026 |
| **Overall Security Rating** | **Moderate Risk** |

### Assessment Overview
This document provides a detailed evaluation of the security posture of the OutSystems application portfolio. The assessment analyzed application role configurations, data access boundaries, REST/SOAP endpoint exposures, and compliance with OWASP Top 10 guidelines for low-code environments.

---

## Risk Profile Summary

```
   [CRITICAL]  ▉▉ 2 Issues Identified
   [HIGH]      ▉▉▉▉ 4 Issues Identified
   [MEDIUM]    ▉▉▉▉▉▉▉ 7 Issues Identified
   [LOW]       ▉▉▉▉▉▉▉▉▉▉▉ 11 Issues Identified
```

### Risk Severity Matrix

| Severity Level | Open Findings | Target Remediation Window |
| :--- | :---: | :--- |
| **Critical** | **2** | Immediate (24-48 Hours) |
| **High** | **4** | 7 Days |
| **Medium** | **7** | 30 Days |
| **Low / Informational** | **11** | Next Release Cycle |

---

## Key Assessment Findings

### 1. Access Control & Role Validation

#### Finding SEC-01: Exposed Server Actions (Critical)
- **Description:** Server Actions set to `Public = Yes` without explicit `Check<Role>Role()` checks.
- **Impact:** Unauthorized users can invoke internal application logic remotely.
- **Affected Modules:** `Core_Customer_CS`, `Billing_Engine_BL`
- **Recommendation:** Implement strict role validation on all public server actions or set Visibility to `Private` if external invocation is unnecessary.

#### Finding SEC-02: Screen Anonymous Access (High)
- **Description:** Multiple End-User screens have the `Anonymous` role checked in module configuration.
- **Impact:** Unauthenticated web traffic can view sensitive operational dashboards.
- **Affected Screens:** `FinancialOverview_UI`, `UserManagement_Admin`
- **Recommendation:** Uncheck `Anonymous` and enforce mandatory authentication roles.

---

### 2. Integration & Endpoint Security

#### Finding SEC-03: Unsecured REST API Endpoints (Critical)
- **Description:** Consumed and exposed REST API endpoints lack proper TLS/SSL enforcement and authentication headers.
- **Impact:** Risk of Man-In-The-Middle (MITM) attacks and data leakage.
- **Affected Endpoints:** `POST /rest/v1/PaymentGateway`, `GET /rest/v1/UserData`
- **Recommendation:** Require OAuth2/Bearer Tokens and force HTTPS across all environment endpoints.

#### Finding SEC-04: Hardcoded Secrets in Site Properties (High)
- **Description:** API keys and connection strings stored as plain-text site properties.
- **Impact:** Credential leaks through module exports or unauthorized back-office access.
- **Affected Elements:** `Site.ThirdPartyAPIKey`, `Site.DatabasePass`
- **Recommendation:** Move credentials to environment variables or dedicated Key Vault solutions.

---

### 3. Data Protection & Vulnerability Mitigation

#### Finding SEC-05: SQL Injection Risk in Advanced Queries (Medium)
- **Description:** Advanced SQL queries utilizing unescaped input parameters with `Expand Inline = Yes`.
- **Impact:** Potential SQL injection if parameters are not properly sanitized using `EncodeSql()`.
- **Affected Actions:** `FetchFilteredLogs`, `ExecuteDynamicSearch`
- **Recommendation:** Replace inline parameters with standard Aggregates or wrap inputs with `SanitizeSql()`.

#### Finding SEC-06: Unmasked Sensitive Data in ViewState (Medium)
- **Description:** Sensitive fields (SSN, credit card details) stored in screen variables passed via ViewState.
- **Impact:** Exposure of Personal Identifiable Information (PII) to client-side inspect tools.
- **Affected Components:** `CustomerRegistration_Form`
- **Recommendation:** Fetch sensitive fields on-demand inside Server Actions rather than storing them in screen variables.

---

## Action Plan & Remediation Roadmap

```
+-----------------------------------------------------------------------------------+
|  PHASE 1: Immediate Containment (Days 1 - 7)                                     |
|  - Restrict Public Server Actions & enforce Role Validation                       |
|  - Remove Anonymous access from internal screens                                   |
|  - Rotate hardcoded secrets & migrate to secure Vaults                           |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|  PHASE 2: API & Data Governance (Days 8 - 30)                                    |
|  - Enforce OAuth2 / API Tokens on all exposed REST Services                       |
|  - Remediate SQL inline parameters using standard Aggregates                      |
|  - Sanitize ViewState & clear PII from screen buffers                             |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|  PHASE 3: Continuous Monitoring & Automation (Days 31+)                          |
|  - Integrate automated security scans into OutSystems CI/CD pipelines             |
|  - Conduct quarterly architecture & security reviews                              |
+-----------------------------------------------------------------------------------+
```

---

## Conclusion & Next Steps

Addressing the identified critical vulnerabilities will significantly harden the OutSystems factory against unauthorized access and data breach risks. Immediate priority should be given to **SEC-01** and **SEC-03**.

For further clarification or assistance with remediation, please contact the **Security & Architecture Governance Team**.