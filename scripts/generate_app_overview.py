"""Render output/Application_Overview_Report.html (business/application overview).

Reads the extracted model (output/model/*.json) and the index (output/index.json); run extract_model.py and
build_index.py first (run_pipeline.py does). Module purposes, domains and applications below are curated text
(inferred from names, descriptions, screens, entities and services); every count, screen, entity, service and
dependency comes from the model. A module with no curated entry falls back to its XML description.
"""
import html
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import date

from layers import CORE, END_USER, FOUNDATION
from build_index import load_models
from report_html import narrative

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(HERE, "..", "output")
OUT = os.path.join(OUTPUT, "Application_Overview_Report.html")
esc = lambda s: html.escape(str(s), quote=True)  # noqa: E731
TEMPLATE_ACTIONS = {"TriggerOfflineDataSync", "OfflineDataSync", "OfflineDataSyncConfiguration", "ServerDataSync"}

PEOPLE, TIME, ALLOC, FIN, REC, TRAIN, MOM, PLAT, INTEG, EMAIL = (
    "People & HR", "Time & Leaves", "Allocation & Projects", "Finance & Benefits", "Recruitment",
    "Training & Certification", "Project Moments", "Platform & Shared", "Integration", "Notifications")
DOMAIN_NOTE = {
    PEOPLE: "Employee records, onboarding, CVs, skills, kudos/badges, access control.",
    TIME: "Timesheets, activity approval, leave and vacation requests, holidays.",
    ALLOC: "Assigning people to projects, global/project allocation views, customers and projects.",
    FIN: "Invoicing and payment of approved timesheet activity, finance dashboards, employee benefits.",
    REC: "Public job applications, candidate pipeline, interviews, hiring into an employee record.",
    TRAIN: "Certification requests, vouchers and approval flow.",
    MOM: "Project “moments” and “spotlights” (project highlights) with comments, owners and e-mail notifications.",
    PLAT: "Themes, layouts, shared widgets, utility libraries, cross-cutting services.",
    INTEG: "Connectors to external systems (logging, Microsoft login/Graph, smart locks, public holidays, SUNO).",
    EMAIL: "Transactional e-mails and scheduled alerts.",
}

# module -> (domain, purpose, key business features)
M = {
 "ERP_UI": (PEOPLE, "Main end-user web application of ERP Indigo: the screens employees, managers and admins use every day.",
            "Employee, customer, project, business-unit and job-position management; timesheets and activity lists; leave and benefit self-service; registration/onboarding and password flows; admin dashboard."),
 "ProERP": (PEOPLE, "Newer ‘ProERP’ front-end that re-implements and extends the ERP UI as a single Reactive app with a homepage and dashboards.",
            "Dashboard and homepage, My Profile, Employees, Timesheets and activity approval, vacations/leaves approval and company leave table, allocations, finance dashboard, invoices and payments, hours overview (forecast/historical), certification voucher requests and management, forms and resources."),
 "ERP_UI_FIN": (FIN, "Admin-only finance front-end (restricted audience).", "Timesheet-activities list for finance administrators."),
 "ProERP_BackOffice": (PEOPLE, "Back-office application for administrators of the ProERP platform.",
                       "Manage resources and resource tags, roles management, sub-skill catalogue and proposed sub-skills, holiday management, timesheet generation, leaves back-office."),
 "Allocation_UI": (ALLOC, "End-user app dedicated to resource allocation planning.",
                   "Global allocations, allocations by end date, my-projects allocations, project allocation detail, calendar views, export of allocations, email requests to admins."),
 "Recruitment_UI": (REC, "Internal recruitment application for HR/recruiters.",
                    "Candidate list and candidate file (also PDF), applications, interviews list, job offers/users, skills."),
 "DocumentTemplate_BO": (PEOPLE, "Back-office to maintain employee document templates.", "List and detail screens for document templates used to generate employee documents."),
 "ProERP_ProjectMoments": (MOM, "Main UI of the Project Moments app.", "Project moments list and detail, moment spotlights and spotlight detail, token-based sign-in."),
 "ProERP_Project_Moments_BackOffice": (MOM, "Back office for the Moments app.", "Spotlight-type administration."),
 "ERP_CS": (PEOPLE, "Central core data module of the whole ERP: owns the shared domain model (employees, projects, customers, allocations, leave) and its CRUD services.",
            "Employee, resource, project, customer, business-unit, allocation, leave allocation/period/day, holidays, document templates, onboarding checklist, tokens, audit tables, system locks, chat, photos; public create/update/delete actions and an EmployeePhoto REST endpoint."),
 "Timesheet_CS": (TIME, "Core data and rules for timesheets.", "Timesheet, timesheet activity and activity-day entities; expected hours, holiday hour filling, admin status, payment undo, audit of rejections."),
 "Benefit_CS": (FIN, "Core data and rules for employee benefits.", "Benefits, monthly benefit summaries, recurring benefits, KM entries, benefit types/status; monthly processing and comparison/audit actions; REST delete endpoint."),
 "Curriculum_CS": (PEOPLE, "Core data for employee CVs and skills.", "CV, CV items, academic education, professional experience, certifications, skills and proficiency levels, CV profiles."),
 "Badges_CS": (PEOPLE, "Core data for the badges/kudos recognition feature.", "Badge, badge icon, badge type and employee badge entities with create/update/delete services."),
 "Recruitment_CS": (REC, "Core data and rules for recruitment.", "Candidates, job offers, applications, interviews, attachments, education, skills, hiring (candidate → employee), notifications of closing offers."),
 "Training_CS": (TRAIN, "Core data for training and certification.", "Certification vouchers, employee certification processes, file processing, approval types and statuses."),
 "ProERP_ProjectMoments_CS": (MOM, "Core data model for Project Moments.", "Moments, spotlights, comments, statuses/types, large-text and binary extensions, plus CRUD actions."),
 "Leave_CS": (TIME, "Legacy leave/vacation queries (leave allocation, vacations of previous years, holidays). Declares no entities, references no factory module and is consumed by none — likely superseded by Timeflow_BL and ERP_CS.", "Leave allocation and vacation lookups, login/logout and sync boilerplate."),
 "ERP_BL": (PEOPLE, "Largest business-logic module: cross-domain rules, audit logging and role handling for the ERP.",
            "Audit-logged create/update/delete for employees, allocations, benefits, accounts and contacts; benefit limit checks (KM, max amount); month closing; role grants/checks; curriculum creation; candidate-to-employee invitations; Excel export/consult; client time-zone handling."),
 "ProERP_BL": (PEOPLE, "Business logic of ProERP: resources, tags, annual leave allocation, tokens and office-door control.",
               "Resource and tag handling with logs, annual leave allocation, vacation/leave scheduling, token creation/extension, redirect URL generation, enable/disable employees, door access grant/revoke."),
 "Timeflow_BL": (TIME, "Business logic for timesheet activity and leave workflows, including payment.",
                 "Leave request/approval/rejection and allocation, leave documents, timesheet activity status changes and payment, company leaves table, holiday calculations by country, Excel exports of hours and leaves."),
 "Timesheet_BL": (TIME, "Small timesheet rules module.", "Check if a period has hours, approve activity status, related-allocation saving, deletion of leave-related records."),
 "Project_BL": (ALLOC, "Business logic for allocations and projects.", "Allocation create/update/delete with logging, global-allocation role checks, exports of global/my/other allocations, job-position and business-unit lookups, Luxembourg privilege-leave timer."),
 "People_BL": (PEOPLE, "Business logic for employee profile, skills and group roles.", "Job position lookup, employee Excel exports (all/registered/not registered), skill and sub-skill suggestion approve/reject, group role grant/revoke, profile and allocation URLs."),
 "Badges_BL": (PEOPLE, "Business logic of the badges feature.", "Employee badge notifications and badge/icon create-or-update."),
 "Training_BL": (TRAIN, "Business logic of training/certification requests.", "Request, approve, reject and cancel certification requests; assign/save/delete vouchers; import and export voucher/request data."),
 "ProERP_ProjectMoments_BL": (MOM, "Business rules for Project Moments.", "Moment and spotlight creation, status change, ownership assignment, comments, deliverables, permissions per user."),
 "ERP_CW": (PEOPLE, "Core widgets (reusable UI blocks and layouts) for the ERP front-ends.",
            "Layouts (side/top menu), employee profile tabs (general info, CV, benefits, leaves, allocations), onboarding checklist, new-employee form, KM entries, kudos blocks, document template detail, timesheet creation by admin."),
 "People_CW": (PEOPLE, "Core widgets for the employee/profile area.", "Profile header and tabs (general info, CV, kudos, onboarding), skills and sub-skills tables/approvals, office-door controller, forms and resources card."),
 "Timeflow_CW": (TIME, "Largest widget library: time, leave and finance dashboards.",
                 "Activity timesheet lists, all timesheets, leave allocation tables and scheduling, company leave table, hours overview (forecast/historical), control, finance and invoiced-projects dashboards, conflict warnings between leave and timesheets."),
 "Leaves_CW": (TIME, "Core widgets for leaves and vacations.", "Leave overview and my-leaves tables, period create/edit, leave allocation detail, schedule leave by admin, privilege leave, chat messages on leave requests, leave layouts."),
 "Finance_CW": (FIN, "Core widgets for finance.", "Invoicing and payment project tables, dashboard counters/cards, pending-validation and ready-to-invoice dashboards, payment status chart, timesheet approval detail, Excel export."),
 "Project_CW": (ALLOC, "Core widgets for projects/allocations.", "Projects list and allocation widgets."),
 "Recruitment_CW": (REC, "Core widgets for recruitment and the public application form.", "Application form (name/phone/e-mail, education, languages, programming languages, OutSystems certifications), interview create/edit, keyword search, phone/e-mail validation, layouts and menu."),
 "Training_CW": (TRAIN, "Core widgets for training.", "Certification request and voucher list/detail blocks, vouchers-to-assign."),
 "ProERP_ProjectMoments_CW": (MOM, "Core widgets for Project Moments.", "Moment and spotlight forms, lists, detail, comments, deliverables, owner assignment, history log, status tags."),
 "ERP_Th": (PLAT, "Theme, menus and layouts of ERP Indigo, and the role catalogue of the ERP.", "Layouts and menus, app-name/toggle links to ProERP, UserData service; roles such as Employee, Administrator, LeaveAdministrator, TeamCaptain, BenefitApprover, BenefitProcessor, Recruitment_Manager."),
 "ProERP_Th": (PLAT, "Theme and sign-in experience of ProERP, plus its role catalogue.", "Login, logout, link-expired, invalid-permission and unavailable screens; roles such as Resources_Editor, Operations, Training_Editor, Roles_Manager, Department_ManagePeople."),
 "ProERPProject_Moments_Th": (PLAT, "Theme for the Project Moments app.", "App theme/layout only."),
 "ProERP_CommonWidgets": (PLAT, "Shared UI widget library for ProERP screens.", "Calendar, date picker, multi-select/server-search dropdowns, confirmation and feedback popups, tags, empty state, expandable rows, monthly-hours and activity cards."),
 "Training": (TRAIN, "Application shell for training (HomeScreen only); it declares no references to other factory modules. Its description is copied from Training_CW.", "Home screen and offline-sync boilerplate."),
 "ERP_API": (INTEG, "REST API exposed by the ERP to other systems.", "Authentication, data retrieval (RetrieveData), allocation list/versions."),
 "ProERP_API": (INTEG, "REST API of ProERP.", "Employees listing endpoint."),
 "ERP_Sync": (INTEG, "Scheduled synchronisation jobs of the ERP.", "Missing-timesheet detection, allocation status updates, role-to-employee sync, allocations-ending e-mails."),
 "Training_Bootstraps": (TRAIN, "Bootstrap/data-import validation for training.", "Bootstrap of certification vouchers and validation of employees, certifications and vouchers."),
 "ERPIndigo_Email": (EMAIL, "All e-mails sent by ERP Indigo (and the recruitment mailbox REST service).",
                     "Timesheet-not-submitted and submission warnings, leave/vacation alerts, birthdays, invitations, onboarding, password reset, allocation requests/ending alerts, candidate and job-offer e-mails."),
 "ProERPProject_MomentsEmails": (EMAIL, "E-mails of the Project Moments app.", "Moment/spotlight created, edited, owner changed and comment-added notifications."),
 "ERPForms_IS": (INTEG, "Integration with the external ‘Forms’ service (declared via REST client).", "Forms service consumption wrappers."),
 "Audit_IS": (INTEG, "Integration service writing audit/log records through the LogAPI.", "Sync and async log message/error/operation-success actions; audit entities."),
 "ProERP_IS": (INTEG, "External integrations of ProERP: NUKI smart locks, public-holiday API (DateNager) and SUNO.", "Lock/unlock office doors, door/auth/account management, EmployeeData service."),
 "ProERPProject_Moments_IS": (INTEG, "Microsoft Graph/Login integration for Project Moments.", "OAuth token retrieval against Microsoft Online / Graph."),
 "ERP_MicrosoftLoginConnectorReact": (INTEG, "Front-end component supporting OAuth 2.0 (Microsoft) authentication for Reactive apps.", "Callback page, invalid permissions, OAuth2 login/logout URL generation."),
 "ERP_Lib": (PLAT, "Utility library with non business-related logic.", "SQL encoding sort helper."),
 "ProERP_Lib": (PLAT, "Utility library for ProERP.", "List/string/filter helpers, redirects, image size and table size limits, production-environment check."),
 "URL_Lib": (PLAT, "Holds the URLs of the ERP Indigo application.", "Resolves the ERP_UI espace name for links."),
 "Users_Lib": (PLAT, "User provider library (identity for the factory).", "Provides the user provider referenced by the other modules."),
}


def chips(items, cls="chip", limit=10):
    items = [i for i in items if i]
    shown = items[:limit]
    out = "".join(f'<span class="{cls}">{esc(i)}</span>' for i in shown)
    if len(items) > limit:
        out += f'<span class="chip more">+{len(items) - limit} more</span>'
    return out or '<span class="mut">—</span>'


def uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def table(headers, rows, tid, filt=False):
    out = []
    if filt:
        out.append(f'<input class="tfilter" data-for="{tid}" placeholder="Filter…" aria-label="Filter table">')
    out.append(f'<div class="tablewrap"><table class="data" id="{tid}"><thead><tr>' +
               "".join(f"<th>{h}</th>" for h in headers) + "</tr></thead><tbody>")
    for r in rows:
        out.append("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


LAYER_CLASS = {END_USER: "eu", CORE: "core", FOUNDATION: "fnd"}
badge = lambda t, c: f'<span class="badge b-{c}">{esc(t)}</span>'  # noqa: E731


def load(output=OUTPUT):
    """Model + index -> the shapes this report uses (layers, kinds, edges with weights and consumed elements)."""
    models = load_models(os.path.join(output, "model"))
    with open(os.path.join(output, "index.json"), encoding="utf-8") as fh:
        idx = json.load(fh)
    mods = idx["modules"]
    L = {n: m["layer"] for n, m in mods.items()}
    K = {n: m["kind"] for n, m in mods.items()}
    edge_w, elems = Counter(), {}
    for c, m in mods.items():
        for t in m["references"]:
            d = models[c]["dependencies"][t]
            edge_w[(c, t)] = d["uses"]
            elems[(c, t)] = {k: set(v) for k, v in d["elements"].items()}
    external = defaultdict(set)
    for n, m in mods.items():
        for r in m["externalReferences"]:
            if r != "(System)":
                external[r].add(n)
    return models, mods, L, K, edge_w, elems, external


def facts_of(m):
    flows = [f for f in m["flows"] if f["kind"] in ("ServerAction", "ClientAction", "ServiceAPIMethod")]
    screens = [s for s in m["screens"] if s["kind"] == "Screen"]
    return {
        "screens": uniq((s.get("title") or s["name"]) for s in screens if s["name"] != "HomeScreen"),
        "n_screens": len(screens),
        "entities": [e["name"] for e in m["entities"] if not e.get("staticRecords")],
        "statics": [e["name"] for e in m["entities"] if e.get("staticRecords")],
        "actions": [f["name"] for f in flows if f.get("public") and f["name"] not in TEMPLATE_ACTIONS],
        "rest_x": [(r["name"], [x["name"] for x in r["methods"]]) for r in m.get("restExposed", [])],
        "rest_c": [r["name"] for r in m.get("restConsumed", [])],
        "rest_c_desc": [(r["name"], r.get("description") or "") for r in m.get("restConsumed", [])],
        "roles": m.get("roles", []), "timers": [t["name"] for t in m.get("timers", []) if t["action"] != "<unresolved>"], "desc": m.get("description") or "",
        "blocks": uniq(s["name"] for s in m["screens"] if s["kind"] == "Block" and s.get("public")),
    }


def build(output=OUTPUT):
    models, mods, L, K, edge_w, elems, external = load(output)
    for n in mods:  # modules added after the curation: show their own description instead of failing
        if n not in M:
            M[n] = (PLAT if L[n] == FOUNDATION else PEOPLE, models[n].get("description") or "(no curated description yet)", "—")

    facts = {n: facts_of(models[n]) for n in mods}
    n_scr = sum(f["n_screens"] for f in facts.values())
    n_ent = sum(len(f["entities"]) + len(f["statics"]) for f in facts.values())
    n_rest = sum(len(f["rest_x"]) for f in facts.values())
    n_act = sum(len(f["actions"]) for f in facts.values())
    roles = sorted({r for f in facts.values() for r in f["roles"]})
    ext_rest = sorted({r for f in facts.values() for r in f["rest_c"]})
    layers = Counter(L.values())
    by_domain = defaultdict(list)
    for n in mods:
        by_domain[M[n][0]].append(n)

    h = []
    w = h.append
    kpis = [(len(mods), "Modules", f"{layers[END_USER]} End-User · {layers[CORE]} Core · {layers[FOUNDATION]} Foundation"),
            (n_scr, "UI screens", f"{sum(1 for n in mods if facts[n]['n_screens'])} modules with screens"),
            (n_ent, "Entities", "business data tables"),
            (n_act, "Public services", "actions other modules can call"),
            (n_rest, "REST services exposed", f"{len(ext_rest)} external REST APIs consumed"),
            (len(roles), "Security roles", "defined across the factory")]
    kpi_html = "".join(f'<div class="kpi"><div class="v">{v}</div><div class="l">{esc(l)}</div><div class="s">{esc(s)}</div></div>'
                       for v, l, s in kpis)

    # ---------------- summary
    dom_rows = []
    for d in (PEOPLE, TIME, ALLOC, FIN, REC, TRAIN, MOM, EMAIL, INTEG, PLAT):
        ms = sorted(by_domain.get(d, []), key=lambda n: (["End-User", "Core Services", "Foundation"].index(L[n]), n))
        dom_rows.append([f"<b>{esc(d)}</b>", esc(DOMAIN_NOTE[d]),
                         " ".join(f'<span class="mod {LAYER_CLASS[L[n]]}">{esc(n)}</span>' for n in ms)])
    domain_tbl = table(["Business domain", "What it covers", "Modules (colour = layer)"], dom_rows, "tbl-domain")

    apps = [
        ("ERP Indigo (ERP_UI)", "Original employee portal: people, customers, projects, timesheets, leaves, benefits, registration.", ["ERP_UI", "ERP_UI_FIN"]),
        ("ProERP", "Next-generation ERP front-end with dashboards, finance, approvals and training; plus its back office.", ["ProERP", "ProERP_BackOffice"]),
        ("Allocation", "Resource allocation planning across projects and business units.", ["Allocation_UI"]),
        ("Recruitment", "Candidate pipeline and public application form.", ["Recruitment_UI"]),
        ("Project Moments", "Project highlights (moments/spotlights) with comments and notifications.", ["ProERP_ProjectMoments", "ProERP_Project_Moments_BackOffice"]),
        ("Document Templates BO", "Maintenance of employee document templates.", ["DocumentTemplate_BO"]),
        ("Training", "Certification requests and vouchers (UI lives in ProERP; shell app only).", ["Training"]),
    ]
    app_rows = []
    for name, desc, ms in apps:
        sc = sum(len(facts[x]["screens"]) for x in ms)
        deps = sorted({t for x in ms for (c, t) in edge_w if c == x})
        app_rows.append([f"<b>{esc(name)}</b>", esc(desc), " ".join(f'<span class="mod {LAYER_CLASS[L[x]]}">{esc(x)}</span>' for x in ms),
                         sc, len(deps)])
    app_tbl = table(["Application", "Purpose", "Entry modules", "Screens", "Modules it depends on"], app_rows, "tbl-apps")

    # ---------------- catalog
    order = lambda n: (["End-User", "Core Services", "Foundation"].index(L[n]), M[n][0], n)  # noqa: E731
    cat_rows, cards = [], []
    for n in sorted(mods, key=order):
        dom, purpose, feats = M[n]
        f = facts[n]
        lay = L[n]
        cat_rows.append([f"<b>{esc(n)}</b>", badge(lay, LAYER_CLASS[lay]) + " " + badge(K[n], "kind"), esc(dom), esc(purpose), esc(feats)])
        facets = []
        if f["screens"]:
            facets.append(("Screens", chips(f["screens"], limit=12)))
        if f["entities"]:
            facets.append(("Data entities", chips(f["entities"], limit=14)))
        if f["blocks"] and not f["screens"]:
            facets.append(("Reusable UI blocks", chips(f["blocks"], limit=12)))
        if f["actions"]:
            facets.append(("Public services", chips(f["actions"], limit=8)))
        if f["rest_x"]:
            facets.append(("REST exposed", chips([f"{a} ({', '.join(b[:3])})" for a, b in f["rest_x"]], "chip rest")))
        if f["rest_c"]:
            facets.append(("External APIs consumed", chips(f["rest_c"], "chip rest")))
        if f["roles"]:
            facets.append(("Roles", chips(f["roles"], limit=8)))
        if f["timers"]:
            facets.append(("Scheduled jobs", chips(f["timers"], limit=6)))
        cons = sorted({c for (c, t) in edge_w if t == n})
        facets.append(("Used by", chips(cons, limit=8) if cons else '<span class="mut">no other module</span>'))
        cards.append(
            f'<article class="card {LAYER_CLASS[lay]}" data-layer="{esc(lay)}" data-domain="{esc(dom)}">'
            f'<header><h4>{esc(n)}</h4><div>{badge(lay, LAYER_CLASS[lay])} {badge(dom, "dom")}</div></header>'
            f'<p>{esc(purpose)}</p><p class="feat"><b>Key features:</b> {esc(feats)}</p>'
            + (f'<p class="src">{esc("XML description: " + f["desc"])}</p>' if f["desc"] else "")
            + "<dl>" + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in facets) + "</dl></article>")
    cat_tbl = table(["Module", "Layer / type", "Business domain", "Functional purpose", "Key business features"], cat_rows, "tbl-catalog", True)

    # ---------------- dependencies
    app_dep_rows = []
    for name, desc, ms in apps:
        for x in ms:
            for t in sorted({t for (c, t) in edge_w if c == x}, key=lambda t: (["Core Services", "Foundation", "End-User"].index(L[t]), -edge_w[(x, t)])):
                el = elems.get((x, t), {})
                sample = uniq(sorted(el.get("blocks", set())) + sorted(el.get("actions", set())) + sorted(el.get("entities", set())) + sorted(el.get("client actions", set())))
                app_dep_rows.append([f"<b>{esc(name)}</b><br><span class='mut'>{esc(x)}</span>", f"<b>{esc(t)}</b>", badge(L[t], LAYER_CLASS[L[t]]),
                                     esc(M[t][1]), chips(sample, limit=6) if sample else '<span class="mut">structures, roles, themes, site properties</span>'])
    app_dep_tbl = table(["Application (module)", "Consumes", "Layer", "What that module provides", "Elements used (sample)"], app_dep_rows, "tbl-appdeps", True)

    mod_dep_rows = []
    for n in sorted(mods, key=order):
        outs = sorted((t for (c, t) in edge_w if c == n), key=lambda t: -edge_w[(n, t)])
        if not outs:
            mod_dep_rows.append([f"<b>{esc(n)}</b>", badge(L[n], LAYER_CLASS[L[n]]), '<span class="mut">none (self-contained)</span>', 0])
            continue
        mod_dep_rows.append([f"<b>{esc(n)}</b>", badge(L[n], LAYER_CLASS[L[n]]),
                             " ".join(f'<span class="mod {LAYER_CLASS[L[t]]}" title="{edge_w[(n, t)]} references">{esc(t)}</span>' for t in outs), len(outs)])
    mod_dep_tbl = table(["Consumer module", "Layer", "Consumes (heaviest first)", "# modules"], mod_dep_rows, "tbl-moddeps", True)

    svc_rows = []
    for t in sorted(mods, key=lambda t: -len({c for (c, x) in edge_w if x == t})):
        cs = sorted({c for (c, x) in edge_w if x == t}, key=lambda c: -edge_w[(c, t)])
        if not cs:
            continue
        svc_rows.append([f"<b>{esc(t)}</b>", badge(L[t], LAYER_CLASS[L[t]]), esc(M[t][1]), len(cs),
                         " ".join(f'<span class="mod {LAYER_CLASS[L[c]]}">{esc(c)}</span>' for c in cs[:12]) + (f' <span class="chip more">+{len(cs) - 12}</span>' if len(cs) > 12 else "")])
    svc_rows = svc_rows[:25]
    svc_tbl = table(["Shared module", "Layer", "Role", "Consumers", "Who uses it"], svc_rows, "tbl-shared")

    ext_rows = []
    for n, f in sorted(facts.items()):
        for name, desc in f["rest_c_desc"]:
            ext_rows.append([f"<b>{esc(name)}</b>", esc(n), esc(desc) or "—"])
    ext_tbl = table(["External REST API", "Consumed by", "Description"], ext_rows, "tbl-rest")
    forge = sorted(external.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    forge_tbl = table(["Platform / Forge component", "Used by (modules)", "Modules"],
                      [[esc(k), len(v), esc(", ".join(sorted(v)[:8]) + (" …" if len(v) > 8 else ""))] for k, v in forge], "tbl-forge", True)
    rest_x_rows = [[f"<b>{esc(a)}</b>", esc(n), esc(", ".join(b))] for n, f in sorted(facts.items()) for a, b in f["rest_x"]]
    rest_x_tbl = table(["REST service exposed", "Module", "Methods"], rest_x_rows, "tbl-restx")

    purpose_text = narrative("overview", output) or (
        f"The factory implements <b>ERP Indigo / ProERP</b>, Indigo’s internal enterprise-resource-planning platform. Across "
        f"{len(mods)} modules and {n_scr} screens it manages the whole employee lifecycle — <b>recruitment</b> of candidates, "
        f"<b>onboarding</b> and employee/CV/skill records — and the day-to-day operations of the company: <b>timesheets</b>, "
        f"<b>leave and vacation</b>, <b>allocation of people to projects and customers</b>, <b>invoicing and payment</b> of "
        f"approved activity, <b>employee benefits</b>, <b>training and certification vouchers</b>, kudos/badges and a "
        f"“Project Moments” highlights app. It follows the OutSystems four-layer pattern: {layers[END_USER]} End-User apps/back-offices on top, "
        f"{layers[CORE]} Core modules (data <code>_CS</code>, business logic <code>_BL</code>, widgets <code>_CW</code>, APIs, e-mails) and "
        f"{layers[FOUNDATION]} Foundation modules (themes, libraries, integrations such as Microsoft login, NUKI smart locks, public-holiday "
        f"and logging APIs). A single shared data core (<code>ERP_CS</code>) feeds almost every module; two generations of front-end "
        f"(<code>ERP_UI</code> and the newer <code>ProERP</code>) coexist on top of the same services.")

    w(f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Application &amp; Business Overview</title><style>{CSS}</style></head><body>
<header class="top"><div class="wrap"><h1>Application &amp; Business Overview</h1>
<p>ERP Indigo / ProERP factory · {len(mods)} modules analysed from OML exports · generated {date.today().isoformat()}</p>
<nav><a href="#s1">1 · Executive summary</a><a href="#s2">2 · Module &amp; feature catalog</a><a href="#s3">3 · Dependencies</a></nav></div></header>
<main class="wrap">
<section class="kpis">{kpi_html}</section>
<section id="s1"><h2>1. Executive Application Summary</h2><p class="lead">{purpose_text}</p>
<h3>1.1 Business capabilities</h3>{domain_tbl}
<h3>1.2 User-facing applications</h3>{app_tbl}
<p class="mut">Purposes are inferred from module names, XML descriptions, screens, entities and exposed services; confirm wording with the product owners.</p></section>

<section id="s2"><h2>2. Module &amp; Feature Catalog</h2>
<p>Layer follows OutSystems conventions: <b>End-User</b> = apps and back-offices people open; <b>Core</b> = data (<code>_CS</code>), business logic (<code>_BL</code>),
widgets (<code>_CW</code>), APIs, e-mail and sync modules; <b>Foundation</b> = themes, libraries and external integrations.</p>
<h3>2.1 Catalog table</h3>{cat_tbl}
<h3>2.2 Module cards</h3>
<div class="controls"><button data-f="" class="on">All</button><button data-f="End-User">End-User</button><button data-f="Core Services">Core</button><button data-f="Foundation">Foundation</button>
<input id="cardfilter" class="tfilter" placeholder="Search modules, screens, entities…" aria-label="Search cards"></div>
<div class="cards" id="cards">{''.join(cards)}</div></section>

<section id="s3"><h2>3. Inter-Application &amp; Module Dependencies</h2>
<p>Read each row as “<i>consumer</i> uses <i>producer</i>”. Dependencies are the references a module actually uses (declared-but-unused references are excluded).
{len(edge_w)} dependencies exist between the {len(mods)} modules.</p>
<h3>3.1 Applications → services they consume</h3>{app_dep_tbl}
<h3>3.2 All modules → what each one consumes</h3>{mod_dep_tbl}
<h3>3.3 Most-shared services (who consumes what)</h3>{svc_tbl}
<h3>3.4 REST services exposed</h3>{rest_x_tbl}
<h3>3.5 External systems consumed (REST)</h3>{ext_tbl}
<details><summary>3.6 Platform &amp; Forge components used ({len(forge)})</summary>{forge_tbl}</details></section>
</main><script>{JS}</script></body></html>""")
    return "".join(h)


CSS = """
:root{--bg:#f6f7fb;--card:#fff;--ink:#0f172a;--mut:#64748b;--line:#e2e8f0;--acc:#2563eb;--eu:#2563eb;--core:#16a34a;--fnd:#9333ea;--head:#0f172a}
@media (prefers-color-scheme:dark){:root{--bg:#0b1020;--card:#131a2e;--ink:#e5e7eb;--mut:#94a3b8;--line:#243049;--acc:#60a5fa;--head:#050814}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1280px;margin:0 auto;padding:0 20px}header.top{background:var(--head);color:#fff;padding:22px 0 0}header.top h1{margin:0;font-size:26px}
header.top p{margin:4px 0 14px;color:#cbd5e1}nav{display:flex;gap:4px;flex-wrap:wrap}nav a{color:#cbd5e1;text-decoration:none;padding:9px 14px;border-radius:8px 8px 0 0}nav a:hover{background:#1e293b;color:#fff}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:22px 24px;margin:22px 0}
section.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;background:none;border:0;padding:0}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}.kpi .v{font-size:30px;font-weight:700;line-height:1.1}.kpi .l{font-weight:600}.kpi .s{color:var(--mut);font-size:12px}
h2{margin:0 0 10px;font-size:21px;border-bottom:2px solid var(--line);padding-bottom:8px}h3{margin:26px 0 8px;font-size:16px}.lead{font-size:15px}
.mut{color:var(--mut)}code{background:rgba(100,116,139,.15);padding:1px 5px;border-radius:4px;font-size:12px}
.tablewrap{overflow:auto;max-height:640px;border:1px solid var(--line);border-radius:8px;margin:6px 0 10px}
table.data{border-collapse:collapse;width:100%;font-size:13px}table.data th{position:sticky;top:0;background:var(--card);text-align:left;padding:8px 10px;border-bottom:2px solid var(--line);white-space:nowrap}
table.data td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}table.data tr:hover td{background:rgba(100,116,139,.08)}
.badge{display:inline-block;padding:1px 9px;border-radius:99px;font-size:11.5px;font-weight:600;color:#fff;white-space:nowrap}
.b-eu{background:var(--eu)}.b-core{background:var(--core)}.b-fnd{background:var(--fnd)}.b-kind{background:#64748b}.b-dom{background:#0e7490}
.mod{display:inline-block;margin:1px 3px 1px 0;padding:0 8px;border-radius:6px;font-size:12px;border:1px solid;white-space:nowrap}
.mod.eu{background:rgba(37,99,235,.12);border-color:#2563eb}.mod.core{background:rgba(22,163,74,.12);border-color:#16a34a}.mod.fnd{background:rgba(147,51,234,.12);border-color:#9333ea}
.chip{display:inline-block;margin:2px 4px 2px 0;padding:0 8px;border-radius:99px;font-size:12px;background:rgba(100,116,139,.15)}.chip.rest{background:rgba(217,119,6,.2)}.chip.more{color:var(--mut);font-style:italic}
.tfilter{width:100%;max-width:340px;padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink)}
.controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:10px 0}.controls button{padding:6px 14px;border:1px solid var(--line);border-radius:99px;background:var(--card);color:var(--ink);cursor:pointer}
.controls button.on{background:var(--acc);color:#fff;border-color:var(--acc)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px}
.card{border:1px solid var(--line);border-top:4px solid var(--acc);border-radius:10px;padding:14px 16px;background:var(--bg)}
.card.eu{border-top-color:var(--eu)}.card.core{border-top-color:var(--core)}.card.fnd{border-top-color:var(--fnd)}
.card header{display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:flex-start}.card h4{margin:0;font-size:16px}
.card p{margin:8px 0}.card .src{color:var(--mut);font-size:12px}.card dl{margin:8px 0 0}.card dt{font-weight:600;font-size:12px;color:var(--mut);margin-top:8px;text-transform:uppercase;letter-spacing:.03em}.card dd{margin:2px 0 0}
details summary{cursor:pointer;color:var(--acc);margin:10px 0}@media (max-width:640px){section{padding:16px}.cards{grid-template-columns:1fr}}
"""

JS = r"""
const $$=s=>[...document.querySelectorAll(s)];
$$('.tfilter[data-for]').forEach(f=>f.addEventListener('input',()=>{const q=f.value.toLowerCase();
 [...document.getElementById(f.dataset.for).tBodies[0].rows].forEach(r=>r.hidden=q&&!r.textContent.toLowerCase().includes(q))}));
let layer='';function apply(){const q=document.getElementById('cardfilter').value.toLowerCase();
 $$('#cards .card').forEach(c=>c.hidden=(layer&&c.dataset.layer!==layer)||(q&&!c.textContent.toLowerCase().includes(q)))}
$$('.controls button').forEach(b=>b.addEventListener('click',()=>{layer=b.dataset.f;$$('.controls button').forEach(x=>x.classList.toggle('on',x===b));apply()}));
document.getElementById('cardfilter').addEventListener('input',apply);
"""

def overview_report(output=OUTPUT, out=None):
    out = out or os.path.join(output, "Application_Overview_Report.html")
    page = build(output)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(page)
    print(f"Wrote {os.path.abspath(out)} ({len(page) / 1024:.0f} KB)", flush=True)


if __name__ == "__main__":
    overview_report(out=sys.argv[1] if len(sys.argv) > 1 else None)
