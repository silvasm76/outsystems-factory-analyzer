"""Render the assessment reports from output/findings/*.json (+ index.json) into output/*.html.

  security        -> output/Security_Assessment_Report.html
  maintainability -> output/Maintainability_Report.html
  performance     -> output/Performance_Report.html

Each report starts with the executive summary in output/narrative/<report>.html when present (written from the
findings, see prompts/NARRATIVE.md); otherwise a factual summary is generated from the counts.

Usage: python scripts/generate_reports.py [security ...]   (default: all available)
"""
import os
import re
import sys
from collections import Counter, defaultdict

from report_html import (SEV_CLASS, badge, code_link, esc, filters, kpis, load_json, narrative, page, sev_badge,
                         table)

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(HERE, "..", "output")
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
BAR_COLOR = {"Critical": "var(--crit)", "High": "var(--high)", "Medium": "var(--med)", "Low": "var(--low)", "Info": "var(--info)"}


def rule_titles(module_file):
    """Rule id -> description, read from the check's docstring (single source of truth)."""
    with open(module_file, encoding="utf-8") as fh:
        doc = fh.read().split('"""')[1]
    return dict(re.findall(r"^\s+(\w+-\d+)\s+(.+)$", doc, re.M))


def rating(counts):
    if counts["Critical"]:
        return "Critical risk", "crit"
    if counts["High"]:
        return "High risk", "high"
    if counts["Medium"]:
        return "Moderate risk", "med"
    return "Low risk", "low"


def severity_matrix(findings, key, label):
    by = defaultdict(Counter)
    for f in findings:
        by[f[key]][f["severity"]] += 1
    rows, attrs = [], []
    for k, c in sorted(by.items(), key=lambda kv: [-kv[1][s] for s in SEVERITIES]):
        total = sum(c.values())
        worst = next(s for s in SEVERITIES if c[s])
        rows.append([esc(k)] + ['<span data-sort="%d">%s</span>' % (c[s], c[s] or "") for s in SEVERITIES]
                    + [str(total), sev_badge(worst)])
        attrs.append({})
    return table([label] + SEVERITIES + ["Total", "Worst"], rows, numeric=(1, 2, 3, 4, 5, 6))


def grouped_cards(findings, titles, severities=("Critical", "High")):
    """One card per rule for the given severities, listing every affected element."""
    out = []
    by_rule = defaultdict(list)
    for f in findings:
        if f["severity"] in severities:
            by_rule[f["rule"]].append(f)
    for rule, fs in sorted(by_rule.items(), key=lambda kv: (SEVERITIES.index(kv[1][0]["severity"]), -len(kv[1]))):
        worst = fs[0]["severity"]
        items = "".join("<li>%s <b>%s</b> · <code>%s</code><br><span class=\"mut\">%s</span>%s</li>" % (
            sev_badge(f["severity"]), esc(f["module"]), esc(f["element"]), esc(f["evidence"]),
            (" · " + code_link(f["file"])) if f.get("file") else "") for f in fs)
        out.append('<div class="card %s"><h4>%s %s · %s <span class="mut">(%d)</span></h4>'
                   '<dl><dt>Category</dt><dd>%s</dd><dt>Recommendation</dt><dd>%s</dd><dt>Affected</dt><dd><ul>%s</ul></dd></dl></div>'
                   % (SEV_CLASS[worst], sev_badge(worst), esc(rule), esc(titles.get(rule, fs[0]["title"])), len(fs),
                      esc(fs[0]["category"]), esc(fs[0]["recommendation"]), items))
    return "".join(out) or "<p>No %s findings.</p>" % " or ".join(s.lower() for s in severities)


def findings_table(findings, tid):
    rows, attrs = [], []
    for f in findings:
        rows.append(['<span data-sort="%d">%s</span>' % (SEVERITIES.index(f["severity"]), sev_badge(f["severity"])),
                     esc(f["rule"]), esc(f["title"]), esc(f["module"]), "<code>%s</code>" % esc(f["element"]),
                     esc(f["evidence"]), code_link(f.get("file"))])
        attrs.append({"severity": f["severity"], "rule": f["rule"], "module": f["module"]})
    sel = [("severity", "Severity", [s for s in SEVERITIES if any(f["severity"] == s for f in findings)]),
           ("rule", "Rule", sorted({f["rule"] for f in findings})), ("module", "Module", sorted({f["module"] for f in findings}))]
    return filters(tid, sel) + table(["Sev", "Rule", "Finding", "Module", "Element", "Evidence", "Pseudocode"], rows, tid,
                                     row_attrs=attrs)


def security_report(output=OUTPUT):
    data = load_json(os.path.join(output, "findings", "security.json"))
    idx = load_json(os.path.join(output, "index.json"))
    findings, inv = data["findings"], data.get("inventory", {})
    titles = rule_titles(os.path.join(HERE, "checks", "security.py"))
    counts = Counter(f["severity"] for f in findings)
    counts = {s: counts.get(s, 0) for s in SEVERITIES}
    label, cls = rating(counts)
    exposed = inv.get("restExposed", [])
    unauth = [s for s in exposed if s["authentication"] == "None"]

    summary = narrative("security", output) or (
        '<p class="lead">Static review of %d modules. Overall rating: <b>%s</b> — %d critical and %d high findings. '
        '%d of %d exposed REST APIs have no authentication.</p>' % (
            len(idx["modules"]), label, counts["Critical"], counts["High"], len(unauth), len(exposed)))

    k = kpis([(label, "Overall rating", "%d findings in %d modules" % (len(findings), len({f["module"] for f in findings})), cls)]
             + [(counts[s], s, "", SEV_CLASS[s]) for s in SEVERITIES]
             + [("%d / %d" % (len(unauth), len(exposed)), "Exposed APIs without auth", "REST services", "high" if unauth else "")])

    exp_rows = [[esc(s["module"]), esc(s["service"]), "<code>%s</code>" % esc(s["url"]),
                 badge(s["authentication"], "no" if s["authentication"] == "None" else "ok"),
                 badge("HTTPS" if s["https"] else "HTTP", "ok" if s["https"] else "no"),
                 "Yes" if s["internalOnly"] else "No", esc(", ".join(s["methods"]))] for s in exposed]
    con_rows = [[esc(s["module"]), esc(s["service"]), "<code>%s</code>" % esc(s["baseUrl"]), str(s["methods"])]
                for s in inv.get("restConsumed", [])]
    rule_rows = [[esc(r), esc(t), str(sum(1 for f in findings if f["rule"] == r))] for r, t in titles.items()]

    body = """
<section id="summary"><h2>1. Executive summary</h2><div class="narr">%s</div></section>
%s
<section id="profile"><h2>2. Risk profile</h2>
<h3>2.1 By category (OWASP Top 10 2021)</h3>%s
<h3>2.2 By module</h3>%s</section>
<section id="priority"><h2>3. Critical and high findings</h2>
<p class="mut">Grouped by rule; each entry links to the pseudocode of the affected flow under <code>output/code</code>.</p>%s</section>
<section id="all"><h2>4. All findings (%d)</h2>%s</section>
<section id="apis"><h2>5. API and integration inventory</h2>
<h3>5.1 Exposed REST APIs (%d)</h3>%s
<h3>5.2 Consumed REST integrations (%d)</h3>%s</section>
<section id="method"><h2>6. Method and limitations</h2>
<p>Findings come from deterministic rules over the module exports (<code>scripts/checks/security.py</code>); the same input always
gives the same findings. Secrets are masked in this report. Rules:</p>%s
<p class="mut">Limitations: static analysis only — no runtime configuration (Service Center effective URLs, site property values set per
environment, IP restrictions, Users app settings) and no traffic. Roles are checked at screen level; role checks inside server actions
are not yet evaluated. Reachability ("reachable from") follows calls up to 4 levels.</p></section>
""" % (summary, k, severity_matrix(findings, "category", "Category"), severity_matrix(findings, "module", "Module"),
       grouped_cards(findings, titles), len(findings), findings_table(findings, "allf"),
       len(exposed), table(["Module", "Service", "URL", "Authentication", "Transport", "Internal only", "Methods"], exp_rows),
       len(con_rows), table(["Module", "Service", "Base URL", "Methods"], con_rows, numeric=(3,)),
       table(["Rule", "Checks for", "Findings"], rule_rows, numeric=(2,)))
    nav = [("summary", "Summary"), ("profile", "Risk profile"), ("priority", "Critical & high"), ("all", "All findings"),
           ("apis", "APIs"), ("method", "Method")]
    html = page("Security Assessment", "OutSystems factory · %d modules" % len(idx["modules"]), nav, body,
                "Generated by scripts/generate_reports.py from output/findings/security.json")
    path = os.path.join(output, "Security_Assessment_Report.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print("Wrote %s (%d findings)" % (os.path.abspath(path), len(findings)), flush=True)


GRADE_CLASS = {"A": "ok", "B": "low", "C": "med", "D": "high", "E": "crit"}


def maintainability_report(output=OUTPUT):
    data = load_json(os.path.join(output, "findings", "maintainability.json"))
    findings, mods = data["findings"], data["modules"]
    titles = rule_titles(os.path.join(HERE, "checks", "maintainability.py"))
    counts = Counter(f["severity"] for f in findings)
    total_flows = sum(m["flows"] for m in mods.values()) or 1
    factory = round(sum(m["score"] * max(m["flows"], 1) for m in mods.values()) / sum(max(m["flows"], 1) for m in mods.values()))
    fgrade = "A" if factory >= 85 else "B" if factory >= 70 else "C" if factory >= 55 else "D" if factory >= 40 else "E"
    grades = Counter(m["grade"] for m in mods.values())
    complex_flows = sum(m["complexFlows"] for m in mods.values())
    documented = round(sum(m["documented"] * max(m["flows"], 1) for m in mods.values()) / sum(max(m["flows"], 1) for m in mods.values()))
    unused = sum(m["unused"] for m in mods.values())
    unresolved = sum(m["unresolved"] for m in mods.values())
    timers = sum(1 for f in findings if f["rule"] == "MNT-07" and f["severity"] in ("High", "Medium"))

    summary = narrative("maintainability", output) or (
        '<p class="lead">Factory maintainability score <b>%d/100 (grade %s)</b> over %d modules and %d logic flows. '
        '%d high and %d medium findings.</p>' % (factory, fgrade, len(mods), total_flows, counts["High"], counts["Medium"]))
    k = kpis([("%d · %s" % (factory, fgrade), "Factory score", "flow-weighted average of module scores",
               SEV_CLASS.get({"A": "Info", "B": "Low", "C": "Medium", "D": "High", "E": "Critical"}[fgrade])),
              (" ".join("%s:%d" % (g, grades.get(g, 0)) for g in "ABCDE"), "Modules by grade", "", ""),
              (complex_flows, "Complex flows", "cyclomatic complexity ≥ 10", "med"),
              ("%d%%" % documented, "Documented", "module, public actions, entities, attributes", "low"),
              (unused, "Unused actions", "no caller in the factory", "med"),
              (unresolved, "Broken references", "unresolved elements", "high" if unresolved else ""),
              (timers, "Fragile timers", "timeout / resume / error handling", "high" if timers else "")])

    rows, attrs = [], []
    for name, m in sorted(mods.items(), key=lambda kv: kv[1]["score"]):
        rows.append([esc(name), esc(m["layer"]), badge(m["grade"], GRADE_CLASS[m["grade"]]),
                     '<div class="bar" data-sort="%d"><i style="width:%d%%;background:%s"></i><span>%d</span></div>' % (
                         m["score"], m["score"], "var(--%s)" % ("low" if m["score"] >= 70 else "med" if m["score"] >= 55 else "high"), m["score"]),
                     str(m["flows"]), str(m["avgCC"]), str(m["maxCC"]), str(m["complexFlows"]), "%d%%" % m["documented"],
                     str(m["unused"]), str(m["unresolved"]), str(m["duplicated"]), str(m["timerIssues"])])
        attrs.append({"layer": m["layer"], "grade": m["grade"]})
    scorecard = filters("mods", [("layer", "Layer", sorted({m["layer"] for m in mods.values()})),
                                 ("grade", "Grade", list("ABCDE"))]) + table(
        ["Module", "Layer", "Grade", "Score", "Flows", "Avg CC", "Max CC", "Complex", "Documented", "Unused", "Broken refs",
         "Duplicated", "Timer issues"], rows, "mods", numeric=tuple(range(4, 13)), row_attrs=attrs)

    hot = sorted((f for f in findings if f["rule"] == "MNT-01"),
                 key=lambda f: -int(re.search(r"complexity (\d+)", f["evidence"]).group(1)))[:20]
    hot_rows = [[sev_badge(f["severity"]), esc(f["module"]), "<code>%s</code>" % esc(f["element"]), esc(f["evidence"]),
                 code_link(f.get("file"))] for f in hot]
    rule_rows = [[esc(r), esc(t), str(sum(1 for f in findings if f["rule"] == r))] for r, t in titles.items()]

    body = """
<section id="summary"><h2>1. Executive summary</h2><div class="narr">%s</div></section>
%s
<section id="scorecard"><h2>2. Module scorecard</h2>
<p class="mut">Worst first. Score 0–100 per module; see the method section for the formula.</p>%s</section>
<section id="hotspots"><h2>3. Complexity hotspots</h2><p class="mut">The 20 most complex flows (cyclomatic complexity).</p>%s</section>
<section id="priority"><h2>4. High and medium findings</h2>%s</section>
<section id="all"><h2>5. All findings (%d)</h2>%s</section>
<section id="method"><h2>6. Method and limitations</h2>
<p>Rules follow Indigo's OutSystems 11 guidelines (naming, descriptions, small flows, timers, static entities, reuse) and run on the
module exports (<code>scripts/checks/maintainability.py</code>). Rules:</p>%s
<p><b>Module score</b> = 100 minus: documentation gaps (up to 25, by share undocumented), complex flows (up to 20, share with
complexity ≥ 10), unused actions (up to 15), broken references (up to 15, one point each), duplicated flows (up to 10),
fragile timers (5 each, up to 10), flows with disconnected nodes (1 each, up to 5). Grades: A ≥ 85, B ≥ 70, C ≥ 55, D ≥ 40, E &lt; 40.
The factory score is the average weighted by the number of flows.</p>
<p class="mut">Limitations: "unused" only knows the modules in this export, so public actions may still be used by other
applications. Timer checks look at the timer's own action, not the actions it calls. Cyclomatic complexity counts
If (plus and/or), Switch cases, For Each and exception handlers. Widget-level rules (inline styles, ExtendedClass) are not
covered yet.</p></section>
""" % (summary, k, scorecard, table(["Sev", "Module", "Flow", "Evidence", "Pseudocode"], hot_rows),
       grouped_cards(findings, titles, ("High", "Medium")), len(findings), findings_table(findings, "allf"),
       table(["Rule", "Checks for", "Findings"], rule_rows, numeric=(2,)))
    nav = [("summary", "Summary"), ("scorecard", "Scorecard"), ("hotspots", "Hotspots"), ("priority", "High & medium"),
           ("all", "All findings"), ("method", "Method")]
    html = page("Maintainability Analysis", "OutSystems factory · %d modules" % len(mods), nav, body,
                "Generated by scripts/generate_reports.py from output/findings/maintainability.json")
    path = os.path.join(output, "Maintainability_Report.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print("Wrote %s (%d findings)" % (os.path.abspath(path), len(findings)), flush=True)


def performance_report(output=OUTPUT):
    data = load_json(os.path.join(output, "findings", "performance.json"))
    idx = load_json(os.path.join(output, "index.json"))
    findings = data["findings"]
    titles = rule_titles(os.path.join(HERE, "checks", "performance.py"))
    by_rule = defaultdict(list)
    for f in findings:
        by_rule[f["rule"]].append(f)
    counts = Counter(f["severity"] for f in findings)
    n1_high = sum(1 for f in by_rule["PRF-01"] if f["severity"] == "High")

    summary = narrative("performance", output) or (
        '<p class="lead">%d performance findings in %d modules: %d high, %d medium. %d flows run queries or server calls inside '
        'loops and %d attributes are filtered or joined without an index.</p>' % (
            len(findings), len({f["module"] for f in findings}), counts["High"], counts["Medium"], len(by_rule["PRF-01"]),
            len(by_rule["PRF-02"])))
    k = kpis([(len(by_rule["PRF-01"]), "Queries in loops", "%d high (query or server call per iteration)" % n1_high, "high"),
              (len(by_rule["PRF-02"]), "Missing indexes", "%d used in 6+ flows" % sum(f["severity"] == "High" for f in by_rule["PRF-02"]), "high"),
              (len(by_rule["PRF-03"]), "Heavy client queries", "Max Records ≥ 1000 or unbounded", "med"),
              (len(by_rule["PRF-06"]), "Broken Left Joins", "Where turns them into Inner Joins", "med"),
              (len(by_rule["PRF-05"]), "Unused joins", "grouped aggregates", "low"),
              (len(by_rule["PRF-07"]), "Binary in main entity", "", "med")])

    def num_flows(f):
        m = re.search(r"in (\d+) flow", f["evidence"])
        return int(m.group(1)) if m else 0
    idx_rows, idx_attrs = [], []
    for f in sorted(by_rule["PRF-02"], key=lambda f: -num_flows(f)):
        ent, attr = f["element"].split(" ", 1)[1].rsplit(".", 1)
        uses = re.search(r"used to (\S+)", f["evidence"]).group(1)
        idx_rows.append([sev_badge(f["severity"]), esc(f["module"]), esc(ent), "<b>%s</b>" % esc(attr), esc(uses.replace("/", ", ")),
                         str(num_flows(f)), '<span class="mut">%s</span>' % esc(f["evidence"].split(": ", 1)[-1])])
        idx_attrs.append({"severity": f["severity"], "module": f["module"]})
    index_tbl = filters("idx", [("severity", "Severity", ["High", "Medium", "Low"]),
                                ("module", "Module", sorted({f["module"] for f in by_rule["PRF-02"]}))]) + table(
        ["Sev", "Module", "Entity", "Attribute", "Used to", "Flows", "Where"], idx_rows, "idx", numeric=(5,), row_attrs=idx_attrs)

    n1 = sorted(by_rule["PRF-01"], key=lambda f: SEVERITIES.index(f["severity"]))
    n1_rows = [[sev_badge(f["severity"]), esc(f["module"]), "<code>%s</code>" % esc(f["element"]), esc(f["evidence"]),
                code_link(f.get("file"))] for f in n1]
    rule_rows = [[esc(r), esc(t), str(len(by_rule.get(r, [])))] for r, t in titles.items()]

    body = """
<section id="summary"><h2>1. Executive summary</h2><div class="narr">%s</div></section>
%s
<section id="indexes"><h2>2. Index recommendations (%d)</h2>
<p class="mut">Attributes used to filter, join or sort, on entities with no index starting with that attribute. Boolean flags and
static entities are excluded. Sorted by the number of flows that use them: the top of the list is where an index pays off most.
Check table sizes and query plans before creating them.</p>%s</section>
<section id="loops"><h2>3. Queries and server calls inside loops (%d)</h2>%s</section>
<section id="bymodule"><h2>4. Findings by module</h2>%s</section>
<section id="all"><h2>5. All findings (%d)</h2>%s</section>
<section id="method"><h2>6. Method and limitations</h2>
<p>Rules run on the module exports (<code>scripts/checks/performance.py</code>) and follow Indigo's OS11 guidelines (no queries in
loops, indexes on filtered attributes, pagination, no broken left joins, binaries out of main entities). Rules:</p>%s
<p class="mut">Limitations: no data volumes or execution statistics, so severities reflect how widely a pattern is used, not measured
time. A query "in a loop" is found in the flow itself and in the actions it calls one level down. Advanced SQL is parsed for
attributes written as <code>{Entity}.[Attribute]</code>; columns referenced through table aliases are not seen.</p></section>
""" % (summary, k, len(idx_rows), index_tbl, len(n1_rows),
       table(["Sev", "Module", "Flow", "What runs per iteration", "Pseudocode"], n1_rows),
       severity_matrix(findings, "module", "Module"), len(findings), findings_table(findings, "allf"),
       table(["Rule", "Checks for", "Findings"], rule_rows, numeric=(2,)))
    nav = [("summary", "Summary"), ("indexes", "Indexes"), ("loops", "Loops"), ("bymodule", "By module"),
           ("all", "All findings"), ("method", "Method")]
    html = page("Performance Assessment", "OutSystems factory · %d modules" % len(idx["modules"]), nav, body,
                "Generated by scripts/generate_reports.py from output/findings/performance.json")
    path = os.path.join(output, "Performance_Report.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print("Wrote %s (%d findings)" % (os.path.abspath(path), len(findings)), flush=True)


REPORTS = {"security": security_report, "maintainability": maintainability_report, "performance": performance_report}

if __name__ == "__main__":
    for name in (sys.argv[1:] or list(REPORTS)):
        REPORTS[name]()
