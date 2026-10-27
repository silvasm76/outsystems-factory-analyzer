"""Render output/Factory_Audit_Report.html from output/factory_data.json.

Usage: python scripts/generate_report.py [factory_data.json] [report.html]
Run parse_factory.py first.
"""
import html
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import date

import analyze_factory as af
from analyze_factory import CORE, END_USER, FOUNDATION

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT_HTML = os.path.join(HERE, "..", "output", "Factory_Audit_Report.html")

esc = lambda s: html.escape(str(s), quote=True)  # noqa: E731
SEV_CLASS = {"High": "high", "Medium": "med", "Low": "low"}
LAYER_CLASS = {END_USER: "eu", CORE: "core", FOUNDATION: "fnd"}
LAYER_ORDER = [END_USER, CORE, FOUNDATION]


def badge(text, cls):
    return f'<span class="badge b-{cls}">{esc(text)}</span>'


def sev(s):
    return badge(s, SEV_CLASS[s])


def layer_badge(l):
    return badge(l, LAYER_CLASS[l])


def table(headers, rows, tid=None, filterable=False, numeric=(), cls=""):
    """rows: list of lists of already-escaped html strings (or (html, sortkey) tuples)."""
    out = []
    if filterable:
        out.append(f'<input class="tfilter" data-for="{tid}" placeholder="Filter rows…" aria-label="Filter table">')
    out.append(f'<div class="tablewrap"><table class="data {cls}"' + (f' id="{tid}"' if tid else "") + "><thead><tr>")
    for i, h in enumerate(headers):
        out.append(f'<th data-num="{1 if i in numeric else 0}" tabindex="0">{h}</th>')
    out.append("</tr></thead><tbody>")
    for r in rows:
        out.append("<tr>")
        for i, c in enumerate(r):
            key = ""
            if isinstance(c, tuple):
                c, key = c
                key = f' data-k="{esc(key)}"'
            out.append(f'<td{key}{" class=num" if i in numeric else ""}>{c}</td>')
        out.append("</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def nid(name):
    return re.sub(r"\W", "_", name)


def heat(v, med, high):
    cls = "hot" if v >= high else "warm" if v >= med else ""
    return f'<span class="heat {cls}">{v}</span>', v


def mermaid_graph(A):
    L, mods = A["layer"], sorted(A["mods"])
    lines = ["graph TD"]
    titles = {END_USER: "End-User Layer", CORE: "Core Services Layer", FOUNDATION: "Foundation Layer"}
    for lay in LAYER_ORDER:
        lines.append(f'  subgraph {LAYER_CLASS[lay].upper()}["{titles[lay]}"]')
        for n in mods:
            if L[n] == lay:
                lines.append(f'    {nid(n)}["{n}"]:::{LAYER_CLASS[lay]}')
        lines.append("  end")
    viol_i, cyc_i, edges = [], [], sorted(A["edge_w"])
    for i, (c, t) in enumerate(edges):
        lines.append(f"  {nid(c)} --> {nid(t)}")
        if (c, t) in A["viol"]:
            viol_i.append(i)
        elif (c, t) in A["cyc_edges"]:
            cyc_i.append(i)
    in_cycle = sorted({n for comp in A["comps"] for n in comp})
    if in_cycle:
        lines.append("  class " + ",".join(nid(n) for n in in_cycle) + " cyc")
    lines.append("  style EU fill:#eff6ff,stroke:#93c5fd,color:#0f172a")
    lines.append("  style CORE fill:#f0fdf4,stroke:#86efac,color:#0f172a")
    lines.append("  style FND fill:#faf5ff,stroke:#d8b4fe,color:#0f172a")
    lines.append("  classDef eu fill:#dbeafe,stroke:#2563eb,color:#0f172a")
    lines.append("  classDef core fill:#dcfce7,stroke:#16a34a,color:#0f172a")
    lines.append("  classDef fnd fill:#f3e8ff,stroke:#9333ea,color:#0f172a")
    lines.append("  classDef cyc stroke:#f59e0b,stroke-width:4px")
    lines.append("  linkStyle default stroke:#94a3b8,stroke-width:1px")
    if viol_i:
        lines.append("  linkStyle " + ",".join(map(str, viol_i)) + " stroke:#dc2626,stroke-width:3px")
    if cyc_i:
        lines.append("  linkStyle " + ",".join(map(str, cyc_i)) + " stroke:#f59e0b,stroke-width:3px,stroke-dasharray:5 3")
    return "\n".join(lines)


def build(A, data):
    mods, L, coup, K = A["mods"], A["layer"], A["coup"], A["kind"]
    edge_w, elems = A["edge_w"], A["edge_elems"]
    n_mod = len(mods)
    pub_total = sum(sum(m["public"].values()) for m in mods.values())
    risks = A["risks"]
    sev_count = Counter(r["sev"] for r in risks)
    fs = A["filter_stats"]
    soft = sorted(
        (c, t) for (c, t) in edge_w
        if L[c] == CORE and L[t] == CORE and (
            (K[c] == "CS" and K[t] in ("BL", "CW", "Email", "API")) or (K[c] == "BL" and K[t] == "CW"))
        and (c, t) not in A["viol"])

    h = []
    w = h.append

    # ------------------------------------------------------------------ KPIs
    kpis = [
        (n_mod, "Modules analysed", f"{sum(1 for v in L.values() if v == END_USER)} End-User · "
                                    f"{sum(1 for v in L.values() if v == CORE)} Core · "
                                    f"{sum(1 for v in L.values() if v == FOUNDATION)} Foundation"),
        (len(edge_w), "Module dependencies", f"{len(A['viol'])} layer violations · {len(A['cyc_edges'])} cyclic edges"),
        (A["entities_total"], "Entities", f"{A['attrs_total']} attributes · {pub_total} public elements"),
        (sev_count["High"], "High-risk unindexed filters", f"{sev_count['Medium']} medium · {sev_count['Low']} low"),
        (len(A["dead_actions"]), "Public actions, zero consumers",
         f"of {A['public_actions_total']['server'] + A['public_actions_total']['client']} public actions"),
        (max(c["blast"] for c in coup.values()), "Largest blast radius",
         max(coup, key=lambda n: (coup[n]["blast"], coup[n]["ca"]))),
    ]
    kpi_html = "".join(f'<div class="kpi"><div class="v">{v}</div><div class="l">{esc(l)}</div>'
                       f'<div class="s">{esc(s)}</div></div>' for v, l, s in kpis)

    # ------------------------------------------------------------------ Section 1
    nodes_json = [{"id": nid(n), "name": n, "layer": L[n], "cls": LAYER_CLASS[L[n]]} for n in sorted(mods)]
    edges_json = [{"s": nid(c), "t": nid(t), "sn": c, "tn": t, "w": edge_w[(c, t)],
                   "v": (c, t) in A["viol"], "c": (c, t) in A["cyc_edges"]} for (c, t) in sorted(edge_w)]
    cyc_nodes = sorted({nid(n) for comp in A["comps"] for n in comp})
    graph = mermaid_graph(A)
    focus_opts = "".join(f'<option value="{esc(nid(n))}">{esc(n)}</option>' for n in sorted(mods))

    ov_rows = []
    for n in sorted(mods, key=lambda x: (LAYER_ORDER.index(L[x]), x)):
        m, c = mods[n], coup[n]
        flags = []
        if any(n in comp for comp in A["comps"]):
            flags.append(badge("cycle", "cyc"))
        if any(n == a for a, _ in A["viol"]):
            flags.append(badge("violates layering", "high"))
        if any(n == b for _, b in A["viol"]):
            flags.append(badge("consumed upward", "med"))
        pub = m["public"]
        ov_rows.append([
            f"<b>{esc(n)}</b>", layer_badge(L[n]), esc(K[n]),
            len(m["entities"]), len(m["server_actions"]), f"{len(m['screens'])} / {len(m['blocks'])}",
            (str(sum(pub.values())),
             sum(pub.values())),
            c["ce"], c["ca"], " ".join(flags) or "—"])
    overview = table(["Module", "Layer", "Type", "Entities", "Server actions", "Screens / Blocks",
                      "Public elements", "Consumes (modules)", "Consumed by (modules)", "Findings"],
                     ov_rows, "tbl-overview", True, numeric=(3, 4, 6, 7, 8))

    viol_rows = []
    for (c, t) in sorted(A["viol"], key=lambda e: -edge_w[e]):
        el = elems.get((c, t), {})
        sample = ", ".join(sorted(el.get("entities", set()) | el.get("actions", set()) | el.get("blocks", set())
                                  | el.get("client actions", set()))[:6]) or "structures / roles / themes"
        viol_rows.append([f"<b>{esc(c)}</b> {layer_badge(L[c])}", f"<b>{esc(t)}</b> {layer_badge(L[t])}",
                          edge_w[(c, t)], esc(sample),
                          "Foundation modules must not depend on Core/End-User; move the shared element down into a "
                          "Foundation module or invert the dependency." if L[c] == FOUNDATION else
                          "Lower layer consuming a higher layer; invert via callback/event or extract to a lower layer."])
    viol_tbl = table(["Consumer", "Producer", "Reference sites", "Elements consumed (sample)", "Remediation"],
                     viol_rows, "tbl-viol", numeric=(2,))

    cyc_rows = []
    for comp in A["comps"]:
        inner = sorted((a, b) for (a, b) in A["cyc_edges"] if a in comp and b in comp)
        cyc_rows.append([" ⇄ ".join(esc(x) for x in comp), len(comp),
                         "<br>".join(f"{esc(a)} → {esc(b)} <span class='mut'>({edge_w[(a, b)]} sites)</span>"
                                     for a, b in inner)])
    cyc_tbl = table(["Modules in cycle", "Size", "Edges inside the cycle"], cyc_rows, "tbl-cyc", numeric=(1,))

    soft_rows = [[f"<b>{esc(c)}</b> <span class='mut'>({esc(K[c])})</span>",
                  f"<b>{esc(t)}</b> <span class='mut'>({esc(K[t])})</span>", edge_w[(c, t)],
                  ", ".join(sorted(elems.get((c, t), {}).get("actions", set()))[:5]) or "—"] for c, t in soft]
    soft_tbl = table(["Consumer", "Producer", "Reference sites", "Actions consumed (sample)"], soft_rows,
                     "tbl-soft", numeric=(2,))

    ext_rows = sorted(((n, len(cs)) for n, cs in A["external"].items()), key=lambda x: (-x[1], x[0]))
    ext_tbl = table(["External module (platform / Forge / not in export)", "Consumed by (modules)"],
                    [[esc(n), c] for n, c in ext_rows], "tbl-ext", numeric=(1,))

    # ------------------------------------------------------------------ Section 2
    by_mod = defaultdict(Counter)
    for r in risks:
        by_mod[r["module"]][r["sev"]] += 1
    mod_risk_rows = [[esc(n), c["High"], c["Medium"], c["Low"], sum(c.values())]
                     for n, c in sorted(by_mod.items(), key=lambda kv: (-kv[1]["High"], -kv[1]["Medium"], kv[0]))]
    mod_risk_tbl = table(["Entity owner module", "High", "Medium", "Low", "Total"], mod_risk_rows, "tbl-riskmod",
                         numeric=(1, 2, 3, 4))
    risk_rows = []
    for r in risks:
        sites = r["sites"]
        det = "".join(f"<li><b>{esc(s[0])}</b> › {esc(s[1])} › <code>{esc(s[2])}</code> "
                      f"<span class='mut'>({'Advanced SQL' if s[3] == 'sql' else 'Aggregate'})</span></li>"
                      for s in sites[:40])
        if len(sites) > 40:
            det += f"<li class='mut'>… and {len(sites) - 40} more</li>"
        note = []
        if r["flag"]:
            note.append("boolean/flag: low selectivity")
        if r["partial"]:
            note.append("only a non-leading column of a composite index")
        if r["static"]:
            note.append("static entity (few rows)")
        risk_rows.append([
            (sev(r["sev"]), {"High": 0, "Medium": 1, "Low": 2}[r["sev"]]),
            f"<b>{esc(r['entity'])}</b><br><span class='mut'>{esc(r['module'])}</span>",
            f"<code>{esc(r['attr'])}</code>",
            (f"{r['n_sites']}<details><summary>show</summary><ul class='sites'>{det}</ul></details>", r["n_sites"]),
            r["usage"], r["consumers"], len(r["mods"]),
            esc("; ".join(note)) or "—",
            f"<code>CREATE INDEX on {esc(r['entity'])}({esc(r['attr'])})</code>".replace("CREATE INDEX on", "Index"),
        ])
    risk_tbl = table(["Priority", "Entity (owner module)", "Unindexed attribute", "Filtering queries",
                      "Queries reading entity", "Consumer modules", "Querying modules", "Notes", "Suggested fix"],
                     risk_rows, "tbl-risk", True, numeric=(3, 4, 5, 6))

    # ------------------------------------------------------------------ Section 3
    dead_rows = [[f"<b>{esc(d['name'])}</b>", esc(d["module"]), esc(d["kind"]), esc(K[d["module"]]), d["nodes"]]
                 for d in sorted(A["dead_actions"], key=lambda d: (d["module"], d["name"]))]
    dead_tbl = table(["Public action", "Module", "Kind", "Module type", "Nodes"], dead_rows, "tbl-dead", True,
                     numeric=(4,))
    dead_by_mod = Counter(d["module"] for d in A["dead_actions"])
    dead_mod_rows = [[esc(n), c, sum(1 for a in mods[n]["server_actions"].values() if a["public"]) +
                      sum(1 for a in mods[n]["client_actions"].values() if a["public"])]
                     for n, c in dead_by_mod.most_common()]
    dead_mod_tbl = table(["Module", "Public actions without consumers", "Public actions total"], dead_mod_rows,
                         "tbl-deadmod", numeric=(1, 2))
    int_rows = [[f"<b>{esc(d['name'])}</b>", esc(d["module"]), esc(d["kind"]), d["internal"]]
                for d in sorted(A["internal_only_actions"], key=lambda d: (d["module"], d["name"]))]
    int_tbl = table(["Public action", "Module", "Kind", "Internal call sites"], int_rows, "tbl-int", True,
                    numeric=(3,))

    pub_int = sorted(A["pub_internal_entities"], key=lambda d: (d["module"], d["entity"]))
    pub_int_tbl = table(["Public entity", "Module", "Internal references"],
                        [[f"<b>{esc(d['entity'])}</b>", esc(d["module"]), d["local"] + d["fk"]] for d in pub_int],
                        "tbl-pubent", True, numeric=(2,))
    attr_rows = [[f"<b>{esc(d['entity'])}</b><br><span class='mut'>{esc(d['module'])}</span>",
                  f"{len(d['unused'])} / {d['total']}", esc(", ".join(d["unused"][:14]) +
                                                           (f" … +{len(d['unused']) - 14}" if len(d["unused"]) > 14 else "")),
                  d["consumers"]]
                 for d in sorted(A["dead_attrs"], key=lambda d: (-len(d["unused"]), d["module"], d["entity"]))]
    attr_tbl = table(["Entity (module)", "Unreferenced / total attrs", "Attributes", "Consumer modules"], attr_rows,
                     "tbl-attr", True)
    blk_rows = [[f"<b>{esc(d['name'])}</b>", esc(d["module"]), "yes" if d["public"] else "no", d["widgets"]]
                for d in sorted(A["dead_blocks"], key=lambda d: (-d["widgets"], d["module"], d["name"]))]
    blk_tbl = table(["UI block", "Module", "Public", "Widgets"], blk_rows, "tbl-blk", True, numeric=(3,))

    cc_rows = [[f"<b>{esc(a['name'])}</b>", esc(a["module"]), esc(a["type"]), heat(a["cc"], 15, 30), a["nodes"],
                a["loops"], a["aggs"] + a["sql"], a["calls"], "yes" if a["public"] else "no"]
               for a in A["actions"][:25]]
    cc_tbl = table(["Action", "Module", "Type", "Cyclomatic complexity", "Nodes", "Loops", "Queries", "Calls", "Public"],
                   cc_rows, "tbl-cc", numeric=(3, 4, 5, 6, 7))
    ui_rows = [[f"<b>{esc(u['name'])}</b>", esc(u["module"]), esc(u["type"]), heat(u["depth"], 10, 15), u["widgets"]]
               for u in A["ui"][:25]]
    ui_tbl = table(["Screen / Block", "Module", "Type", "Widget nesting depth", "Widgets"], ui_rows, "tbl-ui",
                   numeric=(3, 4))
    heat_rows = []
    for n in sorted(mods):
        acts = [a for a in A["actions"] if a["module"] == n]
        uis = [u for u in A["ui"] if u["module"] == n]
        if not acts and not uis:
            continue
        mx = max((a["cc"] for a in acts), default=0)
        n15 = sum(1 for a in acts if a["cc"] > 15)
        md = max((u["depth"] for u in uis), default=0)
        n10 = sum(1 for u in uis if u["depth"] > 10)
        heat_rows.append([esc(n), layer_badge(L[n]), heat(mx, 15, 30), n15, heat(md, 10, 15), n10,
                          sum(a["nodes"] for a in acts)])
    heat_rows.sort(key=lambda r: -(r[2][1] + r[4][1]))
    heat_tbl = table(["Module", "Layer", "Max action complexity", "Actions CC>15", "Max widget depth",
                      "Screens/blocks depth>10", "Total action nodes"], heat_rows, "tbl-heat", True,
                     numeric=(2, 3, 4, 5, 6))

    # ------------------------------------------------------------------ Section 4
    rank = sorted(mods, key=lambda n: (-coup[n]["blast"], -coup[n]["ca"], n))
    max_blast = max(coup[n]["blast"] for n in mods) or 1
    imp_rows = []
    for n in rank[:25]:
        c = coup[n]
        bar = f'<div class="bar"><i style="width:{100 * c["blast"] / max_blast:.0f}%"></i><span>{c["blast"]}</span></div>'
        imp_rows.append([f"<b>{esc(n)}</b>", layer_badge(L[n]), (bar, c["blast"]), c["blast_end_user"], c["ca"], c["uses_in"],
                         c["ce"], f"{c['instability']:.2f}", c["public"]])
    imp_tbl = table(["Module", "Layer", "Blast radius (transitive consumers)", "End-User modules impacted",
                     "Direct consumers", "Reference sites (inbound)", "Direct dependencies", "Instability I=Ce/(Ca+Ce)",
                     "Public elements"], imp_rows, "tbl-impact", True, numeric=(3, 4, 5, 6, 7, 8))

    el_rows = []
    for kind, cons in (("Entity", A["ent_cons"]), ("Server action", A["act_cons"]), ("Client action", A["cact_cons"]),
                       ("UI block", A["blk_cons"])):
        for (t, name), cs in cons.items():
            el_rows.append((len(cs), sum(cs.values()), kind, t, name, cs))
    el_rows.sort(key=lambda r: (-r[0], -r[1], r[3], r[4]))
    elem_rows = []
    for nc, tot, kind, t, name, cs in el_rows[:30]:
        ends = sum(1 for c in cs if L[c] == END_USER)
        elem_rows.append([f"<b>{esc(name)}</b>", esc(kind), esc(t), nc, ends, tot,
                          esc(", ".join(sorted(cs, key=lambda c: -cs[c])[:6]) + (" …" if len(cs) > 6 else ""))])
    elem_tbl = table(["Public element", "Kind", "Owner module", "Consuming modules", "of which End-User",
                      "Reference sites", "Top consumers"], elem_rows, "tbl-elems", True, numeric=(3, 4, 5))

    pair_rows = []
    for (a, b), p in sorted(A["pairs"].items(), key=lambda kv: -(kv[1]["ab"] + kv[1]["ba"]))[:20]:
        e1, e2 = elems.get((a, b), {}), elems.get((b, a), {})
        pair_rows.append([f"<b>{esc(a)}</b> ⇄ <b>{esc(b)}</b>", p["ab"], p["ba"], p["ab"] + p["ba"],
                          badge("bidirectional", "cyc") if p["ab"] and p["ba"] else "—"])
    pair_tbl = table(["Module pair", "A → B sites", "B → A sites", "Total coupling", "Note"], pair_rows, "tbl-pairs",
                     numeric=(1, 2, 3))
    fan_rows = [[f"<b>{esc(n)}</b>", layer_badge(L[n]), coup[n]["ce"], coup[n]["uses_out"]]
                for n in sorted(mods, key=lambda n: (-coup[n]["ce"], -coup[n]["uses_out"]))[:12]]
    fan_tbl = table(["Module (most dependencies)", "Layer", "Producers consumed", "Reference sites (outbound)"], fan_rows,
                    "tbl-fan", numeric=(2, 3))

    # ------------------------------------------------------------------ assemble
    w(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OutSystems Factory Audit Report</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
<script>mermaid.initialize({{startOnLoad:true, securityLevel:'loose', maxEdges:5000, maxTextSize:2000000,
  theme: window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'default',
  flowchart:{{useMaxWidth:false, curve:'basis', nodeSpacing:30, rankSpacing:90}}}});</script>
<style>{CSS}</style></head><body>
<header class="top"><div class="wrap"><h1>OutSystems Factory Audit Report</h1>
<p>Static analysis of {n_mod} module OML exports · generated {date.today().isoformat()}</p>
<nav><a href="#s1">1 · Architecture</a><a href="#s2">2 · Database performance</a><a href="#s3">3 · Debt &amp; dead code</a>
<a href="#s4">4 · Impact analysis</a><a href="#method">Method</a></nav></div></header>
<main class="wrap">
<section class="kpis">{kpi_html}</section>

<section id="s1"><h2>1. Global Architecture &amp; Module Dependency Diagram</h2>
<p>Arrows point from the <b>consumer</b> to the module it <b>consumes</b> (<code>A --&gt; B</code> = A depends on B). Modules are
grouped by Architecture Canvas layer. <span class="lg red"></span> <b>red</b> = layer violation (lower layer consuming a higher one),
<span class="lg amber"></span> <b>amber dashed</b> = edge inside a dependency cycle (cyclic modules get a thick amber border).
Click a module to focus on its direct neighbours.</p>
<div class="controls">
<label><input type="checkbox" class="lay" value="End-User" checked> End-User</label>
<label><input type="checkbox" class="lay" value="Core Services" checked> Core Services</label>
<label><input type="checkbox" class="lay" value="Foundation" checked> Foundation</label>
<label><input type="checkbox" id="onlyIssues"> Only violations &amp; cycles</label>
<label>Focus <select id="focus"><option value="">All modules</option>{focus_opts}</select></label>
<button id="zin" type="button">＋</button><button id="zout" type="button">－</button><button id="reset" type="button">Reset</button>
<span id="gstat" class="mut"></span></div>
<div class="diagram" id="diagramwrap"><div class="mermaid" id="arch">
{esc(graph)}
</div></div>
<noscript><p>Enable JavaScript to render the diagram.</p></noscript>
<p id="offline" class="mut" hidden>The Mermaid library could not be loaded (offline?). The diagram source is in the
<a href="#src">appendix</a>.</p>

<h3>1.1 Architecture overview — all modules</h3>
<p>Layer is inferred from OutSystems naming conventions (<code>_Lib/_Th/_IS</code> → Foundation, <code>_CS/_BL/_CW/_API</code> → Core,
<code>_UI/_BackOffice</code> and app modules → End-User) and confirmed by content (screens). “Public elements” = entities, actions,
structures, UI blocks, screens and site properties marked <code>Public</code>.</p>
{overview}

<h3>1.2 Layer violations ({len(A['viol'])})</h3>
{viol_tbl if A['viol'] else '<p>None detected.</p>'}
<h3>1.3 Cyclic dependencies ({len(A['comps'])} groups)</h3>
{cyc_tbl if A['comps'] else '<p>None detected.</p>'}
<h3>1.4 Sub-layer warnings inside Core ({len(soft)})</h3>
<p>Core Services (<code>_CS</code>, data + CRUD) consuming Business Logic / Widgets / Email modules inverts the usual
CS ← BL ← CW stacking and is what turns most of the Core cycles above into loops.</p>
{soft_tbl if soft else '<p>None detected.</p>'}
<details><summary>1.5 External producers not part of this export ({len(ext_rows)})</summary>{ext_tbl}</details>
</section>

<section id="s2"><h2>2. Performance &amp; Database Health (Unindexed Queries)</h2>
<p>{fs['queries']} queries scanned ({fs['aggregates']} Aggregates, {fs['sql']} Advanced SQL); {fs['with_filters']} apply filters.
{fs['total']} filter-attribute usages were checked against the owner entity's indexes; {fs['external']} target platform / Forge
entities not present in the export and were skipped. An attribute counts as indexed if it is the identifier or the
<b>leading</b> column of any index (OutSystems auto-indexes foreign keys). <b>{len(risks)}</b> distinct entity attributes are
filtered without an index.</p>
<div class="legend"><b>Priority score</b> (per entity attribute):
{sev('High')} filtered in ≥{af.HIGH_SITES} queries, or ≥{af.HIGH_MIX_SITES} queries on an entity read by ≥{af.HIGH_MIX_USAGE} queries ·
{sev('Medium')} ≥{af.MED_SITES} queries or entity read by ≥{af.MED_USAGE} queries · {sev('Low')} otherwise.
Boolean/flag attributes (<code>Is*</code>, <code>*Active</code>) drop one level (low selectivity); static entities are Low.</div>
<h3>2.1 Summary by owner module</h3>{mod_risk_tbl}
<h3>2.2 All unindexed filters ({len(risks)})</h3>
<p class="mut">Sorted by priority; click a header to re-sort, expand “show” for the exact queries.</p>{risk_tbl}
</section>

<section id="s3"><h2>3. Technical Debt &amp; Dead Code Analysis</h2>
<h3>3.1 Public actions with zero consumers ({len(A['dead_actions'])})</h3>
<p>Public server/client actions that are called neither from another module in the factory nor from inside their own module.
Candidates for removal or for making private. Excludes platform-invoked entry points that are not visible in the XML
(REST/SOAP exposure, BPT, external callers) — verify before deleting.</p>
{dead_mod_tbl}<br>{dead_tbl}
<h3>3.2 Public actions used only inside their own module ({len(A['internal_only_actions'])})</h3>
<details><summary>Show list — can be made private (reduces public surface and refactoring risk)</summary>{int_tbl}</details>
<h3>3.3 Unused entities</h3>
<p><b>{len(A['dead_entities'])}</b> of {A['entities_total']} entities are completely unreferenced.
{len(pub_int)} entities are public but consumed by no other module (internal only).</p>
<details><summary>Public entities with no external consumers ({len(pub_int)})</summary>{pub_int_tbl}</details>
<h3>3.4 Unreferenced attributes — candidates ({sum(len(d['unused']) for d in A['dead_attrs'])} of {A['attrs_total']})</h3>
<p>Attributes never read in an Aggregate filter/sort/expression, assignment or Advanced SQL column list, in this module or any
consumer. They may still be populated implicitly through whole-record <code>CreateOrUpdate</code> calls or reached through
structures/REST — treat as candidates and confirm with data usage before dropping.</p>{attr_tbl}
<h3>3.5 Unused UI blocks ({len(A['dead_blocks'])} of {A['blocks_total']})</h3>{blk_tbl}
<h3>3.6 Complexity hot-spots</h3>
<p>Cyclomatic complexity ≈ 1 + decisions (If, ForEach, Switch branches, error handlers, And/Or operators).
{badge('≥ 30', 'high')} very high · {badge('≥ 15', 'med')} high. Widget depth counts nested widgets
(Containers, Ifs, Tables…); {badge('≥ 15', 'high')} · {badge('≥ 10', 'med')}.</p>
<h4>Most complex actions</h4>{cc_tbl}
<h4>Deepest screens &amp; blocks</h4>{ui_tbl}
<h4>Maintainability heatmap by module</h4>{heat_tbl}
</section>

<section id="s4"><h2>4. Cross-Module Impact Analysis</h2>
<p><b>Blast radius</b> = number of modules that would be (transitively) affected by a breaking change in the module.</p>
<h3>4.1 Critical modules by blast radius</h3>{imp_tbl}
<h3>4.2 Highest-risk public elements (most consuming modules)</h3>{elem_tbl}
<h3>4.3 Most tightly coupled module pairs</h3>{pair_tbl}
<h3>4.4 Modules with the widest dependency footprint</h3>{fan_tbl}
</section>

<section id="method"><h2>Method &amp; limitations</h2>
<ul>
<li>Source: {n_mod} OML XML exports in <code>input/</code>, parsed by <code>scripts/parse_factory.py</code>; analysis in
<code>scripts/analyze_factory.py</code>; rendering in <code>scripts/generate_report.py</code>.</li>
<li>Dependencies come from each module's declared references, weighted by the number of attribute-level references actually
used in the module (declared-but-unused references: {len(A['unused_deps'])}).</li>
<li>Advanced SQL <code>WHERE</code> clauses are parsed heuristically (alias resolution, parenthesis depth); filters hidden in
dynamic SQL parameters cannot be seen. Index checks cover single and composite indexes (leading column rule); index
cardinality, row counts and actual DB statistics are not available, so priority is based on usage in the codebase.</li>
<li>Consumption is resolved by element name across modules; elements invoked outside the XML (REST consumers, BPT,
external systems) are not visible.</li>
<li>Layer assignment is convention-based and should be reviewed by the architects.</li>
</ul>
<details id="src"><summary>Appendix — Mermaid source of the full diagram</summary><pre>{esc(graph)}</pre></details>
</section></main>
<script>
const NODES={json.dumps(nodes_json)}, EDGES={json.dumps(edges_json)}, CYC={json.dumps(cyc_nodes)};
{JS}
</script></body></html>""")
    return "".join(h)


CSS = """
:root{--bg:#f6f7fb;--card:#fff;--ink:#0f172a;--mut:#64748b;--line:#e2e8f0;--acc:#2563eb;
--high:#dc2626;--med:#d97706;--low:#2563eb;--eu:#2563eb;--core:#16a34a;--fnd:#9333ea;--cyc:#f59e0b;--head:#0f172a}
@media (prefers-color-scheme:dark){:root{--bg:#0b1020;--card:#131a2e;--ink:#e5e7eb;--mut:#94a3b8;--line:#243049;--acc:#60a5fa;
--high:#f87171;--med:#fbbf24;--low:#60a5fa;--head:#050814}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1280px;margin:0 auto;padding:0 20px}
header.top{background:var(--head);color:#fff;padding:22px 0 0}header.top h1{margin:0;font-size:26px}
header.top p{margin:4px 0 14px;color:#cbd5e1}nav{display:flex;gap:4px;flex-wrap:wrap;padding-bottom:0}
nav a{color:#cbd5e1;text-decoration:none;padding:9px 14px;border-radius:8px 8px 0 0}nav a:hover{background:#1e293b;color:#fff}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:22px 24px;margin:22px 0}
section.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;background:none;border:0;padding:0}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.kpi .v{font-size:30px;font-weight:700;line-height:1.1}.kpi .l{font-weight:600}.kpi .s{color:var(--mut);font-size:12px}
h2{margin:0 0 10px;font-size:21px;border-bottom:2px solid var(--line);padding-bottom:8px}h3{margin:26px 0 8px;font-size:16px}h4{margin:18px 0 6px}
.mut{color:var(--mut)}code{background:rgba(100,116,139,.15);padding:1px 5px;border-radius:4px;font-size:12px}
pre{background:rgba(100,116,139,.12);padding:12px;border-radius:8px;overflow:auto;font-size:12px}
.tablewrap{overflow:auto;max-height:620px;border:1px solid var(--line);border-radius:8px;margin:6px 0 10px}
table.data{border-collapse:collapse;width:100%;font-size:13px}
table.data th{position:sticky;top:0;background:var(--card);text-align:left;padding:8px 10px;border-bottom:2px solid var(--line);
cursor:pointer;white-space:nowrap;z-index:1}table.data th:hover{color:var(--acc)}
table.data td{padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
table.data tr:hover td{background:rgba(100,116,139,.08)}td.num{text-align:right;font-variant-numeric:tabular-nums}
.badge{display:inline-block;padding:1px 9px;border-radius:99px;font-size:11.5px;font-weight:600;color:#fff;white-space:nowrap}
.b-high{background:var(--high)}.b-med{background:var(--med)}.b-low{background:var(--low)}
.b-eu{background:var(--eu)}.b-core{background:var(--core)}.b-fnd{background:var(--fnd)}.b-cyc{background:var(--cyc);color:#1f2937}
.heat{display:inline-block;min-width:34px;text-align:center;padding:1px 8px;border-radius:6px;background:rgba(22,163,74,.18);font-weight:600}
.heat.warm{background:rgba(217,119,6,.35)}.heat.hot{background:rgba(220,38,38,.45)}
.tfilter{width:100%;max-width:340px;padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink)}
.controls{display:flex;gap:14px;flex-wrap:wrap;align-items:center;margin:10px 0}.controls button,.controls select{padding:5px 10px;
border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink);cursor:pointer}
.diagram{border:1px solid var(--line);border-radius:10px;overflow:auto;max-height:80vh;background:var(--bg);padding:8px}
.diagram svg{height:auto}.lg{display:inline-block;width:22px;height:4px;vertical-align:middle;border-radius:2px}
.lg.red{background:#dc2626}.lg.amber{background:#f59e0b}
.legend{background:rgba(100,116,139,.1);border-radius:8px;padding:10px 14px;margin:10px 0}
ul.sites{margin:6px 0 0;padding-left:18px;font-size:12px;max-height:260px;overflow:auto}details summary{cursor:pointer;color:var(--acc)}
.bar{position:relative;background:rgba(100,116,139,.15);border-radius:6px;height:20px;min-width:140px}
.bar i{position:absolute;left:0;top:0;bottom:0;background:var(--acc);border-radius:6px;opacity:.55}
.bar span{position:relative;padding-left:8px;font-weight:600}
@media (max-width:640px){section{padding:16px}}
"""

JS = r"""
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
let zoom=1;
function graphText(){
  const layers=new Set($$('.lay:checked').map(x=>x.value)), only=$('#onlyIssues').checked, focus=$('#focus').value;
  const byId=Object.fromEntries(NODES.map(n=>[n.id,n]));
  let es=EDGES.filter(e=>layers.has(byId[e.s].layer)&&layers.has(byId[e.t].layer));
  if(only) es=es.filter(e=>e.v||e.c);
  if(focus) es=es.filter(e=>e.s===focus||e.t===focus);
  const used=new Set(focus?[focus]:[]); es.forEach(e=>{used.add(e.s);used.add(e.t)});
  if(!only&&!focus) NODES.forEach(n=>{if(layers.has(n.layer)) used.add(n.id)});
  const titles={'End-User':['EU','End-User Layer'],'Core Services':['CORE','Core Services Layer'],'Foundation':['FND','Foundation Layer']};
  const L=['graph TD'];
  for(const lay of ['End-User','Core Services','Foundation']){
    const ns=NODES.filter(n=>n.layer===lay&&used.has(n.id)); if(!ns.length) continue;
    L.push(`  subgraph ${titles[lay][0]}["${titles[lay][1]}"]`);
    ns.forEach(n=>L.push(`    ${n.id}["${n.name}"]:::${n.cls}`)); L.push('  end');
    L.push(`  style ${titles[lay][0]} fill:${{'EU':'#eff6ff','CORE':'#f0fdf4','FND':'#faf5ff'}[titles[lay][0]]},stroke:#94a3b8,color:#0f172a`);
  }
  const v=[],c=[]; es.forEach((e,i)=>{L.push(`  ${e.s} --> ${e.t}`); if(e.v)v.push(i); else if(e.c)c.push(i)});
  const cn=CYC.filter(x=>used.has(x)); if(cn.length) L.push('  class '+cn.join(',')+' cyc');
  [...used].forEach(id=>L.push(`  click ${id} call modClick("${id}")`));
  L.push('  classDef eu fill:#dbeafe,stroke:#2563eb,color:#0f172a','  classDef core fill:#dcfce7,stroke:#16a34a,color:#0f172a',
         '  classDef fnd fill:#f3e8ff,stroke:#9333ea,color:#0f172a','  classDef cyc stroke:#f59e0b,stroke-width:4px',
         '  linkStyle default stroke:#94a3b8,stroke-width:1px');
  if(v.length) L.push('  linkStyle '+v.join(',')+' stroke:#dc2626,stroke-width:3px');
  if(c.length) L.push('  linkStyle '+c.join(',')+' stroke:#f59e0b,stroke-width:3px,stroke-dasharray:5 3');
  $('#gstat').textContent=`${used.size} modules · ${es.length} dependencies`;
  return es.length||used.size?L.join('\n'):'graph TD\n  none["Nothing to show"]';
}
async function render(){
  if(typeof mermaid==='undefined'){ $('#offline').hidden=false; return; }
  const el=$('#arch'); el.removeAttribute('data-processed'); el.textContent=graphText();
  try{ await mermaid.run({nodes:[el]}); applyZoom(); }catch(e){ console.error(e); $('#offline').hidden=false; }
}
function applyZoom(){ const s=$('#arch svg'); if(s){ s.style.maxWidth='none'; s.style.width=(zoom*100)+'%'; } }
window.modClick=id=>{ $('#focus').value=id; render(); };
$$('.lay,#onlyIssues,#focus').forEach(x=>x.addEventListener('change',()=>{zoom=1;render()}));
$('#zin').onclick=()=>{zoom=Math.min(zoom*1.25,4);applyZoom()}; $('#zout').onclick=()=>{zoom=Math.max(zoom/1.25,.3);applyZoom()};
$('#reset').onclick=()=>{ $$('.lay').forEach(x=>x.checked=true); $('#onlyIssues').checked=false; $('#focus').value=''; zoom=1; render(); };
window.addEventListener('load',()=>{ if(typeof mermaid==='undefined') $('#offline').hidden=false; else setTimeout(()=>{ $('#gstat').textContent=`${NODES.length} modules · ${EDGES.length} dependencies`; applyZoom(); },800); });

// sortable + filterable tables
function cellKey(td){ return td.dataset.k!==undefined?td.dataset.k:td.textContent.trim(); }
$$('table.data th').forEach((th,i)=>{
  const sort=()=>{ const t=th.closest('table'), tb=t.tBodies[0], num=th.dataset.num==='1', dir=th.dataset.dir==='asc'?-1:1;
    th.dataset.dir=dir===1?'asc':'desc';
    [...tb.rows].sort((a,b)=>{ let x=cellKey(a.cells[i]), y=cellKey(b.cells[i]);
      if(num||(!isNaN(parseFloat(x))&&!isNaN(parseFloat(y))&&String(parseFloat(x))===x&&String(parseFloat(y))===y)){x=parseFloat(x)||0;y=parseFloat(y)||0;return (x-y)*dir;}
      return x.localeCompare(y)*dir; }).forEach(r=>tb.appendChild(r)); };
  th.addEventListener('click',sort); th.addEventListener('keydown',e=>{if(e.key==='Enter')sort()});
});
$$('.tfilter').forEach(f=>f.addEventListener('input',()=>{ const q=f.value.toLowerCase();
  [...document.getElementById(f.dataset.for).tBodies[0].rows].forEach(r=>r.hidden=q&&!r.textContent.toLowerCase().includes(q)); }));
"""


def main(argv):
    src = argv[0] if argv else af.DATA_JSON
    out = argv[1] if len(argv) > 1 else REPORT_HTML
    data = af.load(src)
    A = af.analyze(data)
    page = build(A, data)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(page)
    print(f"Wrote {os.path.abspath(out)} ({len(page) / 1024:.0f} KB)")


if __name__ == "__main__":
    main(sys.argv[1:])
