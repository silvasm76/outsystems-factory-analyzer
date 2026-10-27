"""Shared HTML template for the assessment reports (same look as Factory_Audit_Report.html).

A report is one standalone file: page(title, subtitle, nav, body). Helpers build the usual pieces:
kpis(), table() (sortable, optional text filter), sev_badge(), finding_card(), narrative().
"""
import html
import json
import os
from datetime import date

esc = lambda s: html.escape("" if s is None else str(s), quote=True)  # noqa: E731

SEV_CLASS = {"Critical": "crit", "High": "high", "Medium": "med", "Low": "low", "Info": "info"}

CSS = """
:root{--bg:#f6f7fb;--card:#fff;--ink:#0f172a;--mut:#64748b;--line:#e2e8f0;--acc:#2563eb;--head:#0f172a;
--crit:#7f1d1d;--high:#dc2626;--med:#d97706;--low:#2563eb;--info:#64748b}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0b1020;--card:#131a2e;--ink:#e5e7eb;--mut:#94a3b8;
--line:#243049;--acc:#60a5fa;--head:#050814;--crit:#ef4444;--high:#f87171;--med:#fbbf24;--low:#60a5fa;--info:#94a3b8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1280px;margin:0 auto;padding:0 20px}
header.top{background:var(--head);color:#fff;padding:22px 0 0}header.top h1{margin:0;font-size:26px}
header.top p{margin:4px 0 14px;color:#cbd5e1}nav{display:flex;gap:4px;flex-wrap:wrap}
nav a{color:#cbd5e1;text-decoration:none;padding:9px 14px;border-radius:8px 8px 0 0}nav a:hover{background:#1e293b;color:#fff}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:22px 24px;margin:22px 0}
section.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;background:none;border:0;padding:0}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;border-top:4px solid var(--line)}
.kpi .v{font-size:30px;font-weight:700;line-height:1.1}.kpi .l{font-weight:600}.kpi .s{color:var(--mut);font-size:12px}
.kpi.crit{border-top-color:var(--crit)}.kpi.high{border-top-color:var(--high)}.kpi.med{border-top-color:var(--med)}
.kpi.low{border-top-color:var(--low)}.kpi.info{border-top-color:var(--info)}
h2{margin:0 0 10px;font-size:21px;border-bottom:2px solid var(--line);padding-bottom:8px}h3{margin:26px 0 8px;font-size:16px}
.mut{color:var(--mut)}code{background:rgba(100,116,139,.15);padding:1px 5px;border-radius:4px;font-size:12px;word-break:break-word}
.tablewrap{overflow:auto;max-height:640px;border:1px solid var(--line);border-radius:8px;margin:6px 0 10px}
table.data{border-collapse:collapse;width:100%;font-size:13px}
table.data th{position:sticky;top:0;background:var(--card);text-align:left;padding:8px 10px;border-bottom:2px solid var(--line);
cursor:pointer;white-space:nowrap;z-index:1}table.data th:hover{color:var(--acc)}
table.data td{padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
table.data tr:hover td{background:rgba(100,116,139,.08)}td.num{text-align:right;font-variant-numeric:tabular-nums}
.badge{display:inline-block;padding:1px 9px;border-radius:99px;font-size:11.5px;font-weight:600;color:#fff;white-space:nowrap}
.b-crit{background:var(--crit)}.b-high{background:var(--high)}.b-med{background:var(--med)}.b-low{background:var(--low)}
.b-info{background:var(--info)}.b-ok{background:#16a34a}.b-no{background:var(--high)}
.controls{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:10px 0}
.controls input,.controls select{padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink)}
.controls input{min-width:260px}
.card{border:1px solid var(--line);border-left:5px solid var(--line);border-radius:10px;padding:12px 16px;margin:12px 0}
.card.crit{border-left-color:var(--crit)}.card.high{border-left-color:var(--high)}.card.med{border-left-color:var(--med)}
.card h4{margin:0 0 6px;font-size:15px}.card dl{display:grid;grid-template-columns:130px 1fr;gap:4px 12px;margin:8px 0 0}
.card dt{color:var(--mut);font-weight:600}.card dd{margin:0}
.narr p{margin:0 0 10px}.narr ul{margin:4px 0 10px}.lead{font-size:15px}
.bar{position:relative;background:rgba(100,116,139,.15);border-radius:6px;height:20px;min-width:120px}
.bar i{position:absolute;left:0;top:0;bottom:0;border-radius:6px;opacity:.7}.bar span{position:relative;padding-left:8px;font-weight:600}
a{color:var(--acc)}footer{color:var(--mut);font-size:12px;padding:10px 0 40px}
@media (max-width:640px){.wrap{padding:0 16px}section{padding:16px}.card dl{grid-template-columns:1fr}.controls input{min-width:0;width:100%}}
"""

JS = r"""
document.querySelectorAll('table.data').forEach(t=>{
  t.querySelectorAll('th').forEach((th,i)=>th.addEventListener('click',()=>{
    const tb=t.tBodies[0], rows=[...tb.rows], asc=th.dataset.asc!=='1'; th.dataset.asc=asc?'1':'0';
    const key=r=>{const c=r.cells[i]; return c.dataset.sort!==undefined?c.dataset.sort:c.innerText.trim().toLowerCase()};
    const num=rows.every(r=>key(r)===''||!isNaN(parseFloat(key(r))));
    rows.sort((a,b)=>{let x=key(a),y=key(b); if(num){x=parseFloat(x)||0;y=parseFloat(y)||0}
      return (x>y?1:x<y?-1:0)*(asc?1:-1)}); rows.forEach(r=>tb.appendChild(r));}));
});
document.querySelectorAll('.controls[data-for]').forEach(c=>{
  const t=document.getElementById(c.dataset.for), inp=c.querySelector('input'), sels=[...c.querySelectorAll('select')];
  const apply=()=>{const q=(inp?inp.value:'').toLowerCase();
    [...t.tBodies[0].rows].forEach(r=>{let ok=!q||r.innerText.toLowerCase().includes(q);
      sels.forEach(s=>{if(s.value&&r.dataset[s.name]!==s.value)ok=false}); r.hidden=!ok});};
  if(inp)inp.addEventListener('input',apply); sels.forEach(s=>s.addEventListener('change',apply));
});
"""


def sev_badge(sev):
    return '<span class="badge b-%s">%s</span>' % (SEV_CLASS.get(sev, "info"), esc(sev))


def badge(text, cls):
    return '<span class="badge b-%s">%s</span>' % (cls, esc(text))


def kpis(items):
    """items: [(value, label, sublabel, css_class)]"""
    return '<section class="kpis">%s</section>' % "".join(
        '<div class="kpi %s"><div class="v">%s</div><div class="l">%s</div><div class="s">%s</div></div>'
        % (cls or "", esc(v), esc(l), esc(s)) for v, l, s, cls in items)


def table(headers, rows, tid=None, numeric=(), row_attrs=None):
    """rows are lists of already-escaped HTML cells; row_attrs (optional) is a list of {data-x: value}."""
    head = "".join("<th>%s</th>" % esc(h) for h in headers)
    body = []
    for i, r in enumerate(rows):
        attrs = "".join(' data-%s="%s"' % (k, esc(v)) for k, v in (row_attrs[i] if row_attrs else {}).items())
        body.append("<tr%s>%s</tr>" % (attrs, "".join('<td%s>%s</td>' % (' class="num"' if j in numeric else "", c)
                                                       for j, c in enumerate(r))))
    return '<div class="tablewrap"><table class="data"%s><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>' % (
        ' id="%s"' % tid if tid else "", head, "".join(body))


def filters(tid, selects=()):
    """Search box + dropdowns filtering table tid; selects: [(name, label, [values])] matched against data-<name>."""
    sel = "".join('<select name="%s"><option value="">%s: all</option>%s</select>' % (
        n, esc(lbl), "".join('<option>%s</option>' % esc(v) for v in vals)) for n, lbl, vals in selects)
    return '<div class="controls" data-for="%s"><input type="search" placeholder="Filter rows...">%s</div>' % (tid, sel)


def code_link(file, code_rel="code"):
    if not file:
        return ""
    return '<a href="%s/%s" title="Open the pseudocode">%s</a>' % (code_rel, esc(file), esc(file))


def narrative(name, output_dir):
    """Optional hand/LLM-written HTML fragment output/narrative/<name>.html (executive summary, priorities)."""
    p = os.path.join(output_dir, "narrative", name + ".html")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as fh:
            return fh.read()
    return None


def page(title, subtitle, nav, body, footer=""):
    navh = "".join('<a href="#%s">%s</a>' % (esc(a), esc(t)) for a, t in nav)
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title><style>%s</style></head><body>
<header class="top"><div class="wrap"><h1>%s</h1><p>%s · generated %s</p><nav>%s</nav></div></header>
<main class="wrap">%s</main><footer class="wrap">%s</footer><script>%s</script></body></html>""" % (
        esc(title), CSS, esc(title), esc(subtitle), date.today().isoformat(), navh, body, footer, JS)


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
