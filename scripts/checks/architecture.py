"""Architecture rules (Architecture Canvas / Indigo OS11 layering) over the model and index.
Writes output/findings/architecture.json.

Rules (ids are stable; the report groups by them):
  ARC-01 Upward dependency (a lower layer consumes a higher one)
  ARC-02 Side dependency between End-User modules
  ARC-03 Circular dependency between modules
  ARC-04 Core sub-layer inversion (CS consuming BL/CW/Email, BL consuming CW)
  ARC-05 Data model outside the Core layer
  ARC-06 Business logic (data writes) in End-User modules
  ARC-07 Public entity writable by consumers
  ARC-08 Unused module dependency
  ARC-09 Module with no consumers and no entry points
  ARC-10 Hub module with a large blast radius

Usage: python scripts/checks/architecture.py
"""
import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Context, finding, write  # noqa: E402
import layers as af  # noqa: E402

RANK = af.RANK
CORE_ORDER = {"CS": 0, "BL": 1, "Sync": 1, "Email": 1, "API": 2, "CW": 2}


def consumed(ctx, consumer, producer):
    """'entities: A, B; actions: C' consumed by consumer from producer."""
    els = ctx.models[consumer].get("dependencies", {}).get(producer, {}).get("elements", {})
    return "; ".join("%s: %s%s" % (k, ", ".join(v[:6]), " ..." if len(v) > 6 else "") for k, v in els.items()) or \
        "%d reference(s)" % ctx.models[consumer]["dependencies"].get(producer, {}).get("uses", 0)


def graph(ctx):
    mods = ctx.index["modules"]
    edges = [(c, t) for c, m in mods.items() for t in m["references"]]
    adj = defaultdict(set)
    for c, t in edges:
        adj[c].add(t)
    comps = [sorted(c) for c in af.tarjan(sorted(mods), adj) if len(c) > 1]
    return mods, edges, adj, comps


def closure(adj_rev, start):
    seen, stack = set(), [start]
    while stack:
        n = stack.pop()
        for c in adj_rev.get(n, ()):
            if c not in seen and c != start:
                seen.add(c)
                stack.append(c)
    return seen


def check_layers(ctx, out, mods, edges, comps):
    for c, t in edges:
        lc, lt = mods[c]["layer"], mods[t]["layer"]
        if RANK[lc] < RANK[lt]:
            out.append(finding("ARC-01", "High", "Layering", "Upward dependency", c, "%s → %s" % (c, t), None,
                               "%s (%s) consumes %s (%s): %s" % (c, lc, t, lt, consumed(ctx, c, t)),
                               "Move what is consumed down to the consumer's layer (or lower), or reclassify the module if its "
                               "name/layer is wrong; a lower layer must never depend on a higher one."))
        elif lc == lt == af.END_USER:
            out.append(finding("ARC-02", "Medium", "Layering", "Side dependency between End-User modules", c,
                               "%s → %s" % (c, t), None, "consumes %s" % consumed(ctx, c, t),
                               "Move the shared elements to a Core module (CS/BL/CW) that both applications consume, so each "
                               "End-User module can be deployed on its own."))
        else:
            kc, kt = mods[c]["kind"], mods[t]["kind"]
            if lc == lt == af.CORE and kc in CORE_ORDER and kt in CORE_ORDER and CORE_ORDER[kc] < CORE_ORDER[kt]:
                out.append(finding("ARC-04", "Medium", "Layering", "Core sub-layer inversion", c, "%s → %s" % (c, t), None,
                                   "_%s consumes _%s: %s" % (kc, kt, consumed(ctx, c, t)),
                                   "Core Services (_CS) hold data and CRUD and should not depend on business logic (_BL), "
                                   "widgets (_CW) or e-mail modules; invert the call (event, callback) or move the logic up."))
    for comp in comps:
        inner = [(c, t) for c, t in edges if c in comp and t in comp]
        out.append(finding("ARC-03", "High", "Coupling", "Circular dependency between modules", comp[0],
                           "Cycle of %d modules: %s" % (len(comp), ", ".join(comp)), None,
                           "; ".join("%s → %s (%s)" % (c, t, consumed(ctx, c, t)) for c, t in inner)[:900],
                           "Break the cycle at the weakest edge (fewest consumed elements): move those elements to the "
                           "producer's layer or below. Cycles force modules to be published together."))


def writes(f):
    return [n.get("action") for n in f.get("nodes", [])
            if n.get("action_ref", "").startswith("EntityActions") and re.match(r"(Create|Update|Delete)", (n.get("action") or "").split(".")[-1])] + \
           ["SQL %s" % n.get("name") for n in f.get("nodes", []) if n["type"] == "AdvancedQuery"
            and re.match(r"\s*(delete|update|insert|merge)\b", n.get("sql", ""), re.I)]


def check_placement(ctx, out, mods):
    for mod, m in ctx.models.items():
        layer, kind = mods[mod]["layer"], mods[mod]["kind"]
        data_ents = [e["name"] for e in m["entities"] if not e.get("staticRecords")]
        if data_ents and layer != af.CORE and kind not in ("IS",):
            out.append(finding("ARC-05", "Medium" if layer == af.END_USER else "Low", "Placement",
                               "Data model outside the Core layer", mod, "Module %s" % mod, None,
                               "%s module (%s) defines %d entities: %s" % (layer, kind, len(data_ents), ", ".join(data_ents[:8])),
                               "Keep entities in a Core Services (_CS) module that owns them, so other applications reuse the "
                               "data and its rules instead of duplicating them."))
        elif data_ents and kind == "BL":
            out.append(finding("ARC-05", "Low", "Placement", "Data model outside the Core layer", mod, "Module %s" % mod, None,
                               "business-logic module defines entities: %s" % ", ".join(data_ents[:8]),
                               "Move the entities to the corresponding _CS module."))
        if layer == af.END_USER:
            w = [(f, writes(f)) for f in m["flows"] if f["kind"] == "ServerAction"]
            w = [(f, x) for f, x in w if x]
            if w:
                out.append(finding("ARC-06", "Medium", "Placement", "Business logic (data writes) in End-User modules", mod,
                                   "Module %s" % mod, ctx.file_of(mod, w[0][0]),
                                   "%d server action(s) write data directly: %s" % (
                                       len(w), ", ".join("%s (%s)" % (f["name"], ", ".join(x[:2])) for f, x in w[:6])
                                       + (" ..." if len(w) > 6 else "")),
                                   "Move the writes to Core business-logic actions (_BL/_CS) that validate the business rules; "
                                   "keep End-User modules to UI and orchestration."))


def check_entities(ctx, out, mods):
    writers = defaultdict(set)
    for mod, m, f, n in ctx.iter_nodes():
        a = n.get("action") or ""
        if n.get("action_ref", "").startswith("EntityActions") and "." in a:
            producer, op = a.split(".", 1)
            mm = re.match(r"(Create|Update|Delete|CreateOrUpdate)(\w+)", op)
            if mm and producer != mod:
                writers[(producer, mm.group(2))].add(mod)
    for mod, m in ctx.models.items():
        for e in m["entities"]:
            if not e.get("public") or e.get("exposeReadOnly", True) or e.get("staticRecords"):
                continue
            w = sorted(writers.get((mod, e["name"]), []))
            out.append(finding("ARC-07", "Medium" if w else "Low", "Encapsulation", "Public entity writable by consumers", mod,
                               "Entity %s" % e["name"], None,
                               "Expose Read Only = No; written directly by %s" % (", ".join(w) if w else "no other module (yet)"),
                               "Set Expose Read Only = Yes and expose wrapper actions (EntityCreate/Update/Delete) that apply "
                               "validation and auditing."))


def check_usage(ctx, out, mods, edges):
    rev = defaultdict(set)
    for c, t in edges:
        rev[t].add(c)
    for mod, m in mods.items():
        # a reference nothing uses may still be required indirectly: consuming an entity/structure of Q that points to P
        # makes Service Studio add P too; skip P when a producer this module uses depends on it
        types = ("entities", "structures")
        own = ctx.models[mod].get("dependencies", {})
        indirect = {p for q in m["references"] if any(k in own.get(q, {}).get("elements", {}) for k in types)
                    for p, d in ctx.models[q].get("dependencies", {}).items()
                    if any(k in d.get("elements", {}) for k in types)}
        unused = [r for r in m["unusedReferences"] if r != "(System)" and r not in indirect]
        if unused:
            out.append(finding("ARC-08", "Low", "Coupling", "Unused module dependency", mod, "Module %s" % mod, None,
                               "references with nothing used: " + ", ".join(unused),
                               "Remove the dependencies in Manage Dependencies; unused references still force republishing "
                               "and widen the impact of changes."))
        mm = ctx.models[mod]
        entry = mm.get("timers") or mm.get("restExposed") or any(f["kind"] == "ServiceAPIMethod" for f in mm["flows"])
        if not m["consumers"] and m["layer"] != af.END_USER and not entry:
            out.append(finding("ARC-09", "Low", "Coupling", "Module with no consumers and no entry points", mod,
                               "Module %s" % mod, None,
                               "%s module consumed by no analysed module and with no timers, REST APIs or service actions" % m["layer"],
                               "Confirm in Service Center whether another application uses it; otherwise retire it."))
        blast = closure(rev, mod)
        if len(m["consumers"]) >= len(mods) // 3:
            out.append(finding("ARC-10", "Info", "Coupling", "Hub module with a large blast radius", mod, "Module %s" % mod, None,
                               "consumed directly by %d and transitively by %d of %d modules" % (
                                   len(m["consumers"]), len(blast), len(mods)),
                               "Treat its public API as a contract: avoid breaking changes, version public actions and keep "
                               "it free of business logic that changes often."))


def run(ctx):
    out = []
    mods, edges, adj, comps = graph(ctx)
    check_layers(ctx, out, mods, edges, comps)
    check_placement(ctx, out, mods)
    check_entities(ctx, out, mods)
    check_usage(ctx, out, mods, edges)
    rev = defaultdict(set)
    for c, t in edges:
        rev[t].add(c)
    in_cycle = {n for c in comps for n in c}
    summary = {
        "modules": {n: {"layer": m["layer"], "kind": m["kind"], "fanIn": len(m["consumers"]), "fanOut": len(m["references"]),
                        "blast": len(closure(rev, n)), "inCycle": n in in_cycle, "counts": m["counts"],
                        "public": sum(1 for f in ctx.models[n]["flows"] if f.get("public"))
                        + sum(1 for e in ctx.models[n]["entities"] if e.get("public"))}
                    for n, m in mods.items()},
        "edges": [[c, t, ctx.models[c]["dependencies"].get(t, {}).get("uses", 0)] for c, t in edges],
        "cycles": comps,
        "external": sorted({r for m in mods.values() for r in m["externalReferences"] if r != "(System)"}),
        "externalUse": {r: sorted(n for n, m in mods.items() if r in m["externalReferences"])
                        for r in {r for m in mods.values() for r in m["externalReferences"] if r != "(System)"}},
    }
    return out, summary


if __name__ == "__main__":
    c = Context()
    findings, summary = run(c)
    path = write("architecture", findings)
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    data.update(summary)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1)
