"""Cross-module analysis on output/factory_data.json (produced by parse_factory.py)."""
import json
import os
import re
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_JSON = os.path.join(HERE, "..", "output", "factory_data.json")

FOUNDATION, CORE, END_USER = "Foundation", "Core Services", "End-User"
RANK = {FOUNDATION: 0, CORE: 1, END_USER: 2}

FOUNDATION_RE = re.compile(r"(_Lib|_Th|_IS|Connector\w*|_CommonWidgets)$")
END_USER_RE = re.compile(r"(_UI|_UI_FIN|_BackOffice|_BO)$")
END_USER_EXACT = {"ProERP", "Training", "ProERP_ProjectMoments"}

# severity thresholds for unindexed filters (see report legend)
HIGH_SITES, HIGH_MIX_SITES, HIGH_MIX_USAGE = 6, 3, 30
MED_SITES, MED_USAGE = 2, 20
FLAG_RE = re.compile(r"^(Is|Has|Can)[A-Z_]|^Is_|Active$|^Enabled$|^Deleted$", re.I)


def classify(name, mod):
    """Layer from OutSystems naming conventions (_Lib/_Th/_IS = Foundation, _CS/_BL/_CW/_API = Core,
    _UI/_BackOffice/app modules = End-User), falling back to content (many screens => End-User)."""
    if FOUNDATION_RE.search(name):
        return FOUNDATION
    if END_USER_RE.search(name) or name in END_USER_EXACT:
        return END_USER
    if re.search(r"_(CS|BL|CW|API|Sync|Email|Bootstraps)$", name) or "Emails" in name:
        return CORE
    return END_USER if len(mod["screens"]) >= 5 else CORE


def kind_of(name):
    m = re.search(r"_(CS|BL|CW|API|IS|Th|Lib|UI|UI_FIN|BackOffice|BO|Sync|Email|Bootstraps|CommonWidgets)$", name)
    if m:
        return m.group(1)
    if "Connector" in name:
        return "Connector"
    return "App"


def tarjan(nodes, adj):
    index, low, onst, st, out, idx = {}, {}, set(), [], [], [0]

    def strong(v):
        index[v] = low[v] = idx[0]
        idx[0] += 1
        st.append(v)
        onst.add(v)
        for w in adj.get(v, ()):
            if w not in index:
                strong(w)
                low[v] = min(low[v], low[w])
            elif w in onst:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = st.pop()
                onst.discard(w)
                comp.append(w)
                if w == v:
                    break
            out.append(comp)

    for v in nodes:
        if v not in index:
            strong(v)
    return out


def load(path=DATA_JSON):
    return json.load(open(path, encoding="utf-8"))


def analyze(data):
    mods = data["modules"]
    key2name = {m["key"]: n for n, m in mods.items()}
    A = {"mods": mods}

    # ---- layers
    layer = {n: classify(n, m) for n, m in mods.items()}
    A["layer"] = layer
    A["kind"] = {n: kind_of(n) for n in mods}

    # ---- reference resolution helpers
    def ref_target(m, rk):
        r = m["references"].get(rk)
        return key2name.get(r["target_key"]) if r else None

    ext_name = {}

    def ref_label(m, rk):
        r = m["references"].get(rk)
        return r["name"] if r else "?"

    # ---- edges (consumer -> producer) weighted by every use of the reference
    edge_w, edge_elems, unused_deps, external = Counter(), defaultdict(set), [], defaultdict(set)
    for n, m in mods.items():
        for rk, r in m["references"].items():
            t = key2name.get(r["target_key"])
            used = m["ref_any"].get(rk, 0)
            if t is None:
                if r["name"] != "(System)":
                    external[r["name"]].add(n)
                continue
            if t == n:
                continue
            if used:
                edge_w[(n, t)] += used
            else:
                unused_deps.append((n, t))
    adj = defaultdict(set)
    radj = defaultdict(set)
    for (c, t) in edge_w:
        adj[c].add(t)
        radj[t].add(c)

    # ---- consumed elements per producer (by name)
    ent_cons, act_cons, cact_cons, blk_cons, attr_cons = (defaultdict(Counter) for _ in range(5))
    for n, m in mods.items():
        for rk, ek, cnt in m["ref_ent"]:
            t, r = ref_target(m, rk), m["references"].get(rk)
            if t and t != n and r and ek in r["entities"]:
                ent_cons[(t, r["entities"][ek])][n] += cnt
        for rk, ek, ak, cnt in m["ref_ent_attr"]:
            t, r = ref_target(m, rk), m["references"].get(rk)
            if t and t != n and r and ek in r["entities"] and ak in r["attrs"]:
                attr_cons[(t, r["entities"][ek], r["attrs"][ak])][n] += cnt
        for rk, ak, cnt in m["ref_act"]:
            t, r = ref_target(m, rk), m["references"].get(rk)
            if t and t != n and r and ak in r["actions"]:
                act_cons[(t, r["actions"][ak])][n] += cnt
        for rk, ak, cnt in m["ref_cact"]:
            t, r = ref_target(m, rk), m["references"].get(rk)
            if t and t != n and r and ak in r["cactions"]:
                cact_cons[(t, r["cactions"][ak])][n] += cnt
        for rk, bk, cnt in m["ref_blk"]:
            t, r = ref_target(m, rk), m["references"].get(rk)
            if t and t != n and r and bk in r["blocks"]:
                blk_cons[(t, r["blocks"][bk])][n] += cnt
    for (c, t) in edge_w:
        pass

    # ---- cycles and layer violations
    comps = [sorted(c) for c in tarjan(sorted(mods), adj) if len(c) > 1]
    in_cycle = {n for c in comps for n in c}
    cyc_edges = {(c, t) for (c, t) in edge_w if c in in_cycle and t in in_cycle
                 and any(c in comp and t in comp for comp in comps)}
    viol = {(c, t) for (c, t) in edge_w if RANK[layer[c]] < RANK[layer[t]]}
    A.update(ent_cons=ent_cons, act_cons=act_cons, cact_cons=cact_cons, blk_cons=blk_cons, attr_cons=attr_cons)
    A.update(edge_w=edge_w, adj=adj, radj=radj, comps=comps, cyc_edges=cyc_edges, viol=viol,
             unused_deps=unused_deps, external=external)

    # ---- distinct elements consumed per edge
    edge_elems = defaultdict(lambda: {"entities": set(), "actions": set(), "client actions": set(), "blocks": set()})
    for (t, e), cs in ent_cons.items():
        for c in cs:
            edge_elems[(c, t)]["entities"].add(e)
    for (t, e), cs in act_cons.items():
        for c in cs:
            edge_elems[(c, t)]["actions"].add(e)
    for (t, e), cs in cact_cons.items():
        for c in cs:
            edge_elems[(c, t)]["client actions"].add(e)
    for (t, e), cs in blk_cons.items():
        for c in cs:
            edge_elems[(c, t)]["blocks"].add(e)
    A["edge_elems"] = edge_elems

    # ---- coupling / blast radius
    def closure(start, g):
        seen, stack = set(), [start]
        while stack:
            v = stack.pop()
            for w in g.get(v, ()):
                if w not in seen and w != start:
                    seen.add(w)
                    stack.append(w)
        return seen

    coup = {}
    for n in mods:
        ca, ce = len(radj.get(n, ())), len(adj.get(n, ()))
        dependents = closure(n, radj)
        coup[n] = {
            "ca": ca, "ce": ce, "instability": (ce / (ca + ce)) if ca + ce else 0.0,
            "blast": len(dependents), "blast_end_user": sum(1 for d in dependents if layer[d] == END_USER),
            "blast_set": sorted(dependents), "uses_in": sum(edge_w[(c, n)] for c in radj.get(n, ())),
            "uses_out": sum(edge_w[(n, t)] for t in adj.get(n, ())),
            "public": sum(m for m in mods[n]["public"].values()),
        }
    A["coup"] = coup
    pair = {}
    for (c, t), w in edge_w.items():
        k = tuple(sorted((c, t)))
        p = pair.setdefault(k, {"ab": 0, "ba": 0})
        p["ab" if k[0] == c else "ba"] += w
    A["pairs"] = pair

    # ---- entity index info
    ent_idx = {}
    for n, m in mods.items():
        for ek, e in m["entities"].items():
            lead = {i["cols"][0].lower() for i in e["indexes"] if i["cols"]}
            anyc = {c.lower() for i in e["indexes"] for c in i["cols"]}
            ent_idx[(n, e["name"])] = {"lead": lead, "any": anyc, "pk": e["id_name"].lower(), "static": e["static"],
                                       "attrs": {a["name"].lower(): a["name"] for a in e["attrs"].values()}}
    A["ent_idx"] = ent_idx

    def resolve_ent(m, n, rk, ek):
        if rk is None:
            e = m["entities"].get(ek)
            return (n, e["name"]) if e else (None, None)
        t = ref_target(m, rk)
        r = m["references"].get(rk)
        return (t, r["entities"].get(ek)) if r else (None, None)

    # ---- entity usage by query sources
    src_sites = Counter()
    for n, m in mods.items():
        for q in m["queries"]:
            seen = set()
            for rk, ek, nm in q.get("sources", []):
                k = resolve_ent(m, n, rk, ek)
                if k[0] and k not in seen:
                    seen.add(k)
                    src_sites[k] += 1
    A["src_sites"] = src_sites

    # ---- unindexed filters
    groups = defaultdict(lambda: {"sites": [], "mods": set()})
    unresolved = 0
    ext_filters = 0
    total_filters = 0
    for n, m in mods.items():
        for q in m["queries"]:
            for rk, ek, en, at in q["filters"]:
                total_filters += 1
                t, ename = resolve_ent(m, n, rk, ek)
                if not t or (t, ename) not in ent_idx:
                    unresolved += 1
                    ext_filters += 1
                    continue
                info = ent_idx[(t, ename)]
                al = at.lower()
                if al not in info["attrs"]:
                    unresolved += 1
                    continue
                if al == info["pk"] or al in info["lead"]:
                    continue
                g = groups[(t, ename, info["attrs"][al])]
                site = (n, q["container"] or "(screen/preparation)", q["name"], q["kind"])
                if site not in g["sites"]:
                    g["sites"].append(site)
                g["mods"].add(n)
                g["partial"] = al in info["any"]
    risks = []
    for (t, ename, at), g in groups.items():
        sites = len(g["sites"])
        usage = src_sites[(t, ename)]
        consumers = len(ent_cons.get((t, ename), {}))
        flag = bool(FLAG_RE.search(at))
        if sites >= HIGH_SITES or (sites >= HIGH_MIX_SITES and usage >= HIGH_MIX_USAGE):
            sev = "High"
        elif sites >= MED_SITES or usage >= MED_USAGE:
            sev = "Medium"
        else:
            sev = "Low"
        if flag and sev != "Low":  # boolean flags are low-selectivity: one level down
            sev = "Medium" if sev == "High" else "Low"
        if ent_idx[(t, ename)]["static"]:
            sev = "Low"
        risks.append({"module": t, "entity": ename, "attr": at, "sites": g["sites"], "n_sites": sites,
                      "usage": usage, "consumers": consumers, "sev": sev, "partial": g.get("partial", False),
                      "static": ent_idx[(t, ename)]["static"], "flag": flag, "mods": sorted(g["mods"])})
    order = {"High": 0, "Medium": 1, "Low": 2}
    risks.sort(key=lambda r: (order[r["sev"]], -r["n_sites"], -r["usage"], r["module"], r["entity"], r["attr"]))
    A["risks"] = risks
    A["filter_stats"] = {"total": total_filters, "unresolved": unresolved, "external": ext_filters,
                         "queries": sum(len(m["queries"]) for m in mods.values()),
                         "aggregates": sum(1 for m in mods.values() for q in m["queries"] if q["kind"] == "aggregate"),
                         "sql": sum(1 for m in mods.values() for q in m["queries"] if q["kind"] == "sql"),
                         "with_filters": sum(1 for m in mods.values() for q in m["queries"] if q["filters"])}

    # ---- dead code
    dead_actions, internal_only = [], []
    for n, m in mods.items():
        for ak, a in m["server_actions"].items():
            if not a["public"]:
                continue
            ext = act_cons.get((n, a["name"]), {})
            internal = m["act_use"].get(ak, 0)
            row = {"module": n, "name": a["name"], "internal": internal, "nodes": a["nodes"], "kind": "server"}
            if not ext and not internal:
                dead_actions.append(row)
            elif not ext:
                internal_only.append(row)
        for ak, a in m["client_actions"].items():
            if not a["public"]:
                continue
            ext = cact_cons.get((n, a["name"]), {})
            internal = m["cact_use"].get(ak, 0)
            row = {"module": n, "name": a["name"], "internal": internal, "nodes": a["nodes"], "kind": "client"}
            if not ext and not internal:
                dead_actions.append(row)
            elif not ext:
                internal_only.append(row)
    A["dead_actions"], A["internal_only_actions"] = dead_actions, internal_only
    A["public_actions_total"] = {
        "server": sum(1 for m in mods.values() for a in m["server_actions"].values() if a["public"]),
        "client": sum(1 for m in mods.values() for a in m["client_actions"].values() if a["public"])}

    # columns referenced by Advanced SQL, per entity the query reads from
    sql_cols = defaultdict(set)
    sql_star = set()
    for n, m in mods.items():
        for q in m["queries"]:
            if q["kind"] != "sql":
                continue
            for rk, ek, nm in q["sources"]:
                k = resolve_ent(m, n, rk, ek)
                if k[0]:
                    sql_cols[k].update(q["cols"])
                    if q.get("star"):
                        sql_star.add(k)
    dead_entities, dead_attrs, pub_internal_entities = [], [], []
    for n, m in mods.items():
        attr_use = {(ek, ak): c for ek, ak, c in m["attr_use"]}
        for ek, e in m["entities"].items():
            ext = ent_cons.get((n, e["name"]), {})
            local = m["ent_use"].get(ek, 0)
            fk = m["ent_use_fk"].get(ek, 0)
            if not ext and not local and not fk:
                dead_entities.append({"module": n, "entity": e["name"], "public": e["public"], "attrs": len(e["attrs"]),
                                      "static": e["static"]})
                continue
            if e["public"] and not ext:
                pub_internal_entities.append({"module": n, "entity": e["name"], "local": local, "fk": fk})
            unused = []
            for ak, a in e["attrs"].items():
                an = a["name"]
                if an.lower() == e["id_name"].lower():
                    continue
                if attr_use.get((ek, ak)) or attr_cons.get((n, e["name"], an)):
                    continue
                if (n, e["name"]) in sql_star or an.lower() in sql_cols.get((n, e["name"]), ()):
                    continue
                unused.append(an)
            if unused:
                dead_attrs.append({"module": n, "entity": e["name"], "unused": unused, "total": len(e["attrs"]),
                                   "consumers": len(ext)})
    A["dead_entities"], A["dead_attrs"], A["pub_internal_entities"] = dead_entities, dead_attrs, pub_internal_entities
    A["entities_total"] = sum(len(m["entities"]) for m in mods.values())
    A["attrs_total"] = sum(len(e["attrs"]) for m in mods.values() for e in m["entities"].values())

    dead_blocks = []
    for n, m in mods.items():
        for bk, b in m["blocks"].items():
            ext = blk_cons.get((n, b["name"]), {})
            if not ext and not m["blk_use"].get(bk):
                dead_blocks.append({"module": n, "name": b["name"], "public": b["public"], "widgets": b["widgets"]})
    A["dead_blocks"] = dead_blocks
    A["blocks_total"] = sum(len(m["blocks"]) for m in mods.values())

    # ---- technical debt
    acts = []
    for n, m in mods.items():
        for src, label in ((m["server_actions"], "Server"), (m["client_actions"], "Client")):
            for a in src.values():
                acts.append({"module": n, "name": a["name"] or "?", "type": label, "nodes": a["nodes"],
                             "cc": 1 + a["decisions"], "loops": a["loops"], "sql": a["sql"], "aggs": a["aggs"],
                             "calls": a["calls"], "public": a["public"]})
    acts.sort(key=lambda a: (-a["cc"], -a["nodes"]))
    A["actions"] = acts
    ui = []
    for n, m in mods.items():
        for src, label in ((m["screens"], "Screen"), (m["blocks"], "Block")):
            for s in src.values():
                ui.append({"module": n, "name": s["name"], "type": label, "widgets": s["widgets"], "depth": s["depth"],
                           "public": s["public"]})
    ui.sort(key=lambda s: (-s["depth"], -s["widgets"]))
    A["ui"] = ui
    return A


if __name__ == "__main__":
    A = analyze(load())
    print("layers", Counter(A["layer"].values()))
    print("edges", len(A["edge_w"]), "viol", len(A["viol"]), "cycle comps", A["comps"], "cyc edges", len(A["cyc_edges"]))
    print("unused deps", len(A["unused_deps"]))
    print("filter stats", A["filter_stats"])
    print("risks", Counter(r["sev"] for r in A["risks"]), len(A["risks"]))
    print("dead actions", len(A["dead_actions"]), "internal only", len(A["internal_only_actions"]), A["public_actions_total"])
    print("dead ents", len(A["dead_entities"]), "of", A["entities_total"], "dead attrs", sum(len(d["unused"]) for d in A["dead_attrs"]), "of", A["attrs_total"])
    print("dead blocks", len(A["dead_blocks"]), "of", A["blocks_total"])
    print("depth top", [(u["name"], u["depth"], u["widgets"]) for u in A["ui"][:5]])
    print("cc top", [(a["name"], a["cc"], a["nodes"]) for a in A["actions"][:5]])
    print("blast top", sorted(((c["blast"], n) for n, c in A["coup"].items()), reverse=True)[:8])
    print("viol", sorted(A["viol"])[:20])
