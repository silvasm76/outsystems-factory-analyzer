"""Performance rules over the extracted model. Writes output/findings/performance.json.

Rules (ids are stable; the report groups by them):
  PRF-01 Queries or server calls inside a loop (N+1)
  PRF-02 Filter, join or sort on an attribute without an index
  PRF-03 Client-side query fetching too many records (Max Records >= 1000, unbounded data actions)
  PRF-04 SELECT * in an Advanced Query
  PRF-05 Join not used by a grouped aggregate
  PRF-06 Where condition turns a Left Join into an Inner Join
  PRF-07 Binary data stored in a main entity
  PRF-08 Several sequential server calls from one client action

Usage: python scripts/checks/performance.py
"""
import json
import os
import re
import sys
from collections import defaultdict, deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Context, finding, write  # noqa: E402

CLIENT_KINDS = ("ScreenAction", "ClientAction")  # data actions run on the server
QUERY_NODES = ("DataSet", "AdvancedQuery", "WebScreenDataSet")


def loop_bodies(flow):
    """{ForEach key: set of node keys executed per iteration}."""
    nodes = {n["key"]: n for n in flow.get("nodes", [])}
    out = {}
    for fe in nodes.values():
        if fe["type"] != "ForEach":
            continue
        start = next((l[1] for l in fe["links"] if l[0] == "Cycle"), None)
        seen, q = set(), deque([start])
        while q:
            k = q.popleft()
            if k is None or k in seen or k == fe["key"] or k not in nodes:
                continue
            seen.add(k)
            q.extend(l[1] for l in nodes[k]["links"])
        out[fe["key"]] = seen
    return out


def queries_in(ctx, action, module):
    """Does the called server action (resolved through the index) run a query itself?"""
    fid = action if action.split(".")[0] in ctx.models else "%s.%s" % (module, action)
    meta = ctx.flows.get(fid)
    if not meta:
        return False
    m = ctx.models.get(meta["module"], {})
    f = next((x for x in m.get("flows", []) if x["name"] == meta["name"] and x["kind"] == meta["kind"]), None)
    return bool(f) and any(n["type"] in QUERY_NODES or (n.get("action_ref", "").startswith("EntityActions")
                                                        and n.get("action", "").split(".")[-1].startswith("Get"))
                           for n in f["nodes"])


def check_loops(ctx, out):
    for mod, m, f in ctx.iter_flows():
        bodies = loop_bodies(f)
        if not bodies:
            continue
        nodes = {n["key"]: n for n in f["nodes"]}
        client = f["kind"] in CLIENT_KINDS
        items, worst = [], "Low"
        for fe_key, body in bodies.items():
            lst = nodes[fe_key].get("list")
            for k in body:
                n = nodes[k]
                a = n.get("action") or ""
                ref = n.get("action_ref", "")
                if n["type"] in QUERY_NODES:
                    items.append(("High", "%s %s per iteration of %s" % ("SQL" if n["type"] == "AdvancedQuery" else "Aggregate",
                                                                         n.get("name"), lst)))
                elif client and n["type"] == "ExecuteAction":
                    items.append(("High", "server call %s per iteration of %s (one round trip each)" % (a, lst)))
                elif ref.startswith("EntityActions") and a.split(".")[-1].startswith("Get"):
                    items.append(("Medium", "%s per iteration of %s" % (a, lst)))
                elif n["type"] == "ExecuteAction" and not ref.startswith(("EntityActions", "RoleActions", "TimerActions")) \
                        and queries_in(ctx, a, mod):
                    items.append(("Medium", "%s (runs a query) per iteration of %s" % (a, lst)))
        if not items:
            continue
        sevs = ["Critical", "High", "Medium", "Low", "Info"]
        worst = min((s for s, _ in items), key=sevs.index)
        out.append(finding("PRF-01", worst, "Data access", "Queries or server calls inside a loop (N+1)", mod,
                           ctx.element(f), ctx.file_of(mod, f),
                           "; ".join(sorted({t for _, t in items}))[:400],
                           "Fetch the data once before the loop (one aggregate with a join or an IN filter) and look it up "
                           "in memory; from the client, send the whole list in a single server call."))


def entity_catalog(ctx):
    """'Module.Entity' -> {indexed: set(first index columns + Id), static, types}."""
    cat = {}
    for mod, m in ctx.models.items():
        for e in m["entities"]:
            idx = {"Id"} | {ix["cols"][0] for ix in e["indexes"] if ix["cols"]}
            cat["%s.%s" % (mod, e["name"])] = {"indexed": idx, "static": bool(e.get("staticRecords")),
                                                "types": {a["name"]: a["type"] for a in e["attributes"]}}
    return cat


def check_indexes(ctx, out):
    cat = entity_catalog(ctx)
    sites = defaultdict(lambda: {"flows": set(), "kinds": set()})
    for mod, m, f, n in ctx.iter_nodes():
        for kind, ent, attr in n.get("uses", []):
            if kind in ("group", "calc"):
                continue
            sites[(ent, attr)]["flows"].add(ctx.label(mod, f))
            sites[(ent, attr)]["kinds"].add(kind)
    for (ent, attr), s in sites.items():
        e = cat.get(ent)
        if not e or e["static"] or attr in e["indexed"] or attr not in e["types"]:
            continue
        if e["types"][attr] == "Boolean":
            continue  # low selectivity: an index alone rarely helps
        n = len(s["flows"])
        sev = "High" if n >= 6 else "Medium" if n >= 2 or "join" in s["kinds"] else "Low"
        out.append(finding("PRF-02", sev, "Indexes", "Filter, join or sort on an attribute without an index",
                           ent.split(".")[0], "Entity %s.%s" % (ent.split(".", 1)[1], attr), None,
                           "used to %s in %d flow(s): %s" % ("/".join(sorted(s["kinds"])), n,
                                                             ", ".join(sorted(s["flows"])[:6]) + (" ..." if n > 6 else "")),
                           "Add an index on %s (or a composite index starting with it, matching the most common filter); "
                           "check the table size and the query plan first." % attr))


def check_queries(ctx, out):
    for mod, m, f, n in ctx.iter_nodes():
        t = n["type"]
        grouped = any(" GROUP " in q for q in n.get("query", []))
        mr = n.get("maxRecords") or ""
        big = mr.isdigit() and int(mr) >= 1000
        if (t == "WebScreenDataSet" and big) or (t == "DataSet" and f["kind"] == "DataAction" and not mr and not grouped):
            out.append(finding("PRF-03", "Medium" if t == "WebScreenDataSet" else "Low", "Data access",
                               "Client-side query fetching too many records", mod,
                               ctx.element(f) + " / Aggregate %s" % (n.get("name")), ctx.file_of(mod, f),
                               "Max Records = %s; %d source(s): %s" % (mr or "none (unbounded)", len(n.get("sources", [])),
                                                                         ", ".join(s[0] for s in n.get("sources", []))),
                               "Bind Max Records to the list's page size and paginate (or aggregate on the server); every row "
                               "returned is serialized and sent to the browser."))
        if t == "AdvancedQuery" and re.search(r"select\s+(distinct\s+)?(top\s*\(?\s*\d+\s*\)?\s+)?(\{\w+\}\.)?\*", n.get("sql", ""), re.I):
            out.append(finding("PRF-04", "Low", "Data access", "SELECT * in an Advanced Query", mod,
                               ctx.element(f) + " / SQL %s" % (n.get("name")), ctx.file_of(mod, f),
                               " ".join(n.get("sql", "").split())[:160],
                               "Select only the columns the output structure needs."))
        if t in ("DataSet", "WebScreenDataSet") and n.get("joins"):
            q = n.get("query", [])
            used = {ent for kind, ent, attr in n.get("uses", []) if kind != "join"}
            if grouped:  # only a grouped aggregate's output is known; an unused INNER join still filters rows
                lefts = {j[1] for j in n["joins"]}
                for label, ent in n.get("sources", []):
                    optional = any(j[0] == "LEFT" and j[2] == label for j in n["joins"])
                    if optional and label not in lefts and ent not in used:
                        out.append(finding("PRF-05", "Low", "Data access", "Join not used by a grouped aggregate", mod,
                                           ctx.element(f) + " / Aggregate %s" % (n.get("name")), ctx.file_of(mod, f),
                                           "%s is joined but not used in any filter, sort, group or aggregate" % label,
                                           "Remove the join; it costs a table access on every execution."))
            reported = set()
            for jt, left, right in n["joins"]:
                if jt != "LEFT":
                    continue
                for line in q:
                    s = line.strip()
                    if s.startswith("WHERE ") and re.search(r"\b%s\." % re.escape(right), s) \
                            and not re.search(r"Null|\bor\b", s) and (right, s) not in reported:
                        reported.add((right, s))
                        out.append(finding("PRF-06", "Medium", "Correctness", "Where condition turns a Left Join into an Inner Join",
                                           mod, ctx.element(f) + " / Aggregate %s" % (n.get("name")),
                                           ctx.file_of(mod, f), "LEFT JOIN %s ~ %s, but %s" % (left, right, s),
                                           "Move the condition into the join or allow NULL (e.g. %s.Id = NullIdentifier() or ...)."
                                           % right))


def check_entities(ctx, out):
    for mod, m in ctx.models.items():
        for e in m["entities"]:
            blobs = [a["name"] for a in e["attributes"] if a["type"] == "Binary Data"]
            others = [a for a in e["attributes"] if a["type"] != "Binary Data"]
            if blobs and len(others) > 3:
                out.append(finding("PRF-07", "Medium", "Data model", "Binary data stored in a main entity", mod,
                                   "Entity %s" % e["name"], None,
                                   "binary attribute(s) %s next to %d other attributes" % (", ".join(blobs), len(others)),
                                   "Move the binary to a dedicated 1:1 entity (or external storage) so queries on %s do not "
                                   "read it." % e["name"]))


def check_round_trips(ctx, out):
    for mod, m, f in ctx.iter_flows():
        if f["kind"] not in ("ScreenAction", "ClientAction"):
            continue
        in_loop = set().union(*loop_bodies(f).values()) if loop_bodies(f) else set()
        calls = [n.get("action") for n in f["nodes"] if n["type"] == "ExecuteAction" and n["key"] not in in_loop]
        if len(calls) >= 3:
            out.append(finding("PRF-08", "Low", "Round trips", "Several sequential server calls from one client action", mod,
                               ctx.element(f), ctx.file_of(mod, f),
                               "%d server calls: %s" % (len(calls), ", ".join(calls[:6]) + (" ..." if len(calls) > 6 else "")),
                               "Wrap them in one server action so the screen makes a single request."))


def run(ctx):
    out = []
    for check in (check_loops, check_indexes, check_queries, check_entities, check_round_trips):
        check(ctx, out)
    return out


if __name__ == "__main__":
    write("performance", run(Context()))
