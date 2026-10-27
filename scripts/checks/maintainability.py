"""Maintainability rules over the extracted model (Indigo OS11 guidelines). Writes output/findings/maintainability.json.

Rules (ids are stable; the report groups by them):
  MNT-01 Flow too large or complex (cyclomatic complexity / node count; comments missing on complex logic)
  MNT-02 Documentation gaps (module, public actions, entities, attributes without description)
  MNT-03 Naming conventions (Timer_ prefix, PascalCase, foreign keys ending in Id, module suffix)
  MNT-04 Unused actions (no caller in the factory: flows, timers or UI widgets)
  MNT-05 Broken references (<unresolved> elements in the flows)
  MNT-06 Disconnected nodes left in flows
  MNT-07 Timer robustness (timeout control, resume position, kill switch, error handling)
  MNT-08 Duplicated logic (identical flows in several places)
  MNT-09 Hard-coded identifiers instead of static entities
  MNT-10 Too many input parameters
  MNT-11 Screen or block concentrating too much logic

Each module also gets a maintainability score (0-100, grade A-E); see score() for the formula.

Usage: python scripts/checks/maintainability.py
"""
import hashlib
import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Context, finding, write  # noqa: E402
from decompile_actions import FlowRenderer  # noqa: E402

LOGIC_KINDS = ("ServerAction", "ClientAction", "ScreenAction", "DataAction", "ServiceAPIMethod", "RESTMethod")
TEMPLATE_ACTIONS = re.compile(r"^(OfflineDataSync|OfflineDataSyncConfiguration|TriggerOfflineDataSync|ServerDataSync|"
                              r"DoLogout|DoLogin|OnApplicationReady|OnApplicationResume|OnException|"
                              r"CheckPermissions|GetUserInfo)$")
MODULE_SUFFIX = re.compile(r"_(Lib|IS|Drv|Th|Pat|CS|BL|CW|Eng|Sync|API|MCS|MBL|MCW|UI|BO|BackOffice|Bootstraps)$")
PASCAL = re.compile(r"^[A-Z][A-Za-z0-9]*(_[A-Za-z0-9]+)*$")
MAGIC_ID = re.compile(r"\b(\w*Id)\)? (=|<>) (\d+)\b")


def complexity(flow):
    cc = 1
    for n in flow.get("nodes", []):
        t = n["type"]
        if t in ("If", "ForEach", "ErrorHandler"):
            cc += 1
        if t == "Switch":
            cc += len(n.get("conds", {}))
        if t == "If":
            cc += len(re.findall(r"\b(and|or)\b", n.get("cond") or ""))
    return cc


def logic_nodes(flow):
    return [n for n in flow.get("nodes", []) if n["type"] not in ("Start", "End", "Comment")]


def text_of(flow):
    return json.dumps(flow.get("nodes", []), ensure_ascii=False)


def check_complexity(ctx, out, metrics):
    for mod, m, f in ctx.iter_flows():
        if f["kind"] not in LOGIC_KINDS:
            continue
        cc, size = complexity(f), len(logic_nodes(f))
        comments = sum(1 for n in f["nodes"] if n["type"] == "Comment")
        metrics[mod]["cc"].append(cc)
        if cc >= 25 or size >= 80:
            sev = "High"
        elif cc >= 15 or size >= 40:
            sev = "Medium"
        elif cc >= 10 or size >= 25:
            sev = "Low"
        else:
            continue
        loops = sum(1 for n in f["nodes"] if n["type"] == "ForEach")
        ifs = sum(1 for n in f["nodes"] if n["type"] in ("If", "Switch"))
        out.append(finding("MNT-01", sev, "Complexity", "Flow too large or complex", mod, ctx.element(f),
                           ctx.file_of(mod, f),
                           "cyclomatic complexity %d, %d nodes, %d decisions, %d loops, %s" % (
                               cc, size, ifs, loops, "%d comment(s)" % comments if comments else "no comments"),
                           "Split into smaller actions with one responsibility each (guideline: a flow fits on one screen); "
                           "comment the intent of complex branches."))


def check_documentation(ctx, out, metrics):
    for mod, m in ctx.models.items():
        layer = ctx.index["modules"][mod]["layer"]
        pub = [f for f in m["flows"] if f.get("public") and f["kind"] in LOGIC_KINDS]
        pub_nodesc = [f["name"] for f in pub if not f.get("description")]
        ents_nodesc = [e["name"] for e in m["entities"] if not e.get("description")]
        attrs = [a for e in m["entities"] for a in e["attributes"]]
        attrs_nodesc = [a for a in attrs if not a.get("description")]
        docs_total = 1 + len(pub) + len(m["entities"]) + len(attrs)
        docs_ok = (1 if m.get("description") else 0) + len(pub) - len(pub_nodesc) + len(m["entities"]) - len(ents_nodesc) \
            + len(attrs) - len(attrs_nodesc)
        metrics[mod]["documented"] = docs_ok / docs_total
        gaps = []
        if not m.get("description"):
            gaps.append("module has no description")
        if pub_nodesc:
            gaps.append("%d/%d public actions without description (%s%s)" % (
                len(pub_nodesc), len(pub), ", ".join(pub_nodesc[:5]), " ..." if len(pub_nodesc) > 5 else ""))
        if ents_nodesc:
            gaps.append("%d/%d entities without description (%s%s)" % (
                len(ents_nodesc), len(m["entities"]), ", ".join(ents_nodesc[:5]), " ..." if len(ents_nodesc) > 5 else ""))
        if attrs_nodesc:
            gaps.append("%d/%d entity attributes without description" % (len(attrs_nodesc), len(attrs)))
        if not gaps:
            continue
        # consumers depend on the descriptions of a shared (Core/Foundation) module's public API
        sev = "Medium" if layer != "End-User" and pub and len(pub_nodesc) > len(pub) / 2 else "Low"
        out.append(finding("MNT-02", sev, "Documentation", "Documentation gaps", mod, "Module %s" % mod, None,
                           "; ".join(gaps), "Describe the module, every public action and its parameters, entities and "
                                            "attributes (guideline: no empty descriptions)."))


def check_naming(ctx, out):
    for mod, m in ctx.models.items():
        issues = []
        if not MODULE_SUFFIX.search(mod):
            issues.append("module name has no standard suffix (_CS, _BL, _CW, _IS, _Lib, _Th, _API, _Sync...)")
        bad_timers = [t["action"] for t in m.get("timers", []) if t["action"] != "<unresolved>"
                      and not t["action"].split(".")[-1].startswith("Timer_")]
        if bad_timers:
            issues.append("timer actions without Timer_ prefix: " + ", ".join(bad_timers))
        not_pascal = sorted({f["name"] for f in m["flows"] if f["kind"] in ("ServerAction", "ClientAction", "ServiceAPIMethod")
                             and f["name"] and not PASCAL.match(f["name"]) and not TEMPLATE_ACTIONS.match(f["name"])}
                            | {e["name"] for e in m["entities"] if not PASCAL.match(e["name"] or "")})
        if not_pascal:
            issues.append("names not in PascalCase: " + ", ".join(not_pascal[:8]) + (" ..." if len(not_pascal) > 8 else ""))
        fks = ["%s.%s" % (e["name"], a["name"]) for e in m["entities"] for a in e["attributes"]
               if a["type"].endswith(" Identifier") and a["name"] != "Id" and not a["name"].endswith("Id")]
        if fks:
            issues.append("foreign keys not ending in Id: " + ", ".join(fks[:8]) + (" ..." if len(fks) > 8 else ""))
        if issues:
            out.append(finding("MNT-03", "Low", "Naming", "Naming conventions not followed", mod, "Module %s" % mod, None,
                               "; ".join(issues), "Follow the naming standard: PascalCase, EntityVerb for actions, "
                                                 "Timer_ prefix for timer actions, Id suffix for foreign keys, module suffixes."))


def check_unused(ctx, out, metrics):
    per_mod = defaultdict(lambda: {"public": [], "private": []})
    for fid, f in ctx.flows.items():
        if f["kind"] not in ("ServerAction", "ClientAction") or f["callers"] or TEMPLATE_ACTIONS.match(f["name"]):
            continue
        per_mod[f["module"]]["public" if f["public"] else "private"].append(f["name"])
    for mod, d in per_mod.items():
        n = len(d["public"]) + len(d["private"])
        metrics[mod]["unused"] = n
        parts = []
        if d["private"]:
            parts.append("%d private (certainly unused): %s" % (len(d["private"]), ", ".join(sorted(d["private"])[:10])
                                                                + (" ..." if len(d["private"]) > 10 else "")))
        if d["public"]:
            parts.append("%d public (no consumer in the analysed modules): %s" % (
                len(d["public"]), ", ".join(sorted(d["public"])[:10]) + (" ..." if len(d["public"]) > 10 else "")))
        out.append(finding("MNT-04", "Medium" if n >= 15 else "Low", "Dead code", "Unused actions", mod, "Module %s" % mod,
                           None, "; ".join(parts),
                           "Delete private actions that are never called; for public ones confirm in Service Center "
                           "(Dependencies) that no application outside this export uses them, then deprecate and remove."))


def check_broken(ctx, out, metrics):
    for mod, m in ctx.models.items():
        broken = []
        for f in m["flows"] + m["screens"]:
            n = text_of(f).count("<unresolved")
            if n:
                broken.append((f, n))
        unreachable = []
        for f in m["flows"]:
            r = FlowRenderer(f)
            r.render()
            left = [k for k, n in r.nodes.items() if k not in r.done and n["type"] not in ("Comment",)]
            if left and f["kind"] in LOGIC_KINDS:
                unreachable.append((f, len(left)))
        dead_timers = [t["name"] for t in m.get("timers", []) if t["action"] == "<unresolved>"]
        metrics[mod]["unresolved"] = sum(n for _, n in broken) + len(dead_timers)
        metrics[mod]["unreachable"] = len(unreachable)
        if broken or dead_timers:
            parts = []
            if broken:
                parts.append("%d unresolved reference(s) in %d element(s): %s" % (
                    sum(n for _, n in broken), len(broken),
                    ", ".join("%s (%d)" % (f["name"], n) for f, n in broken[:8]) + (" ..." if len(broken) > 8 else "")))
            if dead_timers:
                parts.append("%d timer(s) whose action was deleted: %s" % (len(dead_timers), ", ".join(dead_timers)))
            out.append(finding("MNT-05", "Medium", "Broken references", "Broken references in flows", mod, "Module %s" % mod,
                               ctx.file_of(mod, broken[0][0]) if broken else None, "; ".join(parts),
                               "Open the module in Service Studio, refresh dependencies and fix or remove the elements that "
                               "point to deleted entities, structures or actions."))
        if unreachable:
            out.append(finding("MNT-06", "Low", "Dead code", "Disconnected nodes left in flows", mod, "Module %s" % mod,
                               ctx.file_of(mod, unreachable[0][0]),
                               "%d flow(s) with nodes not connected to the flow: %s" % (
                                   len(unreachable), ", ".join("%s (%d)" % (f["name"], n) for f, n in unreachable[:8])
                                   + (" ..." if len(unreachable) > 8 else "")),
                               "Remove the disconnected nodes or connect them; they confuse readers and hide unfinished changes."))


def check_timers(ctx, out, metrics):
    for mod, m in ctx.models.items():
        flows = {f["name"]: f for f in m["flows"]}
        sps = [sp["name"] for sp in m.get("siteProperties", [])]
        for t in m.get("timers", []):
            f = flows.get(t["action"])
            if not f:
                continue
            txt = text_of(f)
            local_types = {v["name"]: v["type"] for v in f.get("locals", [])}
            issues = []
            loops = any(n["type"] == "ForEach" for n in f["nodes"])
            checks = [n.get("cond") or "" for n in f["nodes"] if n["type"] == "If" and re.search(r"Diff(Seconds|Minutes)", n.get("cond") or "")]
            for c in checks:
                mm = re.search(r"Diff(?:Seconds|Minutes)\((\w+), CurrDateTime\(\)\)\s*<", c)
                if mm and local_types.get(mm.group(1)) == "Time":
                    issues.append(("High", "timeout check never fires: %s is a Time variable, so it is compared with "
                                           "1900-01-01 (%s)" % (mm.group(1), c)))
                elif mm:
                    issues.append(("High", "timeout check has its arguments inverted and fires on the first iteration (%s)" % c))
            if loops and not checks:
                issues.append(("Medium", "loops over records with no elapsed-time check before the %s-minute timeout" % t.get("timeout")))
            for n in f["nodes"]:
                if n["type"] == "ForEach" and n.get("startIndex") in local_types:
                    if "WakeTimer" in txt:
                        issues.append(("Medium", "resume position %s is a local variable, so after WakeTimer the timer "
                                                 "restarts from the beginning (duplicates)" % n["startIndex"]))
            if not any(sp in txt for sp in sps):
                issues.append(("Low", "no kill switch (no site property checked)"))
            if not any(n["type"] == "ErrorHandler" for n in f["nodes"]):
                issues.append(("Low", "no exception handler"))
            if not issues:
                continue
            sev = min((s for s, _ in issues), key=["Critical", "High", "Medium", "Low", "Info"].index)
            if sev in ("High", "Medium"):
                metrics[mod]["timerIssues"] += 1
            out.append(finding("MNT-07", sev, "Timers", "Timer robustness", mod, "Timer %s -> %s" % (t["name"], t["action"]),
                               ctx.file_of(mod, f), "; ".join(i for _, i in issues),
                               "Store the timeout as DateTime = AddMinutes(CurrDateTime(), N) and stop when "
                               "DiffMinutes(CurrDateTime(), TimeOut) < 1; save progress in an entity/site property before "
                               "WakeTimer; add a kill-switch site property and an exception handler that logs."))


def check_duplicates(ctx, out, metrics):
    groups = defaultdict(list)
    for mod, m, f in ctx.iter_flows():
        if f["kind"] not in LOGIC_KINDS or len(logic_nodes(f)) < 8 or TEMPLATE_ACTIONS.match(f["name"] or ""):
            continue
        body = "\n".join(FlowRenderer(f).render())
        groups[hashlib.sha1(body.encode("utf-8")).hexdigest()].append((mod, f))
    for g in groups.values():
        if len(g) < 2:
            continue
        for mod, _ in g:
            metrics[mod]["duplicated"] += 1
        mod, f = g[0]
        where = [ctx.label(gm, gf) for gm, gf in g]
        out.append(finding("MNT-08", "Medium" if len(g) >= 3 else "Low", "Duplication", "Duplicated logic", mod,
                           ctx.element(f), ctx.file_of(mod, f),
                           "%d identical copies (%d nodes): %s" % (len(g), len(logic_nodes(f)), ", ".join(where)),
                           "Keep one implementation in the right module (a Core action or a reusable block/client action) "
                           "and call it from the others."))


def check_magic_and_params(ctx, out):
    for mod, m, f in ctx.iter_flows():
        if f["kind"] not in LOGIC_KINDS:
            continue
        hits = set()
        for n in f["nodes"]:
            for v in [n.get("cond") or ""] + [a[1] or "" for a in (n.get("assign") or []) + (n.get("args") or [])] \
                    + n.get("query", []):
                for mm in MAGIC_ID.finditer(v):
                    hits.add(mm.group(0))
        if hits:
            out.append(finding("MNT-09", "Low", "Hard-coded values", "Hard-coded identifiers instead of static entities", mod,
                               ctx.element(f), ctx.file_of(mod, f), ", ".join(sorted(hits)),
                               "Compare with static entity records (Entities.X.Y) instead of numeric ids, which differ "
                               "between environments."))
        ins = f.get("inputs", [])
        if len(ins) > 8:
            out.append(finding("MNT-10", "Low", "Design", "Too many input parameters", mod, ctx.element(f),
                               ctx.file_of(mod, f), "%d inputs: %s" % (len(ins), ", ".join(i["name"] for i in ins)),
                               "Group related inputs in a structure or split the action by responsibility."))


def check_screens(ctx, out):
    for mod, m in ctx.models.items():
        per_screen = defaultdict(list)
        for f in m["flows"]:
            if f.get("screen"):
                per_screen[f["screen"]].append(f)
        for s in m["screens"]:
            fl = per_screen.get(s["key"], [])
            aggs = sum(1 for n in s.get("nodes", []) if n["type"] in ("WebScreenDataSet", "DataSet"))
            nodes = sum(len(logic_nodes(f)) for f in fl)
            if len(fl) >= 30 or aggs >= 15 or nodes >= 300:
                out.append(finding("MNT-11", "Medium" if nodes >= 500 or len(fl) >= 50 else "Low", "Design",
                                   "Screen or block concentrating too much logic", mod,
                                   "%s %s" % (s["kind"], s["name"]), ctx.file_of(mod, s),
                                   "%d actions, %d aggregates, %d logic nodes" % (len(fl), aggs, nodes),
                                   "Move business logic to server actions and split the UI into blocks with their own data."))


def score(mt, n_flows):
    """0-100: documentation 25, complexity 20, unused code 15, broken refs 15, duplication 10, timers 10, disconnected 5."""
    ccs = mt["cc"] or [1]
    s = 100.0
    s -= 25 * (1 - mt.get("documented", 1))
    s -= min(20, 100 * sum(1 for c in ccs if c >= 10) / len(ccs))
    s -= min(15, 50 * mt.get("unused", 0) / max(n_flows, 1))
    s -= min(15, mt.get("unresolved", 0))
    s -= min(10, 50 * mt.get("duplicated", 0) / max(n_flows, 1))
    s -= min(10, 5 * mt.get("timerIssues", 0))
    s -= min(5, mt.get("unreachable", 0))
    s = max(0, round(s))
    grade = "A" if s >= 85 else "B" if s >= 70 else "C" if s >= 55 else "D" if s >= 40 else "E"
    return s, grade


def run(ctx):
    out = []
    metrics = defaultdict(lambda: {"cc": [], "unused": 0, "unresolved": 0, "duplicated": 0, "timerIssues": 0,
                                   "unreachable": 0})
    for check in (check_complexity, check_documentation, check_unused, check_broken, check_timers, check_duplicates):
        check(ctx, out, metrics)
    check_naming(ctx, out)
    check_magic_and_params(ctx, out)
    check_screens(ctx, out)
    modules = {}
    for mod, m in ctx.models.items():
        mt = metrics[mod]
        n_flows = sum(1 for f in m["flows"] if f["kind"] in LOGIC_KINDS)
        sc, grade = score(mt, n_flows)
        ccs = mt["cc"] or [1]
        modules[mod] = {"layer": ctx.index["modules"][mod]["layer"], "flows": n_flows, "screens": len(m["screens"]),
                        "entities": len(m["entities"]), "avgCC": round(sum(ccs) / len(ccs), 1), "maxCC": max(ccs),
                        "complexFlows": sum(1 for c in ccs if c >= 10), "documented": round(100 * mt.get("documented", 1)),
                        "unused": mt["unused"], "unresolved": mt["unresolved"], "duplicated": mt["duplicated"],
                        "timerIssues": mt["timerIssues"], "score": sc, "grade": grade}
    return out, modules


if __name__ == "__main__":
    c = Context()
    findings, modules = run(c)
    path = write("maintainability", findings)
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    data["modules"] = modules
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1)
