"""Render the extracted model (output/model/*.json) as readable pseudocode.

Writes output/code/<Module>/:
  _module.txt                  module summary: references, entities, structures, site properties, timers, index
  <Kind>/<Name>.txt            one file per server/client/service action
  Screens/<Flow>.<Screen>.txt  one file per screen or block, with its aggregates, data actions and screen actions

Flows are structured from the node graph: If/Switch branches are nested until they re-join, ForEach bodies
are indented, and anything reached twice becomes a "goto". Callers (local actions and timers) are listed.

Usage: python scripts/decompile_actions.py [model_dir] [code_dir] [--only Module1,Module2]
"""
import json
import os
import re
import sys
from collections import defaultdict, deque

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(HERE, "..", "output", "model")
CODE_DIR = os.path.join(HERE, "..", "output", "code")

KIND_DIRS = {"ServerAction": "ServerActions", "ClientAction": "ClientActions", "ServiceAPIMethod": "ServiceAPI",
             "CustomAction": "CustomActions", "Callback": "Callbacks", "ExceptionFlow": "ExceptionFlows",
             "Process": "Processes", "Activity": "Processes", "Decision": "Processes", "Preparation": "Preparations",
             "EmailPreparation": "Preparations", "OnClose": "Processes", "RESTMethod": "REST",
             "RESTAuthentication": "REST"}
IND = "    "


def safe(name):
    return re.sub(r'[<>:"/\\|?*\s]+', "_", name or "unnamed")[:120]


def flow_rel(f):
    """Path (relative to the module folder) of a non-screen flow's pseudocode file."""
    nm = f["name"]
    if f["kind"].startswith("REST") and f.get("path"):  # method names repeat across REST services
        nm = f["path"] + "." + nm
    return "%s/%s.txt" % (KIND_DIRS.get(f["kind"], "Other"), safe(nm))


def node_label(n):
    return "%s %s" % (n["type"], n.get("name", "")) if n.get("name") else n["type"]


def args_text(n):
    return ", ".join("%s: %s" % (p, v if v is not None else "") for p, v in n.get("args", []))


def node_lines(n):
    """Text for a single (non-branching) node."""
    t = n["type"]
    name = n.get("name")
    if t == "Assign":
        head = ["// %s" % name] if name and not any(name == a[0] for a in n.get("assign", [])) else []
        return head + ["%s = %s" % (v, e) for v, e in n.get("assign", [])]
    if t in ("ExecuteAction", "ExecuteClientAction"):
        prefix = "%s = " % name if name and name != n.get("action", "").split(".")[-1] else ""
        return ["%s%s(%s)" % (prefix, n.get("action", "?"), args_text(n))]
    if t in ("DataSet", "WebScreenDataSet", "ViewEntityDataDataSet"):
        extra = ", ".join("%s=%s" % (k, n[k]) for k in ("maxRecords", "startIndex") if n.get(k))
        out = ["Aggregate %s%s  -> %s" % (name or "", " (%s)" % extra if extra else "", n.get("out_type", ""))]
        out += [IND + q for q in n.get("query", [])]
        return out
    if t == "AdvancedQuery":
        params = ", ".join("%s: %s%s" % (p, ty, " [ExpandInline]" if inl else "") for p, ty, inl in n.get("params", []))
        out = ["SQL %s(%s)%s  -> %s" % (name or "", params, " maxRecords=%s" % n["maxRecords"] if n.get("maxRecords") else "",
                                       n.get("out_type", ""))]
        if n.get("args"):
            out.append(IND + "args: " + args_text(n))
        out += [IND + l.rstrip() for l in n.get("sql", "").splitlines() if l.strip()]
        return out
    if t == "RaiseError":
        return ["Raise %s(%s)" % (n.get("exception"), n.get("message") or "")]
    if t == "RefreshQuery":
        return ["Refresh %s" % n.get("target")]
    if t == "JavascriptNode":
        out = ["JavaScript %s(%s):" % (name or "", args_text(n))]
        return out + [IND + l for l in (n.get("js") or "").splitlines() if l.strip()]
    if t in ("End", "Start"):
        return [t]
    if t == "Comment":
        return ["// " + n.get("text", "").replace("\n", " ")]
    bits = [node_label(n)]
    for k in ("destination", "event", "target", "screen"):
        if n.get(k):
            bits.append("%s=%s" % (k, n[k]))
    for k, v in n.get("fields", {}).items():
        bits.append("%s=%s" % (k, v))
    if n.get("args"):
        bits.append("(%s)" % args_text(n))
    return [" ".join(bits)]


class FlowRenderer:
    def __init__(self, flow):
        self.nodes = {n["key"]: n for n in flow.get("nodes", [])}
        self.out = []
        self.done = set()

    def succ(self, k):
        return [l[1] for l in self.nodes[k]["links"] if l[1] in self.nodes] if k in self.nodes else []

    def reach(self, start, stop):
        order, seen, q = [], set(), deque([start])
        while q:
            k = q.popleft()
            if k is None or k in seen or k in stop or k not in self.nodes:
                continue
            seen.add(k)
            order.append(k)
            q.extend(self.succ(k))
        return order

    def join_of(self, targets, stop):
        targets = [t for t in targets if t]
        if len(targets) < 2:
            return None
        reaches = [self.reach(t, stop) for t in targets]
        others = [set(r) for r in reaches[1:]]
        for k in reaches[0]:
            if all(k in o for o in others):
                return k
        return None

    def emit(self, k, stop, depth):
        while k is not None and k not in stop:
            n = self.nodes.get(k)
            if n is None:
                self.line(depth, "?? missing node %s" % k)
                return
            if k in self.done:
                self.line(depth, "goto %s" % node_label(n))
                return
            self.done.add(k)
            t = n["type"]
            links = n["links"]
            if t == "If":
                tk = next((l[1] for l in links if l[0] == "True"), None)
                fk = next((l[1] for l in links if l[0] == "False"), None)
                j = self.join_of([tk, fk], stop)
                self.line(depth, "If %s%s:" % (n.get("cond"), "   // " + n["name"] if n.get("name") else ""))
                self.branch(tk, stop | {j}, depth + 1)
                self.line(depth, "Else:")
                self.branch(fk, stop | {j}, depth + 1)
                k = j
                continue
            if t == "Switch":
                conds = n.get("conds", {})
                branches = [(conds.get(l[2], "?"), l[1]) for l in links if l[0] == "Condition"]
                other = next((l[1] for l in links if l[0] == "Otherwise"), None)
                j = self.join_of([b for _, b in branches] + [other], stop)
                self.line(depth, "Switch%s:" % (" // " + n["name"] if n.get("name") else ""))
                for c, b in branches:
                    self.line(depth + 1, "Case %s:" % c)
                    self.branch(b, stop | {j}, depth + 2)
                self.line(depth + 1, "Otherwise:")
                self.branch(other, stop | {j}, depth + 2)
                k = j
                continue
            if t == "ForEach":
                body = next((l[1] for l in links if l[0] == "Cycle"), None)
                after = next((l[1] for l in links if l[0] == "Sequence"), None)
                extra = ", ".join("%s=%s" % (x, n[x]) for x in ("startIndex", "maximum") if n.get(x))
                self.line(depth, "ForEach %s%s:" % (n.get("list"), " (%s)" % extra if extra else ""))
                self.emit(body, stop | {k} | ({after} if after else set()), depth + 1)
                k = after
                continue
            if t != "Start":
                for l in node_lines(n):
                    self.line(depth, l)
            if t in ("End", "RaiseError"):
                return
            nxt = [l[1] for l in links if l[0] in ("Sequence", "Navigation", "Named")]
            k = nxt[0] if nxt else None

    def branch(self, k, stop, depth):
        if k in stop and self.nodes.get(k, {}).get("type") == "ForEach":
            self.line(depth, "continue  // next iteration")
        elif k is None or k in stop:
            self.line(depth, "(nothing)")
        else:
            self.emit(k, stop, depth)

    def line(self, depth, text):
        self.out.append(IND * depth + text)

    def render(self):
        starts = [k for k, n in self.nodes.items() if n["type"] == "Start"]
        for c in (n for n in self.nodes.values() if n["type"] == "Comment"):
            self.line(0, "// " + c.get("text", "").replace("\n", " "))
            self.done.add(c["key"])
        for s in starts:
            self.emit(s, frozenset(), 0)
        for h in (n for n in self.nodes.values() if n["type"] == "ErrorHandler"):
            self.done.add(h["key"])
            self.line(0, "")
            self.line(0, "On %s%s%s:" % (h.get("exception"), "" if h.get("abortTransaction") else " (no abort)",
                                          "" if h.get("logError") else " (no log)"))
            nxt = [l[1] for l in h["links"]]
            self.emit(nxt[0] if nxt else None, frozenset(), 1)
        if not starts:
            # screens/blocks: list their nodes (aggregates etc.) flat
            for n in self.nodes.values():
                if n["key"] not in self.done:
                    self.done.add(n["key"])
                    for l in node_lines(n):
                        self.line(0, l)
        left = [node_label(n) for k, n in self.nodes.items() if k not in self.done]
        if left:
            self.line(0, "")
            self.line(0, "// unreachable: " + ", ".join(left))
        return self.out


def vars_lines(f):
    out = []
    for key, label in (("inputs", "in"), ("outputs", "out"), ("locals", "local")):
        for v in f.get(key, []):
            s = "  %-5s %s: %s" % (label, v["name"], v["type"])
            if v.get("mandatory") and key == "inputs":
                s += " (mandatory)"
            if v.get("default"):
                s += " = " + v["default"]
            out.append(s)
    return out


def flow_text(f, callers):
    flags = [x for x in ("public", "isFunction", "anonymous") if f.get(x)]
    head = "%s %s%s" % (f["kind"], f["name"], "  [%s]" % ", ".join(flags) if flags else "")
    out = [head]
    if f.get("path"):
        out.append("  path: " + f["path"])
    if f.get("roles"):
        out.append("  roles: " + ", ".join(f["roles"]))
    if f.get("props"):
        out.append("  props: " + ", ".join("%s=%s" % kv for kv in f["props"].items()))
    if f.get("description"):
        out.append("  // " + f["description"].replace("\n", " "))
    cs = callers.get(f["key"])
    if cs:
        out.append("  called by: " + ", ".join(sorted(set(cs))))
    out += vars_lines(f)
    out.append("")
    out += [IND + l if l else "" for l in FlowRenderer(f).render()]
    return out


def module_text(m, flows_index):
    out = ["Module %s  (%s)  file=%s" % (m["module"], m.get("espaceType"), m["file"]), ""]
    if m.get("references"):
        out.append("References: " + ", ".join(m["references"]))
    for t in m.get("timers", []):
        out.append("Timer %s -> %s  schedule=%s timeout=%s" % (t["name"], t["action"], t.get("schedule") or "(none)", t.get("timeout")))
    for p in m.get("siteProperties", []):
        out.append("SiteProperty %s: %s%s" % (p["name"], p["type"], " = " + p["default"] if p.get("default") else ""))
    if m.get("roles"):
        out.append("Roles: " + ", ".join(m["roles"]))
    if m.get("exceptions"):
        out.append("Exceptions: " + ", ".join(m["exceptions"]))
    for e in m.get("entities", []):
        out.append("")
        out.append("Entity %s%s%s" % (e["name"], "  [public]" if e.get("public") else "",
                                      "  static: " + ", ".join(map(str, e["staticRecords"])) if e.get("staticRecords") else ""))
        for a in e["attributes"]:
            out.append("  %s: %s%s%s" % (a["name"], a["type"], "(%s)" % a["length"] if a.get("length") else "",
                                         " mandatory" if a.get("mandatory") else ""))
        for ix in e["indexes"]:
            out.append("  index %s%s (%s)" % (ix["name"], " unique" if ix.get("unique") else "", ", ".join(map(str, ix["cols"]))))
    for s in m.get("structures", []):
        out.append("")
        out.append("Structure %s%s: %s" % (s["name"], "  [public]" if s.get("public") else "",
                                           ", ".join("%s: %s" % (a["name"], a["type"]) for a in s["attributes"])))
    out.append("")
    out.append("Files:")
    out += ["  " + l for l in sorted(flows_index)]
    return out


def decompile_module(m, code_dir):
    mdir = os.path.join(code_dir, m["module"])
    os.makedirs(mdir, exist_ok=True)
    callers = defaultdict(list)
    for f in m["flows"] + m["screens"]:
        for n in f.get("nodes", []):
            if n.get("action_key"):
                callers[n["action_key"]].append(f["name"])
    for t in m.get("timers", []):
        if t.get("actionKey"):
            callers[t["actionKey"]].append("Timer " + t["name"])

    index = []
    by_screen = defaultdict(list)
    for f in m["flows"]:
        if f.get("screen"):
            by_screen[f["screen"]].append(f)
            continue
        rel = flow_rel(f)
        index.append("%s%s" % (rel, "  [public]" if f.get("public") else ""))
        os.makedirs(os.path.dirname(os.path.join(mdir, rel)), exist_ok=True)
        with open(os.path.join(mdir, rel), "w", encoding="utf-8") as fh:
            fh.write("\n".join(flow_text(f, callers)) + "\n")
    for s in m["screens"]:
        rel = os.path.join("Screens" if s["kind"] != "Block" else "Blocks",
                           safe((s["path"] + "." if s.get("path") else "") + s["name"]) + ".txt")
        index.append(rel.replace(os.sep, "/") + ("  [anonymous]" if s.get("anonymous") else ""))
        os.makedirs(os.path.dirname(os.path.join(mdir, rel)), exist_ok=True)
        out = flow_text(s, callers)
        for f in sorted(by_screen.get(s["key"], []), key=lambda x: (x["kind"], x["name"] or "")):
            out += ["", "-" * 80] + flow_text(f, callers)
        with open(os.path.join(mdir, rel), "w", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
    with open(os.path.join(mdir, "_module.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(module_text(m, index)) + "\n")
    return len(index)


def decompile_factory(model_dir=MODEL_DIR, code_dir=CODE_DIR, only=None):
    files = sorted(f for f in os.listdir(model_dir) if f.endswith(".json") and not f.startswith("_"))
    if only:
        files = [f for f in files if f[:-5] in only]
    total = 0
    for f in files:
        with open(os.path.join(model_dir, f), encoding="utf-8") as fh:
            m = json.load(fh)
        try:
            total += decompile_module(m, code_dir)
        except Exception as exc:  # keep going; one bad module should not stop the rest
            print("FAIL %s %r" % (f, exc), flush=True)
    print("Wrote %d files for %d module(s) to %s" % (total, len(files), os.path.abspath(code_dir)), flush=True)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    only = None
    if "--only" in sys.argv:
        val = sys.argv[sys.argv.index("--only") + 1]
        only = set(val.split(","))
        args = [a for a in args if a != val]
    decompile_factory(*(args[:2]), only=only)
