"""Build the factory-wide index from output/model/*.json.

Writes output/index.json:
  modules:  {Module: {layer, kind, espaceType, references, consumers, counts}}
  flows:    {"Module.Name": {module, kind, name, public, file, callers: ["Module.Flow", ...]}}
  timers:   [{module, name, action, schedule}]
so checks and reports can answer "who calls this", "which layer is this" and "where is its pseudocode"
without reloading every model.

Usage: python scripts/build_index.py [model_dir] [index_json]
"""
import json
import os
import sys
from collections import defaultdict

import analyze_factory as af
from decompile_actions import flow_rel, safe

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(HERE, "..", "output", "model")
INDEX_JSON = os.path.join(HERE, "..", "output", "index.json")


def load_models(model_dir=MODEL_DIR):
    models = {}
    for f in sorted(os.listdir(model_dir)):
        if f.endswith(".json") and not f.startswith("_"):
            with open(os.path.join(model_dir, f), encoding="utf-8") as fh:
                m = json.load(fh)
            models[m["module"]] = m
    return models


def code_file(module, flow, screens_by_key=None):
    """Relative path (under output/code) of the pseudocode file holding this flow or screen."""
    if flow["kind"] in ("Screen", "Block", "Email"):
        sub = "Blocks" if flow["kind"] == "Block" else "Screens"
        return "%s/%s/%s.txt" % (module, sub, safe((flow["path"] + "." if flow.get("path") else "") + flow["name"]))
    if flow.get("screen") and screens_by_key and flow["screen"] in screens_by_key:
        return code_file(module, screens_by_key[flow["screen"]])
    return "%s/%s" % (module, flow_rel(flow))


def build(models):
    idx = {"modules": {}, "flows": {}, "timers": []}
    consumers = defaultdict(set)
    for name, m in models.items():
        for r, d in m.get("dependencies", {}).items():
            if r in models and r != name and d["uses"]:
                consumers[r].add(name)
    for name, m in models.items():
        screens = [s for s in m["screens"] if s["kind"] == "Screen"]
        idx["modules"][name] = {
            "layer": af.classify(name, {"screens": screens}), "kind": af.kind_of(name),
            "espaceType": m.get("espaceType"), "description": m.get("description"),
            "references": sorted(r for r, d in m.get("dependencies", {}).items() if r in models and r != name and d["uses"]),
            "unusedReferences": sorted(r for r, d in m.get("dependencies", {}).items() if r != name and not d["uses"]),
            "externalReferences": sorted(r for r in m.get("references", []) if r not in models),
            "consumers": sorted(consumers[name]),
            "counts": {"screens": len(screens), "blocks": sum(1 for s in m["screens"] if s["kind"] == "Block"),
                       "flows": len(m["flows"]), "entities": len(m["entities"]),
                       "restExposed": len(m.get("restExposed", [])), "restConsumed": len(m.get("restConsumed", [])),
                       "timers": len(m.get("timers", []))},
        }
        by_key = {s["key"]: s for s in m["screens"]}
        for f in m["flows"] + m["screens"]:
            fid = "%s.%s" % (name, f["name"])
            idx["flows"].setdefault(fid, {"module": name, "kind": f["kind"], "name": f["name"],
                                          "public": bool(f.get("public")), "file": code_file(name, f, by_key),
                                          "callers": []})
        for t in m.get("timers", []):
            idx["timers"].append({"module": name, "name": t["name"], "action": t["action"], "schedule": t.get("schedule")})

    # call graph: local calls use the bare action name, cross-module calls "Producer.Action"
    for name, m in models.items():
        for f in m["flows"] + m["screens"]:
            caller = "%s.%s" % (name, f["name"])
            for n in f.get("nodes", []):
                a = n.get("action")
                if not a or n.get("action_ref", "").startswith(("EntityActions", "RoleActions", "TimerActions")):
                    continue
                target = a if a.split(".")[0] in models else "%s.%s" % (name, a)
                if target in idx["flows"]:
                    idx["flows"][target]["callers"].append(caller)
        for t in m.get("timers", []):
            target = t["action"] if t["action"].split(".")[0] in models else "%s.%s" % (name, t["action"])
            if target in idx["flows"]:
                idx["flows"][target]["callers"].append("%s.Timer %s" % (name, t["name"]))
        for target in m.get("widgetUses", []):
            if target in idx["flows"]:
                idx["flows"][target]["callers"].append("%s (UI widget)" % name)
    for f in idx["flows"].values():
        f["callers"] = sorted(set(f["callers"]))
    return idx


def main(model_dir=MODEL_DIR, index_json=INDEX_JSON):
    idx = build(load_models(model_dir))
    with open(index_json, "w", encoding="utf-8") as fh:
        json.dump(idx, fh, ensure_ascii=False, indent=1)
    print("Wrote %s: %d modules, %d flows" % (index_json, len(idx["modules"]), len(idx["flows"])), flush=True)


if __name__ == "__main__":
    main(*sys.argv[1:3])
