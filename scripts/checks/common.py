"""Shared plumbing for the rule checks (checks/<pillar>.py).

Every check produces findings with the same shape, written to output/findings/<pillar>.json:
  {rule, severity, category, title, module, element, file, evidence, recommendation}
`file` is the pseudocode path under output/code, so a report (or a person) can open the exact flow.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)
OUTPUT = os.path.join(SCRIPTS, "..", "output")
sys.path.insert(0, SCRIPTS)

from build_index import code_file, load_models  # noqa: E402

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]


class Context:
    """Models + index, plus lookups the rules share."""

    def __init__(self, output=OUTPUT):
        self.models = load_models(os.path.join(output, "model"))
        with open(os.path.join(output, "index.json"), encoding="utf-8") as fh:
            self.index = json.load(fh)
        self.flows = self.index["flows"]
        self._screens = {}

    def flow_id(self, module, flow):
        return "%s.%s" % (module, flow["name"])

    def file_of(self, module, flow):
        """Pseudocode path of this exact flow (screen actions with the same name live in different screen files)."""
        if flow is None:
            return None
        if module not in self._screens:
            self._screens[module] = {s["key"]: s for s in self.models[module]["screens"]}
        return code_file(module, flow, self._screens[module])

    @staticmethod
    def element(flow):
        """'<Kind> [Flow.Screen.]Name' for a finding's element column."""
        return "%s %s%s" % (flow["kind"], flow["path"] + "." if flow.get("path") else "", flow["name"])

    def label(self, module, flow):
        """Module.[Flow.Screen.]Name, unique enough to tell same-named screen actions apart."""
        return "%s.%s%s" % (module, flow["path"] + "." if flow.get("path") else "", flow["name"])

    def callers_upstream(self, fid, depth=4):
        """All flows that reach fid through calls, up to depth levels (breadth-first)."""
        seen, frontier = set(), [fid]
        for _ in range(depth):
            nxt = []
            for f in frontier:
                for c in self.flows.get(f, {}).get("callers", []):
                    if c not in seen:
                        seen.add(c)
                        nxt.append(c)
            frontier = nxt
        return seen

    def iter_flows(self):
        for name, m in self.models.items():
            for f in m["flows"] + m["screens"]:
                yield name, m, f

    def iter_nodes(self):
        for name, m, f in self.iter_flows():
            for n in f.get("nodes", []):
                yield name, m, f, n


def finding(rule, severity, category, title, module, element, file=None, evidence="", recommendation=""):
    assert severity in SEVERITIES, severity
    return {"rule": rule, "severity": severity, "category": category, "title": title, "module": module,
            "element": element, "file": file, "evidence": evidence, "recommendation": recommendation}


def lower(severity, steps=1):
    return SEVERITIES[min(SEVERITIES.index(severity) + steps, len(SEVERITIES) - 1)]


def mask(value):
    """Never copy a secret into a report: keep the first 2 characters and the length."""
    v = str(value).strip('"')
    return (v[:2] + "*" * max(len(v) - 2, 3)) if v else v


def mask_literals(expr):
    return re.sub(r'"([^"]{4,})"', lambda m: '"%s"' % mask(m.group(1)), expr or "")


def write(pillar, findings, output=OUTPUT):
    findings.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["rule"], f["module"], f["element"]))
    d = os.path.join(output, "findings")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, pillar + ".json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"pillar": pillar, "findings": findings}, fh, ensure_ascii=False, indent=1)
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    print("Wrote %s: %s" % (os.path.abspath(path), ", ".join("%s %d" % kv for kv in counts.items())), flush=True)
    return path
