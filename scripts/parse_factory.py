"""Extract architecture facts from OutSystems OML XML exports.

Reads every module XML in input/ and writes output/factory_data.json with, per module:
references (producer modules + the elements consumed), entities/attributes/indexes,
server/client actions (public flag, complexity), screens/blocks (widget depth),
aggregate + Advanced SQL filters and local/external usage counters.

Usage: python scripts/parse_factory.py [input_dir] [output_json]
"""
import json
import os
import re
import sys
import threading
import xml.etree.ElementTree as ET
from collections import Counter
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(HERE, "..", "input")
OUTPUT_JSON = os.path.join(HERE, "..", "output", "factory_data.json")

K = r"[A-Za-z0-9_+\-]{22}"
RE_REF_ENT = re.compile(rf"References\.({K})/ReferenceEntities\.({K})(?:/Attributes\.({K}))?")
RE_REF_ACT = re.compile(rf"References\.({K})/ReferenceActions\.({K})")
RE_REF_CACT = re.compile(rf"References\.({K})/ReferenceClientActions\.({K})")
RE_REF_BLK = re.compile(rf"References\.({K})/ReferenceNRWebFlows\.{K}/ReferenceWebBlocks\.({K})")
RE_REF_ANY = re.compile(rf"References\.({K})/")
RE_ENT = re.compile(rf"(?<![A-Za-z])/Entities\.({K})(?:/Attributes\.({K}))?")
RE_LOCAL_ACT = re.compile(rf"^Flows\.UserAction\w*:/UserActions\.({K})$")
RE_LOCAL_CACT = re.compile(rf"^NRFlows\.\w+:/ClientActionFlows\.({K})$")
RE_LOCAL_BLK = re.compile(rf"^NRNodes\.WebBlock:.*\.({K})$")

SKIP_TAGS = {
    "CompilationUnits", "ElementSignatures", "ServiceStudioData", "Referers", "SharedReferers",
    "RebindData", "TopLevelReferenceableElementsWithInvalidSignature",
    "TopLevelReferenceableElementsThatDontNeedSignature", "AnonymousTypesNames",
    "ReferedAnonymousTypesByObject", "VerifyCache", "VerifyMessages", "ChildCache", "Usage",
    "Flows.EntityDiagram", "EntityDiagrams", "Nodes.DiagramEntity", "TestAttributeValues", "AttributesInPreview",
}
SERVER_ACTIONS = {"Flows.UserAction", "Flows.UserActionInsideFolder"}
CLIENT_ACTIONS = {
    "NRFlows.ClientActionFlow", "NRFlows.ClientActionFlowInsideFolder",
    "NRFlows.ClientScreenActionFlow", "NRFlows.DataScreenActionFlow",
}
PUBLIC_KINDS = {
    "Entity": "entity", "Flows.UserAction": "server action", "Flows.UserActionInsideFolder": "server action",
    "NRFlows.ClientActionFlow": "client action", "NRFlows.ClientActionFlowInsideFolder": "client action",
    "Structure": "structure", "NRNodes.WebBlock": "ui block", "NRNodes.WebScreen": "screen",
    "Variables.SiteProperty": "site property",
}
STRUCTURAL_WIDGETS = {"NRWebWidgets.PlaceholderArgument", "NRWebWidgets.IfBranch"}
SQL_STOP = re.compile(r"\b(GROUP\s+BY|ORDER\s+BY|HAVING|UNION|OFFSET|FETCH|FOR\s+XML|OPTION)\b", re.I)
SQL_KEYWORDS = {"WHERE", "ON", "LEFT", "RIGHT", "INNER", "OUTER", "FULL", "CROSS", "JOIN", "GROUP", "ORDER",
                "HAVING", "UNION", "SET", "VALUES", "SELECT", "AND", "OR", "WITH", "OUTPUT", "USING"}


def sql_text(sql_el):
    """Flatten ParsedSQLExpression into text; entities become {ENT:i} placeholders."""
    parts, ents = [], []
    expr = sql_el.find("ParsedSQLExpression")
    if expr is None:
        return "", ents
    for c in expr:
        if c.tag in ("Text", "Unbound"):
            parts.append(c.get("SQLText", ""))
        elif c.tag == "Entity":
            ref = c.get("Ref", "")
            m = RE_REF_ENT.search(ref)
            if m:
                ents.append((m.group(1), m.group(2), c.get("RefName", "").split(".")[-1]))
            else:
                m = RE_ENT.search(ref)
                ents.append((None, m.group(1) if m else "", c.get("RefName", "").split(".")[-1]))
            parts.append("{ENT:%d}" % (len(ents) - 1))
        elif c.tag == "Parameter":
            parts.append("@" + c.get("RefName", "p"))
        else:
            parts.append(c.get("SQLText", c.get("RefName", "")))
    return "".join(parts), ents


def where_segments(text):
    out = []
    for m in re.finditer(r"\bWHERE\b", text, re.I):
        depth, i, start = 0, m.end(), m.end()
        end = len(text)
        while i < len(text):
            ch = text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    end = i
                    break
            elif depth == 0:
                s = SQL_STOP.match(text, i)
                if s and (i == 0 or not text[i - 1].isalnum()):
                    end = i
                    break
            i += 1
        out.append(text[start:end])
    return out


def sql_where_attrs(text, ents):
    """Return [(ent_index, attr_name)] used inside WHERE clauses."""
    alias = {}
    for m in re.finditer(r"\{ENT:(\d+)\}\s+(?:AS\s+)?\[?(\w+)\]?", text, re.I):
        a = m.group(2)
        if a.upper() not in SQL_KEYWORDS:
            alias[a.lower()] = int(m.group(1))
    found = set()
    for seg in where_segments(text):
        for m in re.finditer(r"\{ENT:(\d+)\}\.\[?(\w+)\]?", seg):
            found.add((int(m.group(1)), m.group(2)))
        for m in re.finditer(r"\[?(\w+)\]?\.\[(\w+)\]|\b(\w+)\.(\w+)\b", seg):
            a = (m.group(1) or m.group(3) or "").lower()
            at = m.group(2) or m.group(4)
            if a in alias:
                found.add((alias[a], at))
        if len(ents) == 1:
            for m in re.finditer(r"(?<![\w.\]])\[(\w+)\](?!\.)", seg):
                found.add((0, m.group(1)))
    return sorted(found)


def parse_module(path):
    sys.setrecursionlimit(100000)
    tree = ET.parse(path)
    root = tree.getroot()
    fname = os.path.basename(path)
    es = next(root.iter("ESpace"), None)
    mod = {
        "file": fname, "size": os.path.getsize(path),
        "name": es.get("Name") if es is not None else fname[:-4],
        "key": es.get("Key") if es is not None else None,
        "references": {}, "entities": {}, "server_actions": {}, "client_actions": {},
        "screens": {}, "blocks": {}, "queries": [], "public": Counter(),
        "ref_ent": Counter(), "ref_ent_attr": Counter(), "ref_act": Counter(), "ref_cact": Counter(),
        "ref_blk": Counter(), "ref_any": Counter(), "ent_use": Counter(), "ent_use_fk": Counter(), "attr_use": Counter(),
        "act_use": Counter(), "cact_use": Counter(), "blk_use": Counter(), "sql_tokens": set(),
    }

    # ---- references (producer modules and the elements imported from them)
    for ref in root.iter("Reference"):
        if not ref.get("ReferenceKey"):
            continue
        r = mod["references"].setdefault(ref.get("Key"), {
            "name": ref.get("Name"), "target_key": ref.get("ReferenceKey"),
            "type": ref.get("ReferenceType"), "entities": {}, "attrs": {}, "actions": {}, "cactions": {},
            "blocks": {},
        })
        for e in ref.iter("ReferenceEntity"):
            r["entities"][e.get("Key")] = e.get("Name")
            for a in e.iter("ReferenceEntityAttribute"):
                r["attrs"][a.get("Key")] = a.get("Name")
        for e in ref.iter("ReferenceAction"):
            r["actions"][e.get("Key")] = e.get("Name")
        for e in ref.iter("ReferenceClientAction"):
            r["cactions"][e.get("Key")] = e.get("Name")
        for e in ref.iter("NewRuntime.ReferenceWebBlock"):
            r["blocks"][e.get("Key")] = e.get("Name")

    owners = {}

    def get_owner(key):
        return owners.setdefault(key, {"name": None, "public": False, "nodes": 0, "decisions": 0, "loops": 0,
                                       "sql": 0, "aggs": 0, "calls": 0, "andor": 0, "switch": 0,
                                       "widgets": 0, "depth": 0})

    def count_refs(el, ent_ctx, in_entity_def):
        for v in el.attrib.values():
            if "/" not in v:
                continue
            if "/References." in v or v.startswith("References."):
                for m in RE_REF_ANY.finditer(v):
                    mod["ref_any"][m.group(1)] += 1
                for m in RE_REF_ENT.finditer(v):
                    if m.group(3):
                        mod["ref_ent_attr"][(m.group(1), m.group(2), m.group(3))] += 1
                    mod["ref_ent"][(m.group(1), m.group(2))] += 1
                for m in RE_REF_ACT.finditer(v):
                    mod["ref_act"][(m.group(1), m.group(2))] += 1
                for m in RE_REF_CACT.finditer(v):
                    mod["ref_cact"][(m.group(1), m.group(2))] += 1
                for m in RE_REF_BLK.finditer(v):
                    mod["ref_blk"][(m.group(1), m.group(2))] += 1
            if "/Entities." in v:
                for m in RE_ENT.finditer(v):
                    ek, ak = m.group(1), m.group(2)
                    if ek == ent_ctx:
                        continue
                    (mod["ent_use_fk"] if in_entity_def else mod["ent_use"])[ek] += 1
                    if ak and not in_entity_def:
                        mod["attr_use"][(ek, ak)] += 1
            if v.startswith("Flows.UserAction"):
                m = RE_LOCAL_ACT.match(v)
                if m:
                    mod["act_use"][m.group(1)] += 1
            elif v.startswith("NRFlows."):
                m = RE_LOCAL_CACT.match(v)
                if m:
                    mod["cact_use"][m.group(1)] += 1
            elif v.startswith("NRNodes.WebBlock:"):
                m = RE_LOCAL_BLK.match(v)
                if m:
                    mod["blk_use"][m.group(1)] += 1

    def record_aggregate(dt, container, node_name):
        q = {"kind": "aggregate", "container": container, "name": node_name, "filters": []}
        seen = set()
        for f in dt.iter("Filter"):
            for ci in f.iter("CompoundIdentifier"):
                if not ci.get("Ref", "").startswith("DataSource:"):
                    continue
                ident = ci.find("Identifier")
                if ident is None:
                    continue
                et = ci.get("ElementType", "")
                m = RE_REF_ENT.search(et)
                if m:
                    rk, ek = m.group(1), m.group(2)
                else:
                    m2 = RE_ENT.search(et)
                    rk, ek = None, (m2.group(1) if m2 else "")
                attr = ident.get("RefName", "").split(".")[-1]
                ename = ci.get("RefName", "")
                sig = (rk, ek, attr)
                if sig not in seen:
                    seen.add(sig)
                    q["filters"].append([rk, ek, ename, attr])
        srcs = []
        for s in dt.iter("DataSetOperations.AddSource"):
            et = s.get("Source", "")
            m = RE_REF_ENT.search(et)
            if m:
                srcs.append([m.group(1), m.group(2), s.get("SourceName")])
            else:
                m2 = RE_ENT.search(et)
                srcs.append([None, m2.group(1) if m2 else "", s.get("SourceName")])
        q["sources"] = srcs
        mod["queries"].append(q)
        return q

    def walk(el, ent_ctx, in_entity_def, act, container, node_name, wdepth, widget_owner):
        tag = el.tag
        if tag in SKIP_TAGS or tag == "References":
            return
        if tag.startswith("Reference") and tag != "References" and el.get("OriginalKey"):
            return

        if el.get("Public") == "Yes" and tag in PUBLIC_KINDS:
            mod["public"][PUBLIC_KINDS[tag]] += 1

        if tag == "Entity" and el.get("Name") and el.get("Key") and not el.get("Ref"):
            attrs = {}
            ae = el.find("Attributes")
            if ae is not None:
                for a in ae:
                    if a.tag == "EntityAttribute":
                        attrs[a.get("Key")] = {"name": a.get("Name"), "mandatory": a.get("IsMandatory") == "Yes"}
            idx = []
            ie = el.find("EntityIndices")
            if ie is not None:
                for ix in ie:
                    if ix.tag != "EntityIndex":
                        continue
                    cols = [x.get("AttributeName") for x in ix.iter("EntityIndexAttribute")]
                    idx.append({"name": ix.get("Name"), "cols": cols, "auto": ix.get("AutoGenerated") == "Yes"})
            sr = el.find("StaticRecords")
            mod["entities"][el.get("Key")] = {
                "name": el.get("Name"), "public": el.get("Public") == "Yes",
                "static": sr is not None and len(sr) > 0, "attrs": attrs, "indexes": idx,
                "id_name": el.get("IdentifierName", "Id"),
            }
            for c in el:
                walk(c, el.get("Key"), True, act, container, node_name, wdepth, widget_owner)
            return

        if tag == "Fragment" and "#" in (el.get("Name") or ""):
            prefix, okey = el.get("Name").split("#", 1)
            o = get_owner(okey)
            if prefix == "Widgets":
                widget_owner, container, wdepth = o, o, 0
            else:
                act, container = o, o
        elif (tag in SERVER_ACTIONS or tag in CLIENT_ACTIONS) and el.get("Key"):
            a = get_owner(el.get("Key"))
            a.update(name=el.get("Name"), public=el.get("Public") == "Yes", tag=tag)
            (mod["server_actions"] if tag in SERVER_ACTIONS else mod["client_actions"])[el.get("Key")] = a
            act, container, node_name = a, a, None
        elif tag in ("NRNodes.WebScreen", "NRNodes.WebBlock") and el.get("Name") and el.get("Key"):
            s = get_owner(el.get("Key"))
            s.update(name=el.get("Name"), public=el.get("Public") == "Yes", title=el.get("Title"))
            (mod["screens"] if tag == "NRNodes.WebScreen" else mod["blocks"])[el.get("Key")] = s
            widget_owner, container, node_name, wdepth = s, s, None, 0
        elif tag.startswith(("Nodes.", "NRNodes.")) and el.get("Name"):
            node_name = el.get("Name")

        if act is not None and tag.startswith(("Nodes.", "NRNodes.")) and el.get("Key"):
            act["nodes"] += 1
            if tag == "Nodes.If":
                act["decisions"] += 1
            elif tag in ("Nodes.ForEach", "NRNodes.ForEach"):
                act["loops"] += 1
                act["decisions"] += 1
            elif tag == "Nodes.Switch":
                n = max(0, len(el.find("Links")) - 1) if el.find("Links") is not None else 0
                act["switch"] += n
                act["decisions"] += n
            elif tag == "Nodes.ErrorHandler":
                act["decisions"] += 1
            elif tag == "Nodes.AdvancedQuery":
                act["sql"] += 1
            elif tag in ("Nodes.DataSet", "NRNodes.WebScreenDataSet"):
                act["aggs"] += 1
            elif tag in ("Nodes.ExecuteAction", "NRNodes.ExecuteClientAction"):
                act["calls"] += 1
        if act is not None and tag == "BinaryOperation" and el.get("Operator") in ("And", "Or"):
            act["andor"] += 1
            act["decisions"] += 1

        if (widget_owner is not None and tag.startswith("NRWebWidgets.") and not tag.startswith("NRWebWidgets.Reference")
                and tag not in STRUCTURAL_WIDGETS):
            wdepth += 1
            widget_owner["widgets"] += 1
            if wdepth > widget_owner["depth"]:
                widget_owner["depth"] = wdepth

        if tag == "DataTable" and not in_entity_def:
            record_aggregate(el, container, node_name)
        elif tag == "Nodes.AdvancedQuery":
            sql = el.find("SQL")
            if sql is not None:
                text, ents = sql_text(sql)
                cols = {t.lower() for t in re.findall(r"\[(\w+)\]", text)}
                cols.update(t.lower() for t in re.findall(r"\.(\w+)", text))
                filt = []
                for ei, at in sql_where_attrs(text, ents):
                    if ei < len(ents):
                        rk, ek, en = ents[ei]
                        filt.append([rk, ek, en, at])
                mod["queries"].append({
                    "kind": "sql", "container": container, "name": el.get("Name"), "filters": filt,
                    "sources": [list(e) for e in ents], "length": len(text),
                    "cols": sorted(cols), "star": bool(re.search(r"\*", text.replace("/*", "").replace("*/", ""))),
                })

        count_refs(el, ent_ctx, in_entity_def)
        for c in el:
            walk(c, ent_ctx, in_entity_def, act, container, node_name, wdepth, widget_owner)

    walk(root, None, False, None, None, None, 0, None)

    for q in mod["queries"]:
        c = q["container"]
        q["container"] = c["name"] if isinstance(c, dict) else c
    # drop the heavy tree before returning
    del tree, root
    mod["public"] = dict(mod["public"])
    mod["sql_tokens"] = sorted(mod["sql_tokens"])
    for name in ("ref_ent", "ref_ent_attr", "ref_act", "ref_cact", "ref_blk"):
        mod[name] = [[*k, v] for k, v in mod[name].items()]
    mod["ref_any"] = dict(mod["ref_any"])
    mod["ent_use"] = dict(mod["ent_use"])
    mod["ent_use_fk"] = dict(mod["ent_use_fk"])
    mod["attr_use"] = [[k[0], k[1], v] for k, v in mod["attr_use"].items()]
    mod["act_use"] = dict(mod["act_use"])
    mod["cact_use"] = dict(mod["cact_use"])
    mod["blk_use"] = dict(mod["blk_use"])
    return mod


def _worker(path):
    result = {}

    def run():
        try:
            result["mod"] = parse_module(path)
        except Exception as exc:  # keep going; report at the end
            result["err"] = repr(exc)

    threading.stack_size(128 * 1024 * 1024)
    t = threading.Thread(target=run)
    t.start()
    t.join()
    print(("OK   " if "mod" in result else "FAIL ") + os.path.basename(path), result.get("err", ""), flush=True)
    return os.path.basename(path), result.get("mod"), result.get("err")


def analyze_factory(input_dir=INPUT_DIR, output_json=OUTPUT_JSON, procs=3):
    files = sorted((os.path.join(input_dir, f) for f in os.listdir(input_dir) if f.lower().endswith(".xml")),
                   key=lambda p: -os.path.getsize(p))
    print(f"Found {len(files)} module XML(s) to process.", flush=True)
    with Pool(procs, maxtasksperchild=1) as pool:
        results = pool.map(_worker, files, chunksize=1)
    data = {"modules": {m["name"]: m for _, m, _ in results if m}, "errors": {f: e for f, m, e in results if e}}
    os.makedirs(os.path.dirname(os.path.abspath(output_json)), exist_ok=True)
    with open(output_json, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    print(f"Wrote {output_json}: {len(data['modules'])} modules, {len(data['errors'])} errors", flush=True)


if __name__ == "__main__":
    args = sys.argv[1:]
    analyze_factory(*(args[:2]))
