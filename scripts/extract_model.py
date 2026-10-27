"""Extract a compact, name-resolved model from OutSystems OML XML exports.

Reads each module XML once and writes output/model/<Module>.json with references, entities,
structures, site properties, timers and every action flow (server, client, screen, data, service)
with its parameters and nodes. Expressions are rendered to text and keys resolved to names, so
downstream scripts (decompile_actions.py, checks, reports) never need to touch the XML again.

A module is only re-extracted when its XML changed (size + mtime cache in output/model/_cache.json).

Usage: python scripts/extract_model.py [input_dir] [output_dir] [--force] [--only Module1,Module2]
"""
import json
import os
import re
import sys
import threading
import xml.etree.ElementTree as ET
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(HERE, "..", "input")
OUTPUT_DIR = os.path.join(HERE, "..", "output", "model")

RE_LAST_KEY = re.compile(r"\.([A-Za-z0-9_+\-]{22})$")
RE_ENTITY = re.compile(r"(?:References\.([A-Za-z0-9_+\-]{22})/ReferenceEntities\.([A-Za-z0-9_+\-]{22})|"
                       r"(?<![A-Za-z])/?Entities\.([A-Za-z0-9_+\-]{22}))")
RE_ENTITY_ATTR = re.compile(r"((?:References\.[A-Za-z0-9_+\-]{22}/Reference)?Entities\.[A-Za-z0-9_+\-]{22})"
                            r"/Attributes\.([A-Za-z0-9_+\-]{22})")
RE_REF_ROOT = re.compile(r"References\.([A-Za-z0-9_+\-]{22})")
RE_REF_ELEM = re.compile(r"/Reference([A-Za-z]+?)s?\.([A-Za-z0-9_+\-]{22})")
REF_KINDS = {"Entitie": "entities", "Entity": "entities", "Action": "actions", "ClientAction": "client actions",
             "WebBlock": "blocks", "Structure": "structures", "Role": "roles", "ServiceAPIMethod": "service actions",
             "StaticEntitie": "entities", "SiteProperty": "site properties", "Theme": "themes", "Image": "images",
             "Resource": "resources", "Script": "scripts", "WebScreen": "screens", "Exception": "exceptions"}
SQL_CLAUSE = re.compile(r"\b(select|from|join|on|where|group\s+by|order\s+by|having|set|values|into)\b", re.I)
SQL_USE_KIND = {"on": "join", "where": "filter", "having": "filter", "order by": "sort", "group by": "group"}
RE_TABLE_OP = re.compile(r"TableOperations\.([A-Za-z0-9_+\-]{22})")

BUILTIN_TYPES = {
    "uROOBXPvQEyU76NWO+1uxQ": "Text", "oD0fxvc7hUOX_305zIXIlg": "Boolean", "j2Lc0phK0kuggij4gQYfAw": "Integer",
    "DnfdUFhShE2uIYCwnadVLQ": "Date", "TI32kQokwEyLhBq6zdg2Tw": "DateTime", "Qs4rEIsOoUmXjigHsikpCg": "Time",
    "snOQIa2+VEi7MGyYOu7OpA": "Decimal", "H6G+eTAigEi7LPUbg3Ey0g": "Long Integer", "EYiTxdlAx0OG1Vuo4D_l4A": "Currency",
    "AIYAbYIrH0SUg8DUlzCMjQ": "Email", "uCRxZE_fNUyUSGrF0nnRIw": "Phone Number", "T8i8SBbo_EyGNoo0ssngsw": "Binary Data",
    "V0DejjDtIU2u1eHsZ158BA": "Object", "tRA5+npp1UKZWp2HHMgLSg": "Integer Identifier",
    "hR+HzvoUvkKth+waVG8Vww": "Text Identifier", "fGmKYNVfKUiGw0c2kUmb1Q": "Long Integer Identifier",
    "xJyn4vH0KkCfmSAS_CIQBg": "RecordList",
}
BIN_OPS = {"Or": ("or", 1), "And": ("and", 2), "Eq": ("=", 4), "NEq": ("<>", 4), "LT": ("<", 4), "LE": ("<=", 4),
           "GT": (">", 4), "GE": (">=", 4), "Like": ("like", 4), "Plus": ("+", 5), "Minus": ("-", 5),
           "Mul": ("*", 6), "Div": ("/", 6)}
FLOW_KINDS = {
    "Flows.UserAction": "ServerAction", "Flows.UserActionInsideFolder": "ServerAction",
    "NRFlows.ClientActionFlow": "ClientAction", "NRFlows.ClientActionFlowInsideFolder": "ClientAction",
    "NRFlows.ClientScreenActionFlow": "ScreenAction", "NRFlows.DataScreenActionFlow": "DataAction",
    "NRFlows.FlowExceptionHandlingFlow": "ExceptionFlow", "Flows.ServiceAPIMethod": "ServiceAPIMethod",
    "Flows.CustomActionFlow": "CustomAction", "Flows.CustomCallbackFlow": "Callback",
    "Flows.EmailPreparation": "EmailPreparation", "Flows.WebPreparation": "Preparation", "Flows.OnClose": "OnClose",
    "Flows.Process": "Process", "Flows.Activity": "Activity", "Flows.Decision": "Decision",
}
SCREEN_KINDS = {"NRNodes.WebScreen": "Screen", "NRNodes.WebBlock": "Block", "Nodes.EmailScreen": "Email",
                "NRNodes.EmailScreen": "Email", "Nodes.WebBlock": "Block"}
CONTAINER_TAGS = {"NRFlows.WebFlow", "Flows.WebFlow", "Folder"}
NON_FLOW_NODES = {"NRNodes.WebScreen", "NRNodes.WebBlock", "Nodes.DiagramEntity", "Nodes.EmailScreen",
                  "NRNodes.EmailScreen", "Nodes.WebBlock"}
SKIP_TAGS = {"CompilationUnits", "ElementSignatures", "ServiceStudioData", "Referers", "SharedReferers", "RebindData",
             "VerifyCache", "VerifyMessages", "ChildCache", "Usage", "TestAttributeValues", "AttributesInPreview",
             "TextResources", "Metadata", "StyleSheet", "Image"}
SKIP_FRAGMENTS = {"ReferersData", "ReferersForCompilerData", "RebindData", "VerifyCaches", "CompilationUnits",
                  "Signature", "Versions"}
USE_PREFIXES = ("NRFlows.", "Flows.UserAction", "ReferenceAction:", "ReferenceClientAction:", "ReferenceServiceAPIMethod:")
CALL_TAGS = {"Nodes.ExecuteAction", "NRNodes.ExecuteClientAction", "Nodes.ErrorHandler"}
DERIVED_NAME_TAGS = {"GroupByAttribute", "AggregateAttribute", "AnonymousStructureAttribute", "CalculatedAttribute"}


def last_key(ref):
    m = RE_LAST_KEY.search(ref or "")
    return m.group(1) if m else None


class Module:
    def __init__(self, root):
        self.root = root
        self.names = {}        # key -> display name
        self.elements = {}     # key -> element (named elements only, for derived lookups)
        self.list_types = {}   # ListType key -> element type ref
        self.anon = {}         # AnonymousStructure key -> [attr keys]
        self.anon_types = {}   # AnonymousStructureAttribute key -> type ref
        self.ref_modules = {}  # Reference key -> producer module name
        self.ref_owner = {}    # referenced element key -> producer module name

    # ---------- names ----------
    def index_names(self):
        for ref in self.root.iter("Reference"):
            if ref.get("ReferenceKey"):
                self.ref_modules[ref.get("Key")] = ref.get("Name")
                for el in ref.iter():
                    if el.get("Key") and el is not ref:
                        self.ref_owner[el.get("Key")] = ref.get("Name")
        derived, unnamed_calls = [], []
        for el in self.root.iter():
            k = el.get("Key")
            if not k:
                continue
            if el.tag == "ListType":
                self.list_types[k] = el.get("ElementType")
            elif el.tag == "AnonymousStructure":
                self.anon[k] = [a.get("Key") for a in el.iter("AnonymousStructureAttribute")]
                for a in el.iter("AnonymousStructureAttribute"):
                    self.anon_types[a.get("Key")] = a.get("Type")
            nm = el.get("Name") or el.get("CustomName")
            if el.tag in CALL_TAGS and not el.get("Name"):
                unnamed_calls.append(el)
            elif el.tag in DERIVED_NAME_TAGS and el.get("CustomNameIsSuffix") == "Yes":
                derived.append(el)
            elif nm:
                self.names[k] = nm
            elif el.tag in DERIVED_NAME_TAGS:
                derived.append(el)
        for el in unnamed_calls:
            self.names[el.get("Key")] = self.call_node_name(el)
        for el in derived:
            nm = None
            orig = el.find("OriginalAttribute")
            if orig is not None:
                idents = [i for i in orig.iter() if i.get("RefName") or i.get("NameRef")]
                if idents:
                    nm = self.ident_name(idents[-1])
            if not nm and el.get("Type"):
                k = last_key(el.get("Type"))
                nm = self.names.get(k)
            if nm and el.get("CustomNameIsSuffix") == "Yes" and el.get("CustomName"):
                nm += el.get("CustomName")
            nm = nm or el.get("CustomName")
            if nm:
                self.names[el.get("Key")] = nm
        self.name_aggregate_outputs()

    def call_node_name(self, el):
        """Name an expression uses for a call/handler node with no Name: the action's name (CheckXRole for roles,
        the exception for handlers), or CustomName, which is a suffix when CustomNameIsSuffix=Yes."""
        if el.tag == "Nodes.ErrorHandler":  # referenced as <Exception>.ExceptionMessage
            exc = el.get("Exception", "")
            base = "BuiltinException" if exc.startswith("%") else self.names.get(last_key(exc), "Exception")
        else:
            base = self.action_name(el)
            parts = base.split(".")
            if (el.get("Action") or "").startswith("RoleActions.") and len(parts) >= 2:
                base = parts[-1].replace("Role", parts[-2] + "Role", 1)  # CheckRole -> CheckXRole
            base = base.split(".")[-1]
        cn = el.get("CustomName")
        if cn:
            return base + cn if el.get("CustomNameIsSuffix") == "Yes" else cn
        return base

    def name_aggregate_outputs(self):
        """Group-by outputs are anonymous attributes with no name in the XML; they are sorted by name,
        so match each unnamed one to a group-by/aggregate attribute of the same type and position."""
        for node in self.root.iter():
            if node.tag not in ("Nodes.DataSet", "NRNodes.WebScreenDataSet") or not node.get("Type"):
                continue
            et = self.list_types.get(last_key(node.get("Type")), "")
            akey = last_key(et) if et.startswith("AnonymousStructure:") else None
            attrs = self.anon.get(akey) or []
            if not attrs or all(a in self.names for a in attrs):
                continue
            cands = []
            for g in node.iter():
                if g.tag in ("GroupByAttribute", "AggregateAttribute") and g.get("Key") in self.names:
                    idents = [i for i in g.iter() if i.get("Type")]
                    cands.append((self.names[g.get("Key")], idents[-1].get("Type") if idents else None))
            used = {self.names[a] for a in attrs if a in self.names}
            types = self.anon_types
            for i, a in enumerate(attrs):
                if a in self.names:
                    continue
                prev = next((self.names[x] for x in reversed(attrs[:i]) if x in self.names), "")
                nxt = next((self.names[x] for x in attrs[i + 1:] if x in self.names), "￿")
                for nm, t in cands:
                    if nm not in used and t == types.get(a) and prev.lower() <= nm.lower() <= nxt.lower():
                        self.names[a] = nm
                        used.add(nm)
                        break

    def ident_name(self, el):
        if el.get("NameRef"):
            return el.get("NameRef")
        ref = el.get("Ref", "")
        k = last_key(ref)
        if k and k in self.names and not ref.startswith("DataSource"):
            return self.names[k]
        rn = el.get("RefName")
        if rn:
            return rn.split(".")[-1]
        if el.get("Value"):  # unresolved reference: Service Studio keeps only the typed text
            return el.get("Value") + "<unresolved>"
        return "<unresolved:%s>" % k if k else "?"

    def type_name(self, t, depth=0):
        if not t:
            return ""
        if depth > 4:
            return "..."
        if t.startswith("%"):
            return BUILTIN_TYPES.get(t[1:], "?" + t[1:6])
        if t.startswith("ListType:"):
            return "List<%s>" % self.type_name(self.list_types.get(last_key(t), ""), depth + 1)
        if t.startswith("AnonymousStructure:"):
            attrs = [self.names.get(a, "?") for a in self.anon.get(last_key(t), [])]
            s = ", ".join(attrs[:8]) + (", ..." if len(attrs) > 8 else "")
            return "Record{%s}" % s
        if t.endswith("/IdentifierType"):
            return self.names.get(last_key(t[:-len("/IdentifierType")]), "?") + " Identifier"
        k = last_key(t)
        return self.names.get(k, t.split(":")[0])

    # ---------- expressions ----------
    def expr(self, holder):
        """Render the ParsedExpression under holder (or holder itself if it is one)."""
        if holder is None:
            return None
        pe = holder if holder.tag == "ParsedExpression" else holder.find("ParsedExpression")
        if pe is None or len(pe) == 0:
            return None
        return self.render(pe[0])

    def render(self, e, parent_prec=0):
        tag = e.tag
        if tag == "Text":
            return json.dumps(e.get("Value", ""), ensure_ascii=False)
        if tag in ("Boolean", "Integer", "Decimal"):
            return e.get("Value", "")
        if tag == "Date":
            return "#%s#" % e.get("Value", "")
        if tag == "EmptyArgument":
            return ""
        if tag == "Identifier":
            return self.ident_name(e)
        if tag == "CompoundIdentifier":
            s = self.ident_name(e)
            for c in e:
                s += ("[%s]" % self.render(c[0]) if len(c) else "[]") if c.tag == "Indexer" else "." + self.render(c)
            return s
        if tag == "Indexer":
            return "[%s]" % (self.render(e[0]) if len(e) else "")
        if tag == "Call":
            return "%s(%s)" % (self.call_name(e), ", ".join(self.render(a) for a in e))
        if tag == "Argument":
            return self.render(e[0]) if len(e) else ""
        if tag == "CompoundCall":
            parts = list(e)
            s = self.render(parts[0]) if parts else ""
            for c in parts[1:]:
                s += self.render(c) if c.tag == "Indexer" else "." + self.render(c)
            return s
        if tag == "BinaryOperation":
            op, prec = BIN_OPS.get(e.get("Operator"), (e.get("Operator"), 3))
            if len(e) < 2:
                return op
            s = "%s %s %s" % (self.render(e[0], prec), op, self.render(e[1], prec + 1))
            return "(%s)" % s if prec < parent_prec else s
        if tag == "UnaryOperation":
            if e.get("Operator") == "Not":
                s = "not " + (self.render(e[0], 3) if len(e) else "")
                return "(%s)" % s if 3 < parent_prec else s
            return "-" + (self.render(e[0], 7) if len(e) else "")
        return tag

    def call_name(self, e):
        if e.get("NameRef"):
            return e.get("NameRef")
        ref, rn = e.get("Ref", ""), e.get("RefName", "")
        if "EntityActions." in ref and "#" in ref:
            return ref.rsplit("#", 1)[1].replace("Entity", rn.split(".")[-1] or "Entity", 1)
        if "References." in ref and rn:
            return rn
        return self.ident_name(e)

    # ---------- variables ----------
    def variables(self, el, section):
        sec = el.find(section)
        out = []
        if sec is None:
            return out
        for v in sec:
            if not v.get("Name"):
                continue
            d = {"name": v.get("Name"), "type": self.type_name(v.get("Type"))}
            if v.get("Description"):
                d["description"] = v.get("Description")
            if v.get("IsMandatory") == "Yes" or (section == "InputParameters" and v.get("IsMandatory") != "No"):
                d["mandatory"] = True
            dv = self.expr(v.find("DefaultValue"))
            if dv:
                d["default"] = dv
            out.append(d)
        return out

    # ---------- aggregates ----------
    def aggregate(self, node):
        dt = node.find("Table/DataTable")
        if dt is None:
            dt = next(node.iter("DataTable"), None)
        if dt is None:
            return []
        ops = {}
        tops = dt.find("TableOperations")
        if tops is not None:
            for op in tops:
                ops[op.get("Key")] = op
        lines, done = [], {}
        # structured facts for the checks: sources, joins and attributes used to join/filter/sort/group
        meta = self.agg_meta = {"sources": [], "joins": [], "uses": []}
        for op in ops.values():
            if op.tag.endswith("AddSource"):
                meta["sources"].append([(op.get("SourceName") or "?").split(".")[-1], self.entity_ref(op.get("Source"))])

        def label(k):
            op = ops.get(k)
            if op is None:
                return "?"
            if op.tag.endswith("AddSource"):
                return (op.get("SourceName") or "?").split(".")[-1]
            if k not in done:
                done[k] = stage(op)
            return done[k]

        def dep_key(el):
            for v in el.attrib.values():
                m = RE_TABLE_OP.search(v)
                if m:
                    return m.group(1)
            return None

        def stage(op):
            name = op.get("Name") or op.get("SourceOperationName") and ("GroupBy(%s)" % op.get("SourceOperationName")) or op.tag.split(".")[-1]
            if op.tag.endswith("CombineSources"):
                srcs = []
                for ds in op.iter("DataSource"):
                    k = dep_key(ds)
                    if k:
                        srcs.append(label(k))
                body = []
                joins = op.find("Joins")
                joined = set()
                if joins is not None:
                    for j in joins:
                        l, r = (j.get("LeftSourceName") or "?").split(".")[-1], (j.get("RightSourceName") or "?").split(".")[-1]
                        joined.update((l, r))
                        jt = (j.get("JoinType") or "").upper()
                        body.append("  %s JOIN %s ~ %s ON %s" % (jt, l, r, self.expr(j.find("Condition")) or "True"))
                        meta["joins"].append([jt, l, r])
                meta["uses"] += self.query_uses(op, "join", "Joins") + self.query_uses(op, "filter", "Filters") \
                    + self.query_uses(op, "sort", "Sorts") + self.query_uses(op, "calc", "CalculatedAttributes")
                calc = op.find("CalculatedAttributes")
                if calc is not None:
                    for c in calc:
                        body.append("  CALC %s = %s" % (c.get("Name") or self.names.get(c.get("Key"), "?"), self.expr(c.find("Value"))))
                filters = op.find("Filters")
                if filters is not None:
                    for f in filters:
                        body.append("  WHERE " + (self.expr(f.find("Condition")) or "?"))
                sorts = op.find("Sorts")
                if sorts is not None:
                    for s in sorts:
                        txt = self.expr(next((x for x in s.iter() if x.find("ParsedExpression") is not None), s)) or "?"
                        body.append("  ORDER BY %s %s" % (txt, "DESC" if s.get("Direction", "").lower().startswith("desc") or s.get("IsDescending") == "Yes" else "ASC"))
                if len(srcs) > 1 and not joins:
                    head = "FROM " + ", ".join(srcs) + "  (no join conditions: cross join)"
                else:
                    head = "FROM " + ", ".join(srcs)
                lines.append("[%s] %s" % (name, head))
                lines.extend(body)
                return name
            if op.tag.endswith("GroupBy"):
                meta["uses"] += self.query_uses(op, "group", "GroupByAttributes") \
                    + self.query_uses(op, "group", "AggregateAttributes")
                k = dep_key(op)
                src = label(k) if k else "?"
                keys = [self.names.get(g.get("Key"), "?") for g in op.iter("GroupByAttribute")]
                aggs = []
                for a in op.iter("AggregateAttribute"):
                    orig = a.find("OriginalAttribute")
                    aggs.append("%s(%s) as %s" % (a.get("AggregationType", "?"), self.expr(orig) if orig is not None else "?",
                                                  self.names.get(a.get("Key"), "?")))
                lines.append("[%s] GROUP %s BY %s" % (name, src, ", ".join(keys)))
                if aggs:
                    lines.append("  AGG " + ", ".join(aggs))
                return name
            lines.append("[%s] %s" % (name, op.tag))
            return name

        root_k = last_key(dt.get("RootOperation"))
        if root_k in ops:
            label(root_k)
        else:
            for k in ops:
                label(k)
        return lines

    # ---------- SQL ----------
    def entity_ref(self, ref):
        """'Module.Entity' for an entity reference (local or from a producer module)."""
        m = RE_ENTITY.search(ref or "")
        if not m:
            return None
        if m.group(1):
            return "%s.%s" % (self.ref_modules.get(m.group(1), "?"), self.names.get(m.group(2), "?"))
        return "%s.%s" % (self.module_name, self.names.get(m.group(3), "?"))

    def attr_ref(self, ref):
        """['Module.Entity', 'Attribute'] for an entity attribute reference, else None."""
        m = RE_ENTITY_ATTR.search(ref or "")
        if not m:
            return None
        ent = self.entity_ref(m.group(1))
        return [ent, self.names.get(m.group(2), "?")] if ent else None

    def query_uses(self, op, kind, child):
        """Attributes referenced in an aggregate's joins/filters/sorts."""
        out = []
        sec = op.find(child)
        if sec is not None:
            for el in sec.iter():
                ref = self.attr_ref(el.get("Ref"))
                if ref:
                    out.append([kind] + ref)
        return out

    def sql(self, node):
        sql = node.find("SQL")
        expr = sql.find("ParsedSQLExpression") if sql is not None else None
        if expr is None:
            return ""
        parts, clause = [], "select"
        self.sql_uses, self.sql_sources = [], []
        for c in expr:
            if c.tag in ("Text", "Unbound"):
                parts.append(c.get("SQLText", ""))
                kws = SQL_CLAUSE.findall(c.get("SQLText", ""))
                if kws:
                    clause = re.sub(r"\s+", " ", kws[-1].lower())
            elif c.tag == "Entity":
                parts.append("{%s}" % (c.get("RefName") or "?").split(".")[-1])
                ref = self.entity_ref(c.get("Ref"))
                if ref:
                    self.sql_sources.append(ref)
            elif c.tag == "Attribute":
                ent = c.find("Entity")
                en = (ent.get("RefName") or "?").split(".")[-1] if ent is not None else "?"
                parts.append("{%s}.[%s]" % (en, (c.get("RefName") or "?").split(".")[-1]))
                kind = SQL_USE_KIND.get(clause)
                ref = self.attr_ref(c.get("Ref"))
                if kind and ref:
                    self.sql_uses.append([kind] + ref)
            elif c.tag == "Parameter":
                parts.append("@" + (c.get("RefName") or "p").split(".")[-1])
            else:
                parts.append(c.get("SQLText") or c.get("RefName") or "")
        return "".join(parts)

    # ---------- nodes ----------
    def action_name(self, el):
        """Display name of the action an ExecuteAction node calls."""
        action = el.get("Action", "")
        an = el.get("ActionName") or self.names.get(last_key(action), "?")
        if "#" not in action:
            return an
        op = action.rsplit("#", 1)[1]
        owner_key = re.findall(r"\.([A-Za-z0-9_+\-]{22})/", action)
        owner_key = owner_key[-1] if owner_key else None
        module = self.ref_owner.get(owner_key) if "References." in action else None
        if action.startswith("EntityActions."):
            an = op.replace("Entity", an.split(".")[-1], 1)
        else:  # RoleActions (CheckRole/GrantRole/RevokeRole), TimerActions.WakeTimer, ProcessActions...
            an = "%s.%s" % (self.names.get(owner_key, "?"), op)
        return "%s.%s" % (module, an) if module else an

    def node(self, el):
        tag = el.tag
        t = tag.split(".", 1)[1]
        n = {"key": el.get("Key"), "type": t}
        label = el.get("Name") or el.get("Label") or (self.names.get(el.get("Key")) if el.get("CustomName") else None)
        if label:
            n["name"] = label
        links = []
        le = el.find("Links")
        if le is not None:
            for l in le:
                if l.get("TargetNode"):
                    links.append([l.tag.split(".", 1)[1], last_key(l.get("TargetNode")), l.get("Key")])
        n["links"] = links
        args = el.find("Arguments")
        if args is not None and len(args):
            n["args"] = [[(a.get("ParameterName") or self.names.get(last_key(a.get("Parameter")), "?")).split(".")[-1],
                          self.expr(a.find("Value"))] for a in args]
        if t == "Assign":
            n["assign"] = [[self.expr(a.find("Variable")), self.expr(a.find("Value"))] for a in el.iter("Assignment")]
        elif t in ("ExecuteAction", "ExecuteClientAction"):
            action = el.get("Action", "")
            n["action"] = self.action_name(el)
            n["action_ref"] = action.split(":")[0]
            ak = last_key(action)
            if ak:
                n["action_key"] = ak
        elif t == "If":
            n["cond"] = self.expr(el.find("Condition"))
        elif t == "Switch":
            n["conds"] = {last_key(c.get("Link")): self.expr(c.find("Value")) for c in el.iter("SwitchCondition")}
        elif t == "ForEach":
            n["list"] = self.expr(el.find("RecordList"))
            for f in ("StartIndex", "Maximum"):
                v = self.expr(el.find(f))
                if v:
                    n[f[0].lower() + f[1:]] = v
        elif t in ("DataSet", "WebScreenDataSet", "ViewEntityDataDataSet"):
            self.agg_meta = {"sources": [], "joins": [], "uses": []}
            n["query"] = self.aggregate(el)
            n.update(self.agg_meta)
            n["out_type"] = self.type_name(el.get("Type"))
            for f in ("MaxRecords", "StartIndex"):
                v = self.expr(el.find(f))
                if v:
                    n[f[0].lower() + f[1:]] = v
        elif t == "AdvancedQuery":
            n["sql"] = self.sql(el)
            n["uses"], n["sources"] = getattr(self, "sql_uses", []), [[None, s] for s in sorted(set(getattr(self, "sql_sources", [])))]
            n["out_type"] = self.type_name(el.get("Type"))
            n["params"] = [[p.get("Name"), self.type_name(p.get("Type")), p.get("ExpandInline") == "Yes"]
                           for p in el.iter("Variables.AdvancedQueryParameter")]
            v = self.expr(el.find("MaxRecords"))
            if v:
                n["maxRecords"] = v
        elif t == "RaiseError":
            n["exception"] = el.get("ExceptionName") or self.names.get(last_key(el.get("Exception")), el.get("Exception"))
            n["message"] = self.expr(el.find("Message"))
        elif t == "ErrorHandler":
            exc = el.get("Exception", "")
            # built-in exceptions (AllExceptions, DatabaseException, ...) are keys with no name in the export
            n["exception"] = self.names.get(last_key(exc), exc) if not exc.startswith("%") else "BuiltinException:" + exc
            n["abortTransaction"] = el.get("AbortTransaction") == "Yes"
            n["logError"] = el.get("LogError", "Yes") != "No"
        elif t == "RefreshQuery":
            n["target"] = self.names.get(last_key(el.get("Target")), el.get("Target"))
        elif t == "Comment":
            n["text"] = el.get("Text", "")
        elif t == "JavascriptNode":
            js = el.find("JavascriptSource/JavascriptExpression")
            if js is not None:
                n["js"] = "".join(c.get("JSText") or "$" + (c.get("RefName") or "?") for c in js)
        elif t in ("WebDestination", "WebExternalSite", "Download", "FeedbackMessage", "TriggerEvent", "JSONSerialize",
                   "JSONDeserialize", "RecordListToExcel", "ExcelToRecordList", "SendEmail", "Outcome"):
            for attr in ("Destination", "Event", "Target", "Screen"):
                if el.get(attr):
                    n[attr.lower()] = self.names.get(last_key(el.get(attr)), el.get(attr))
            for c in el:
                if c.tag in ("Links", "Arguments"):
                    continue
                v = self.expr(c)
                if v:
                    n.setdefault("fields", {})[c.tag] = v
        return n


def custom_props(m, el):
    """Plugin settings (REST services/methods/parameters): {PropertyName: value}, empty values skipped."""
    cps = el.find("CustomProperties")
    out = {}
    if cps is not None:
        for cp in cps:
            v = cp.get("Value") or m.expr(cp.find("ValueExpression"))
            if v:
                out[cp.get("PropertyName")] = v
    return out


def rest_method(m, el):
    d = {"name": el.get("Name"), "props": custom_props(m, el)}
    for sec, key in (("InputParameters", "inputs"), ("OutputParameters", "outputs")):
        sv = el.find(sec)
        if sv is not None and len(sv):
            d[key] = [{"name": v.get("Name"), "type": m.type_name(v.get("Type")), "props": custom_props(m, v)}
                      for v in sv if v.get("Name")]
    return d


def flow_kind(tag):
    """Plugin flows carry a suffix: Flows.CustomActionFlow-OutSystems.Plugin.RESTService.RestServiceAction."""
    base, _, plugin = tag.partition("-")
    if base == "Flows.CustomActionFlow" and "RESTService" in plugin:
        return "RESTMethod"
    if base == "Flows.CustomCallbackFlow" and "Authentication" in plugin:
        return "RESTAuthentication"
    return FLOW_KINDS.get(base)


def flow_info(m, el, kind):
    f = {"key": el.get("Key"), "kind": kind, "name": el.get("Name")}
    for a in ("Public", "IsFunction", "Description", "Title", "Anonymous", "IsDefault"):
        if el.get(a):
            f[a[0].lower() + a[1:]] = el.get(a) if a in ("Description", "Title") else el.get(a) == "Yes"
    perms = el.find("Permissions")
    if perms is not None:  # screens: the roles allowed to open it (Anonymous / Registered / custom)
        f["roles"] = sorted({p.get("RoleName") or m.names.get(last_key(p.get("Role")), "?") for p in perms})
    props = custom_props(m, el)
    if props:
        f["props"] = props
    for sec, key in (("InputParameters", "inputs"), ("OutputParameters", "outputs"), ("LocalVariables", "locals")):
        v = m.variables(el, sec)
        if v:
            f[key] = v
    return f


def extract(path):
    sys.setrecursionlimit(100000)
    root = ET.parse(path).getroot()
    m = Module(root)
    es0 = next(root.iter("ESpace"), None)
    m.module_name = es0.get("Name") if es0 is not None else os.path.basename(path)[:-4]
    m.index_names()
    es = next(root.iter("ESpace"), None)
    sig = next(root.iter("Signature"), None)
    out = {"module": es.get("Name") if es is not None else os.path.basename(path)[:-4],
           "file": os.path.basename(path), "espaceType": sig.get("ESpaceType") if sig is not None else None,
           "description": es.get("Description") if es is not None else None,
           "globalErrorHandler": bool(es is not None and es.get("GlobalErrorHandler")),
           "references": sorted(set(m.ref_modules.values())), "entities": [], "structures": [], "siteProperties": [],
           "timers": [], "exceptions": [], "roles": [], "restExposed": [], "restConsumed": [], "flows": [],
           "screens": []}

    uses = set()     # "Module.Action" referenced from widgets
    info = {}        # key -> {tag, name, parent}
    owner_nodes = {}  # owner key -> [node dict]
    flows, screens = [], []

    def note_uses(el):
        """Actions referenced outside flow nodes (widget events/destinations, function calls in widgets)."""
        for attr in ("Destination", "Handler", "Ref", "Action"):
            v = el.get(attr)
            if v and v.startswith(USE_PREFIXES):
                k = last_key(v)
                if k and k in m.names:
                    owner_mod = m.ref_owner.get(k) if v.startswith("Reference") else out["module"]
                    uses.add("%s.%s" % (owner_mod, m.names[k]))

    def walk(el, parent, owner):
        tag = el.tag
        if tag in SKIP_TAGS:
            return
        if owner is None or not tag.startswith(("Nodes.", "NRNodes.")):
            note_uses(el)
        k = el.get("Key")
        if tag == "Entity" and el.get("Name") and k:
            ent = {"name": el.get("Name"), "public": el.get("Public") == "Yes",
                   "exposeReadOnly": el.get("ExposeReadOnly") != "No", "attributes": [], "indexes": []}
            if el.get("Description"):
                ent["description"] = el.get("Description")
            for a in el.iter("EntityAttribute"):
                d = {"name": a.get("Name"), "type": m.type_name(a.get("Type"))}
                if a.get("Description"):
                    d["description"] = a.get("Description")
                if a.get("IsMandatory") == "Yes":
                    d["mandatory"] = True
                if a.get("Length"):
                    d["length"] = a.get("Length")
                ent["attributes"].append(d)
            for ix in el.iter("EntityIndex"):
                ent["indexes"].append({"name": ix.get("Name"), "unique": ix.get("IsUnique") == "Yes",
                                       "cols": [x.get("AttributeName") or m.names.get(last_key(x.get("Attribute")), "?")
                                                for x in ix.iter("EntityIndexAttribute")]})
            sr = el.find("StaticRecords")
            if sr is not None and len(sr):
                ent["staticRecords"] = [r.get("Name") or r.get("Identifier") for r in sr]
            out["entities"].append(ent)
            return
        if tag == "Structure" and el.get("Name"):
            out["structures"].append({"name": el.get("Name"), "public": el.get("Public") == "Yes",
                                      "attributes": [{"name": a.get("Name"), "type": m.type_name(a.get("Type"))}
                                                     for a in el.iter("StructureAttribute")]})
            return
        if tag == "Variables.SiteProperty":
            out["siteProperties"].append({"name": el.get("Name"), "type": m.type_name(el.get("Type")),
                                          "default": m.expr(el.find("DefaultValue")),
                                          "readOnly": el.get("IsReadOnlySiteProperty") == "Yes",
                                          "description": el.get("Description")})
        elif tag.startswith("CustomService-") and "RESTService" in tag and el.get("Name"):
            cafs = el.find("CustomActionFlows")
            out["restExposed"].append({"name": el.get("Name"), "props": custom_props(m, el),
                                       "methods": [rest_method(m, f) for f in (cafs if cafs is not None else [])],
                                       "callbacks": [c.get("Name") for c in el.iter() if c.tag.startswith("Flows.CustomCallbackFlow")]})
        elif tag.startswith("CustomClient-") and el.get("Name"):
            cas = el.find("CustomActions")
            out["restConsumed"].append({"name": el.get("Name"), "props": custom_props(m, el),
                                        "methods": [rest_method(m, a) for a in (cas if cas is not None else [])
                                                    if a.tag.startswith("CustomAction-")]})
        elif tag == "Timer":
            action = el.get("ActionName") or m.names.get(last_key(el.get("Action")), "?")
            out["timers"].append({"name": el.get("Name") or el.get("CustomName") or action, "action": action,
                                  "actionKey": last_key(el.get("Action")), "schedule": el.get("Schedule"),
                                  "timeout": el.get("Timeout"), "priority": el.get("Priority")})
        elif tag == "UserException" and el.get("Name"):
            out["exceptions"].append(el.get("Name"))
        elif tag == "Role" and el.get("Name") and k:
            out["roles"].append(el.get("Name"))
        if k:
            if flow_kind(tag):
                info[k] = {"tag": tag, "name": el.get("Name"), "parent": parent}
                flows.append((el, k))
                parent, owner = k, k
            elif tag.startswith(("CustomService-", "CustomClient-")) and el.get("Name"):
                info[k] = {"tag": tag, "name": el.get("Name"), "parent": parent}
                parent = k
            elif tag in SCREEN_KINDS and el.get("Name"):
                info[k] = {"tag": tag, "name": el.get("Name"), "parent": parent}
                screens.append((el, k))
                parent, owner = k, k
            elif tag in CONTAINER_TAGS and el.get("Name"):
                info[k] = {"tag": tag, "name": el.get("Name"), "parent": parent}
                parent = k
            elif tag.startswith(("Nodes.", "NRNodes.")) and tag not in NON_FLOW_NODES and owner:
                owner_nodes.setdefault(owner, []).append(m.node(el))
                return
        for c in el:
            walk(c, parent, owner)

    for frag in root:
        name = frag.get("Name") or ""
        if frag.tag == "Fragment" and name in SKIP_FRAGMENTS:
            continue
        if name == "References":
            continue
        if "#" in name:
            okey = name.split("#", 1)[1]
            for c in frag:
                walk(c, okey, okey)
        else:
            walk(frag, None, None)

    def path_of(k):
        parts, seen, screen = [], set(), None
        p = info.get(k, {}).get("parent")
        while p and p in info and p not in seen:
            seen.add(p)
            parts.append(info[p]["name"])
            if screen is None and info[p]["tag"] in SCREEN_KINDS:
                screen = p
            p = info[p]["parent"]
        return ".".join(reversed(parts)), screen

    for el, k in flows:
        f = flow_info(m, el, flow_kind(el.tag))
        f["path"], screen = path_of(k)
        if screen:
            f["screen"] = screen
        f["nodes"] = owner_nodes.get(k, [])
        out["flows"].append(f)
    for el, k in screens:
        s = flow_info(m, el, SCREEN_KINDS[el.tag])
        s["path"] = path_of(k)[0]
        s["nodes"] = owner_nodes.get(k, [])
        out["screens"].append(s)
    out["widgetUses"] = sorted(uses)
    out["dependencies"] = dependencies(m, root)
    return out


def dependencies(m, root):
    """{producer module: {uses: n, elements: {kind: [names]}}} counted over every reference in the module's own code;
    referenced modules with uses == 0 are dependencies nothing uses."""
    deps = {name: {"uses": 0, "elements": {}} for name in set(m.ref_modules.values())}
    elems = {}
    for frag in root:
        name = frag.get("Name") or ""
        if name in SKIP_FRAGMENTS or name == "References":
            continue
        for el in frag.iter():
            for v in el.attrib.values():
                if "References." not in v:
                    continue
                for seg in v.split(":")[-1:]:
                    mm = RE_REF_ROOT.search(seg)
                    if not mm:
                        continue
                    producer = m.ref_modules.get(mm.group(1))
                    if producer is None:
                        continue
                    deps[producer]["uses"] += 1
                    pairs = [p for p in RE_REF_ELEM.findall(seg) if p[0] in REF_KINDS]
                    if pairs:
                        kind, ek = pairs[-1]
                        nm = m.names.get(ek)
                        if nm:
                            elems.setdefault(producer, {}).setdefault(REF_KINDS[kind], set()).add(nm)
    for producer, kinds in elems.items():
        deps[producer]["elements"] = {k: sorted(v) for k, v in sorted(kinds.items())}
    return deps


def _worker(job):
    path, out_dir = job
    result = {}

    def run():
        try:
            mod = extract(path)
            target = os.path.join(out_dir, mod["module"] + ".json")
            with open(target, "w", encoding="utf-8") as fh:
                json.dump(mod, fh, ensure_ascii=False, indent=1)
            result["mod"] = mod["module"]
        except Exception as exc:  # keep going; report at the end
            import traceback
            result["err"] = repr(exc) + "\n" + traceback.format_exc(limit=3)

    threading.stack_size(128 * 1024 * 1024)
    t = threading.Thread(target=run)
    t.start()
    t.join()
    print(("OK   " if "mod" in result else "FAIL ") + os.path.basename(path), result.get("err", ""), flush=True)
    return os.path.basename(path), result.get("mod"), result.get("err")


def extract_factory(input_dir=INPUT_DIR, out_dir=OUTPUT_DIR, force=False, only=None, procs=3):
    os.makedirs(out_dir, exist_ok=True)
    cache_path = os.path.join(out_dir, "_cache.json")
    try:
        with open(cache_path, encoding="utf-8") as fh:
            cache = json.load(fh)
    except (OSError, ValueError):
        cache = {}
    files = sorted((os.path.join(input_dir, f) for f in os.listdir(input_dir) if f.lower().endswith(".xml")),
                   key=lambda p: -os.path.getsize(p))
    if only:
        files = [p for p in files if os.path.basename(p)[:-4] in only]
    todo = []
    for p in files:
        st = os.stat(p)
        sig = "%d:%d" % (st.st_size, int(st.st_mtime))
        if force or only or cache.get(os.path.basename(p), {}).get("sig") != sig:
            todo.append(p)
    print(f"{len(files)} module XML(s), {len(todo)} to extract.", flush=True)
    if todo:
        with Pool(min(procs, len(todo)), maxtasksperchild=1) as pool:
            results = pool.map(_worker, [(p, out_dir) for p in todo], chunksize=1)
        for (fname, mod, err), p in zip(results, todo):
            st = os.stat(p)
            if mod:
                cache[fname] = {"sig": "%d:%d" % (st.st_size, int(st.st_mtime)), "module": mod}
            else:
                cache.pop(fname, None)
        with open(cache_path, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, indent=1)
        errs = [f for f, mod, e in results if e]
        print(f"Done: {len(todo) - len(errs)} extracted, {len(errs)} failed {errs if errs else ''}", flush=True)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    only = None
    if "--only" in sys.argv:
        only = set(sys.argv[sys.argv.index("--only") + 1].split(","))
        args = [a for a in args if a != sys.argv[sys.argv.index("--only") + 1]]
    extract_factory(*(args[:2]), force="--force" in sys.argv, only=only)
