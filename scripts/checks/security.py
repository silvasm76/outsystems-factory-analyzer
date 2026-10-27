"""Security rules over the extracted model. Writes output/findings/security.json.

Rules (ids are stable; the report groups by them):
  SEC-01 Exposed REST API without authentication
  SEC-02 Exposed REST API without HTTPS
  SEC-03 Exposed REST method changes data over GET
  SEC-04 Credentials received in the URL of an exposed REST method
  SEC-05 Hardcoded credentials in a consumed REST integration
  SEC-06 Consumed REST integration hardcoded to a non-production URL
  SEC-07 Secret stored as a site property default value
  SEC-08 Hardcoded secret literal in logic
  SEC-09 SQL injection: Expand Inline parameter without EncodeSql/BuildSafe_InClause
  SEC-10 Screen accessible to anonymous users
  SEC-11 Public entity exposes sensitive personal data
  SEC-12 Risky client-side JavaScript (crypto in the browser, eval, HTML injection)
  SEC-13 Exception details shown to the end user

Usage: python scripts/checks/security.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Context, finding, lower, mask, mask_literals, write  # noqa: E402

SENSITIVE_ATTR = re.compile(r"iban|socialsecurity|taxnumber|civilid|passport|password|passwd|salary|bankcode|"
                            r"birthdate|healthinsurance|medical", re.I)
SECRET_NAME = re.compile(r"password|passwd|pwd|secret|token|api_?key|bearer|authorization|credential", re.I)
NOT_SECRET_NAME = re.compile(r"ValidationMessage|Label|Message|Title|Placeholder|ValidDays|Expiration|Allow|^Has|^Is|Url$",
                             re.I)
WRITE_NAME = re.compile(r"^(Delete|Remove|Create|Update|Insert|Save|Set|Send|Add|Grant|Revoke|Approve|Reject|Import|"
                        r"Upload|Process|Sync|Inactivate|Activate)", re.I)
EXPECTED_ANONYMOUS = re.compile(r"login|logout|invalidpermission|callback|error|notfound|unauthorized", re.I)
NON_PROD_URL = re.compile(r"(^file:|localhost|127\.0\.0\.1|[-.](dev|qa|test|tst|staging|stg|uat)[-.])", re.I)
SAFE_INLINE = re.compile(r"EncodeSql|BuildSafe_InClause", re.I)
LOGIN_NAME = re.compile(r"^(login|authenticat\w*|token|signin)$", re.I)

AUTH = {"": "None", "0": "None", "1": "Basic"}


def writes_data(flow):
    """What a flow changes: entity writes, DML SQL or calls to write-like actions (names)."""
    what = []
    for n in flow.get("nodes", []):
        a = n.get("action") or ""
        if n.get("action_ref", "").startswith("EntityActions") and re.match(r"(Create|Update|Delete)", a.split(".")[-1]):
            what.append(a)
        elif n["type"] == "AdvancedQuery" and re.match(r"\s*(delete|update|insert|merge|truncate)\b", n.get("sql", ""), re.I):
            what.append("SQL %s" % n.get("name"))
        elif a and WRITE_NAME.match(a.split(".")[-1]):
            what.append(a)
    return sorted(set(what))


def personal_types(ctx):
    """Entity/structure names that carry sensitive attributes (any module)."""
    names = set()
    for m in ctx.models.values():
        for e in m["entities"] + m["structures"]:
            if any(SENSITIVE_ATTR.search(a["name"] or "") for a in e["attributes"]):
                names.add(e["name"])
    return names


def rest_flow(m, service, method):
    return next((f for f in m["flows"] if f["kind"] == "RESTMethod" and f.get("path") == service and f["name"] == method), None)


def check_rest_exposed(ctx, out):
    personal = personal_types(ctx)
    for mod, m in ctx.models.items():
        for svc in m.get("restExposed", []):
            p = svc["props"]
            auth = AUTH.get(p.get("Authentication", ""), "configured (type %s)" % p.get("Authentication"))
            internal = p.get("InternalAccess") == "1"
            if p.get("HttpSecurity", "0") == "0":
                out.append(finding("SEC-02", "High", "A02 Cryptographic Failures", "Exposed REST API without HTTPS",
                                   mod, "REST %s" % svc["name"], evidence="URL %s, HttpSecurity=None" % p.get("URL"),
                                   recommendation="Set HTTP Security to SSL/TLS in the exposed REST API properties."))
            for meth in svc["methods"]:
                flow = rest_flow(m, svc["name"], meth["name"])
                file = ctx.file_of(mod, flow) if flow else None
                verb = meth["props"].get("HTTPMethod", "GET").upper()
                url = meth["props"].get("URL", "")
                writes = writes_data(flow) if flow else []
                outs = " ".join(o["type"] for o in meth.get("outputs", []))
                returns_personal = sorted(t for t in personal if re.search(r"\b%s\b" % re.escape(t), outs))
                element = "REST %s.%s (%s %s)" % (svc["name"], meth["name"], verb, url)
                if auth == "None":
                    sev = "Critical" if writes or returns_personal else "High"
                    if internal:
                        sev = lower(sev)
                    ev = ["Authentication=None%s" % (", Internal Access Only" if internal else ", reachable from the internet")]
                    if LOGIN_NAME.search(meth["name"]) and not writes:
                        sev = "Low"
                        ev.append("login endpoint (unauthenticated by design): make sure it is rate limited and logs failures")
                    if meth.get("inputs"):
                        ev.append("inputs: " + ", ".join(i["name"] for i in meth["inputs"]))
                    if writes:
                        ev.append("changes data: " + ", ".join(writes[:6]))
                    if returns_personal:
                        ev.append("returns personal data: " + ", ".join(returns_personal))
                    out.append(finding("SEC-01", sev, "A01 Broken Access Control", "Exposed REST API without authentication",
                                       mod, element, file, "; ".join(ev),
                                       "Enable Basic or Custom authentication (OnAuthentication) and validate the caller; "
                                       "restrict to Internal Access Only if the API is only used inside the infrastructure."))
                if writes and verb == "GET":
                    out.append(finding("SEC-03", "Medium", "A01 Broken Access Control", "Exposed REST method changes data over GET",
                                       mod, element, file, "changes data: " + ", ".join(writes[:6]),
                                       "Use POST/PUT/DELETE for state-changing operations; GET requests are cached, "
                                       "logged with their parameters and easy to trigger cross-site."))
                for i in meth.get("inputs", []):
                    where = i["props"].get("ReceiveIn", "URL" if verb == "GET" else "Body")
                    if SECRET_NAME.search(i["name"]) and where not in ("Body", "Header"):
                        out.append(finding("SEC-04", "High", "A04 Insecure Design", "Credentials received in the URL",
                                           mod, element, file, "input %s received in %s" % (i["name"], where),
                                           "Receive credentials in the request body or an Authorization header (POST); "
                                           "URLs end up in proxy, server and browser logs."))


def check_rest_consumed(ctx, out):
    cred_keys = re.compile(r"password|username|token|secret|api_?key|clientid", re.I)
    for mod, m in ctx.models.items():
        for svc in m.get("restConsumed", []):
            p = svc["props"]
            creds = {k: v for k, v in p.items() if cred_keys.search(k) and v and not v.startswith(("Flows.", "Variables."))}
            if creds:
                sev = "Critical" if any(re.search(r"password|secret|token|api_?key", k, re.I) for k in creds) else "High"
                out.append(finding("SEC-05", sev, "A07 Identification and Authentication Failures",
                                   "Hardcoded credentials in a consumed REST integration", mod, "REST client %s" % svc["name"],
                                   evidence="; ".join("%s=%s" % (k, mask(v)) for k, v in creds.items())
                                   + " (Base URL %s)" % p.get("Base URL", ""),
                                   recommendation="Remove the credentials from the module and rotate them; read them at runtime "
                                                  "from a secret site property/settings entity and set them in OnBeforeRequest."))
            base = p.get("Base URL", "")
            if NON_PROD_URL.search(base):
                out.append(finding("SEC-06", "Low", "A05 Security Misconfiguration",
                                   "Consumed REST integration hardcoded to a non-production URL", mod,
                                   "REST client %s" % svc["name"], evidence="Base URL %s" % base,
                                   recommendation="Configure the Base URL per environment (Service Center effective URL or a "
                                                  "site property) so production never calls development endpoints."))


def check_secrets(ctx, out):
    for mod, m in ctx.models.items():
        for sp in m.get("siteProperties", []):
            if SECRET_NAME.search(sp["name"]) and not NOT_SECRET_NAME.search(sp["name"]) and sp.get("default") \
                    and sp["type"] == "Text" and sp["default"] != '""':
                out.append(finding("SEC-07", "High", "A02 Cryptographic Failures", "Secret stored as a site property default value",
                                   mod, "SiteProperty %s" % sp["name"], evidence="default value %s" % mask_literals(sp["default"]),
                                   recommendation="Remove the default value (it ships in every deployment and in the OAP) and set "
                                                  "the value per environment in Service Center, marked as secret where supported."))
    seen = set()
    for mod, m, f, n in ctx.iter_nodes():
        for target, value in (n.get("assign") or []) + (n.get("args") or []):
            if not value or not target:
                continue
            literal = re.fullmatch(r'"([^"]{6,})"', value)
            named_secret = SECRET_NAME.search(target) and not NOT_SECRET_NAME.search(target.split(".")[-1])
            bearer = re.search(r'"(Bearer|Basic) [A-Za-z0-9+/=._-]{10,}', value)
            if (literal and named_secret) or bearer:
                key = (mod, f["name"], target)
                if key in seen:
                    continue
                seen.add(key)
                out.append(finding("SEC-08", "High", "A07 Identification and Authentication Failures",
                                   "Hardcoded secret literal in logic", mod, ctx.element(f),
                                   ctx.file_of(mod, f), "%s = %s" % (target, mask_literals(value)),
                                   "Move the secret out of the code (site property set per environment or a secrets "
                                   "store) and rotate it."))


def check_sql_injection(ctx, out):
    for mod, m, f, n in ctx.iter_nodes():
        if n["type"] != "AdvancedQuery":
            continue
        args = dict(n.get("args") or [])
        # nodes in this flow that sanitize: X.Output where X calls EncodeSql/BuildSafe_InClause*
        safe_nodes = {(c.get("name") or c.get("action", "").split(".")[-1]) for c in f.get("nodes", [])
                      if c.get("action") and SAFE_INLINE.search(c["action"])}
        for pname, ptype, inline in n.get("params", []):
            if not inline:
                continue
            value = args.get(pname) or ""
            refs = set(re.findall(r"(\w+)\.Output\b", value))
            if SAFE_INLINE.search(value) or (refs and refs <= safe_nodes):
                continue
            fid = ctx.flow_id(mod, f)
            upstream = ctx.callers_upstream(fid) | {fid}
            entry = sorted(u for u in upstream if ctx.flows.get(u, {}).get("kind") in ("RESTMethod", "ScreenAction", "DataAction",
                                                                                         "ServiceAPIMethod"))
            rest = [u for u in entry if ctx.flows[u]["kind"] == "RESTMethod"]
            sev = "High" if ptype == "Text" else "Medium"
            internal = not entry and not any(i["type"] == "Text" for i in f.get("inputs", []))
            if rest:
                sev = "Critical"
            elif internal:
                sev = "Medium"
            ev = "SQL %s: @%s (%s) Expand Inline = %s" % (n.get("name"), pname, ptype, value or "(no value)")
            if entry:
                ev += "; reachable from: " + ", ".join(entry[:5]) + (" ..." if len(entry) > 5 else "")
            elif internal:
                ev += "; value built internally (no Text input, no screen/API entry point found)"
            out.append(finding("SEC-09", sev, "A03 Injection", "SQL injection risk: Expand Inline parameter not sanitized",
                               mod, ctx.element(f) + " / SQL %s" % (n.get("name")), ctx.file_of(mod, f), ev,
                               "Wrap the value with EncodeSql() or build IN lists with BuildSafe_InClauseIntegerList/"
                               "TextList; prefer non-inline parameters wherever possible."))


def check_screens(ctx, out):
    for mod, m in ctx.models.items():
        by_screen = {}
        for f in m["flows"]:
            if f.get("screen"):
                by_screen.setdefault(f["screen"], []).append(f)
        for s in m["screens"]:
            if s["kind"] != "Screen" or "Anonymous" not in (s.get("roles") or []):
                continue
            data = [n.get("name") or n["type"] for n in s.get("nodes", []) if n["type"] in ("WebScreenDataSet", "DataSet")]
            calls = sorted({n["action"] for f in by_screen.get(s["key"], []) for n in f.get("nodes", [])
                            if n.get("action") and n["type"] == "ExecuteAction"})
            data += [f["name"] for f in by_screen.get(s["key"], []) if f["kind"] == "DataAction"]
            if EXPECTED_ANONYMOUS.search(s["name"]):
                sev, why = "Info", "expected for a %s screen" % s["name"]
            elif data or calls:
                sev, why = "Medium", "fetches data or runs server logic without authentication"
            else:
                sev, why = "Low", "no data fetched"
            ev = why
            if data:
                ev += "; data: " + ", ".join(data[:6])
            if calls:
                ev += "; server calls: " + ", ".join(calls[:6]) + (" ..." if len(calls) > 6 else "")
            out.append(finding("SEC-10", sev, "A01 Broken Access Control", "Screen accessible to anonymous users", mod,
                               "Screen %s" % ((s.get("path") + ".") if s.get("path") else "") + s["name"],
                               ctx.file_of(mod, s), ev,
                               "Confirm the screen must be public; validate every input on the server and check roles or "
                               "tokens inside each server action it calls."))


def check_entities(ctx, out):
    for mod, m in ctx.models.items():
        consumers = ctx.index["modules"].get(mod, {}).get("consumers", [])
        for e in m["entities"]:
            attrs = [a["name"] for a in e["attributes"] if SENSITIVE_ATTR.search(a["name"] or "")]
            if not e.get("public") or not attrs:
                continue
            sev = "Medium" if e.get("exposeReadOnly", True) else "High"
            out.append(finding("SEC-11", sev, "A01 Broken Access Control", "Public entity exposes sensitive personal data",
                               mod, "Entity %s" % e["name"], None,
                               "attributes: %s; %s; module consumed by %d module(s)" % (
                                   ", ".join(attrs), "read-only for consumers" if e.get("exposeReadOnly", True)
                                   else "writable by every consumer (Expose Read Only = No)", len(consumers)),
                               "Move sensitive attributes to a separate non-public entity (or encrypt them) and expose them "
                               "only through server actions that check roles and log access (GDPR data minimisation)."))


def check_client(ctx, out):
    for mod, m, f, n in ctx.iter_nodes():
        if n["type"] == "JavascriptNode":
            js = n.get("js") or ""
            risks = []
            if re.search(r"CryptoJS|crypto\.subtle|forge\.", js):
                risks.append(("High", "cryptography in the browser (the key is visible to any user)"))
            if re.search(r"\beval\(|new Function\(", js):
                risks.append(("Medium", "eval/new Function (code injection)"))
            if re.search(r"innerHTML|outerHTML|document\.write|insertAdjacentHTML", js):
                risks.append(("Medium", "HTML injection sink (XSS)"))
            if re.search(r"localStorage|sessionStorage", js) and re.search(r"token|password|secret", js, re.I):
                risks.append(("Medium", "secret kept in browser storage"))
            for sev, why in risks:
                out.append(finding("SEC-12", sev, "A03 Injection" if "injection" in why or "XSS" in why
                                   else "A02 Cryptographic Failures", "Risky client-side JavaScript", mod,
                                   ctx.element(f) + " / JS %s" % (n.get("name") or ""), ctx.file_of(mod, f),
                                   why + ": " + mask_literals(" ".join(js.split()))[:160],
                                   "Keep secrets and cryptography on the server; avoid eval and raw HTML injection, or "
                                   "sanitize the content first."))
        elif n["type"] == "FeedbackMessage" and any("ExceptionMessage" in (v or "") for v in n.get("fields", {}).values()):
            out.append(finding("SEC-13", "Low", "A04 Insecure Design", "Exception details shown to the end user", mod,
                               ctx.element(f), ctx.file_of(mod, f),
                               "; ".join("%s=%s" % kv for kv in n.get("fields", {}).items())[:200],
                               "Show a generic message to the user and log the exception detail on the server."))


def run(ctx):
    out = []
    for check in (check_rest_exposed, check_rest_consumed, check_secrets, check_sql_injection, check_screens,
                  check_entities, check_client):
        check(ctx, out)
    return out


def inventory(ctx):
    """Facts the report shows even when nothing is wrong: exposed/consumed APIs and anonymous screens."""
    inv = {"restExposed": [], "restConsumed": []}
    for mod, m in ctx.models.items():
        for s in m.get("restExposed", []):
            p = s["props"]
            inv["restExposed"].append({"module": mod, "service": s["name"], "url": p.get("URL"),
                                       "authentication": AUTH.get(p.get("Authentication", ""), "configured (type %s)" % p.get("Authentication")),
                                       "https": p.get("HttpSecurity", "0") != "0", "internalOnly": p.get("InternalAccess") == "1",
                                       "methods": ["%s %s" % (x["props"].get("HTTPMethod", "GET").upper(), x["name"]) for x in s["methods"]]})
        for s in m.get("restConsumed", []):
            inv["restConsumed"].append({"module": mod, "service": s["name"], "baseUrl": s["props"].get("Base URL"),
                                        "methods": len(s["methods"])})
    return inv


if __name__ == "__main__":
    import json
    c = Context()
    path = write("security", run(c))
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    data["inventory"] = inventory(c)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1)
