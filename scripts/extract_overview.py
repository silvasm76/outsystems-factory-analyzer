"""Extract business-facing facts (descriptions, screens, entities, public actions, REST, roles, timers)
from input/*.xml into output/overview_data.json for the application overview report."""
import json, os, sys, xml.etree.ElementTree as ET
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
IN, OUT = os.path.join(HERE, "..", "input"), os.path.join(HERE, "..", "output", "overview_data.json")


def one(path):
    sys.setrecursionlimit(100000)
    r = ET.parse(path).getroot()
    es = next(r.iter("ESpace"), None)
    d = {"name": es.get("Name"), "desc": es.get("Description") or "", "entities": [], "screens": [], "pub_actions": [],
         "rest_exposed": [], "rest_consumed": [], "roles": [], "timers": [], "n_public_blocks": 0}
    seen = set()
    for e in r.iter():
        t, k = e.tag, e.get("Key")
        if t == "Entity" and e.get("Name") and k and not e.get("Ref") and ("e", k) not in seen:
            seen.add(("e", k))
            d["entities"].append({"n": e.get("Name"), "p": e.get("PrettyName") or "", "d": e.get("Description") or "",
                                  "pub": e.get("Public") == "Yes", "static": e.find("StaticRecords") is not None and len(e.find("StaticRecords")) > 0})
        elif t == "NRNodes.WebScreen" and e.get("Name") and k and ("s", k) not in seen:
            seen.add(("s", k))
            d["screens"].append({"n": e.get("Name"), "t": e.get("Title") or "", "d": e.get("Description") or ""})
        elif t in ("Flows.UserAction", "Flows.UserActionInsideFolder", "NRFlows.ClientActionFlow",
                   "NRFlows.ClientActionFlowInsideFolder") and e.get("Public") == "Yes" and k and ("a", k) not in seen:
            seen.add(("a", k))
            d["pub_actions"].append({"n": e.get("Name"), "d": e.get("Description") or "", "c": t.startswith("NR")})
        elif t.startswith("CustomService-") and "RestService" in t and k:
            d["rest_exposed"].append({"n": e.get("Name"), "d": e.get("Description") or "",
                                      "m": [a.get("Name") for a in e.iter() if a.tag.startswith("Flows.CustomActionFlow-") and a.get("Name")]})
        elif t.startswith("CustomClient-") and "RestClient" in t and k:
            d["rest_consumed"].append({"n": e.get("Name"), "d": e.get("Description") or ""})
        elif t == "Role" and e.get("Name") and k and ("r", k) not in seen:
            seen.add(("r", k)); d["roles"].append(e.get("Name"))
        elif t == "Timer" and e.get("Name") and k and ("t", k) not in seen:
            seen.add(("t", k)); d["timers"].append({"n": e.get("Name"), "d": e.get("Description") or ""})
        elif t == "NRNodes.WebBlock" and e.get("Public") == "Yes":
            d["n_public_blocks"] += 1
    return d


if __name__ == "__main__":
    files = sorted(os.path.join(IN, f) for f in os.listdir(IN) if f.endswith(".xml"))
    with Pool(3, maxtasksperchild=1) as p:
        res = p.map(one, files, chunksize=1)
    json.dump({d["name"]: d for d in res}, open(OUT, "w", encoding="utf-8"))
    print("wrote", OUT, len(res))
