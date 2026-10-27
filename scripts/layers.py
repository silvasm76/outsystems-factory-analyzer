"""Architecture Canvas layers from OutSystems module naming, and strongly connected components (dependency cycles)."""
import re

FOUNDATION, CORE, END_USER = "Foundation", "Core Services", "End-User"
RANK = {FOUNDATION: 0, CORE: 1, END_USER: 2}

FOUNDATION_RE = re.compile(r"(_Lib|_Th|_IS|Connector\w*|_CommonWidgets)$")
END_USER_RE = re.compile(r"(_UI|_UI_FIN|_BackOffice|_BO)$")
END_USER_EXACT = {"ProERP", "Training", "ProERP_ProjectMoments"}


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
    """Strongly connected components of the graph adj (node -> set of nodes); components of size > 1 are cycles."""
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
