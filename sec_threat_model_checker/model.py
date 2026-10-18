"""Architecture model loading and validation.

Anything the checker cannot judge (dangling reference, unknown zone, duplicate id,
a cycle that makes trust or redundancy undecidable) raises ModelError -> exit 2.
"""
import json

TYPES = ("service", "datastore", "queue", "external", "user")
CLASSES = ("public", "internal", "confidential", "restricted")
RANK = {c: i for i, c in enumerate(CLASSES)}


class ModelError(Exception):
    def __init__(self, errors):
        self.errors = [errors] if isinstance(errors, str) else list(errors)
        super().__init__("; ".join(self.errors))


class JudgeError(ModelError):
    """A rule could not be evaluated. Never treated as a pass."""


def _cycles(nxt):
    out, done = [], set()
    for s in sorted(nxt):
        path, n = [], s
        while n in nxt and n not in path and n not in done:
            path.append(n)
            n = nxt[n]
        if n in path:
            out.append(sorted(path[path.index(n):]))
        done.update(path)
    return out


def _ref(v, known):
    return isinstance(v, str) and v in known


def _bool(v):
    return isinstance(v, bool)


def _int(v, lo, hi):
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


class Model:
    def __init__(self, d):
        self.d = d
        self.name = str(d.get("name", "unnamed"))
        self.zones = {z["id"]: z for z in d["zones"]}
        self.comps = {c["id"]: c for c in d["components"]}
        self.flows = d["flows"]
        self._trust = {z: self._resolve(z) for z in self.zones}

    def _resolve(self, z):
        while self.zones[z].get("trust") is None:
            z = self.zones[z]["parent"]
        return self.zones[z]["trust"]

    def zone_trust(self, z):
        return self._trust[z]

    def zone(self, cid):
        return self.comps[cid]["zone"]

    def trust(self, cid):
        return self._trust[self.zone(cid)]

    def crosses(self, f):
        return self.zone(f["source"]) != self.zone(f["destination"])

    def held(self, cid):
        """Highest classification declared on, or flowing into/out of, a component."""
        r = RANK.get(self.comps[cid].get("classification", "public"), 0)
        for f in self.flows:
            if cid in (f["source"], f["destination"]):
                r = max(r, RANK[f["data"]])
        return r


def validate(d):
    if not isinstance(d, dict):
        raise ModelError("model must be a JSON object")
    errs = []
    for k in ("zones", "components", "flows"):
        if not isinstance(d.get(k), list):
            errs.append(f"'{k}' must be a list")
    if errs:
        raise ModelError(errs)

    def ids(kind, items):
        seen = set()
        for i, x in enumerate(items):
            if not isinstance(x, dict) or not isinstance(x.get("id"), str) or not x["id"]:
                errs.append(f"{kind}[{i}] needs a non-empty string 'id'")
                continue
            if x["id"] in seen:
                errs.append(f"duplicate {kind} id '{x['id']}'")
            seen.add(x["id"])
        return seen

    zs, cs = ids("zone", d["zones"]), ids("component", d["components"])
    ids("flow", d["flows"])
    ok = lambda x: isinstance(x, dict) and isinstance(x.get("id"), str)  # noqa: E731
    if not d["components"]:
        errs.append("model has no components")

    parent = {}
    for z in filter(ok, d["zones"]):
        t, p, n = z.get("trust"), z.get("parent"), z["id"]
        if t is not None and not _int(t, 0, 3):
            errs.append(f"zone '{n}': trust must be an integer 0-3 (0 = untrusted)")
        if p is not None:
            if _ref(p, zs):
                parent[n] = p
            else:
                errs.append(f"zone '{n}': parent {p!r} is not a zone")
        if t is None and p is None:
            errs.append(f"zone '{n}': needs 'trust' or a 'parent' to inherit from")
    for cyc in _cycles(parent):
        errs.append("zone parent cycle makes trust undecidable: " + " -> ".join(cyc))

    failover = {}
    for c in filter(ok, d["components"]):
        n, ty = c["id"], c.get("type")
        if ty not in TYPES:
            errs.append(f"component '{n}': type must be one of {list(TYPES)}")
        if not _ref(c.get("zone"), zs):
            errs.append(f"component '{n}': unknown zone {c.get('zone')!r}")
        for k in ("logging", "rate_limited", "critical", "encrypted_at_rest", "backup", "consumer_authn"):
            if k in c and not _bool(c[k]):
                errs.append(f"component '{n}': '{k}' must be true/false")
        for k in {"datastore": ("encrypted_at_rest", "backup"), "queue": ("consumer_authn",)}.get(ty, ()):
            if k not in c:
                errs.append(f"component '{n}' ({ty}): '{k}' is required, the checker will not guess")
        if "replicas" in c and not _int(c["replicas"], 1, 10**6):
            errs.append(f"component '{n}': replicas must be an integer >= 1")
        if "classification" in c and c["classification"] not in CLASSES:
            errs.append(f"component '{n}': unknown classification {c['classification']!r}")
        if "credential" in c and not isinstance(c["credential"], str):
            errs.append(f"component '{n}': credential must be a string id")
        a = c.get("admin_interface")
        if a is not None:
            if not isinstance(a, dict) or not isinstance(a.get("zones"), list) or not all(_ref(z, zs) for z in a["zones"]):
                errs.append(f"component '{n}': admin_interface.zones must list known zones")
            elif "mfa" in a and not _bool(a["mfa"]):
                errs.append(f"component '{n}': admin_interface.mfa must be true/false")
        if "failover_of" in c:
            if _ref(c["failover_of"], cs) and c["failover_of"] != n:
                failover[n] = c["failover_of"]
            else:
                errs.append(f"component '{n}': failover_of must name another component")
    for cyc in _cycles(failover):
        errs.append("failover_of cycle makes redundancy undecidable: " + " -> ".join(cyc))

    for f in filter(ok, d["flows"]):
        n = f["id"]
        for k in ("source", "destination"):
            if not _ref(f.get(k), cs):
                errs.append(f"flow '{n}': {k} {f.get(k)!r} is not a component")
        if f.get("data") not in CLASSES:
            errs.append(f"flow '{n}': data must be one of {list(CLASSES)}")
        for k in ("encrypted", "audit_logged"):
            if not _bool(f.get(k)):
                errs.append(f"flow '{n}': '{k}' must be true/false")
        if "carries_secrets" in f and not _bool(f["carries_secrets"]):
            errs.append(f"flow '{n}': 'carries_secrets' must be true/false")
        for k in ("authn", "protocol"):
            if not isinstance(f.get(k), str) or not f[k]:
                errs.append(f"flow '{n}': '{k}' must be a non-empty string (authn 'none' means none)")
    if errs:
        raise ModelError(errs)
    return Model(d)


def load_model(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        raise ModelError(f"cannot read model {path}: {e}")
    return validate(data)
