"""Seeded generator of fictional architectures, with one-flaw-type injectors.

The generator and the rules were written by the same person, so detection here measures
consistency with my own definitions, not coverage of real systems.
"""
import copy
import random

NAMES = ["billing", "catalog", "orders", "search", "profile", "notify", "reports", "inventory"]


def clean(seed):
    r = random.Random(seed)
    zones = [{"id": "internet", "trust": 0}, {"id": "dmz", "trust": 1}, {"id": "app", "trust": 2}, {"id": "data", "trust": 3}]
    comps, flows = [], []

    def comp(id, type, zone, **kw):
        comps.append({"id": id, "type": type, "zone": zone, "logging": True, **kw})

    def flow(src, dst, data, authn="mtls", proto="https"):
        flows.append({"id": f"f{len(flows)}-{src}-{dst}", "source": src, "destination": dst, "protocol": proto,
                      "authn": authn, "encrypted": True, "data": data, "audit_logged": True, "carries_secrets": False})

    comp("user", "user", "internet")
    partner = r.random() < 0.5
    if partner:
        comp("partner", "external", "internet")
    comp("gateway", "service", "dmz", rate_limited=True, replicas=r.randint(2, 3), critical=True, credential="cred-gateway")
    svcs = r.sample(NAMES, r.randint(2, 4))
    for s in svcs:
        comp(s, "service", "app", replicas=r.randint(2, 3), critical=False, credential="cred-" + s)
    comps[[c["id"] for c in comps].index(svcs[0])]["admin_interface"] = {"zones": ["app"], "mfa": True}
    comp("bus", "queue", "app", consumer_authn=True)
    dbs = [f"db-{i}" for i in range(r.randint(1, 2))]
    for i, db in enumerate(dbs):
        comp(db, "datastore", "data", encrypted_at_rest=True, backup=True, access_roles=[svcs[i % len(svcs)]],
             replicas=2, critical=True, credential="cred-" + db, classification=r.choice(["confidential", "restricted"]))
    flow("user", "gateway", "internal", "session")
    flow("gateway", "user", "public", "session")
    if partner:
        flow("partner", "gateway", "internal", "token")
    for s in svcs:
        flow("gateway", s, "internal")
    for i, s in enumerate(svcs):
        flow(s, dbs[i % len(dbs)], r.choice(["confidential", "restricted"]))
    for db in dbs:
        if not any(f["destination"] == db for f in flows):
            flow(svcs[0], db, "confidential")
    flow(svcs[0], "bus", "internal")
    flow("bus", svcs[-1], "internal")
    if len(svcs) > 2:
        flow(svcs[1], svcs[2], "internal")
    return {"name": f"generated-{seed}", "zones": zones, "components": comps, "flows": flows}


def _c(d, pred):
    return [c for c in d["components"] if pred(c)]


def _crossing(d, minrank=0):
    z = {c["id"]: c["zone"] for c in d["components"]}
    rk = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
    return [f for f in d["flows"] if z[f["source"]] != z[f["destination"]] and rk[f["data"]] >= minrank]


def i_r01(d, r):
    f = r.choice(_crossing(d, 1))
    f["encrypted"] = False
    if r.random() < 0.5:
        f["authn"] = "none"
    return ["flow:" + f["id"]]


def i_r02(d, r):
    if not _c(d, lambda c: c["id"] == "vendor"):
        d["components"].append({"id": "vendor", "type": "external", "zone": "internet", "logging": True})
    src = r.choice(_c(d, lambda c: c["type"] == "service" and c["zone"] == "app"))["id"]
    d["flows"].append({"id": "f-leak", "source": src, "destination": "vendor", "protocol": "https", "authn": "token",
                       "encrypted": True, "data": r.choice(["confidential", "restricted"]), "audit_logged": True,
                       "carries_secrets": False})
    return ["flow:f-leak"]


def i_r03(d, r):
    c = r.choice(_c(d, lambda c: c["type"] == "datastore"))
    c["encrypted_at_rest"] = False
    return ["component:" + c["id"]]


def i_r04(d, r):
    c = _c(d, lambda c: "admin_interface" in c)[0]
    c["admin_interface"] = {"zones": ["app", "internet"], "mfa": r.random() < 0.5}
    return ["component:" + c["id"]]


def i_r05(d, r):
    f = r.choice(_crossing(d, 1))
    f["audit_logged"] = False
    return ["flow:" + f["id"]]


def i_r06(d, r):
    f = r.choice(d["flows"])
    f["carries_secrets"] = True
    return ["flow:" + f["id"]]


def i_r07(d, r):
    _c(d, lambda c: c["id"] == "gateway")[0]["rate_limited"] = False
    return ["component:gateway"]


def i_r08(d, r):
    c = r.choice(_c(d, lambda c: c.get("critical")))
    c["replicas"] = 1
    return ["component:" + c["id"]]


def i_r09(d, r):
    _c(d, lambda c: c["type"] == "queue")[0]["consumer_authn"] = False
    return ["component:bus"]


def i_r10(d, r):
    a, b = _c(d, lambda c: c["id"] == "gateway")[0], r.choice(_c(d, lambda c: c["type"] == "datastore"))
    a["credential"] = b["credential"] = "cred-shared"
    return ["component:" + a["id"], "component:" + b["id"]]


def i_r11(d, r):
    c = r.choice(_c(d, lambda c: c["type"] == "datastore"))
    c["backup"] = False
    return ["component:" + c["id"]]


INJECT = {f"R{i:02d}": fn for i, fn in enumerate(
    [i_r01, i_r02, i_r03, i_r04, i_r05, i_r06, i_r07, i_r08, i_r09, i_r10, i_r11], 1)}


def flawed(seed, flaws):
    """Return (model, [(rule, expected_elements)]) with the given flaw types injected."""
    d = clean(seed)
    r = random.Random(seed + 7919)
    return d, [(f, INJECT[f](d, r)) for f in flaws]


def ev_transitive_admin(d, r):
    """Admin interface exposed to the dmz, which the internet can reach: R04 only looks at direct trust-0 zones."""
    _c(d, lambda c: "admin_interface" in c)[0]["admin_interface"] = {"zones": ["app", "dmz"], "mfa": False}


def ev_mislabelled_data(d, r):
    """Confidential data sent to an external vendor but labelled 'internal' in the model."""
    i_r02(d, r)
    d["flows"][-1]["data"] = "internal"


def ev_intra_zone_open(d, r):
    """Unencrypted, unauthenticated flow inside one zone: R01 only judges boundary crossings."""
    f = next(f for f in d["flows"] if f["source"] == "bus" or f["destination"] == "bus")
    f["encrypted"], f["authn"] = False, "none"


EVASION = {"admin reachable via dmz (transitive)": ev_transitive_admin,
           "sensitive data mislabelled 'internal'": ev_mislabelled_data,
           "unencrypted flow inside one zone": ev_intra_zone_open}


def bad_dangling(d, r):
    r.choice(d["flows"])["destination"] = "ghost"


def bad_zone(d, r):
    r.choice(d["components"])["zone"] = "nowhere"


def bad_dup(d, r):
    d["components"].append(copy.deepcopy(r.choice(d["components"])))


def bad_zone_cycle(d, r):
    d["zones"] = [{"id": "za", "parent": "zb"}, {"id": "zb", "parent": "za"}] + d["zones"]


def bad_failover_cycle(d, r):
    a, b = r.sample(d["components"], 2)
    a["failover_of"], b["failover_of"] = b["id"], a["id"]


def bad_class(d, r):
    r.choice(d["flows"])["data"] = "top-secret"


def bad_missing(d, r):
    del r.choice(_c(d, lambda c: c["type"] == "datastore"))["encrypted_at_rest"]


INVALID = {"dangling reference": bad_dangling, "unknown zone": bad_zone, "duplicate id": bad_dup,
           "zone parent cycle": bad_zone_cycle, "failover cycle": bad_failover_cycle,
           "unknown classification": bad_class, "missing required flag": bad_missing}
