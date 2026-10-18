"""STRIDE-style rules over the architecture model. Each rule documents why it exists and the fix."""
from dataclasses import dataclass
from typing import Callable

from .model import CLASSES, RANK, JudgeError, validate

SEVS = ("low", "medium", "high", "critical")
SEVRANK = {s: i for i, s in enumerate(SEVS)}
RULES = []


@dataclass
class Rule:
    id: str
    name: str
    stride: str
    severity: str
    rationale: str
    mitigation: str
    fn: Callable


def rule(id, name, stride, severity, rationale, mitigation):
    def deco(fn):
        RULES.append(Rule(id, name, stride, severity, rationale, mitigation, fn))
        return fn
    return deco


def F(f):
    return "flow:" + f["id"]


def C(cid):
    return "component:" + cid


@rule("R01", "boundary-flow-without-tls-or-authn", "Tampering", "high",
      "A flow that crosses a trust boundary without TLS can be read or altered in transit; without "
      "authentication (for non-public data) the receiver cannot tell who sent it.",
      "Use TLS (mTLS between services) and authenticate the caller on every boundary-crossing flow.")
def r01(m):
    for f in m.flows:
        if not m.crosses(f):
            continue
        r, probs = RANK[f["data"]], []
        if not f["encrypted"]:
            probs.append("no TLS")
        if f["authn"] == "none" and r >= 1:
            probs.append("no authn")
        if probs:
            sev = "critical" if len(probs) == 2 and r >= 2 else ("medium" if r == 0 else "high")
            yield [F(f)], f"flow {f['id']} crosses {m.zone(f['source'])}->{m.zone(f['destination'])} with " + " and ".join(probs), sev


@rule("R02", "sensitive-data-to-lower-trust", "Information disclosure", "high",
      "Confidential or restricted data sent to an external party, or to a zone with lower trust than "
      "its source, leaves the area where it is protected.",
      "Minimise or tokenise the data, keep it inside the higher-trust zone, or document a data-sharing agreement.")
def r02(m):
    for f in m.flows:
        r = RANK[f["data"]]
        if r < 2:
            continue
        s, d = f["source"], f["destination"]
        if m.comps[d]["type"] == "external" or m.trust(d) < m.trust(s):
            yield [F(f)], f"{f['data']} data flows {s} -> {d} (lower trust or external)", "critical" if r == 3 else "high"


@rule("R03", "datastore-unencrypted-at-rest", "Information disclosure", "high",
      "A datastore holding confidential or restricted data without encryption at rest exposes it through "
      "stolen disks, snapshots and backups.",
      "Enable encryption at rest with managed keys; rotate keys and restrict key access.")
def r03(m):
    for c in m.comps.values():
        if c["type"] == "datastore" and not c["encrypted_at_rest"] and m.held(c["id"]) >= 2:
            yield [C(c["id"])], f"datastore {c['id']} holds {CLASSES[m.held(c['id'])]} data without encryption at rest", ("critical" if m.held(c["id"]) == 3 else "high")


@rule("R04", "admin-interface-reachable-from-untrusted-zone", "Elevation of privilege", "high",
      "An administrative interface reachable from an untrusted zone (trust 0) invites credential attacks "
      "on the most powerful function of the component.",
      "Move the admin interface behind a bastion or VPN in a trusted zone and require MFA.")
def r04(m):
    for c in m.comps.values():
        a = c.get("admin_interface")
        bad = [z for z in (a or {}).get("zones", []) if m.zone_trust(z) == 0]
        if bad:
            yield [C(c["id"])], f"admin interface of {c['id']} reachable from untrusted zone(s) {bad}", ("high" if a.get("mfa") else "critical")


@rule("R05", "boundary-crossing-without-audit-logging", "Repudiation", "medium",
      "If boundary-crossing flows carrying non-public data are not audit-logged, actors can deny actions "
      "and investigations have nothing to work from.",
      "Log who, what and when at the boundary and ship the log to tamper-evident storage.")
def r05(m):
    for f in m.flows:
        r = RANK[f["data"]]
        if m.crosses(f) and r >= 1 and not f["audit_logged"]:
            yield [F(f)], f"flow {f['id']} crosses a boundary with {f['data']} data and no audit logging", ("high" if r >= 2 else "medium")


@rule("R06", "secrets-carried-in-flow", "Information disclosure", "high",
      "Credentials or keys travelling as flow payload get logged, cached and replayed.",
      "Use a secrets manager with short-lived, scoped tokens fetched by the consumer instead of passing secrets.")
def r06(m):
    for f in m.flows:
        if f.get("carries_secrets"):
            yield [F(f)], f"flow {f['id']} carries secrets", ("critical" if not f["encrypted"] else "high")


@rule("R07", "public-ingress-without-rate-limiting", "Denial of service", "medium",
      "A component that accepts traffic from an untrusted zone with no rate limiting can be exhausted by "
      "one noisy client.",
      "Add rate limits and quotas at the gateway, plus load shedding.")
def r07(m):
    seen = set()
    for f in m.flows:
        d = f["destination"]
        if m.trust(f["source"]) == 0 and d not in seen:
            seen.add(d)
            if not m.comps[d].get("rate_limited", False):
                yield [C(d)], f"public ingress {d} (fed from {f['source']}) has no rate limiting", "medium"


@rule("R08", "single-point-of-failure-on-critical-path", "Denial of service", "high",
      "A component on the critical path with one replica and no declared failover takes the service down "
      "when it fails.",
      "Run at least two replicas, or declare a standby with failover_of.")
def r08(m):
    covered = {c["failover_of"] for c in m.comps.values() if "failover_of" in c}
    for c in m.comps.values():
        if c.get("critical") and c.get("replicas", 1) < 2 and c["id"] not in covered:
            yield [C(c["id"])], f"critical component {c['id']} has {c.get('replicas', 1)} replica and no failover", "high"


@rule("R09", "unauthenticated-queue-consumers", "Spoofing", "high",
      "If any party can attach as a consumer to a queue, messages can be read or stolen by an impostor.",
      "Require authenticated, authorised consumers (per-consumer credentials or mTLS).")
def r09(m):
    for c in m.comps.values():
        if c["type"] == "queue" and not c["consumer_authn"]:
            yield [C(c["id"])], f"queue {c['id']} accepts unauthenticated consumers", "high"


@rule("R10", "shared-credentials-across-zones", "Elevation of privilege", "high",
      "One credential used in several zones lets a compromise in the weakest zone reach the strongest.",
      "Issue a distinct credential per component and zone, scoped to least privilege.")
def r10(m):
    groups = {}
    for c in m.comps.values():
        if c.get("credential"):
            groups.setdefault(c["credential"], []).append(c)
    for cred, cs in sorted(groups.items()):
        zones = sorted({c["zone"] for c in cs})
        if len(zones) > 1:
            yield [C(c["id"]) for c in cs], f"credential '{cred}' is shared across zones {zones}", "high"


@rule("R11", "datastore-without-backup", "Tampering", "medium",
      "A datastore holding internal or higher data with no backup cannot be recovered after corruption "
      "or malicious modification.",
      "Take regular, tested, access-controlled backups stored in a separate failure domain.")
def r11(m):
    for c in m.comps.values():
        if c["type"] == "datastore" and not c["backup"] and m.held(c["id"]) >= 1:
            yield [C(c["id"])], f"datastore {c['id']} has no backup", "medium"


def evaluate(m):
    out = []
    for r in RULES:
        try:
            hits = list(r.fn(m))
        except Exception as e:  # a rule that blows up must never read as a pass
            raise JudgeError(f"rule {r.id} could not be evaluated: {e!r}") from e
        for els, msg, sev in hits:
            out.append({"id": r.id + ":" + "+".join(sorted(els)), "rule": r.id, "name": r.name,
                        "severity": sev, "stride": r.stride, "elements": sorted(els), "message": msg,
                        "mitigation": r.mitigation, "status": "open"})
    out.sort(key=lambda f: (-SEVRANK[f["severity"]], f["id"]))
    return out


def check_dict(d):
    return evaluate(validate(d))
