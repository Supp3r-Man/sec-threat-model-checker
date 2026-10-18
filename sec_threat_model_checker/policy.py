"""MITIGATION-ACCEPTANCE handling and DIFF mode."""
import datetime
import json

from .model import ModelError
from .rules import SEVRANK, evaluate

ACCEPT_FILE = "MITIGATION-ACCEPTANCE.json"


def parse_today(s):
    if s is None:
        return datetime.date.today()
    try:
        return datetime.date.fromisoformat(s)
    except ValueError:
        raise ModelError(f"--today must be YYYY-MM-DD, got {s!r}")


def load_acceptances(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        raise ModelError(f"cannot read acceptance file {path}: {e}")
    items = data.get("acceptances") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ModelError('acceptance file must be {"acceptances": [...]}')
    errs, out = [], {}
    for i, a in enumerate(items):
        if not isinstance(a, dict):
            errs.append(f"acceptance[{i}] must be an object")
            continue
        for k in ("finding_id", "reason", "owner", "expires"):
            if not isinstance(a.get(k), str) or not a[k].strip():
                errs.append(f"acceptance[{i}]: '{k}' is required")
        if errs and errs[-1].startswith(f"acceptance[{i}]"):
            continue
        if len(a["reason"].strip()) < 10:
            errs.append(f"acceptance[{i}]: reason must be at least 10 characters")
            continue
        try:
            exp = datetime.date.fromisoformat(a["expires"])
        except ValueError:
            errs.append(f"acceptance[{i}]: expires must be YYYY-MM-DD")
            continue
        if a["finding_id"] in out:
            errs.append(f"acceptance[{i}]: duplicate acceptance for {a['finding_id']}")
            continue
        out[a["finding_id"]] = {**{k: a[k] for k in ("finding_id", "reason", "owner", "expires")}, "_exp": exp}
    if errs:
        raise ModelError(errs)
    return out


def apply_acceptances(findings, acc, today):
    """Mark findings accepted / expired-acceptance in place. Returns acceptances that matched nothing."""
    matched = set()
    for f in findings:
        a = acc.get(f["id"])
        if a is None:
            continue
        matched.add(f["id"])
        f["status"] = "accepted" if a["_exp"] >= today else "expired-acceptance"
        f["acceptance"] = {k: a[k] for k in ("reason", "owner", "expires")}
    return [{k: v for k, v in a.items() if k != "_exp"} for fid, a in acc.items() if fid not in matched]


def effective(findings):
    return [f for f in findings if f["status"] != "accepted"]


def regressions(old, new):
    """Controls that existed before and were weakened, whether or not a finding results."""
    out = []
    of = {f["id"]: f for f in old.flows}
    for f in new.flows:
        o = of.get(f["id"])
        if not o:
            continue
        if o["encrypted"] and not f["encrypted"]:
            out.append(f"flow {f['id']}: TLS removed")
        if o["authn"] != "none" and f["authn"] == "none":
            out.append(f"flow {f['id']}: authentication removed")
        if o["audit_logged"] and not f["audit_logged"]:
            out.append(f"flow {f['id']}: audit logging removed")
    for c in new.comps.values():
        o = old.comps.get(c["id"])
        if not o:
            continue
        for k in ("encrypted_at_rest", "backup", "rate_limited", "logging", "consumer_authn"):
            if o.get(k) is True and not c.get(k):
                out.append(f"component {c['id']}: {k} removed")
        if o.get("replicas", 1) >= 2 and c.get("replicas", 1) < 2:
            out.append(f"component {c['id']}: replicas reduced below 2")
        if c.get("admin_interface") and (o.get("admin_interface") or {}).get("mfa") and not c["admin_interface"].get("mfa"):
            out.append(f"component {c['id']}: admin MFA removed")
    return out


def diff(old, new, old_acc, new_acc, today, fail_on="high"):
    fo, fn = evaluate(old), evaluate(new)
    apply_acceptances(fo, old_acc, today)
    apply_acceptances(fn, new_acc, today)
    old_ids = {f["id"] for f in fo}
    old_accepted = {f["id"] for f in fo if f["status"] == "accepted"}
    thr = SEVRANK[fail_on]
    new_open = [f for f in effective(fn) if f["id"] not in old_ids]
    res = {
        "new_findings": [f for f in new_open if SEVRANK[f["severity"]] >= thr],
        "new_below_threshold": [f for f in new_open if SEVRANK[f["severity"]] < thr],
        "removed_acceptances": [f for f in effective(fn) if f["id"] in old_accepted],
        "control_regressions": regressions(old, new),
        "fixed": sorted(old_ids - {f["id"] for f in fn}),
    }
    res["fail"] = bool(res["new_findings"] or res["removed_acceptances"] or res["control_regressions"])
    return res
