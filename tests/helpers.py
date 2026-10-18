import copy
import json
import pathlib
import subprocess
import sys

from sec_threat_model_checker.rules import check_dict

ROOT = pathlib.Path(__file__).resolve().parent.parent


def fl(id, src, dst, data="internal", authn="mtls", enc=True, audit=True, **kw):
    return {"id": id, "source": src, "destination": dst, "protocol": "https", "authn": authn,
            "encrypted": enc, "data": data, "audit_logged": audit, "carries_secrets": False, **kw}


def base():
    """Small hand-written model that must produce zero findings."""
    return copy.deepcopy({
        "name": "base",
        "zones": [{"id": "internet", "trust": 0}, {"id": "dmz", "trust": 1}, {"id": "app", "trust": 2}, {"id": "data", "trust": 3}],
        "components": [
            {"id": "user", "type": "user", "zone": "internet"},
            {"id": "gateway", "type": "service", "zone": "dmz", "rate_limited": True, "replicas": 2, "critical": True, "credential": "c-gw", "logging": True},
            {"id": "api", "type": "service", "zone": "app", "replicas": 2, "credential": "c-api", "logging": True,
             "admin_interface": {"zones": ["app"], "mfa": True}},
            {"id": "bus", "type": "queue", "zone": "app", "consumer_authn": True},
            {"id": "db", "type": "datastore", "zone": "data", "encrypted_at_rest": True, "backup": True, "replicas": 2,
             "critical": True, "credential": "c-db", "access_roles": ["api"]},
        ],
        "flows": [
            fl("f-user-gw", "user", "gateway", "internal", "session"),
            fl("f-gw-api", "gateway", "api"),
            fl("f-api-db", "api", "db", "confidential"),
            fl("f-api-bus", "api", "bus"),
        ],
    })


def findings(d):
    return check_dict(d)


def rules_of(d):
    return {f["rule"] for f in check_dict(d)}


def one(d, rule):
    got = [f for f in check_dict(d) if f["rule"] == rule]
    assert len(got) == 1, got
    return got[0]


def get(d, kind, id):
    return next(x for x in d[kind] if x["id"] == id)


def write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def cli(*args):
    return subprocess.run([sys.executable, "-m", "sec_threat_model_checker", *map(str, args)], cwd=ROOT,
                          capture_output=True, text=True, timeout=120)
