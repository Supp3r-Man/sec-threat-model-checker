from sec_threat_model_checker.rules import RULES
from tests.helpers import base, findings, fl, get, one, rules_of

STRIDE = {"Spoofing", "Tampering", "Repudiation", "Information disclosure", "Denial of service", "Elevation of privilege"}


def test_r01_boundary_flow_without_tls():
    d = base()
    get(d, "flows", "f-gw-api")["encrypted"] = False
    f = one(d, "R01")
    assert f["elements"] == ["flow:f-gw-api"] and f["severity"] == "high" and f["stride"] == "Tampering"
    d = base()  # intra-zone plaintext is out of R01 scope (documented gap)
    get(d, "flows", "f-api-bus")["encrypted"] = False
    assert "R01" not in rules_of(d)
    d = base()  # worst case: no TLS and no authn on confidential data
    f = get(d, "flows", "f-api-db")
    f["encrypted"], f["authn"] = False, "none"
    assert one(d, "R01")["severity"] == "critical"


def test_r01_authn_only_required_for_non_public_data():
    d = base()
    d["flows"].append(fl("f-pub", "gateway", "user", "public", "none"))
    assert "R01" not in rules_of(d)
    get(d, "flows", "f-pub")["data"] = "internal"
    assert one(d, "R01")["elements"] == ["flow:f-pub"]
    get(d, "flows", "f-pub").update(data="public", encrypted=False)
    assert one(d, "R01")["severity"] == "medium"


def test_r02_sensitive_data_to_external_or_lower_trust():
    d = base()
    d["components"].append({"id": "vendor", "type": "external", "zone": "internet"})
    d["flows"].append(fl("f-v", "api", "vendor", "confidential", "token"))
    assert one(d, "R02")["severity"] == "high"
    get(d, "flows", "f-v")["data"] = "restricted"
    assert one(d, "R02")["severity"] == "critical"
    get(d, "flows", "f-v")["data"] = "internal"
    assert "R02" not in rules_of(d)
    d = base()  # restricted data flowing down in trust (db -> api) is flagged, up (api -> db) is not
    d["flows"].append(fl("f-back", "db", "api", "restricted"))
    assert one(d, "R02")["elements"] == ["flow:f-back"]


def test_r03_encryption_at_rest_and_r11_backup_depend_on_data_held():
    d = base()
    get(d, "components", "db").update(encrypted_at_rest=False, backup=False)
    assert one(d, "R03")["severity"] == "high" and one(d, "R11")["severity"] == "medium"
    get(d, "flows", "f-api-db")["data"] = "restricted"
    assert one(d, "R03")["severity"] == "critical"
    get(d, "flows", "f-api-db")["data"] = "internal"
    assert "R03" not in rules_of(d) and "R11" in rules_of(d)
    get(d, "flows", "f-api-db")["data"] = "public"
    assert rules_of(d) == set()
    get(d, "components", "db")["classification"] = "confidential"  # declared class counts too
    assert {"R03", "R11"} <= rules_of(d)


def test_r04_admin_interface_untrusted_zone():
    d = base()
    get(d, "components", "api")["admin_interface"] = {"zones": ["app", "dmz"], "mfa": False}
    assert "R04" not in rules_of(d)  # dmz is low trust but not untrusted: documented gap
    get(d, "components", "api")["admin_interface"] = {"zones": ["internet"], "mfa": True}
    assert one(d, "R04")["severity"] == "high"
    get(d, "components", "api")["admin_interface"]["mfa"] = False
    assert one(d, "R04")["severity"] == "critical"


def test_r05_audit_logging_at_boundaries_scales_with_data():
    d = base()
    get(d, "flows", "f-gw-api")["audit_logged"] = False
    assert one(d, "R05")["severity"] == "medium"
    get(d, "flows", "f-gw-api")["data"] = "confidential"
    assert one(d, "R05")["severity"] == "high"
    get(d, "flows", "f-gw-api")["data"] = "public"
    assert "R05" not in rules_of(d)
    d = base()
    get(d, "flows", "f-api-bus")["audit_logged"] = False  # intra-zone
    assert "R05" not in rules_of(d)


def test_r06_secrets_in_flow():
    d = base()
    get(d, "flows", "f-api-bus")["carries_secrets"] = True
    assert one(d, "R06")["severity"] == "high"
    get(d, "flows", "f-api-bus")["encrypted"] = False
    assert one(d, "R06")["severity"] == "critical"


def test_r07_rate_limiting_on_public_ingress_only():
    d = base()
    get(d, "components", "gateway")["rate_limited"] = False
    d["components"].append({"id": "partner", "type": "external", "zone": "internet"})
    d["flows"].append(fl("f-p", "partner", "gateway", "internal", "token"))
    assert one(d, "R07")["elements"] == ["component:gateway"]  # two untrusted sources, one finding
    d = base()
    get(d, "components", "api")["rate_limited"] = False  # not fed from untrusted zone
    assert "R07" not in rules_of(d)


def test_r08_spof_needs_critical_single_replica_without_failover():
    d = base()
    get(d, "components", "gateway")["replicas"] = 1
    assert one(d, "R08")["elements"] == ["component:gateway"]
    d["components"].append({"id": "gw2", "type": "service", "zone": "dmz", "failover_of": "gateway"})
    assert "R08" not in rules_of(d)
    d = base()
    get(d, "components", "api")["replicas"] = 1  # not critical
    assert "R08" not in rules_of(d)
    get(d, "components", "gateway").pop("replicas")  # default is one replica
    assert "R08" in rules_of(d)


def test_r09_unauthenticated_queue_consumers():
    d = base()
    get(d, "components", "bus")["consumer_authn"] = False
    f = one(d, "R09")
    assert f["elements"] == ["component:bus"] and f["stride"] == "Spoofing"


def test_r10_shared_credentials_only_across_zones():
    d = base()
    get(d, "components", "api")["credential"] = get(d, "components", "db")["credential"]
    assert one(d, "R10")["elements"] == ["component:api", "component:db"]
    d = base()
    d["components"].append({"id": "api2", "type": "service", "zone": "app", "credential": "c-api"})
    assert "R10" not in rules_of(d)


def test_every_rule_is_documented_and_findings_are_well_formed():
    assert len(RULES) == 11 and len({r.id for r in RULES}) == 11
    for r in RULES:
        assert r.stride in STRIDE and len(r.rationale) > 30 and len(r.mitigation) > 20
    d = base()
    get(d, "flows", "f-gw-api").update(encrypted=False, audit_logged=False)
    get(d, "components", "bus")["consumer_authn"] = False
    fs = findings(d)
    assert len(fs) == 3
    for f in fs:
        assert {"id", "severity", "stride", "elements", "mitigation", "rule", "message", "status"} <= set(f)
        assert f["id"].startswith(f["rule"] + ":")
    assert [f["severity"] for f in fs] == sorted((f["severity"] for f in fs), key=["critical", "high", "medium", "low"].index)
