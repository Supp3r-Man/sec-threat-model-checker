import json

import pytest

from sec_threat_model_checker.model import ModelError, load_model, validate
from tests.helpers import base, findings, get


def bad(mutate, needle=None):
    d = base()
    mutate(d)
    with pytest.raises(ModelError) as e:
        validate(d)
    if needle:
        assert needle in str(e.value)


def test_base_model_is_valid_and_clean():
    assert findings(base()) == []


def test_dangling_references_rejected():
    bad(lambda d: get(d, "flows", "f-gw-api").update(destination="ghost"), "ghost")
    bad(lambda d: get(d, "flows", "f-gw-api").update(source="ghost"), "ghost")
    bad(lambda d: get(d, "components", "api").update(failover_of="ghost"), "failover_of")
    bad(lambda d: get(d, "components", "api")["admin_interface"].update(zones=["ghost"]), "admin_interface")
    bad(lambda d: d["zones"].append({"id": "z", "parent": "ghost"}), "parent")


def test_unknown_zone_rejected():
    bad(lambda d: get(d, "components", "api").update(zone="nowhere"), "unknown zone")


def test_duplicate_ids_rejected():
    bad(lambda d: d["components"].append(dict(get(d, "components", "api"))), "duplicate component")
    bad(lambda d: d["zones"].append({"id": "app", "trust": 2}), "duplicate zone")
    bad(lambda d: d["flows"].append(dict(d["flows"][0])), "duplicate flow")


def test_zone_parent_cycle_makes_trust_undecidable():
    bad(lambda d: d["zones"].extend([{"id": "a", "parent": "b"}, {"id": "b", "parent": "a"}]), "cycle")


def test_failover_cycle_and_self_failover_rejected():
    def cyc(d):
        get(d, "components", "api")["failover_of"] = "gateway"
        get(d, "components", "gateway")["failover_of"] = "api"
    bad(cyc, "failover_of cycle")
    bad(lambda d: get(d, "components", "api").update(failover_of="api"), "failover_of")


def test_bad_enums_and_missing_required_flags_all_reported():
    d = base()
    get(d, "flows", "f-gw-api")["data"] = "top-secret"
    del get(d, "components", "db")["backup"]
    del get(d, "components", "bus")["consumer_authn"]
    del get(d, "flows", "f-api-bus")["encrypted"]
    get(d, "components", "api")["replicas"] = 0
    d["zones"][0]["trust"] = 9
    with pytest.raises(ModelError) as e:
        validate(d)
    assert len(e.value.errors) == 6
    bad(lambda d: get(d, "components", "db").update(type="database"), "type")
    bad(lambda d: get(d, "flows", "f-gw-api").update(authn=""), "authn")


def test_structurally_broken_inputs_and_unreadable_files(tmp_path):
    for junk in ([], "x", {"zones": [], "components": [], "flows": "no"}, {"zones": [], "components": [], "flows": []}):
        with pytest.raises(ModelError):
            validate(junk)
    p = tmp_path / "m.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ModelError):
        load_model(p)
    with pytest.raises(ModelError):
        load_model(tmp_path / "missing.json")
    p.write_text(json.dumps(base()), encoding="utf-8")
    assert load_model(p).name == "base"


def test_trust_is_inherited_from_parent_zone():
    d = base()
    d["zones"].append({"id": "app2", "parent": "app"})
    d["zones"].append({"id": "override", "parent": "app", "trust": 0})
    m = validate(d)
    assert m.zone_trust("app2") == 2 and m.zone_trust("override") == 0
