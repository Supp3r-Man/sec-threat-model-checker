import datetime
import json

import pytest

from sec_threat_model_checker import policy
from sec_threat_model_checker.model import ModelError, validate
from sec_threat_model_checker.rules import evaluate
from tests.helpers import base, fl, get, write

TODAY = datetime.date(2026, 6, 15)


def flawed_db():
    d = base()
    get(d, "components", "db")["encrypted_at_rest"] = False
    return d


def with_unlogged_flow():
    d = base()
    d["flows"].append(fl("f-x", "api", "gateway", "internal", audit=False))
    return d


def acc_file(tmp_path, fid, expires="2026-06-30", **kw):
    a = {"finding_id": fid, "reason": "compensating control: disk-level encryption by platform", "owner": "team-data", "expires": expires, **kw}
    return write(tmp_path, "a.json", {"acceptances": [a]})


FID = "R03:component:db"


def test_acceptance_suppresses_a_reviewed_finding(tmp_path):
    fs = evaluate(validate(flawed_db()))
    acc = policy.load_acceptances(acc_file(tmp_path, FID))
    assert policy.apply_acceptances(fs, acc, TODAY) == []
    assert fs[0]["status"] == "accepted" and fs[0]["acceptance"]["owner"] == "team-data"
    assert policy.effective(fs) == []


def test_acceptance_expiry_boundary_expired_finding_returns(tmp_path):
    acc = policy.load_acceptances(acc_file(tmp_path, FID, expires="2026-06-15"))
    on_day = evaluate(validate(flawed_db()))
    policy.apply_acceptances(on_day, acc, TODAY)
    assert on_day[0]["status"] == "accepted"  # the expiry date itself is still covered
    day_after = evaluate(validate(flawed_db()))
    policy.apply_acceptances(day_after, acc, TODAY + datetime.timedelta(days=1))
    assert day_after[0]["status"] == "expired-acceptance" and policy.effective(day_after) == day_after


def test_invalid_acceptance_files_are_rejected(tmp_path):
    good = {"finding_id": FID, "reason": "long enough reason text", "owner": "o", "expires": "2026-06-30"}
    cases = [{**good, "owner": ""}, {k: v for k, v in good.items() if k != "reason"}, {**good, "reason": "too short"},
             {**good, "expires": "soon"}, {k: v for k, v in good.items() if k != "expires"}, "nope"]
    for c in cases:
        with pytest.raises(ModelError):
            policy.load_acceptances(write(tmp_path, "x.json", {"acceptances": [c]}))
    with pytest.raises(ModelError):
        policy.load_acceptances(write(tmp_path, "x.json", {"acceptances": [good, good]}))
    with pytest.raises(ModelError):
        policy.load_acceptances(write(tmp_path, "x.json", [good]))
    with pytest.raises(ModelError):
        policy.load_acceptances(tmp_path / "absent.json")


def test_acceptance_that_matches_nothing_is_reported_stale(tmp_path):
    acc = policy.load_acceptances(acc_file(tmp_path, "R09:component:ghost"))
    stale = policy.apply_acceptances(evaluate(validate(base())), acc, TODAY)
    assert [s["finding_id"] for s in stale] == ["R09:component:ghost"]


def run_diff(old, new, oa=None, na=None, fail_on="high", today=TODAY):
    return policy.diff(validate(old), validate(new), oa or {}, na or {}, today, fail_on)


def test_diff_identical_models_pass():
    r = run_diff(flawed_db(), flawed_db())
    assert not r["fail"] and r["fixed"] == [] and r["new_findings"] == []


def test_diff_fails_on_new_findings_only_at_or_above_threshold():
    new = with_unlogged_flow()  # R05 medium, no control removed
    r = run_diff(base(), new)
    assert not r["fail"] and len(r["new_below_threshold"]) == 1
    assert run_diff(base(), new, fail_on="medium")["fail"]
    r = run_diff(base(), flawed_db())
    assert r["fail"] and [f["id"] for f in r["new_findings"]] == [FID]


def test_diff_does_not_fail_on_existing_findings_and_reports_fixes():
    assert not run_diff(flawed_db(), flawed_db())["fail"]
    r = run_diff(flawed_db(), base())
    assert not r["fail"] and r["fixed"] == [FID]


def test_diff_fails_when_an_acceptance_is_removed_or_expires(tmp_path):
    acc = policy.load_acceptances(acc_file(tmp_path, FID))
    assert not run_diff(flawed_db(), flawed_db(), acc, acc)["fail"]  # still covered
    r = run_diff(flawed_db(), flawed_db(), acc, {})
    assert r["fail"] and [f["id"] for f in r["removed_acceptances"]] == [FID]
    lapsed = policy.load_acceptances(acc_file(tmp_path, FID, expires="2026-06-01"))
    r = run_diff(flawed_db(), flawed_db(), acc, lapsed)  # acceptance in the new version has expired
    assert r["fail"] and [f["id"] for f in r["removed_acceptances"]] == [FID]
    both_expired = run_diff(flawed_db(), flawed_db(), acc, acc, today=datetime.date(2026, 7, 1))
    assert not both_expired["fail"]  # old and new both unmitigated: nothing new
    acc5 = policy.load_acceptances(acc_file(tmp_path, "R05:flow:f-x"))
    assert not run_diff(base(), with_unlogged_flow(), {}, acc5, fail_on="medium")["fail"]  # new finding, but accepted
    assert run_diff(base(), with_unlogged_flow(), {}, {}, fail_on="medium")["fail"]
    assert run_diff(base(), flawed_db(), {}, acc)["fail"]  # removing a control fails even if its finding is accepted


def test_diff_fails_on_removed_control_even_without_a_new_finding():
    new = base()
    get(new, "flows", "f-api-bus")["encrypted"] = False  # intra-zone: no rule fires
    r = run_diff(base(), new)
    assert r["fail"] and r["new_findings"] == [] and r["control_regressions"] == ["flow f-api-bus: TLS removed"]
    new = base()
    get(new, "components", "api")["replicas"] = 1
    get(new, "components", "api")["admin_interface"]["mfa"] = False
    r = run_diff(base(), new)
    assert r["fail"] and len(r["control_regressions"]) == 2
