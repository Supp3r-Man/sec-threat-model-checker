import json

from tests.helpers import base, cli, get, write


def flawed(**kw):
    d = base()
    get(d, "components", "db").update(encrypted_at_rest=False, **kw)
    return d


def test_exit_0_on_a_clean_model_with_json_output(tmp_path):
    r = cli("check", write(tmp_path, "m.json", base()), "--format", "json")
    assert r.returncode == 0, r.stderr
    rep = json.loads(r.stdout)
    assert rep["verdict"] == "PASS" and rep["findings"] == []


def test_exit_1_on_findings_and_acceptance_file_next_to_model_suppresses(tmp_path):
    m = write(tmp_path, "m.json", flawed())
    r = cli("check", m)
    assert r.returncode == 1 and "R03:component:db" in r.stdout
    acc = {"acceptances": [{"finding_id": "R03:component:db", "reason": "platform encrypts the volume underneath",
                            "owner": "team-data", "expires": "2999-01-01"}]}
    write(tmp_path, "MITIGATION-ACCEPTANCE.json", acc)
    assert cli("check", m).returncode == 0
    acc["acceptances"][0]["expires"] = "2020-01-01"
    write(tmp_path, "MITIGATION-ACCEPTANCE.json", acc)
    r = cli("check", m)
    assert r.returncode == 1 and "expired-acceptance" in r.stdout


def test_exit_2_when_the_model_or_inputs_cannot_be_judged(tmp_path):
    d = base()
    get(d, "flows", "f-gw-api")["destination"] = "ghost"
    r = cli("check", write(tmp_path, "bad.json", d))
    assert r.returncode == 2 and "ghost" in r.stderr and r.stdout == ""
    assert cli("check", tmp_path / "missing.json").returncode == 2
    (tmp_path / "junk.json").write_text("{", encoding="utf-8")
    assert cli("check", tmp_path / "junk.json").returncode == 2
    good = write(tmp_path, "m.json", base())
    assert cli("check", good, "--accept", write(tmp_path, "a.json", {"acceptances": [{"finding_id": "x"}]})).returncode == 2
    assert cli("check", good, "--today", "tomorrow").returncode == 2
    assert cli("check", good, "--bogus").returncode == 2


def test_fail_on_threshold_changes_the_exit_code(tmp_path):
    m = write(tmp_path, "m.json", flawed())  # one high finding
    assert cli("check", m, "--fail-on", "high").returncode == 1
    assert cli("check", m, "--fail-on", "critical").returncode == 0
    assert cli("check", m, "--fail-on", "low").returncode == 1


def test_diff_exit_codes(tmp_path):
    old, new = write(tmp_path, "old.json", base()), write(tmp_path, "new.json", flawed())
    r = cli("diff", old, new)
    assert r.returncode == 1 and "R03:component:db" in r.stdout and "DIFF FAIL" in r.stdout
    assert cli("diff", old, old).returncode == 0
    assert cli("diff", new, old).returncode == 0
    bad = write(tmp_path, "bad.json", {"zones": 1})
    assert cli("diff", old, bad).returncode == 2


def test_mermaid_out_file_and_rules_listing(tmp_path):
    out = tmp_path / "d.mmd"
    r = cli("check", write(tmp_path, "m.json", base()), "--format", "mermaid", "--out", out)
    assert r.returncode == 0 and out.read_text(encoding="utf-8").startswith("flowchart LR")
    r = cli("rules")
    assert r.returncode == 0 and r.stdout.count("why:") == 11 and r.stdout.count("fix:") == 11


def test_demo_prints_the_measured_table():
    r = cli("demo")
    assert r.returncode == 0, r.stderr
    for s in ("Per-rule detection", "False positives on clean baselines: 0/200", "Invalid-model rejection", "Known evasions", "MODEL, not the real system"):
        assert s in r.stdout
