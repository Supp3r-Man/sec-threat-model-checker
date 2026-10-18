import datetime
import json

from sec_threat_model_checker import render
from sec_threat_model_checker.model import validate
from sec_threat_model_checker.rules import evaluate
from tests.helpers import base, get

TODAY = datetime.date(2026, 6, 15)


def report(d):
    m = validate(d)
    fs = evaluate(m)
    return m, fs, render.build_report(m, fs, [], TODAY, "high")


def test_mermaid_diagram_has_zones_nodes_flows_and_marks_problems():
    d = base()
    get(d, "flows", "f-gw-api")["encrypted"] = False
    get(d, "components", "db")["encrypted_at_rest"] = False
    m, fs, _ = report(d)
    src = render.mermaid(m, fs)
    assert src.startswith("flowchart LR")
    assert src.count("subgraph") == 4 and src.count("  end") == 4
    for cid in d["components"]:
        assert "n_" + cid["id"] in src
    assert src.count("-->") == 3 and src.count("-.->") == 1 and "NO-TLS" in src
    assert "class n_db flagged" in src
    assert "classDef" not in render.mermaid(*report(base())[:2])


def test_markdown_and_json_reports_carry_findings_and_the_disclaimer():
    d = base()
    get(d, "components", "bus")["consumer_authn"] = False
    _, fs, rep = report(d)
    assert rep["verdict"] == "FAIL" and rep["summary"]["failing"] == 1
    assert json.loads(json.dumps(rep))["findings"][0]["id"] == "R09:component:bus"
    md = render.markdown(rep)
    assert "R09:component:bus" in md and "Spoofing" in md and "MODEL, not the real system" in md
    assert "Verdict: **PASS**" in render.markdown(report(base())[2])
    assert "-> FAIL" in render.text(rep)
