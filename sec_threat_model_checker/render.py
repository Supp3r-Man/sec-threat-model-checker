"""JSON, Markdown, text and Mermaid outputs."""
import re

from .policy import effective
from .rules import SEVRANK


def build_report(m, findings, stale, today, fail_on, accept_path=None):
    eff = effective(findings)
    failing = [f for f in eff if SEVRANK[f["severity"]] >= SEVRANK[fail_on]]
    return {
        "model": m.name, "date": today.isoformat(), "fail_on": fail_on, "acceptance_file": accept_path,
        "summary": {"total": len(findings), "open": len(eff), "accepted": len(findings) - len(eff),
                    "expired_acceptances": sum(f["status"] == "expired-acceptance" for f in findings),
                    "failing": len(failing)},
        "verdict": "FAIL" if failing else "PASS",
        "findings": findings, "stale_acceptances": stale,
        "disclaimer": "This checks the MODEL, not the real system.",
    }


def text(rep):
    L = [f"model: {rep['model']}  date: {rep['date']}  fail-on: {rep['fail_on']}"]
    for f in rep["findings"]:
        tag = "" if f["status"] == "open" else f" ({f['status']})"
        L.append(f"[{f['severity'].upper():8}] {f['id']}{tag}\n           {f['message']}\n           fix: {f['mitigation']}")
    s = rep["summary"]
    L.append(f"{s['open']} open, {s['accepted']} accepted, {s['failing']} at or above '{rep['fail_on']}' -> {rep['verdict']}")
    for a in rep["stale_acceptances"]:
        L.append(f"note: acceptance for {a['finding_id']} matches no finding (stale)")
    L.append(rep["disclaimer"])
    return "\n".join(L) + "\n"


def markdown(rep):
    s = rep["summary"]
    L = [f"# Threat model report: {rep['model']}", "", f"Verdict: **{rep['verdict']}** (fail-on `{rep['fail_on']}`, date {rep['date']})", "",
         f"{s['total']} findings: {s['open']} open, {s['accepted']} accepted, {s['expired_acceptances']} with an expired acceptance.", "",
         "| Severity | Id | STRIDE | Status | Message |", "|---|---|---|---|---|"]
    for f in rep["findings"]:
        L.append(f"| {f['severity']} | `{f['id']}` | {f['stride']} | {f['status']} | {f['message']} |")
    L += ["", "## Mitigations", ""]
    for f in rep["findings"]:
        a = f.get("acceptance")
        extra = f" Accepted by {a['owner']} until {a['expires']}: {a['reason']}" if a else ""
        L.append(f"- `{f['id']}`: {f['mitigation']}{extra}")
    for a in rep["stale_acceptances"]:
        L.append(f"- stale acceptance for `{a['finding_id']}` (matches no finding)")
    L += ["", f"_{rep['disclaimer']}_", ""]
    return "\n".join(L)


def _sid(s):
    return "n_" + re.sub(r"\W", "_", s)


def mermaid(m, findings=()):
    flagged = {e.split(":", 1)[1] for f in findings if f["status"] != "accepted" for e in f["elements"] if e.startswith("component:")}
    shape = {"service": '["{}"]', "datastore": '[("{}")]', "queue": '[/"{}"/]', "external": '(["{}"])', "user": '(("{}"))'}
    L = ["flowchart LR"]
    for z in m.zones:
        zid = re.sub(r"\W", "_", z)
        L.append(f'  subgraph z_{zid}["{z} (trust {m.zone_trust(z)})"]')
        for c in m.comps.values():
            if c["zone"] == z:
                L.append("    " + _sid(c["id"]) + shape[c["type"]].format(c["id"].replace('"', "")))
        L.append("  end")
    for f in m.flows:
        lbl = f"{f['protocol']} {f['data']}" + ("" if f["encrypted"] else " NO-TLS") + (" SECRET" if f.get("carries_secrets") else "")
        L.append(f'  {_sid(f["source"])} {"-->" if f["encrypted"] else "-.->"}|"{lbl}"| {_sid(f["destination"])}')
    if flagged:
        L += ["  classDef flagged fill:#fdd,stroke:#c00", "  class " + ",".join(sorted(_sid(c) for c in flagged)) + " flagged"]
    return "\n".join(L) + "\n"
