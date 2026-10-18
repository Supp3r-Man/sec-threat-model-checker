"""Command line. Exit codes: 0 pass, 1 findings above threshold, 2 invalid model or could not judge."""
import argparse
import json
import os
import sys

from . import measure, policy, render
from .model import ModelError, load_model
from .rules import RULES, SEVS, evaluate


def _emit(s, out):
    if out:
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(s)
    else:
        sys.stdout.write(s)


def _acc(path, model_path=None):
    if path is None and model_path:
        cand = os.path.join(os.path.dirname(os.path.abspath(model_path)), policy.ACCEPT_FILE)
        path = cand if os.path.exists(cand) else None
    return path, (policy.load_acceptances(path) if path else {})


def cmd_check(a):
    today = policy.parse_today(a.today)
    m = load_model(a.model)
    path, acc = _acc(a.accept, a.model)
    fs = evaluate(m)
    stale = policy.apply_acceptances(fs, acc, today)
    rep = render.build_report(m, fs, stale, today, a.fail_on, path)
    if a.format == "json":
        _emit(json.dumps(rep, indent=2) + "\n", a.out)
    elif a.format == "markdown":
        _emit(render.markdown(rep), a.out)
    elif a.format == "mermaid":
        _emit(render.mermaid(m, fs), a.out)
    else:
        _emit(render.text(rep), a.out)
    return 1 if rep["verdict"] == "FAIL" else 0


def cmd_diff(a):
    today = policy.parse_today(a.today)
    old, new = load_model(a.old), load_model(a.new)
    oa, na = _acc(a.accept_old)[1], _acc(a.accept_new)[1]
    res = policy.diff(old, new, oa, na, today, a.fail_on)
    if a.format == "json":
        _emit(json.dumps(res, indent=2) + "\n", None)
    else:
        L = [f"new findings at/above '{a.fail_on}': {len(res['new_findings'])}"]
        L += [f"  {f['id']}: {f['message']}" for f in res["new_findings"]]
        L += [f"new findings below threshold: {len(res['new_below_threshold'])}",
              f"previously accepted, now unmitigated: {len(res['removed_acceptances'])}"]
        L += [f"  {f['id']}" for f in res["removed_acceptances"]]
        L += [f"control regressions: {len(res['control_regressions'])}"] + ["  " + x for x in res["control_regressions"]]
        L += [f"fixed: {len(res['fixed'])}", "DIFF " + ("FAIL" if res["fail"] else "PASS")]
        _emit("\n".join(L) + "\n", None)
    return 1 if res["fail"] else 0


def cmd_rules(a):
    for r in RULES:
        sys.stdout.write(f"{r.id} {r.name} [{r.stride}, {r.severity}]\n  why: {r.rationale}\n  fix: {r.mitigation}\n")
    return 0


def cmd_demo(a):
    sys.stdout.write(measure.table(measure.run()))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="sec_threat_model_checker", description="Threat-model-as-code checker (checks the MODEL, not the real system)")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check one model")
    c.add_argument("model")
    c.add_argument("--accept", help=f"acceptance file (default: {policy.ACCEPT_FILE} next to the model, if present)")
    c.add_argument("--fail-on", choices=SEVS, default="high")
    c.add_argument("--format", choices=["text", "json", "markdown", "mermaid"], default="text")
    c.add_argument("--out")
    c.add_argument("--today", help="YYYY-MM-DD, for reproducible expiry checks")
    c.set_defaults(fn=cmd_check)
    d = sub.add_parser("diff", help="compare two model versions")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--accept-old")
    d.add_argument("--accept-new")
    d.add_argument("--fail-on", choices=SEVS, default="high")
    d.add_argument("--format", choices=["text", "json"], default="text")
    d.add_argument("--today")
    d.set_defaults(fn=cmd_diff)
    sub.add_parser("rules", help="list rules").set_defaults(fn=cmd_rules)
    sub.add_parser("demo", help="print the measured table").set_defaults(fn=cmd_demo)
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except ModelError as e:
        sys.stderr.write("INVALID INPUT, could not judge (exit 2):\n" + "".join(f"  - {x}\n" for x in e.errors))
        return 2
    except Exception as e:  # never turn an internal failure into a pass
        sys.stderr.write(f"COULD NOT JUDGE (exit 2): {e!r}\n")
        return 2
