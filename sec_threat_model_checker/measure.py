"""Seeded measurement: per-rule detection, false positives on clean models, invalid-model rejection."""
import copy
import random

from . import gen
from .model import ModelError, validate
from .rules import RULES, check_dict

BLIND = [
    "business-logic abuse (e.g. skipping a workflow step, price or quota tampering)",
    "authorisation logic flaws (IDOR, broken object-level checks) inside a component",
    "implementation bugs (injection, deserialisation, memory safety) behind a modelled 'TLS + authn' flow",
    "vulnerable dependencies and misconfigured hosts",
    "insider threat and process failures (key handling, offboarding)",
    "anything the model omits, or states wrongly: a flow nobody drew is invisible; a control marked true that is not is believed",
    "access_roles are modelled but no rule judges them (over-broad roles pass)",
]


def run(n=100, n_clean=200):
    res = {"n": n, "n_clean": n_clean, "rules": {}, "mix": {}, "invalid": {}}
    names = {r.id: r.name for r in RULES}
    for rid in gen.INJECT:
        hit = coll = coll_models = 0
        for s in range(n):
            d, exp = gen.flawed(10_000 + s, [rid])
            fs = check_dict(d)
            hit += any(f["rule"] == rid and set(exp[0][1]) <= set(f["elements"]) for f in fs)
            extra = [f for f in fs if f["rule"] != rid]
            coll += len(extra)
            coll_models += bool(extra)
        res["rules"][rid] = {"name": names[rid], "hit": hit, "collateral": coll, "collateral_models": coll_models}
    fp = 0
    fp_by_rule = {}
    for s in range(n_clean):
        fs = check_dict(gen.clean(50_000 + s))
        fp += bool(fs)
        for f in fs:
            fp_by_rule[f["rule"]] = fp_by_rule.get(f["rule"], 0) + 1
    res["clean"] = {"models": n_clean, "with_findings": fp, "by_rule": fp_by_rule}
    ids = sorted(gen.INJECT)
    all_hit = found = total = 0
    for s in range(n):
        rng = random.Random(90_000 + s)
        flaws = rng.sample(ids, rng.choice([2, 3]))
        d, exp = gen.flawed(90_000 + s, flaws)
        fs = check_dict(d)
        ok = [any(f["rule"] == rid and set(e) <= set(f["elements"]) for f in fs) for rid, e in exp]
        all_hit += all(ok)
        found += sum(ok)
        total += len(ok)
    res["mix"] = {"models": n, "all_found": all_hit, "flaws_found": found, "flaws_total": total}
    for name, fn in gen.INVALID.items():
        rej = 0
        for s in range(n):
            d = gen.clean(130_000 + s)
            fn(d, random.Random(s))
            try:
                validate(copy.deepcopy(d))
            except ModelError:
                rej += 1
        res["invalid"][name] = rej
    res["evasion"] = {}
    for name, fn in gen.EVASION.items():
        res["evasion"][name] = sum(not check_dict(_apply(fn, 170_000 + s)) for s in range(n))
    return res


def _apply(fn, seed):
    d = gen.clean(seed)
    fn(d, random.Random(seed))
    return d


def table(res):
    n = res["n"]
    L = [f"Per-rule detection ({n} seeded models per flaw, one flaw each; hit = right rule on the right element)",
         f"{'rule':5} {'name':46} {'detected':>9} {'collateral':>11}"]
    for rid, r in res["rules"].items():
        L.append(f"{rid:5} {r['name']:46} {r['hit']:>4}/{n:<4} {r['collateral_models']:>5}/{n:<5}")
    tot = sum(r["hit"] for r in res["rules"].values())
    L.append(f"{'all':5} {'':46} {tot:>4}/{n * len(res['rules']):<4}")
    c, m = res["clean"], res["mix"]
    L += ["", f"False positives on clean baselines: {c['with_findings']}/{c['models']} models had any finding",
          f"Mixed flaws (2-3 per model): {m['flaws_found']}/{m['flaws_total']} flaws found; {m['all_found']}/{m['models']} models fully caught",
          "", f"Invalid-model rejection (must be exit 2, {n} each):"]
    L += [f"  {k:24} {v}/{n}" for k, v in res["invalid"].items()]
    L += ["", f"Known evasions (a real flaw in the modelled world that the rules do not flag; models passing clean, of {n}):"]
    L += [f"  {k:42} {v}/{n} missed" for k, v in res["evasion"].items()]
    L += ["", "What this cannot see (by construction, not measured):"] + ["  - " + b for b in BLIND]
    L += ["", "Caveat: synthetic models, flaws injected by the same author as the rules. This checks the MODEL, not the real system."]
    return "\n".join(L) + "\n"
