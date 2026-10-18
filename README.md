# sec-threat-model-checker

![ci](https://github.com/Supp3r-Man/sec-threat-model-checker/actions/workflows/ci.yml/badge.svg)

Threat-model-as-code: describe an architecture as JSON (components, trust zones, data flows, datastores, admin interfaces) and run **11 documented STRIDE-style rules** over it. Findings carry an id, severity, STRIDE category, the offending elements and a suggested mitigation. A **reviewed-risk acceptance file** (reason, owner, expiry) suppresses findings until they expire, a **diff mode** gates pull requests on *new* risk, and a model that cannot be judged **exits 2 instead of passing**.

> **What is verified, and what is not.** 44 tests pass locally on Python 3.13 on Windows (stdlib only, plus pytest); it has not run in CI yet, so I make no CI claim. I broke 12 key behaviours on purpose (a TLS check, the R03 threshold, the acceptance expiry boundary, diff's two failure conditions and its severity threshold, the cycle and dangling-reference checks, the exit code, R04 and R10 scope, the diagram's dashed edges) and the tests failed for all 12. **All data is synthetic**: generated, fictional architectures with flaws injected by the same person who wrote the rules, so the detection numbers below measure consistency with my own definitions, not coverage of real systems. **This checks the MODEL, not the real system**: if the model omits a flow or says a control exists when it does not, the checker believes the model.

## Measured results (`python -m sec_threat_model_checker demo`, seeded, reproducible)

100 generated models per flaw type, one flaw each (hit = right rule on the right element); 200 clean baselines.

| Rule | Checks | Detected | Collateral findings |
|---|---|---|---|
| R01 | boundary flow without TLS/authn | 100/100 | 0 |
| R02 | confidential/restricted data to external or lower trust | 100/100 | 0 |
| R03 | confidential datastore not encrypted at rest | 100/100 | 0 |
| R04 | admin interface reachable from untrusted zone | 100/100 | 0 |
| R05 | boundary crossing without audit logging | 100/100 | 0 |
| R06 | secrets carried in a flow | 100/100 | 0 |
| R07 | public ingress without rate limiting | 100/100 | 0 |
| R08 | single point of failure on critical path | 100/100 | 0 |
| R09 | unauthenticated queue consumers | 100/100 | 0 |
| R10 | shared credentials across zones | 100/100 | 0 |
| R11 | datastore without backup | 100/100 | 0 |

- **False positives on clean baselines: 0/200.**
- **Mixed flaws (2-3 per model): 257/257 flaws found, 100/100 models fully caught.**
- **Invalid models rejected (exit-2 path), 100 each:** dangling reference, unknown zone, duplicate id, zone-parent cycle, failover cycle, unknown classification, missing required flag: 100/100 each.
- **Known evasions, 0 of 100 flagged each:** admin interface exposed to the dmz (reachable from the internet only transitively), confidential data mislabelled `internal`, an unencrypted flow *inside* one zone.

**What the numbers do NOT show.** 100% is what you get when the injector and the rule share one author and one definition; it says the code does what I meant, not that the rules find real flaws. Real models are messier than these templates. The checker is blind by construction to business-logic abuse, authorisation flaws (IDOR), implementation bugs behind a "TLS + authn" flow, vulnerable dependencies, insider threats, anything not modelled, and anything modelled wrongly.

## Run

```
python -m sec_threat_model_checker check examples/shop-flawed.json            # exit 1, text report
python -m sec_threat_model_checker check examples/shop.json --format mermaid  # data-flow diagram source
python -m sec_threat_model_checker check MODEL --format json|markdown --out report.md --fail-on critical
python -m sec_threat_model_checker diff examples/shop.json examples/shop-flawed.json
python -m sec_threat_model_checker rules      # every rule with rationale and mitigation
python -m sec_threat_model_checker demo       # the table above
python -m pytest                              # 44 tests
```

Exit codes: **0** pass, **1** findings at or above `--fail-on` (default `high`), **2** invalid model, invalid acceptance file, bad arguments, or a rule that could not be evaluated.

Acceptances: `MITIGATION-ACCEPTANCE.json` next to the model (or `--accept FILE`): `{"acceptances": [{"finding_id": "R03:component:db", "reason": "...", "owner": "team", "expires": "2026-12-31"}]}`. Reason (10+ chars), owner and expiry are required; the expiry day itself is still covered, the day after the finding returns. Acceptances that match nothing are reported as stale.

Diff mode fails on: a new finding at or above the threshold; a finding that was accepted before and is not now (removed or expired); or a control that was weakened (TLS, authn, audit logging, encryption at rest, backup, rate limiting, consumer authn, replicas below 2, admin MFA), even if no finding results. Existing findings do not fail a diff.

## Layout

```
sec_threat_model_checker/  model.py (schema + validation)  rules.py (11 rules + engine)  policy.py (acceptance, diff)
                           render.py (text/Markdown/Mermaid)  gen.py (generator, injectors)  measure.py  cli.py
tests/                     44 tests: validation, one per rule with boundaries, policy, render, subprocess exit codes, seeded properties
examples/                  a generated clean model and a flawed one
```

## Known gaps

- Models are trusted as written. There is no discovery from real infrastructure, so drift between model and reality is invisible.
- Rules are intentionally simple: R01 and R05 only judge boundary crossings (plaintext inside a zone passes), R04 only direct exposure to trust-0 zones, `critical` is declared rather than derived from paths, and `access_roles` are modelled but no rule judges them.
- Removing a control fails a diff even when the resulting finding is accepted; that is deliberate but strict.
- Severity levels are my judgement, not a scoring standard. No CVSS, no likelihood.
- Only run on Windows with Python 3.13; code avoids 3.12-only syntax but 3.11 is untested here.
