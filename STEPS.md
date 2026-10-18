# STEPS

**Part A** is what I did, in order. **Part B** is how you run it.

---

## Part A: steps taken

1. **Chose the shape of the model** so every rule needs only facts the model states: zones with an integer trust (0 = untrusted, optional parent to inherit from), components of five types, flows with protocol, authn, encrypted, data class and audit flag, plus a few per-component flags (rate limiting, replicas, critical, failover_of, credential, admin interface). Classification labels are the generic public/internal/confidential/restricted; no payment or health categories are modelled.
2. **Wrote validation first** (`model.py`) because "could not judge" has to be a first-class outcome: dangling references, unknown zones, duplicate ids, bad enums and missing required flags (datastore and queue flags are required, never guessed), and two kinds of cycle that make a rule undecidable (zone parent chains for trust, failover chains for redundancy). All errors are collected and exit 2.
3. **Wrote 11 rules** (`rules.py`), each with STRIDE category, rationale and mitigation, and an engine that turns a rule crash into exit 2 instead of a pass. Finding ids are `RULE:element+element`, so they are stable across model versions (diff and acceptances depend on that).
4. **Wrote the acceptance file and diff mode** (`policy.py`): required reason/owner/expiry, expiry day inclusive, stale acceptances reported. Diff fails on new findings at the threshold, on a removed or expired acceptance, and on any weakened control.
5. **Wrote the outputs** (JSON, Markdown, text, Mermaid with dashed edges for plaintext flows and highlighted offenders) and the CLI with exit codes 0/1/2.
6. **Wrote the seeded generator** with one injector per rule, mixes, invalid-model injectors, and three evasion variants, then `demo` to print the measured table.
7. **Wrote 44 tests**: validation (9), one per rule with boundaries (12), policy (9), render (2), real-subprocess CLI exit codes (7), seeded properties (5).
8. **Mutation-checked** 12 deliberate breaks on a fresh copy each; a script prints "PATTERN MISSED" if a break did not apply. All 12 were killed.
9. **Wrote README and this file**, then committed locally. Not pushed, CI has not run.

Problems and choices along the way:
- First draft of the rules had an unreadable `__import__` hack and a circular import (`render` needed `effective` from `rules`); fixed before the first run.
- A nested f-string with a backslash in `render.py` would be a syntax error on Python 3.11 (the CI matrix), so it was rewritten.
- My first diff tests were wrong, not the code: weakening a control (rate limiting, encryption at rest) fails a diff by design, so tests of "new finding below threshold" had to use a new flow instead of flipping a flag.
- The generated detection numbers came out at 100% on the first run. That is a warning sign, not a result, so I added the evasion variants and the blind-spot list.
- With the zone-cycle check removed, trust resolution loops forever; the mutation was "killed" by a timeout, which is a crash and not a clean assertion.

---

## Part B: steps for you

1. Python 3.11+; no packages to install (pytest for tests only).
2. From the repo folder: `python -m sec_threat_model_checker check examples/shop-flawed.json` (exit code 1; `echo $?` or `$LASTEXITCODE`).
3. Make your own model: copy `examples/shop.json`, edit components and flows, run `check`. Use `--format mermaid` and paste the output into any Mermaid renderer.
4. Accept a reviewed risk: create `MITIGATION-ACCEPTANCE.json` next to the model (format in the README), re-run, then re-run with `--today 2999-01-01` to see it expire.
5. Gate a change: `python -m sec_threat_model_checker diff old.json new.json` in CI.
6. `python -m sec_threat_model_checker demo` reprints the measured table; `python -m pytest` runs the 44 tests.
