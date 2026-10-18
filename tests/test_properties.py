import copy
import datetime
import random

import pytest

from sec_threat_model_checker import gen, policy
from sec_threat_model_checker.model import ModelError, validate
from sec_threat_model_checker.rules import check_dict

TODAY = datetime.date(2026, 6, 15)


def caught(fs, rid, els):
    return any(f["rule"] == rid and set(els) <= set(f["elements"]) for f in fs)


def test_clean_generated_models_are_valid_and_have_no_findings():
    for s in range(60):
        assert check_dict(gen.clean(s)) == [], s


def test_every_injected_flaw_type_is_found_on_the_right_element():
    for rid in gen.INJECT:
        for s in range(25):
            d, exp = gen.flawed(s, [rid])
            assert caught(check_dict(d), rid, exp[0][1]), (rid, s)


def test_mixed_flaws_are_all_found_and_findings_do_not_depend_on_input_order():
    ids = sorted(gen.INJECT)
    for s in range(30):
        rng = random.Random(s)
        d, exp = gen.flawed(s, rng.sample(ids, 3))
        fs = check_dict(d)
        assert all(caught(fs, rid, e) for rid, e in exp), s
        shuffled = copy.deepcopy(d)
        rng.shuffle(shuffled["components"])
        rng.shuffle(shuffled["flows"])
        assert [f["id"] for f in check_dict(shuffled)] == [f["id"] for f in fs]


def test_every_class_of_invalid_model_is_rejected_never_passed():
    for kind, fn in gen.INVALID.items():
        for s in range(10):
            d = gen.clean(s)
            fn(d, random.Random(s))
            with pytest.raises(ModelError):
                validate(d)


def test_diff_properties_over_generated_pairs():
    for s in range(20):
        clean = validate(gen.clean(s))
        for rid in ("R01", "R03", "R06", "R09"):
            d, _ = gen.flawed(s, [rid])
            bad = validate(d)
            assert policy.diff(clean, clean, {}, {}, TODAY)["fail"] is False
            assert policy.diff(clean, bad, {}, {}, TODAY)["fail"] is True, (rid, s)
            assert policy.diff(bad, clean, {}, {}, TODAY)["fail"] is False
