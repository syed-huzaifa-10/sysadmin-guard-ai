"""Run:  python test_engine.py   (or: pytest)"""
from engine import InferenceEngine
from report import build_pdf
from rules import RULES
from schema import DEFAULTS, FIELDS, PRESETS

ENGINE = InferenceEngine(RULES)


def run(preset):
    return ENGINE.run({**DEFAULTS, **PRESETS[preset]})


def test_rule_count_and_unique_ids():
    assert len(RULES) >= 50
    assert len({r.id for r in RULES}) == len(RULES)


def test_all_condition_facts_are_defined():
    known = {f[0] for f in FIELDS} | {t for r in RULES for t in r.then}
    for r in RULES:
        for fact, _, _ in r.when:
            assert fact in known, f"{r.id} uses unknown fact {fact}"


def test_hardened_server_is_clean():
    res = run("Hardened production server")
    assert res.risk == 0 and not res.fired and res.rating == "HARDENED"


def test_legacy_server_triggers_chain():
    res = run("Neglected legacy server")
    assert {"exposed_remote_access", "vulnerable_platform", "breach_imminent"} <= set(res.derived)
    assert max(f.depth for f in res.fired) >= 4 and res.rating == "CRITICAL"


def test_each_rule_fires_once():
    ids = [f.rule.id for f in run("Neglected legacy server").fired]
    assert len(ids) == len(set(ids))


def test_fresh_install_midrange_and_pdf():
    res = run("Fresh Ubuntu install")
    assert 0 < res.risk < 100 and res.rating in ("AT RISK", "CRITICAL")
    assert build_pdf("test", res)[:4] == b"%PDF"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn(); print("PASS", name)
    for p in PRESETS:
        r = run(p); print(f"{p:28s} risk={r.risk:3d} {r.rating:10s} fired={len(r.fired)}")
