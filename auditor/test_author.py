"""No-network proof for auditor/author.py: the reference and battery are authored
INDEPENDENTLY (two calls), so the gate's step-0 ref_passes is a real cross-acceptance check —
a battery that disagrees with the reference is a SPEC-DISAGREEMENT, not a silent retry. Every
model-failure mode still degrades to a RED ResultRecord (never an exception), and a well-formed
ref+battery pair goes GREEN through the real mutation gate. call_model is stubbed (prompt-aware:
it returns the reference snippet for the reference prompt, the battery snippet for the battery
prompt) — zero spend, deterministic.

Run: ~/projects/cynthia-core/.venv/bin/python auditor/test_author.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import author  # noqa: E402

ENTRY = {
    "qualname": "intcmp", "signature": "(pair)", "auditability": "spec",
    "intent": "compare two integers and return the sign of their difference",
    "auditability_why": "test fixture",
    "doc": "Return a negative number if a < b, zero if a == b, a positive number if a > b. "
           "The pair argument is a tuple (a, b) of integers.",
}

GOOD_REF = '''
def ref_intcmp(pair):
    a, b = pair
    return (a > b) - (a < b)

REFERENCE_FUNC = ref_intcmp
REFERENCE_NAME = "ref_intcmp"
'''

GOOD_BATTERY = '''
PROBE_INPUTS = [(0, 0), (1, 0), (0, 1), (-5, 3), (3, -5), (7, 7), (-2, -2), (-3, -1)]
EQUIV_KEY = lambda r: (r > 0) - (r < 0)

def check_impl(fn):
    expected = [0, 1, -1, -1, 1, 0, 0, -1]
    out = []
    for pair, exp in zip(PROBE_INPUTS, expected):
        try:
            got = fn(pair)
            out.append((((got > 0) - (got < 0)) == exp, f"{pair} -> {got}"))
        except Exception as exc:
            out.append((False, f"{pair} raised {exc}"))
    return out
'''

# always-pass battery — non-vacuity gate must catch it (survivors)
VACUOUS_BATTERY = '''
PROBE_INPUTS = [(0, 0), (1, 0), (0, 1), (-5, 3), (3, -5), (7, 7), (-2, -2), (-3, -1)]

def check_impl(fn):
    return [(True, "looks fine") for _ in PROBE_INPUTS]
'''

# a battery that read the spec BACKWARDS — it expects the sign of (b - a). It REJECTS the correct
# reference, so the gate's step-0 ref_passes is False: an independent spec-disagreement to escalate.
DISAGREE_BATTERY = '''
PROBE_INPUTS = [(1, 0), (0, 1), (-5, 3)]

def check_impl(fn):
    expected = [-1, 1, 1]  # backwards: ref_intcmp gives 1, -1, -1
    out = []
    for pair, exp in zip(PROBE_INPUTS, expected):
        try:
            got = fn(pair)
            out.append((((got > 0) - (got < 0)) == exp, f"{pair} -> {got}"))
        except Exception as exc:
            out.append((False, f"{pair} raised {exc}"))
    return out
'''


def _split_stub(ref_code: str, battery_code: str):
    """Prompt-aware stub: the battery prompt carries the word BATTERY; the reference prompt does
    not. Returns the right snippet so the two independent calls assemble into one oracle."""
    def fake(model, system, user, **kw):
        code = battery_code if "BATTERY" in user else ref_code
        return {"code": code, "raw": code, "in_tok": 100, "out_tok": 200,
                "cost": 0.001, "elapsed": 0.0}
    return fake


def _exc_stub(exc: Exception):
    def fake(model, system, user, **kw):
        raise exc
    return fake


def test_convention_hint() -> None:
    """Multi-arg functions get the EXACT tuple layout pinned into the shared spec text
    (the measured idna fix: 4/4 convention-mismatch REDs were multi-arg, 0/13 single-arg);
    single-arg functions get NO hint; a garbage signature degrades to no hint, never raises."""
    h = author._convention_hint({"qualname": "encode",
                                 "signature": "(s, strict=False, uts46=False)"})
    assert "EXACTLY 3 items" in h and "arg = (s, strict, uts46)" in h, h
    assert "strict=False" in h and "uts46=False" in h, h

    h = author._convention_hint({"qualname": "URL.click", "signature": "(self, href)"})
    assert "EXACTLY 2 items" in h and "<the object's textual form>, href" in h, h

    h = author._convention_hint({"qualname": "URL.child", "signature": "(self, *segments)"})
    assert "AT LEAST 1" in h and "*segments" in h, h

    assert author._convention_hint({"qualname": "parse_host", "signature": "(host)"}) == ""
    assert author._convention_hint({"qualname": "URL.scheme", "signature": "(self)"}) == ""
    assert author._convention_hint({"qualname": "x", "signature": "(not (valid"}) == ""

    # build_spec carries the hint for multi-arg entries and stays hint-free for single-arg
    multi = {**ENTRY, "qualname": "encode", "signature": "(s, strict=False)"}
    assert "CALLING CONVENTION" in author.build_spec(multi)
    assert "CALLING CONVENTION" not in author.build_spec(ENTRY)
    print("test_convention_hint: multi-arg pinned, single-arg untouched, garbage safe OK")


def test_best_of_n_fallback_only() -> None:
    """author_best_of_n(n=0) authors ZERO fast drafts and goes straight to the adaptive
    thinking-ON fallback — the salvage-resume path uses this to pay only the fallback a
    salvaged-RED function is still owed (its fast drafts already exist on disk, all RED)."""
    calls = []
    real = author.call_model

    def fake(model, system, user, **kw):
        calls.append(kw.get("thinking"))
        code = GOOD_BATTERY if "BATTERY" in user else GOOD_REF
        return {"code": code, "raw": code, "in_tok": 100, "out_tok": 200,
                "cost": 0.001, "elapsed": 0.0}

    try:
        with tempfile.TemporaryDirectory() as td:
            author.call_model = fake
            rec = author.author_best_of_n(ENTRY, "stub-model", Path(td), n=0)
        assert rec.green, rec.to_dict()
        assert len(calls) == 2, calls  # ONE fallback draft = one ref call + one battery call
        assert all(t == {"type": "adaptive"} for t in calls), calls
        assert [a["attempt"] for a in rec.attempt_log] == ["adaptive_fallback"], rec.attempt_log
    finally:
        author.call_model = real
    print("test_best_of_n_fallback_only: n=0 -> adaptive fallback only, gates GREEN OK")


def main() -> None:
    real = author.call_model
    try:
        with tempfile.TemporaryDirectory() as td:
            run = Path(td)

            # GREEN: independent reference + battery assemble and pass the REAL gate end to end
            author.call_model = _split_stub(GOOD_REF, GOOD_BATTERY)
            rec = author.author_and_gate(ENTRY, "stub-model", run, attempts=1, gate_cap=40)
            assert rec.green and not rec.spec_disagreement, rec.to_dict()
            assert rec.gate["kill_rate"] == 1.0 and rec.gate["non_equivalent"] > 0, rec.gate
            json.dumps(rec.to_dict())  # serializable
            print(f"GREEN ok: kill {rec.gate['killed']}/{rec.gate['non_equivalent']}")

            # RED (vacuous): the gate catches an always-pass battery — survivors, not a crash
            author.call_model = _split_stub(GOOD_REF, VACUOUS_BATTERY)
            rec = author.author_and_gate({**ENTRY, "qualname": "intcmp_vac"}, "stub-model",
                                         run, attempts=1)
            assert not rec.green and rec.gate["survivors"] and not rec.spec_disagreement, rec.gate
            print(f"RED (vacuous) ok: {len(rec.gate['survivors'])} survivors")

            # SPEC-DISAGREEMENT: an independent battery that rejects the reference -> ref_passes
            # False -> flagged distinctly (escalate), NOT retried into agreement.
            author.call_model = _split_stub(GOOD_REF, DISAGREE_BATTERY)
            rec = author.author_and_gate({**ENTRY, "qualname": "intcmp_dis"}, "stub-model",
                                         run, attempts=4)
            assert not rec.green and rec.spec_disagreement, rec.to_dict()
            assert rec.gate["ref_passes"] is False and rec.attempts == 1, rec.gate  # no retry-into-agreement
            print("SPEC-DISAGREEMENT ok: battery rejects independent reference -> escalate")

            # RED (garbage): un-compilable prose on both calls degrades, never crashes
            author.call_model = _split_stub("not code at all", "also not code")
            rec = author.author_and_gate({**ENTRY, "qualname": "intcmp_junk"}, "stub-model",
                                         run, attempts=2)
            assert not rec.green, rec.to_dict()
            print(f"RED (garbage) ok: {rec.gate['note'][:60]!r}")

            # RED (gateway down): HTTP failure becomes a RED record with the error noted
            author.call_model = _exc_stub(urllib.error.URLError("connection refused"))
            rec = author.author_and_gate({**ENTRY, "qualname": "intcmp_http"}, "stub-model",
                                         run, attempts=2)
            assert not rec.green and "author call failed" in rec.gate["note"], rec.gate
            json.dumps(rec.to_dict())
            print("RED (gateway) ok")
    finally:
        author.call_model = real
    test_convention_hint()
    test_best_of_n_fallback_only()
    print("test_author: OK")


if __name__ == "__main__":
    main()
