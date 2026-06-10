"""No-network proof for auditor/author.py: every model-failure mode degrades to a RED
ResultRecord (never an exception), and a well-formed authored oracle goes GREEN through
the real mutation gate. call_model is stubbed — zero spend, deterministic.

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

GOOD_ORACLE = '''
def ref_intcmp(pair):
    a, b = pair
    return (a > b) - (a < b)

REFERENCE_FUNC = ref_intcmp
REFERENCE_NAME = "ref_intcmp"
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

VACUOUS_ORACLE = '''
def ref_intcmp(pair):
    a, b = pair
    return (a > b) - (a < b)

REFERENCE_FUNC = ref_intcmp
REFERENCE_NAME = "ref_intcmp"
PROBE_INPUTS = [(0, 0), (1, 0), (0, 1), (-5, 3), (3, -5), (7, 7), (-2, -2), (-3, -1)]
EQUIV_KEY = lambda r: (r > 0) - (r < 0)

def check_impl(fn):
    return [(True, "looks fine") for _ in PROBE_INPUTS]
'''


def _stub(code_or_exc):
    def fake_call(model, system, user, *, max_tokens=0, timeout=0):
        if isinstance(code_or_exc, Exception):
            raise code_or_exc
        return {"code": code_or_exc, "raw": code_or_exc,
                "in_tok": 100, "out_tok": 200, "cost": 0.001, "elapsed": 0.0}
    return fake_call


def main() -> None:
    real = author.call_model
    try:
        with tempfile.TemporaryDirectory() as td:
            run = Path(td)

            # GREEN: a contract-conforming oracle passes the REAL gate end to end
            author.call_model = _stub(GOOD_ORACLE)
            rec = author.author_and_gate(ENTRY, "stub-model", run, attempts=1, gate_cap=40)
            assert rec.green, rec.to_dict()
            assert rec.gate["kill_rate"] == 1.0 and rec.gate["non_equivalent"] > 0, rec.gate
            json.dumps(rec.to_dict())  # serializable
            print(f"GREEN ok: kill {rec.gate['killed']}/{rec.gate['non_equivalent']}")

            # RED (vacuous): the gate catches an always-pass battery — survivors, no exception
            author.call_model = _stub(VACUOUS_ORACLE)
            rec = author.author_and_gate({**ENTRY, "qualname": "intcmp_vac"}, "stub-model",
                                         run, attempts=1)
            assert not rec.green and rec.gate["survivors"], rec.gate
            print(f"RED (vacuous) ok: {len(rec.gate['survivors'])} survivors")

            # RED (garbage): un-compilable prose degrades, never crashes
            author.call_model = _stub("I am unable to help with that today\n  - because reasons")
            rec = author.author_and_gate({**ENTRY, "qualname": "intcmp_junk"}, "stub-model",
                                         run, attempts=2)
            assert not rec.green and rec.attempts == 2, rec.to_dict()
            assert "broken" in rec.gate["note"] or "import failed" in rec.gate["note"], rec.gate
            print(f"RED (garbage) ok: {rec.gate['note'][:60]!r}")

            # RED (gateway down): HTTP failure becomes a RED record with the error noted
            author.call_model = _stub(urllib.error.URLError("connection refused"))
            rec = author.author_and_gate({**ENTRY, "qualname": "intcmp_http"}, "stub-model",
                                         run, attempts=2)
            assert not rec.green and "author call failed" in rec.gate["note"], rec.gate
            json.dumps(rec.to_dict())
            print("RED (gateway) ok")
    finally:
        author.call_model = real
    print("test_author: OK")


if __name__ == "__main__":
    main()
