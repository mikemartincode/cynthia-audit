"""Self-contained proof for E03 — assertable VALUE bugs. No network: the spec-vector table is
local ground truth, the mutation gate isn't needed here (the classifier is exercised directly),
and the A06 re-classification reuses the recorded evidence already on disk.

What it demonstrates (the E03 done-criteria):
  1. SPEC-VECTOR GROUND TRUTH: a value divergence whose input is in the RFC 3986 §5.4 table is
     judged against the TABLE's output (not a model), and that promotes to real-bug/high; a value
     matching the table downgrades the disagreeing oracle to bad-oracle. RED-on-bad + GREEN-on-good
     are shown against the REAL hyperlink library (it is correct on 40/41 vectors; `g:h` is the one
     ground-truth divergence — the A06 finding, re-confirmed with no model in the loop).
  2. CROSS-FAMILY MAJORITY: a value divergence corroborated by ≥3 DISTINCT model families promotes
     to real-bug/medium; ≥2 families is NOT enough.
  3. SAME-FAMILY TRAP STAYS CLOSED: a same-family second oracle can NEVER promote a value bug, and
     neither can a single oracle — the exact A05 failure mode.
  4. NO FALSE PROMOTIONS ON A06: re-classifying the real A06 findings under the new rules promotes
     ZERO new value bugs (the 16 review-queue cases are deepseek+minimax = 2 families, below the
     3-family bar) — the honest hand-verification, done deterministically from recorded evidence.

Run: ~/projects/cynthia-core/.venv/bin/python auditor/test_value_bugs.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import spec_vectors as sv  # noqa: E402
from spec_vectors import RFC_BASE, lookup, iter_vectors, vector_count  # noqa: E402
from triage import classify_candidate, spec_vector_check  # noqa: E402
from adapters import ADAPTERS  # noqa: E402


def _cand(cls="divergence", real="'x'", note=""):
    return {"classification": cls, "real_result": real, "oracle_expected": "'y'", "note": note}


# ---------------------------------------------------------------- 1. spec-vector ground truth

def test_spec_vectors_load():
    """The RFC §5.4 table loads; lookup returns the expected output + citation for a tabled input
    and None otherwise; iter_vectors yields every cell."""
    v = lookup("URL.click", (RFC_BASE, "g"))
    assert v is not None and v.expected == "http://a/b/c/g", v
    assert "§5.4.1" in v.citation, v.citation
    v2 = lookup("URL.click", (RFC_BASE, "g:h"))
    assert v2.expected == "g:h", v2
    # not tabled / wrong base / wrong function → no vector (we never assert off-table)
    assert lookup("URL.click", (RFC_BASE, "totally-not-in-table")) is None
    assert lookup("URL.click", ("http://other/", "g")) is None
    assert lookup("URL.host", (RFC_BASE, "g")) is None
    assert vector_count() == len(sv.NORMAL) + len(sv.ABNORMAL) == 41, vector_count()
    print(f"spec-vectors load: {vector_count()} RFC §5.4 vectors, citation travels with each")


def test_spec_vector_check_red_and_green():
    """spec_vector_check is RED on a wrong resolver and GREEN on a correct one — judged purely by
    the table, no model."""
    def correct(x):
        base, ref = x
        return sv.NORMAL.get(ref) or sv.ABNORMAL.get(ref)

    def buggy(x):
        return "http://WRONG/"

    x = (RFC_BASE, "../g")  # tabled: -> http://a/b/g
    good = spec_vector_check("URL.click", x, correct, None)
    assert good["match"] == "real_matches" and "§5.4" in good["citation"], good
    bad = spec_vector_check("URL.click", x, buggy, None)
    assert bad["match"] == "real_wrong" and bad["expected"] == "http://a/b/g", bad
    # an input with no published vector → no verdict (we only assert on the table)
    assert spec_vector_check("URL.click", (RFC_BASE, "no-vector-here"), buggy, None) is None
    print("spec-vector check: real_wrong on a bad resolver, real_matches on a correct one")


def test_hyperlink_spec_vector_sweep():
    """Run the REAL hyperlink URL.click over EVERY RFC §5.4 vector. Ground truth, no model: it is
    correct on 40/41; the single divergence is `g:h` (NotImplementedError) — the A06 finding,
    re-confirmed against the spec's own example. GREEN-on-good + RED-on-the-one-real-bug."""
    adapter = ADAPTERS["URL.click"]
    wrong, matches = [], 0
    for qual, x, expected, citation in iter_vectors():
        chk = spec_vector_check(qual, x, adapter, None)
        assert chk is not None, (x, "every iter_vectors input must be tabled")
        if chk["match"] == "real_wrong":
            wrong.append((x, chk))
        else:
            matches += 1
    assert matches == 40, matches                       # hyperlink is correct on 40 vectors
    assert len(wrong) == 1, wrong
    (x, chk), = wrong
    assert x == (RFC_BASE, "g:h") and chk["real"] == "RAISED", (x, chk)
    assert chk["expected"] == "g:h" and "§5.4.1" in chk["citation"], chk
    print(f"hyperlink §5.4 sweep: 40/41 match the RFC table; 1 ground-truth divergence "
          f"{x} (expected {chk['expected']!r}, library RAISED) — confirmed with no model")


# ---------------------------------------------------------------- 2+3. classification rules

def test_spec_vector_promotes_value_bug():
    """A value divergence with a ground-truth spec vector promotes — real_wrong → real-bug/high,
    real_matches → bad-oracle/high. This is the assertable VALUE-bug path (was: never promote)."""
    rw = {"match": "real_wrong", "expected": "g:h", "citation": "RFC 3986 §5.4.1", "real": "RAISED"}
    assert classify_candidate(_cand(), valid=True, vote="no_second", spec_match="skipped",
                              spec_vector=rw) == ("real-bug", "high")
    rm = {"match": "real_matches", "expected": "http://a/b/g", "citation": "RFC 3986 §5.4.2",
          "real": "http://a/b/g"}
    assert classify_candidate(_cand(), valid=True, vote="agree_oracle", spec_match="oracle",
                              spec_vector=rm) == ("bad-oracle", "high")
    print("spec-vector: real_wrong -> real-bug/high (ground truth); real_matches -> bad-oracle")


def test_cross_family_majority_promotes():
    """≥3 DISTINCT model families siding with the oracle (2 cross-family oracles + a cross-family
    arbiter) promotes a VALUE divergence to real-bug/medium."""
    got = classify_candidate(
        _cand(), valid=True, vote="agree_oracle", spec_match="oracle",
        first_family="deepseek", vote_family="minimax", spec_family="gemini",
        second_oracle_green=True)
    assert got == ("real-bug", "medium"), got
    print("cross-family majority: 3 distinct families (deepseek/minimax/gemini) -> real-bug/medium")


def test_same_family_cannot_promote():
    """CRITERION 3 — the trap stays closed. A same-family second oracle (only 2 distinct families
    even with the arbiter) does NOT promote; a single oracle does NOT promote. Both stay in the
    conservative human-review / ambiguity lane."""
    # second oracle is SAME family as the first (deepseek) → only {deepseek, gemini} = 2 distinct.
    same_family = classify_candidate(
        _cand(), valid=True, vote="agree_oracle", spec_match="oracle",
        first_family="deepseek", vote_family="deepseek", spec_family="gemini",
        second_oracle_green=True)
    assert same_family == ("spec-ambiguity", "high"), same_family
    # the A06 production config: deepseek first + minimax vote + deepseek arbiter = 2 distinct.
    a06_config = classify_candidate(
        _cand(), valid=True, vote="agree_oracle", spec_match="oracle",
        first_family="deepseek", vote_family="minimax", spec_family="deepseek",
        second_oracle_green=True)
    assert a06_config == ("spec-ambiguity", "high"), a06_config
    # single oracle (no second) → never a value bug.
    single = classify_candidate(
        _cand(), valid=True, vote="no_second", spec_match="oracle",
        first_family="deepseek", vote_family="minimax", spec_family="gemini",
        second_oracle_green=False)
    assert single[0] != "real-bug", single
    # second oracle agrees but was NOT gate-GREEN → not an independent oracle → no promote.
    not_green = classify_candidate(
        _cand(), valid=True, vote="agree_oracle", spec_match="oracle",
        first_family="deepseek", vote_family="minimax", spec_family="gemini",
        second_oracle_green=False)
    assert not_green == ("spec-ambiguity", "high"), not_green
    print("trap closed: same-family / 2-family / single-oracle / non-GREEN -> never a value bug")


# ---------------------------------------------------------------- 4. honest A06 hand-verification

def test_a06_recompute_no_false_value_promotions():
    """CRITERION 4 — re-classify the REAL A06 findings under the new rules and prove ZERO false
    value promotions. The A06 config is deepseek(first) + minimax(vote) + deepseek(arbiter) = 2
    distinct families, below the 3-family bar, so the 16 correlated review-queue cases (default
    ports etc.) correctly STAY spec-ambiguity. Only the pre-existing CRASH bugs remain real-bug.
    Done deterministically from recorded evidence — no re-run, no spend."""
    fpath = Path(__file__).resolve().parent.parent / "results/a06-final/triage/findings.json"
    if not fpath.exists():
        print("a06 recompute: SKIP (results/a06-final not present)")
        return
    findings = json.loads(fpath.read_text())
    value_promotions, crash_real_bugs = [], 0
    for f in findings:
        ev = f["evidence"]
        cand = {"classification": ev.get("a04_classification", "divergence"),
                "real_result": f.get("real_result", ""), "note": ev.get("note", "")}
        cls, conf = classify_candidate(
            cand, valid=ev.get("valid_input", True),
            vote=ev.get("cross_oracle_vote", "no_second"),
            spec_match=ev.get("spec_rederivation", "skipped"),
            spec_vector=None,                                # A06 inputs are not RFC-base vectors
            first_family="deepseek", vote_family="minimax", spec_family="deepseek",
            second_oracle_green=ev.get("second_oracle_green", False))
        if cls == "real-bug":
            if ev.get("is_crash_divergence"):
                crash_real_bugs += 1
            else:
                value_promotions.append(f)   # a VALUE bug promoted by the new rules — must be 0
    assert not value_promotions, [f["qualname"] for f in value_promotions]
    assert crash_real_bugs > 0, "expected the known crash bugs to still classify as real-bug"
    print(f"a06 recompute: {crash_real_bugs} crash real-bugs retained, 0 false VALUE promotions "
          "(2-family agreement stays spec-ambiguity — the trap held on real data)")


def main() -> None:
    test_spec_vectors_load()
    test_spec_vector_check_red_and_green()
    test_hyperlink_spec_vector_sweep()
    test_spec_vector_promotes_value_bug()
    test_cross_family_majority_promotes()
    test_same_family_cannot_promote()
    test_a06_recompute_no_false_value_promotions()
    print("test_value_bugs: OK")


if __name__ == "__main__":
    main()
