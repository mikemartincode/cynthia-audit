"""Self-contained proof for auditor/triage.py's decision logic — no network, no LLM calls.
The conservative classification table, the cross-oracle vote, delta-debug minimal-ize, and
input reconstruction are pure functions, tested directly. The live LLM phases (second-oracle
authorship, spec re-derivation) are exercised by the real triage run, not here.

Run: ~/projects/cynthia-core/.venv/bin/python auditor/test_triage.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from triage import (  # noqa: E402
    _reconstruct, classify_candidate, cross_oracle_vote, minimalize,
)


def _cand(classification="divergence", real="r", oracle="o", note=""):
    return {"classification": classification, "real_result": real,
            "oracle_expected": oracle, "note": note}


def test_classify_conservative():
    # invalid-input / invalid validity -> invalid-input regardless of votes
    assert classify_candidate(_cand("invalid-input"), valid=True, vote="agree_oracle",
                              spec_match="oracle") == ("invalid-input", "high")
    assert classify_candidate(_cand(), valid=False, vote="agree_oracle",
                              spec_match="oracle") == ("invalid-input", "high")

    # VALUE divergence is NEVER auto-promoted to real-bug (correlated-model false-positive
    # lesson). Both checks agreeing with the oracle -> a HIGH-priority human-review item.
    assert classify_candidate(_cand(), valid=True, vote="agree_oracle",
                              spec_match="oracle") == ("spec-ambiguity", "high")
    assert classify_candidate(_cand(), valid=True, vote="agree_oracle",
                              spec_match="skipped") == ("spec-ambiguity", "medium")
    assert classify_candidate(_cand(), valid=True, vote="inconclusive",
                              spec_match="oracle") == ("spec-ambiguity", "medium")

    # real-side support -> bad-oracle (first oracle was wrong)
    assert classify_candidate(_cand(), valid=True, vote="agree_real",
                              spec_match="real") == ("bad-oracle", "high")
    assert classify_candidate(_cand(), valid=True, vote="agree_real",
                              spec_match="skipped") == ("bad-oracle", "medium")

    # genuine three-way / other -> spec-ambiguity
    assert classify_candidate(_cand(), valid=True, vote="three_way",
                              spec_match="skipped") == ("spec-ambiguity", "medium")
    assert classify_candidate(_cand(), valid=True, vote="no_second",
                              spec_match="other") == ("spec-ambiguity", "medium")

    # unconfirmed divergence -> conservative bad-oracle/low (never real-bug by default)
    assert classify_candidate(_cand(), valid=True, vote="no_second",
                              spec_match="skipped") == ("bad-oracle", "low")
    print("test_classify_conservative: value never auto-real-bug -> human-review; "
          "default bad-oracle OK")


def test_classify_crash():
    crash = _cand(real="RAISED NotImplementedError: x", note="library raised NotImplementedError")
    # a library crash, both checks side with oracle -> real-bug high
    assert classify_candidate(crash, valid=True, vote="agree_oracle",
                              spec_match="oracle") == ("real-bug", "high")
    # a crash needs only ONE corroboration (the crash itself is strong) -> real-bug medium
    assert classify_candidate(crash, valid=True, vote="agree_oracle",
                              spec_match="skipped") == ("real-bug", "medium")
    assert classify_candidate(crash, valid=True, vote="no_second",
                              spec_match="oracle") == ("real-bug", "medium")
    # a library crash with NO corroboration -> suspicious but unconfirmed: spec-ambiguity/low
    assert classify_candidate(crash, valid=True, vote="no_second",
                              spec_match="skipped") == ("spec-ambiguity", "low")
    # a crash the cross-check says is CORRECT (real-side support) -> bad-oracle, not real-bug
    assert classify_candidate(crash, valid=True, vote="agree_real",
                              spec_match="skipped") == ("bad-oracle", "medium")
    print("test_classify_crash: crash needs 1 corroboration; bare crash -> ambiguity OK")


def test_cross_oracle_vote():
    real = lambda x: "R"     # noqa: E731
    orac = lambda x: "O"     # noqa: E731
    def boom(x): raise RuntimeError("can't grade")
    assert cross_oracle_vote("q", "x", real, orac, orac, None) == "agree_oracle"   # 2nd w/ oracle
    assert cross_oracle_vote("q", "x", real, orac, real, None) == "agree_real"     # 2nd w/ real
    assert cross_oracle_vote("q", "x", real, orac, lambda x: "S", None) == "three_way"
    assert cross_oracle_vote("q", "x", real, orac, None, None) == "no_second"
    assert cross_oracle_vote("q", "x", real, orac, boom, None) == "inconclusive"
    # real == oracle here (no actual divergence on this value) -> inconclusive
    assert cross_oracle_vote("q", "x", orac, orac, orac, None) == "inconclusive"
    print("test_cross_oracle_vote: agree_oracle/agree_real/three_way/no_second/inconclusive OK")


def test_minimalize():
    # shrink a string to the smallest still-diverging substring
    assert minimalize("aaXbb", lambda s: "X" in s) == "X"
    # tuple: keep the load-bearing parts, shrink the rest
    got = minimalize(("url", "aXa"), lambda t: t[0] == "url" and "X" in t[1])
    assert got == ("url", "X"), got
    # nothing shrinks -> original returned
    assert minimalize("abc", lambda s: s == "abc") == "abc"
    print("test_minimalize: string + tuple delta-debug OK")


def test_reconstruct():
    for v in ["http://a/b?q", ("http://a", "g"), 123, None, True, ("u", None, 5)]:
        assert _reconstruct(repr(v)) == v, v
    print("test_reconstruct: literal round-trip OK")


def main():
    test_classify_conservative()
    test_classify_crash()
    test_cross_oracle_vote()
    test_minimalize()
    test_reconstruct()
    print("test_triage: OK")


if __name__ == "__main__":
    main()
