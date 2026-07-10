"""Self-contained proof for auditor/triage.py's decision logic - no network, no LLM calls.
The conservative classification table, the cross-oracle vote, delta-debug minimal-ize, input
reconstruction, and the salvage-resume contract are tested directly (salvage re-gates through
the REAL local mutation gate - still zero network). The live LLM phases (second-oracle
authorship, spec re-derivation) are exercised by the real triage run, not here.

Run: ~/projects/cynthia-core/.venv/bin/python auditor/test_triage.py
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from triage import (  # noqa: E402
    _meta_settled, _reconstruct, _salvage_drafts, classify_candidate, cross_oracle_vote,
    minimalize,
)
from test_author import GOOD_BATTERY, GOOD_REF, VACUOUS_BATTERY  # noqa: E402


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


def test_meta_settled():
    # GREEN is always settled, however it was produced.
    assert _meta_settled({"green": True})
    assert _meta_settled({"green": True, "salvaged": True})
    # RED after a REAL authoring pass (no salvage marker) is settled - the fallback ran.
    assert _meta_settled({"green": False})
    assert _meta_settled({"green": False, "salvage_then_fallback": True})
    # a salvage-only RED is NOT settled: its adaptive fallback never ran (the dead-end fix).
    assert not _meta_settled({"green": False, "salvaged": True})
    assert not _meta_settled({"green": False, "note": "salvage: no usable draft",
                              "salvaged": True})
    print("test_meta_settled: salvage-only RED re-attempted, everything else settled OK")


def _write_draft(base: Path, qhash: str, name: str, code: str) -> None:
    d = base / name
    d.mkdir(parents=True, exist_ok=True)
    (d / f"orc_{qhash}_{name}.py").write_text(code)


def test_salvage_drafts():
    """Salvage settles only on a GREEN re-gate; RED drafts come back as an UNSETTLED best
    (caller owes the fallback); an empty/missing draft dir returns None (author fresh) -
    previously a dir with no usable drafts persisted a terminal RED that suppressed the
    function's vote on every later resume."""
    qual = "intcmp"
    qhash = hashlib.sha1(qual.encode()).hexdigest()[:10]
    good = GOOD_REF.rstrip() + "\n\n" + GOOD_BATTERY
    vacuous = GOOD_REF.rstrip() + "\n\n" + VACUOUS_BATTERY

    with tempfile.TemporaryDirectory() as td:
        second = Path(td)
        base = second / "oracles" / f"{qual}_{qhash}"

        # no draft dir at all -> None
        assert _salvage_drafts(qual, second) is None

        # dir exists but holds no usable draft -> None (NOT a settled RED) - the dead-end fix
        (base / "n0").mkdir(parents=True)
        assert _salvage_drafts(qual, second) is None

        # only a vacuous (RED) draft -> best RED meta, marked salvaged (=> unsettled)
        _write_draft(base, qhash, "n1", vacuous)
        m = _salvage_drafts(qual, second)
        assert m is not None and not m["green"] and m["salvaged"], m
        assert not _meta_settled(m)

        # a GREEN draft on disk -> settled GREEN meta through the real gate
        _write_draft(base, qhash, "adaptive", good)
        m = _salvage_drafts(qual, second)
        assert m is not None and m["green"] and m["salvaged"], m
        assert _meta_settled(m)
        assert m["oracle_path"].endswith(f"adaptive/orc_{qhash}_adaptive.py"), m
    print("test_salvage_drafts: GREEN settles, RED unsettled-best, empty dir authors fresh OK")


def main():
    test_classify_conservative()
    test_classify_crash()
    test_cross_oracle_vote()
    test_minimalize()
    test_reconstruct()
    test_meta_settled()
    test_salvage_drafts()
    print("test_triage: OK")


if __name__ == "__main__":
    main()
