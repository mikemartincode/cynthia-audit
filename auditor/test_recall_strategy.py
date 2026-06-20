#!/usr/bin/env python3
"""Tests for auditor/recall_strategy.py — shape_key derivation, the GROUP BY recommendation, and
the load-bearing STATELESSNESS property the leave-one-out held-out evaluation depends on."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recall_strategy import (  # noqa: E402
    StrategyRecall, candidate_strategies, shape_key, split_oracle,
)

# a well-formed combined oracle module (reference FIRST, ending REFERENCE_NAME; battery after) — the
# exact structure author._author_independent assembles and author.REFERENCE_CONTRACT pins.
_ORACLE = '''import math

def ref_impl(arg):
    return arg * 2

REFERENCE_FUNC = ref_impl
REFERENCE_NAME = "ref_impl"

import statistics

PROBE_INPUTS = [1, 2, 3]

def check_impl(fn):
    return [(fn(x) == x * 2, str(x)) for x in PROBE_INPUTS]
'''


def _entry(qual, sig, aud, det, why=""):
    return {"qualname": qual, "signature": sig, "auditability": aud,
            "deterministic": det, "auditability_why": why}


def test_shape_key_from_manifest_fields():
    assert shape_key(_entry("m.f", "(a)", "spec", True)) == "spec|det=True|arity=1|inv=False"
    assert shape_key(_entry("m.f", "(a, b)", "spec", True)) == "spec|det=True|arity=2|inv=False"
    assert shape_key(_entry("m.f", "(a, b, c)", "spec", False)) == "spec|det=False|arity=3+|inv=False"
    assert shape_key(_entry("C.m", "(self, x)", "spec", True)) == "spec|det=True|arity=1|inv=False"  # self dropped
    inv = shape_key(_entry("m.encode", "(x)", "invariant", True, why="inverse pair with decode"))
    assert inv == "invariant|det=True|arity=1|inv=True"
    norm = shape_key(_entry("m.normalize", "(x)", "invariant", True, why="idempotent-by-name transform"))
    assert norm == "invariant|det=True|arity=1|inv=False"  # invariant but not an inverse pair


def test_candidate_strategies_gated_by_determinism():
    assert candidate_strategies(_entry("m.f", "(a)", "spec", True)) == ["value", "invariant", "property"]
    assert candidate_strategies(_entry("m.f", "(a)", "spec", False)) == ["stubbed_seam"]


def _seed(r: StrategyRecall):
    sk = "spec|det=True|arity=1|inv=False"
    # repo A: value usually fails, property usually greens for this shape
    for i in range(10):
        r.record(repo="A", qualname=f"A.f{i}", shape_key=sk, strategy="value", model="m",
                 gate_green=(i < 2), strict_green=False, cost=0.01, rep=0)
        r.record(repo="A", qualname=f"A.f{i}", shape_key=sk, strategy="property", model="m",
                 gate_green=(i < 8), strict_green=(i < 5), cost=0.01, rep=0)
    # repo B: value greens often (so it pollutes the global rate the held-out arm must exclude)
    for i in range(10):
        r.record(repo="B", qualname=f"B.f{i}", shape_key=sk, strategy="value", model="m",
                 gate_green=True, strict_green=False, cost=0.01, rep=0)
    return sk


def test_recommend_order_best_first():
    with tempfile.TemporaryDirectory() as td:
        r = StrategyRecall(Path(td) / "r.db")
        sk = _seed(r)
        # over A+B: value greens 2/10 (A) + 10/10 (B) = 12/20 = .60; property 8/10 = .80 -> property first
        order = r.recommend_order(sk, ["value", "invariant", "property"])
        assert order[0] == "property", order
        # invariant has NO rows -> falls behind both known strategies, keeps ladder position last
        assert order[-1] == "invariant", order


def test_statelessness_exclude_equals_delete():
    """THE property leave-one-out rests on: querying exclude_repo=B must be byte-identical to
    physically deleting B's rows and querying. If this ever fails, recall has hidden state and the
    held-out result is contaminated."""
    sk = None
    with tempfile.TemporaryDirectory() as td:
        r1 = StrategyRecall(Path(td) / "r1.db")
        sk = _seed(r1)
        excluded = r1.recommend_order(sk, ["value", "invariant", "property"], exclude_repo="B")
        rates_excl = r1.strategy_rates(sk, exclude_repo="B")

        r2 = StrategyRecall(Path(td) / "r2.db")
        _seed(r2)
        r2.delete_repo("B")
        deleted = r2.recommend_order(sk, ["value", "invariant", "property"])
        rates_del = r2.strategy_rates(sk)

    assert excluded == deleted, (excluded, deleted)
    # full equality of the aggregate rows, not just the order
    assert rates_excl == rates_del, (rates_excl, rates_del)
    # and excluding B (where value always greened) must flip value below property
    assert deleted[0] == "property", deleted


# ---------------------------------------------------------------- exemplar injection (#1)


def test_split_oracle_separates_roles_cleanly():
    """The role-split is the independence guard: the battery half a battery-author would be shown must
    contain NO reference implementation, else injecting it re-couples the two independent spec reads."""
    ref_src, bat_src = split_oracle(_ORACLE)
    assert ref_src and "def ref_impl" in ref_src and 'REFERENCE_NAME = "ref_impl"' in ref_src
    assert "check_impl" not in ref_src and "PROBE_INPUTS" not in ref_src
    assert bat_src and "def check_impl" in bat_src and "PROBE_INPUTS" in bat_src
    assert "def ref_impl" not in bat_src and "REFERENCE_NAME" not in bat_src
    # each half carries its own imports (so an injected half is self-contained)
    assert "import math" in ref_src and "import statistics" in bat_src


def test_split_oracle_rejects_malformed():
    assert split_oracle("this is ((( not python") == (None, None)
    assert split_oracle("x = 1\ndef f():\n    return 2\n") == (None, None)  # no REFERENCE_NAME marker


def _seed_exemplars(r: StrategyRecall, sk: str) -> None:
    # repo A: a STRICT-green exemplar; repo B: a plain-green exemplar of the same shape+strategy
    r.record(repo="A", qualname="A.dbl", shape_key=sk, strategy="value", model="m",
             gate_green=True, strict_green=True, cost=0.01, oracle_code=_ORACLE)
    r.record(repo="B", qualname="B.dbl", shape_key=sk, strategy="value", model="m",
             gate_green=True, strict_green=False, cost=0.01, oracle_code=_ORACLE)
    # a RED row WITH code must never be served as an exemplar (only gate-GREEN oracles are models)
    r.record(repo="A", qualname="A.bad", shape_key=sk, strategy="value", model="m",
             gate_green=False, strict_green=False, cost=0.01, oracle_code=_ORACLE)


def test_nearest_exemplar_prefers_strict_and_splits_role():
    sk = "spec|det=True|arity=1|inv=False"
    with tempfile.TemporaryDirectory() as td:
        r = StrategyRecall(Path(td) / "r.db")
        _seed_exemplars(r, sk)
        ref = r.nearest_exemplar(sk, "value", role="reference")
        bat = r.nearest_exemplar(sk, "value", role="battery")
        assert ref and ref["repo"] == "A" and ref["strict_green"] is True  # strict-first
        assert "def ref_impl" in ref["code"] and "check_impl" not in ref["code"]
        assert bat and "def check_impl" in bat["code"] and "def ref_impl" not in bat["code"]


def test_nearest_exemplar_is_leave_one_out_clean():
    """An exemplar for a held-out function must never come from its own repo, and exclude_repo must be
    byte-identical to having deleted that repo's rows (the same statelessness the selection rests on)."""
    sk = "spec|det=True|arity=1|inv=False"
    with tempfile.TemporaryDirectory() as td:
        r = StrategyRecall(Path(td) / "r.db")
        _seed_exemplars(r, sk)
        # excluding A (the strict one) falls to B, not back to A
        ex = r.nearest_exemplar(sk, "value", role="reference", exclude_repo="A")
        assert ex and ex["repo"] == "B"
        # exclude ≡ delete
        r.delete_repo("A")
        assert r.nearest_exemplar(sk, "value", role="reference") == ex
        # with B's repo also excluded there is no other-repo green oracle -> None (author un-augmented)
        assert r.nearest_exemplar(sk, "value", role="reference", exclude_repo="B") is None


def test_nearest_exemplar_none_when_no_green_in_other_repos():
    sk = "spec|det=True|arity=1|inv=False"
    with tempfile.TemporaryDirectory() as td:
        r = StrategyRecall(Path(td) / "r.db")
        # only a RED row exists -> never an exemplar
        r.record(repo="A", qualname="A.bad", shape_key=sk, strategy="value", model="m",
                 gate_green=False, strict_green=False, cost=0.01, oracle_code=_ORACLE)
        assert r.nearest_exemplar(sk, "value", role="reference") is None


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok: {name}")
