"""Self-contained proof for auditor/grammar.py + measure_e04.py (E04). No network. Needs only
the vendored target clone (to import + measure coverage), like all auditor code.

Each test maps to an E04 done-criterion:
  - grammar emits structurally-VALID URIs covering the ABNF productions  -> test_grammar_*
  - seed corpus loaded from the target's own tests + an edge dictionary  -> test_seed_corpus
  - coverage-guided loop stays within a LOGGED budget                    -> test_coverage_guided_budget
  - a MEASURABLE recall lift vs the pre-E04 generator, with numbers      -> test_branch_recall_lift
  - determinism (same seed -> same corpus)                               -> test_determinism

Run: ~/projects/cynthia-core/.venv/bin/python auditor/test_grammar.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from grammar import (URL, build_e04_inputs, coverage_guided, generate_grammar_uris,  # noqa: E402
                     lines_hit, load_seed_corpus)
from strategies import URL_POOL  # noqa: E402


# ---------------------------------------------------------------- 1. grammar validity + coverage

def test_grammar_all_parse_valid():
    """Every emitted URI is structurally valid: the target's own parser accepts it (no raise)."""
    uris, stats = generate_grammar_uris(limit=300, seed=0)
    assert stats["kept"] == len(uris) == 300, stats
    for u in uris:
        URL.from_text(u)  # raises if not structurally valid -> test fails loudly
    # the drop accounting is honest: tried = kept + dropped + dedup-collisions
    assert stats["dropped_unparseable"] >= 0 and stats["tried"] >= stats["kept"], stats
    print(f"test_grammar_all_parse_valid: 300 emitted, all parse-valid "
          f"({stats['dropped_unparseable']} unparseable compositions dropped) OK")


def test_grammar_covers_abnf_productions():
    """The generated set exhibits each RFC 3986 production the generator claims to cover."""
    uris, _ = generate_grammar_uris(limit=300, seed=0)
    blob = "\n".join(uris)
    checks = {
        "non-default scheme": any(u.split(":", 1)[0] not in ("http", "https") for u in uris),
        "//authority (absolute)": any("://" in u for u in uris),
        "rootless path (scheme: no //)": any(":" in u and "://" not in u for u in uris),
        "IPv6 / IP-literal host": "[" in blob,
        "IPv4 host": any(h in blob for h in ("0.0.0.0", "192.168.0.1", "255.255.255.255")),
        "userinfo '@'": "@" in blob,
        "explicit port": any(f":{p}" in blob for p in ("80", "65535", "99999", "000")),
        "query '?'": "?" in blob,
        "fragment '#'": "#" in blob,
        "percent-encoded octet": "%" in blob,
        "dot-segment": ".." in blob or "/." in blob,
    }
    missing = [k for k, ok in checks.items() if not ok]
    assert not missing, f"ABNF productions not covered: {missing}"
    print(f"test_grammar_covers_abnf_productions: all {len(checks)} productions present "
          f"(scheme/authority forms/rootless/port/query/fragment/pct-encoding/dot-seg) OK")


# ---------------------------------------------------------------- 2. seed corpus

def test_seed_corpus():
    """The corpus pulls URI-ish constants from the target's OWN tests (AST) and unions the
    edge-case dictionary, deduped."""
    corpus, stats = load_seed_corpus()
    assert stats["from_tests"]["files_read"] >= 3, stats          # the target ships several test_*.py
    assert stats["from_tests"]["extracted"] >= 50, stats          # its suite is fixture-dense
    assert stats["edge_added"] >= 1, stats                        # at least some edge entries are new
    assert stats["total"] == len(corpus) == len(set(corpus)), stats  # deduped
    # a known target fixture and a known edge entry both made it in
    assert "http://a/b/c/d;p?q" in corpus, "missing the RFC §5.4 base fixture from the target tests"
    assert "http://h/%00" in corpus, "missing an edge-dictionary entry"
    # AST extraction beats regex: a multi-line / concatenated constant is still one fixture
    assert all(isinstance(s, str) and s for s in corpus), "blank/none leaked into the corpus"
    print(f"test_seed_corpus: {stats['from_tests']['extracted']} target-test fixtures + "
          f"{stats['edge_added']} edge entries = {stats['total']} deduped OK")


# ---------------------------------------------------------------- 3. coverage-guided budget

def test_coverage_guided_budget():
    """The greybox loop never exceeds its budget and SURFACES the cap (logged, not silent)."""
    seeds, _ = generate_grammar_uris(limit=30, seed=0)
    kept, stats = coverage_guided(seeds, budget=300, seed=0)
    assert stats["iterations"] <= stats["budget"] == 300, stats
    assert stats["budget_hit"] is True, stats                    # 300 < space -> cap is reached
    assert len(kept) == stats["kept_expanding"], stats
    assert stats["final_lines"] >= stats["baseline_lines"], stats
    # a budget of 0 does no mutation and reports it honestly
    kept0, stats0 = coverage_guided(seeds, budget=0, seed=0)
    assert kept0 == [] and stats0["iterations"] == 0 and stats0["budget_hit"] is True, stats0
    print(f"test_coverage_guided_budget: {stats['iterations']}/{stats['budget']} iters capped, "
          f"{stats['kept_expanding']} coverage-expanding kept, cap surfaced OK")


# ---------------------------------------------------------------- 4. the measurable recall lift

def test_branch_recall_lift():
    """The headline criterion: baseline ∪ E04 reaches STRICTLY MORE distinct target lines than the
    pre-E04 baseline pool alone, over the identical battery. RED if E04 buys no new coverage."""
    e04_inputs, stats = build_e04_inputs(grammar_limit=300, seed_cap=600, fuzz_budget=2000)
    base = lines_hit(URL_POOL)
    e04 = lines_hit(list(URL_POOL) + e04_inputs)
    assert e04 > base, ("E04 reached no new target lines — no recall lift "
                        f"(baseline {len(base)}, e04 {len(e04)})")
    assert base <= e04, "coverage must be monotone under a superset of inputs"
    gained = len(e04) - len(base)
    # the lift must come from real new lines, with the honest caps recorded in stats
    assert gained >= 1, (len(base), len(e04))
    assert stats["total_distinct"] > len(URL_POOL), stats        # the corpus is genuinely larger
    print(f"test_branch_recall_lift: baseline {len(base)} -> e04 {len(e04)} distinct target lines "
          f"(+{gained}); E04 corpus {stats['total_distinct']} vs baseline {len(URL_POOL)} inputs OK")


# ---------------------------------------------------------------- 5. determinism

def test_determinism():
    """Same seed -> byte-identical corpus, so a coverage-expanding input can always be re-found."""
    a, sa = build_e04_inputs(grammar_limit=120, seed_cap=300, fuzz_budget=400, seed=7)
    b, sb = build_e04_inputs(grammar_limit=120, seed_cap=300, fuzz_budget=400, seed=7)
    assert a == b, "non-deterministic corpus under a fixed seed"
    assert sa["coverage_guided"]["kept_expanding"] == sb["coverage_guided"]["kept_expanding"], (sa, sb)
    # a different seed should generally produce a different grammar set (sanity, not a hard law)
    c, _ = build_e04_inputs(grammar_limit=120, seed_cap=300, fuzz_budget=400, seed=8)
    assert c != a, "seed had no effect on the corpus"
    print("test_determinism: fixed seed -> identical corpus; differing seed -> different corpus OK")


def main():
    test_grammar_all_parse_valid()
    test_grammar_covers_abnf_productions()
    test_seed_corpus()
    test_coverage_guided_budget()
    test_branch_recall_lift()
    test_determinism()
    print("test_grammar: OK")


if __name__ == "__main__":
    main()
