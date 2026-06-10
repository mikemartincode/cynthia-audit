#!/usr/bin/env python3
"""Independent spec oracle for semver comparison — derived from semver.org §11, NOT
from the python-semver source. compare_ref is the mutation target; EXPECTED is a
hand-reasoned, spec-derived answer key (independent of compare_ref) so the oracle
isn't circular.
"""

from __future__ import annotations

from collections.abc import Callable


def compare_ref(pair: tuple) -> int:
    """Compare two semver strings per semver.org §11. Returns -1/0/1. Takes a single
    (a, b) pair so it fits the gate's single-argument probe contract. Self-contained
    (builtins only) so a mutant of it runs standalone in the gate's subprocess."""
    a, b = pair

    def parse(s):
        plus = s.find("+")
        if plus != -1:
            s = s[:plus]  # build metadata is ignored for precedence (§10)
        dash = s.find("-")
        if dash != -1:
            core, pre = s[:dash], s[dash + 1:]
        else:
            core, pre = s, None
        major, minor, patch = (int(x) for x in core.split("."))
        ids = pre.split(".") if pre is not None else None
        return major, minor, patch, ids

    am, an, ap, apre = parse(a)
    bm, bn, bp, bpre = parse(b)
    for x, y in ((am, bm), (an, bn), (ap, bp)):
        if x < y:
            return -1
        if x > y:
            return 1
    # a version WITH prerelease has LOWER precedence than the same version without (§11.3)
    if apre is None and bpre is None:
        return 0
    if apre is None:
        return 1
    if bpre is None:
        return -1
    # compare prerelease identifiers left to right (§11.4)
    for x, y in zip(apre, bpre):
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            xi, yi = int(x), int(y)
            if xi < yi:
                return -1
            if xi > yi:
                return 1
        elif xn and not yn:
            return -1  # numeric identifiers always rank lower than alphanumeric (§11.4.3)
        elif yn and not xn:
            return 1
        else:
            if x < y:
                return -1
            if x > y:
                return 1
    # all preceding identifiers equal: more identifiers ranks higher (§11.4.4)
    if len(apre) < len(bpre):
        return -1
    if len(apre) > len(bpre):
        return 1
    return 0


REFERENCE_FUNC = compare_ref
REFERENCE_NAME = "compare_ref"


def EQUIV_KEY(result: int) -> int:
    """A comparator's contract is the SIGN of its result, not the magnitude — `-2` and `-1`
    mean the same ordering. Projecting through this makes the gate's equivalence filter
    correctly drop magnitude-only mutations (`return 1` -> `return 2`) instead of counting
    them as survivors."""
    return (result > 0) - (result < 0)

# Spec-derived answer key — each sign reasoned from semver.org §11 directly, independent
# of compare_ref. This is the oracle's ground truth; the gate mutates compare_ref and
# requires the oracle to kill any mutant that gets one of these wrong.
_PAIRS: list[tuple[str, str, int]] = [
    ("1.0.0", "2.0.0", -1),
    ("2.0.0", "2.1.0", -1),
    ("2.1.0", "2.1.1", -1),
    ("1.0.0", "1.0.0", 0),
    # build metadata ignored (§10)
    ("1.0.0+build.1", "1.0.0+build.2", 0),
    ("1.0.0+a", "1.0.0", 0),
    # prerelease < release (§11.3)
    ("1.0.0-alpha", "1.0.0", -1),
    ("1.0.0", "1.0.0-rc.1", 1),
    # the canonical §11 ordering chain
    ("1.0.0-alpha", "1.0.0-alpha.1", -1),
    ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
    ("1.0.0-alpha.beta", "1.0.0-beta", -1),
    ("1.0.0-beta", "1.0.0-beta.2", -1),
    ("1.0.0-beta.2", "1.0.0-beta.11", -1),  # numeric compare, not lexical (11 > 2)
    ("1.0.0-beta.11", "1.0.0-rc.1", -1),
    # numeric ranks below alphanumeric (§11.4.3)
    ("1.0.0-1", "1.0.0-alpha", -1),
    ("1.0.0-alpha", "1.0.0-1", 1),
    ("1.0.0-1.2", "1.0.0-1.alpha", -1),
    # equal prereleases
    ("1.0.0-alpha.1", "1.0.0-alpha.1", 0),
]
EXPECTED = {(a, b): s for a, b, s in _PAIRS}
# the gate's equivalence filter calls REFERENCE_FUNC(probe) — one arg per probe — so each
# probe is an (a, b) pair. These distinguish a wrong comparator from the reference.
PROBE_INPUTS = [(a, b) for (a, b) in EXPECTED]


def check_impl(fn: Callable[[tuple], int]) -> list[tuple[bool, str]]:
    """Grade an arbitrary comparator against the spec-derived answer key. Compares the
    SIGN of fn((a,b)) to the spec sign, so a comparator returning any negative/positive
    value is fine — only the ordering matters."""
    checks: list[tuple[bool, str]] = []
    for (a, b), want in EXPECTED.items():
        try:
            got = fn((a, b))
            sgn = (got > 0) - (got < 0)
        except Exception as exc:
            checks.append((False, f"compare({a!r},{b!r}) raised {type(exc).__name__}"))
            continue
        checks.append((sgn == want, f"sign(compare({a!r},{b!r}))=={want} (got {sgn})"))
    return checks
