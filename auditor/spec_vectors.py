#!/usr/bin/env python3
"""auditor/spec_vectors.py — the spec's OWN canonical input→output vectors as GROUND TRUTH.

Triage's hard lesson (A05): a cheap model can author a gate-GREEN oracle that still encodes a
WRONG spec reading, and a second model from the same family shares the misreading — so model
agreement on a subtle VALUE is corroboration, NOT proof (the first all-deepseek run manufactured
a 100% false-positive rate on default-port / normalization semantics). The only thing that makes
a value divergence ASSERTABLE without a human is a source of truth that is NOT a model's guess.

RFC 3986 §5.4 provides exactly that for reference resolution (`URL.click`): a fixed base URL and
a table of relative-reference → resolved-target pairs the RFC itself publishes. Where the target
library's output for a tabled input disagrees with the table, the library is wrong by the spec's
own example — a real bug, anchored to ground truth, no model in the loop. Where it agrees but a
gate-GREEN oracle disagreed, the ORACLE was wrong (bad-oracle, also decided by ground truth).

This is deliberately narrow: vectors exist only where the spec publishes them, and we assert ONLY
on a tabled input. Everything else stays in the conservative model-corroboration path. The base
and tables below are transcribed verbatim from RFC 3986 §5.4.1 (normal) and §5.4.2 (abnormal);
the citation travels with every verdict so a reviewer can check the source line.
"""

from __future__ import annotations

# RFC 3986 §5.4 — the worked reference-resolution example. All targets resolve against this base.
RFC_BASE = "http://a/b/c/d;p?q"

# §5.4.1 Normal Examples — relative ref → resolved target (verbatim from the RFC table).
NORMAL = {
    "g:h": "g:h",
    "g": "http://a/b/c/g",
    "./g": "http://a/b/c/g",
    "g/": "http://a/b/c/g/",
    "/g": "http://a/g",
    "//g": "http://g",
    "?y": "http://a/b/c/d;p?y",
    "g?y": "http://a/b/c/g?y",
    "#s": "http://a/b/c/d;p?q#s",
    "g#s": "http://a/b/c/g#s",
    "g?y#s": "http://a/b/c/g?y#s",
    ";x": "http://a/b/c/;x",
    "g;x": "http://a/b/c/g;x",
    "g;x?y#s": "http://a/b/c/g;x?y#s",
    "": "http://a/b/c/d;p?q",
    ".": "http://a/b/c/",
    "./": "http://a/b/c/",
    "..": "http://a/b/",
    "../": "http://a/b/",
    "../g": "http://a/b/g",
    "../..": "http://a/",
    "../../": "http://a/",
    "../../g": "http://a/g",
}

# §5.4.2 Abnormal Examples — same base, edge relative refs (verbatim from the RFC table).
ABNORMAL = {
    "../../../g": "http://a/g",
    "../../../../g": "http://a/g",
    "/./g": "http://a/g",
    "/../g": "http://a/g",
    "g.": "http://a/b/c/g.",
    ".g": "http://a/b/c/.g",
    "g..": "http://a/b/c/g..",
    "..g": "http://a/b/c/..g",
    "./../g": "http://a/b/g",
    "./g/.": "http://a/b/c/g/",
    "g/./h": "http://a/b/c/g/h",
    "g/../h": "http://a/b/c/h",
    "g;x=1/./y": "http://a/b/c/g;x=1/y",
    "g;x=1/../y": "http://a/b/c/y",
    "g?y/./x": "http://a/b/c/g?y/./x",
    "g?y/../x": "http://a/b/c/g?y/../x",
    "g#s/./x": "http://a/b/c/g#s/./x",
    "g#s/../x": "http://a/b/c/g#s/../x",
}


class SpecVector:
    """A single ground-truth cell: the spec-correct output for a tabled input, plus its citation.
    `__slots__` keeps it a thin value object; the citation is the auditable provenance."""

    __slots__ = ("qualname", "input", "expected", "citation")

    def __init__(self, qualname, input, expected, citation):
        self.qualname = qualname
        self.input = input
        self.expected = expected
        self.citation = citation

    def __repr__(self):
        return f"SpecVector({self.qualname!r}, {self.input!r} -> {self.expected!r} [{self.citation}])"


# qualname -> the resolution table that pins its outputs. `URL.click(base, ref)` is the resolve
# operation; its oracle/adapter convention is the (base, href) tuple (see adapters._click).
_TABLES = {
    "URL.click": [(NORMAL, "RFC 3986 §5.4.1"), (ABNORMAL, "RFC 3986 §5.4.2")],
}


def lookup(qualname: str, x) -> SpecVector | None:
    """Ground-truth cell for input `x` of `qualname`, or None if the spec publishes no vector for
    it. For `URL.click`, `x` is the `(base, ref)` tuple; a vector exists only when the base is the
    RFC's worked base and the ref appears in a published table."""
    tables = _TABLES.get(qualname)
    if not tables:
        return None
    if not (isinstance(x, tuple) and len(x) == 2):
        return None
    base, ref = x
    if base != RFC_BASE:
        return None
    for table, citation in tables:
        if ref in table:
            return SpecVector(qualname, x, table[ref], citation)
    return None


def iter_vectors():
    """Every published vector as (qualname, input_value, expected_output, citation) — the input
    set for a direct ground-truth sweep of the real library (no oracle, no model)."""
    for qualname, tables in _TABLES.items():
        for table, citation in tables:
            for ref, expected in table.items():
                yield (qualname, (RFC_BASE, ref), expected, citation)


def vector_count() -> int:
    return sum(len(t) for tables in _TABLES.values() for t, _ in tables)
