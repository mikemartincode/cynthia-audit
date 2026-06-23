#!/usr/bin/env python3
"""auditor/frontload.py — deterministic, SPEC-side data front-loaded into the authoring prompt to cut
the reasoning the model would otherwise spend, WITHOUT coupling the oracle to the implementation.

The reasoning-token cost of authoring an oracle is dominated by two derivations the model does from
scratch every time: (a) WHICH inputs to probe, (b) the EXPECTED output for each. We hand it both —
but only from sources that can't defeat the oracle's purpose:

  * doctest anchors — `>>> f(x)` / `expected` pairs lifted from the DOCSTRING (the spec). These are
    documented behavior, already legitimately part of the prompt; extracting + highlighting them lets
    the battery anchor expected values instead of re-deriving them. (We never feed the library's SOURCE
    or its RUNTIME output — that would make the oracle bless the implementation and kill bug-finding.)
  * type-derived edge inputs — a fixed edge-case set per primitive arg type (empty/space/unicode/long
    for str, 0/±1/large for int, …). These are INPUTS only (no answers), so they carry no implementation
    bias; they just save the model from inventing a probe list and tend to cover regions it misses.

Stdlib only (doctest, ast). Pure function of the manifest entry — no LLM, no network, deterministic.
"""

from __future__ import annotations

import ast
import doctest

# fixed edge-case input pools per primitive type — INPUTS only (never expected values).
_EDGE = {
    "str": ['""', '" "', '"a"', '"A"', '"aB"', '"a.b"', '"a..b"', '"a-_.b"', '"_a_"', '"café"',
            '"日本"', '"a b"', '"123"', '"a1-b2"', '"x" * 200'],
    "int": ["0", "1", "-1", "2", "10", "-100", "2**31"],
    "float": ["0.0", "1.5", "-1.5", "1e9"],
    "bool": ["True", "False"],
}


def doctest_anchors(doc: str) -> list[tuple[str, str]]:
    """(call_source, expected_repr) pairs parsed from the docstring's `>>>` examples. Statements with
    no expected output (imports, assignments) are dropped — only real input→output anchors remain."""
    if not doc:
        return []
    try:
        examples = doctest.DocTestParser().get_examples(doc)
    except ValueError:
        return []
    out = []
    for ex in examples:
        src, want = ex.source.strip(), ex.want.strip()
        if want and "(" in src:  # a call that produced output (skip bare imports/assignments)
            out.append((src, want))
    return out


def _primary_type(signature: str) -> str:
    """The annotation (or a name-heuristic) of the first real positional parameter — the value the
    edge-input pool is chosen for. Falls back to 'str' (the dominant arg type in the corpus)."""
    try:
        node = ast.parse(f"def _f{signature or '()'}: pass").body[0]
    except SyntaxError:
        return "str"
    a = node.args  # type: ignore[attr-defined]
    params = [p for p in (a.posonlyargs + a.args) if p.arg != "self"]
    if not params:
        return "str"
    ann = params[0].annotation
    if ann is not None:
        txt = ast.unparse(ann).lower()
        for t in ("str", "bytes", "bool", "int", "float"):
            if t in txt:
                return "int" if t == "bytes" else t  # treat bytes edges as str-like below
    return "str"


def type_edge_inputs(signature: str, *, limit: int = 12) -> list[str]:
    """Edge-case INPUT exprs for the function's primary arg type (no expected values)."""
    return _EDGE.get(_primary_type(signature), _EDGE["str"])[:limit]


def frontload_block(entry: dict) -> str:
    """The prompt block, or '' if there's nothing useful to front-load. Goes in the DYNAMIC suffix
    (after the spec) so it never disturbs the cacheable static contract prefix."""
    anchors = doctest_anchors(entry.get("doc") or "")
    edges = type_edge_inputs(entry.get("signature", ""))
    if not anchors and not edges:
        return ""
    lines = ["PRE-SUPPLIED TEST DATA (use this to build the battery — you need not re-derive it):"]
    if anchors:
        lines.append("")
        lines.append("VERIFIED EXAMPLES from the documented spec (known-correct input → expected; "
                     "anchor your battery on these exact pairs):")
        for src, want in anchors:
            lines.append(f"  {src}  ==>  {want}")
    if edges:
        lines.append("")
        lines.append("EDGE-CASE INPUTS to cover (compute each expected output FROM THE SPEC; apply the "
                     "calling convention above). Include these and add any the spec implies are tricky:")
        lines.append("  " + ", ".join(edges))
    return "\n".join(lines)
