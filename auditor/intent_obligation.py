#!/usr/bin/env python3
"""auditor/intent_obligation.py — the auto-obligation FRONT-END for frontier (the keystone).

Turns a function's natural-language docstring into a *proven* property obligation the frontier
queen can verify — with the LLM never the judge. The queen + gates are built; obligations were
hand-authored (the coverage bottleneck). Here a cheap model (M3) only CLASSIFIES intent into a
TRUSTED, hand-written property template; execution renders every verdict.

TEMPLATE LIBRARY (each a trusted, hand-written-once checker — the LLM never writes checking logic):
  * idempotent   — f(f(x)) == f(x)                 (self-checking, parameter-free)
  * case_lower   — str(f(x)) == str(f(x)).lower()  (output is lowercased; self-checking)
  * inverse      — g(f(x)) == x for a sibling g    (round-trip; needs the pair, M3 names the sibling)

All anchored to the maintainer's OWN doctest inputs, so a confirmation is their ground truth.

Proof obligations, all by EXECUTION:
  1. M3 reads the docstring -> which template(s) apply (+ the sibling, for inverse).
  2. resolve the REAL shipped function from its own vendored repo (doc and code, same commit).
  3. run the trusted checker on the function's OWN doctest inputs.
  4. verdict per (function, property):
       applies & holds on real code -> VERIFIED   (classification confirmed by execution)
       applies & fails              -> VIOLATION  (real bug OR misclass) -> triage
       not applicable               -> (no claim)
  The number that proves the path = VERIFIED / (M3-said-applies, on resolvable+testable).

Folds into cynthia.services.frontier as an obligation source (see to_frontier_node)."""

from __future__ import annotations

import argparse
import ast
import importlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import author as author_mod  # noqa: E402
from frontload import doctest_anchors  # noqa: E402


# ---------------------------------------------------------------- trusted checkers (hand-written ONCE)


def _safe_call(f, x):
    """(ok, value_or_exc). f failing on its own documented input is a finding, not an error to hide."""
    try:
        return True, f(x)
    except Exception as e:  # noqa: BLE001
        return False, e


def check_idempotent(f, inputs, *, sibling=None) -> dict:
    """f(f(x)) == f(x). Type-safe: f not re-applicable => NOT idempotent-shaped (refutes the class)."""
    rows = []
    for x in inputs:
        ok, y1 = _safe_call(f, x)
        if not ok:
            rows.append(("f_raised", x, f"{type(y1).__name__}")); continue
        ok2, y2 = _safe_call(f, y1)
        if not ok2:
            rows.append(("not_reapplicable", x, f"f(f(x)) {type(y2).__name__}")); continue
        rows.append(("holds" if y2 == y1 else "VIOLATED", x,
                     "" if y2 == y1 else f"{repr(y1)[:32]} != {repr(y2)[:32]}"))
    return _tally(rows)


def check_case_lower(f, inputs, *, sibling=None) -> dict:
    """f(x) is lowercased (a casing canonicalizer). GUARD: the property only applies to STRING output —
    if f returns a non-str (e.g. a bool predicate M3 misclassified), it is NOT_APPLICABLE, never a
    VIOLATION. A rigorous system must not emit a false bug claim from a category error."""
    rows = []
    for x in inputs:
        ok, y = _safe_call(f, x)
        if not ok:
            rows.append(("f_raised", x, f"{type(y).__name__}")); continue
        if not isinstance(y, str):
            rows.append(("not_applicable", x, f"output is {type(y).__name__}, not str")); continue
        rows.append(("holds" if y == y.lower() else "VIOLATED", x,
                     "" if y == y.lower() else f"output not lowercased: {y[:32]!r}"))
    return _tally(rows)


def check_inverse(f, inputs, *, sibling=None) -> dict:
    """g(f(x)) == x for the sibling g (round-trip). `sibling` is the resolved callable g."""
    if sibling is None:
        return {"results": [], "n": 0, "n_holds": 0, "n_violated": 0, "n_error": 0,
                "note": "no sibling resolved"}
    rows = []
    for x in inputs:
        ok, y = _safe_call(f, x)
        if not ok:
            rows.append(("f_raised", x, f"f {type(y).__name__}")); continue
        ok2, back = _safe_call(sibling, y)
        if not ok2:
            rows.append(("g_raised", x, f"g {type(back).__name__}")); continue
        rows.append(("holds" if back == x else "VIOLATED", x,
                     "" if back == x else f"g(f(x))={repr(back)[:32]} != x={repr(x)[:32]}"))
    return _tally(rows)


def _tally(rows: list[tuple]) -> dict:
    res = [{"status": s, "input": repr(x)[:50], "detail": d} for s, x, d in rows]
    n_h = sum(1 for s, _, _ in rows if s == "holds")
    n_v = sum(1 for s, _, _ in rows if s == "VIOLATED")
    n_na = sum(1 for s, _, _ in rows if s == "not_applicable")
    return {"results": res, "n": len(rows), "n_holds": n_h, "n_violated": n_v,
            "n_not_applicable": n_na, "n_error": len(rows) - n_h - n_v}


# the trusted template registry: name -> (checker, needs_sibling)
TEMPLATES = {
    "idempotent": (check_idempotent, False),
    "case_lower": (check_case_lower, False),
    "inverse": (check_inverse, True),
}


# ---------------------------------------------------------------- M3 multi-property classification


_CLASSIFY_SYSTEM = "You are a precise software-spec classifier. Output ONLY a JSON object."

_CLASSIFY_PROMPT = """\
Read the function's documented behaviour and decide which of these PROPERTIES it satisfies for valid
inputs. Be strict — a property applies only if the DOCS imply it, and the output can be fed where the
checker needs it.

PROPERTIES:
- "idempotent": applying twice == once, f(f(x))==f(x). TRUE for NORMALIZERS/CANONICALIZERS (same
  input/output domain, re-appliable). FALSE for PARSERS/CONSTRUCTORS (str->object, not re-appliable)
  and for PREDICATES (str->bool).
- "case_lower": the output is lowercased (the function lowercases / casefolds its input).
- "inverse": there is a SIBLING function g (e.g. decode for encode) such that g(f(x))==x (round-trip).
  If so, give the sibling's bare name in "inverse_sibling"; else null.

Function: {qualname}{signature}
Documentation:
{doc}

Output EXACTLY this JSON, nothing else:
{{"properties": [<subset of "idempotent","case_lower","inverse">], "inverse_sibling": "<name>"|null, "reason": "<one sentence>"}}
"""


def classify_properties(entry: dict, model: str = "minimax-m3") -> dict:
    prompt = _CLASSIFY_PROMPT.format(qualname=entry["qualname"], signature=entry.get("signature", ""),
                                     doc=(entry.get("doc") or "").strip()[:1500])
    try:
        r = author_mod.call_model(model, _CLASSIFY_SYSTEM, prompt, max_tokens=2000, temperature=0.0,
                                  stream=model.startswith("minimax"), thinking={"type": "disabled"})
    except Exception as e:  # noqa: BLE001
        return {"properties": [], "inverse_sibling": None, "reason": f"call failed: {e}", "error": True}
    txt = re.sub(r"<think>.*?</think>", "", r.get("raw", ""), flags=re.S | re.I)
    m = re.search(r"\{.*\"properties\".*\}", txt, re.S)
    if not m:
        return {"properties": [], "inverse_sibling": None, "reason": "no JSON", "error": True}
    try:
        d = json.loads(m.group(0))
    except Exception:  # noqa: BLE001
        return {"properties": [], "inverse_sibling": None, "reason": "bad JSON", "error": True}
    props = [p for p in (d.get("properties") or []) if p in TEMPLATES]
    return {"properties": props, "inverse_sibling": d.get("inverse_sibling"),
            "reason": d.get("reason", ""), "error": False}


# ---------------------------------------------------------------- resolve REAL code + doctest inputs


def resolve_callable(qualname: str, entry: dict, manifest: dict):
    """Import the REAL shipped function from its vendored repo. v1: module-level only (no '.')."""
    if "." in qualname:
        return None
    module_rel = entry.get("module", "")
    pkg_dir = manifest.get("package_dir") or manifest.get("repo_path")
    repo_path = manifest.get("repo_path", "")
    mod_name = re.sub(r"\.py$", "", module_rel).replace("/", ".")
    mod_name = re.sub(r"^(.*?\bsrc\.)", "", mod_name)
    for base in [p for p in (pkg_dir, repo_path, f"{repo_path}/src") if p]:
        if base not in sys.path:
            sys.path.insert(0, base)
    try:
        mod = importlib.import_module(mod_name)
        fn = getattr(mod, qualname, None)
        return fn if callable(fn) else None
    except Exception:  # noqa: BLE001
        return None


def resolve_sibling(name: str, entry: dict, manifest: dict):
    """Resolve a sibling g by bare name within the same module (for inverse)."""
    if not name:
        return None
    return resolve_callable(name.split(".")[-1], entry, manifest)


def doctest_inputs(entry: dict) -> list:
    vals = []
    for call_src, _ in doctest_anchors(entry.get("doc") or ""):
        try:
            node = ast.parse(call_src.strip(), mode="eval").body
            if isinstance(node, ast.Call) and node.args:
                vals.append(ast.literal_eval(node.args[0]))
        except Exception:  # noqa: BLE001
            continue
    seen, out = set(), []
    for v in vals:
        if repr(v) not in seen:
            seen.add(repr(v)); out.append(v)
    return out


# ---------------------------------------------------------------- frontier fold (step 2 uses this)


def to_frontier_gate(fn_name: str, prop: str, inputs: list, *, sibling_name: str | None = None) -> str:
    """Emit a frontier-compatible gate_src for a property — assertions that PASS on a fill satisfying
    the property and RED otherwise. This is the auto-derived OBLIGATION expressed as a frontier gate
    (frontier runs `preamble + fill_src + gate_src`). The front-end produces the gate; the queen runs it."""
    lit = repr(list(inputs))
    if prop == "idempotent":
        return (f"for _x in {lit}:\n"
                f"    _a = {fn_name}(_x); _b = {fn_name}(_a)\n"
                f"    assert _b == _a, f'idempotence violated on {{_x!r}}: {{_a!r}} != {{_b!r}}'")
    if prop == "case_lower":
        return (f"for _x in {lit}:\n"
                f"    _y = {fn_name}(_x)\n"
                f"    assert isinstance(_y, str) and _y == _y.lower(), f'not lowercased on {{_x!r}}: {{_y!r}}'")
    if prop == "inverse" and sibling_name:
        return (f"for _x in {lit}:\n"
                f"    assert {sibling_name}({fn_name}(_x)) == _x, f'round-trip failed on {{_x!r}}'")
    raise ValueError(f"no gate template for {prop}")


def to_frontier_node_spec(entry: dict, prop: str, inputs: list, *, sibling_name: str | None = None) -> dict:
    """A frontier-shaped obligation for a verified (function, property): the auto-derived Node the queen
    verifies. `gate_src` is the real frontier gate; `func_names`/`signature`/`obligation` are the node
    metadata. (frontier.models.Node(**{k:...}) is constructed in the fold runner.)"""
    fn = entry["qualname"].split(".")[-1]
    return {"name": f"{fn}__{prop}", "func_names": [fn], "signature": entry.get("signature", ""),
            "obligation": f"property:{prop} (auto-derived from docstring)", "oracle_class": "property",
            "property": prop, "qualname": entry["qualname"],
            "gate_src": to_frontier_gate(fn, prop, inputs, sibling_name=sibling_name)}


# ---------------------------------------------------------------- slice runner


def candidates(manifests: list[Path]) -> list[tuple[dict, dict]]:
    """Functions whose docstring invokes ANY template property AND carry a doctest (noisy pre-filter)."""
    kw = re.compile(r"idempotent|normaliz|canonical|lower.?case|casefold|inverse|round.?trip|decode|encode", re.I)
    out = []
    for mp in manifests:
        m = json.loads(mp.read_text())
        for f in m["functions"]:
            if f.get("auditability") == "none":
                continue
            if kw.search(f.get("doc") or "") and ">>>" in (f.get("doc") or ""):
                out.append((f, m))
    return out


def run_slice(manifests: list[Path], model: str, limit: int) -> dict:
    cands = candidates(manifests)
    records = []
    for entry, manifest in cands[: limit or len(cands)]:
        cls = classify_properties(entry, model)
        base = {"repo": manifest.get("target"), "qualname": entry["qualname"],
                "properties": cls["properties"], "reason": cls["reason"]}
        if not cls["properties"]:
            records.append({**base, "verdict": "REFUSED"}); continue
        f = resolve_callable(entry["qualname"], entry, manifest)
        if f is None:
            records.append({**base, "verdict": "UNRESOLVABLE"}); continue
        inputs = doctest_inputs(entry)
        if not inputs:
            records.append({**base, "verdict": "NO_INPUTS"}); continue
        for prop in cls["properties"]:
            checker, needs_sib = TEMPLATES[prop]
            sib = resolve_sibling(cls.get("inverse_sibling"), entry, manifest) if needs_sib else None
            if needs_sib and sib is None:
                records.append({**base, "property": prop, "verdict": "NO_SIBLING"}); continue
            chk = checker(f, inputs, sibling=sib)
            rec = {**base, "property": prop, "n": chk["n"], "n_holds": chk["n_holds"],
                   "n_violated": chk["n_violated"]}
            if chk["n_violated"] > 0:
                rec["verdict"] = "VIOLATION"
                rec["evidence"] = [r for r in chk["results"] if r["status"] == "VIOLATED"][:3]
            elif chk["n_holds"] > 0:
                rec["verdict"] = "VERIFIED"
            elif chk.get("n_not_applicable", 0) > 0:
                rec["verdict"] = "MISCLASSIFIED"  # M3 applied a property whose type the fn doesn't fit
            else:
                rec["verdict"] = "INCONCLUSIVE"  # all f_raised on the documented inputs
            records.append(rec)

    obl = [r for r in records if r.get("property")]  # one row per (fn, property)
    verified = [r for r in obl if r["verdict"] == "VERIFIED"]
    violations = [r for r in obl if r["verdict"] == "VIOLATION"]
    misclass = [r for r in obl if r["verdict"] == "MISCLASSIFIED"]
    inconclusive = [r for r in obl if r["verdict"] == "INCONCLUSIVE"]
    testable = verified + violations  # M3 applied a property the type fits AND we got real verdicts
    summary = {
        "candidates": len(cands), "rows": len(records),
        "obligations_proposed": len(obl),
        "VERIFIED": len(verified), "VIOLATION": len(violations),
        "MISCLASSIFIED": len(misclass), "INCONCLUSIVE": len(inconclusive),
        "by_property": {p: sum(1 for r in verified if r.get("property") == p) for p in TEMPLATES},
        "verified_over_testable": (round(len(verified) / len(testable), 3) if testable else None),
        "records": records,
    }
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="auto-obligation front-end — template registry")
    ap.add_argument("--targets", default="targets")
    ap.add_argument("--model", default="minimax-m3")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--repos", default="packaging,dateutil,idna")
    args = ap.parse_args()
    manifests = sorted(Path(args.targets).glob("*/manifest.json"))
    if args.repos:
        want = set(args.repos.split(","))
        manifests = [m for m in manifests if m.parent.name in want]
    s = run_slice(manifests, args.model, args.limit)
    print(json.dumps({k: v for k, v in s.items() if k != "records"}, indent=2))
    print("\n--- per (function, property) ---")
    for r in s["records"]:
        tag = f"[{r.get('property','-')}]"
        extra = f"  ({r['n_holds']}/{r['n']} hold)" if r.get("n") is not None else ""
        print(f"  {r['verdict']:13s} {tag:12s} {r['repo']}:{r['qualname']}{extra}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
