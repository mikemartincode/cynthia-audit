#!/usr/bin/env python3
"""auditor/authored_oracle.py - the LLM-authored-oracle path: does shipped code obey its own docstring?

The thing pre-LLM tools categorically cannot do: read a function's BESPOKE natural-language behavioural
claim and turn it into an executable check. Here the LLM does exactly two load-bearing things, BOTH
gated by execution so the model is never the judge:

  1. AUTHOR a property `prop(f, x) -> (bool, why)` that encodes THIS function's documented behaviour
     (not a generic template - the specific claim in its prose).
  2. AIM adversarial inputs at the function (smart fuzzing - far better than random/grammar).

Execution then DISPOSES - the LLM's property is trusted only if it passes a two-sided gate (the
frontier property_gate discipline), all by running real code:

  * FAITHFUL  - `prop(real_fn, x)` holds on the function's OWN doctest inputs (the maintainer's ground
                truth). A property that contradicts the docs is wrong -> rejected.
  * TEETH     - `prop` KILLS ≥1 mutant of the real function (operator mutants via cynthia_core.mutate).
                A property that passes a wrong implementation is vacuous -> rejected.

Only a FAITHFUL + TEETHED property is trusted. Then it runs on the real function over (doctest +
LLM-adversarial + Unicode-fuzz) inputs. A FALSE there = shipped code that violates its OWN documented
behaviour = a bug candidate -> hand-triage. No false claims: every candidate is gated + recorded.

The LLM is load-bearing (only it can read the prose) AND trustless (execution validates + judges)."""

from __future__ import annotations

import argparse
import ast
import importlib
import inspect
import json
import re
import signal
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import author as author_mod  # noqa: E402
from frontload import doctest_anchors  # noqa: E402
from fuzz_obligations import fuzz_corpus  # noqa: E402

_THINK_OFF = {"type": "disabled"}


# ---------------------------------------------------------------- LLM: author the bespoke property


_PROP_SYSTEM = "You are a precise Python engineer. Output ONLY a Python function definition, no prose, no fences."

_PROP_PROMPT = """\
Write a Python PROPERTY CHECKER for the function below, derived from its DOCUMENTED behaviour.

Signature: {qualname}{signature}
Documentation:
{doc}

Write EXACTLY one function:

    def prop(f, x):
        # f is the function under test; x is one input value.
        # Compute f(x) and return (ok: bool, why: str) for whether f(x) obeys the DOCUMENTED behaviour.
        # Derive the check from the SPEC above - the SPECIFIC claim, not a generic 'not None'.
        # If x is invalid per the spec, return (True, "n/a") - only judge inputs the spec covers.

HARD rules:
- Encode the SPECIFIC documented behaviour (ordering, dedup, bounds, format, round-trip, sentinel,
  error-on-invalid, etc.) - a check that passes almost any function is USELESS.
- Compute the expected result FROM THE SPEC, never by calling f a second way to grade itself.
- `prop` must NOT raise: wrap f(x) in try/except and judge exceptions per the spec.
- stdlib only; return (bool, str). Output ONLY the `def prop(f, x):` body - no prose, no fences.
"""


def author_property(entry: dict, model: str) -> str:
    prompt = _PROP_PROMPT.format(qualname=entry["qualname"], signature=entry.get("signature", ""),
                                 doc=(entry.get("doc") or "").strip()[:1800])
    r = author_mod.call_model(model, _PROP_SYSTEM, prompt, max_tokens=20000, temperature=0.2,
                              stream=model.startswith("minimax"),
                              thinking=_THINK_OFF if model.startswith("minimax") else None)
    return author_mod.extract_code(r["raw"])


_INPUT_SYSTEM = "You are a software tester. Output ONLY a JSON array of input values."

_INPUT_PROMPT = """\
Generate ADVERSARIAL inputs that are most likely to BREAK this function - the edge cases its
documented behaviour is easiest to get wrong on.

Signature: {qualname}{signature}
Documentation:
{doc}

Output ONLY a JSON array of 12-25 input VALUES for the FIRST argument (literals only: strings,
numbers, lists, tuples, booleans, null). Aim at boundaries the spec implies: empties, duplicates,
already-processed input, unicode, very large/small, malformed-but-plausible, the exact edges the
documented behaviour pivots on. JSON array only, no prose."""


def author_adversarial_inputs(entry: dict, model: str) -> list:
    prompt = _INPUT_PROMPT.format(qualname=entry["qualname"], signature=entry.get("signature", ""),
                                  doc=(entry.get("doc") or "").strip()[:1500])
    try:
        r = author_mod.call_model(model, _INPUT_SYSTEM, prompt, max_tokens=4000, temperature=0.5,
                                  stream=model.startswith("minimax"),
                                  thinking=_THINK_OFF if model.startswith("minimax") else None)
        txt = re.sub(r"<think>.*?</think>", "", r["raw"], flags=re.S | re.I)
        m = re.search(r"\[.*\]", txt, re.S)
        return json.loads(m.group(0)) if m else []
    except Exception:  # noqa: BLE001
        return []


# ---------------------------------------------------------------- compile + validate the property (execution)


def compile_prop(prop_src: str):
    ns: dict = {}
    exec(compile(prop_src, "<prop>", "exec"), ns)  # noqa: S102 - sandboxed below by the caller's scope
    fn = ns.get("prop")
    return fn if callable(fn) else None


class _PropTimeout(Exception):
    pass


def _run_prop(prop, f, x, *, timeout_s: float = 4.0) -> tuple[bool | None, str]:
    """(ok, why). None = prop unusable (raised OR timed out). HARD timeout via SIGALRM - authored
    properties run real/mutant code (regex, loops) that can hang or catastrophically backtrack; an
    unbounded in-process run wedges the whole hunt (the gate-must-be-timeout-guarded lesson)."""
    def _alarm(_s, _fr):
        raise _PropTimeout()
    old = signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, timeout_s)
    try:
        res = prop(f, x)
        if isinstance(res, tuple) and len(res) == 2:
            return bool(res[0]), str(res[1])
        return bool(res), ""
    except _PropTimeout:
        return None, f"timeout >{timeout_s}s"
    except Exception as e:  # noqa: BLE001 - a property that crashes is unusable, not a verdict
        return None, f"prop raised {type(e).__name__}: {e}"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def resolve_callable(qualname: str, entry: dict, manifest: dict):
    if "." in qualname:
        return None
    mod_name = re.sub(r"\.py$", "", entry.get("module", "")).replace("/", ".")
    mod_name = re.sub(r"^(.*?\bsrc\.)", "", mod_name)
    for base in [p for p in (manifest.get("package_dir"), manifest.get("repo_path"),
                             f"{manifest.get('repo_path','')}/src") if p]:
        if base not in sys.path:
            sys.path.insert(0, base)
    try:
        return getattr(importlib.import_module(mod_name), qualname, None)
    except Exception:  # noqa: BLE001
        return None


def doctest_inputs(entry: dict) -> list:
    out, seen = [], set()
    for call_src, _ in doctest_anchors(entry.get("doc") or ""):
        try:
            node = ast.parse(call_src.strip(), mode="eval").body
            if isinstance(node, ast.Call) and node.args:
                v = ast.literal_eval(node.args[0])
                if repr(v) not in seen:
                    seen.add(repr(v)); out.append(v)
        except Exception:  # noqa: BLE001
            continue
    return out


def validate(prop, real_fn, doctest_in: list, *, mutant_cap: int = 20) -> dict:
    """The two-sided execution gate. FAITHFUL: prop holds (no error) on every doctest input of the real
    function. TEETH: prop kills >=1 operator-mutant of the real function. Trusted iff both."""
    # FAITHFUL
    if not doctest_in:
        return {"trusted": False, "reason": "no doctest inputs to anchor faithfulness"}
    for x in doctest_in:
        ok, why = _run_prop(prop, real_fn, x)
        if ok is None:
            return {"trusted": False, "reason": f"prop unusable: {why}"}
        if ok is False:
            return {"trusted": False, "reason": f"NOT FAITHFUL: prop fails real fn on documented input {x!r}: {why}"}
    # TEETH - mutate the real function source, the property must kill >=1
    try:
        from cynthia_core.mutate import generate_mutants
        src = inspect.getsource(real_fn)
        import textwrap
        src = textwrap.dedent(src)
        muts = generate_mutants(src, [real_fn.__name__], cap=mutant_cap)
    except Exception as e:  # noqa: BLE001
        return {"trusted": False, "reason": f"could not mutate (likely C/builtin/undecompilable): {type(e).__name__}"}
    killed = 0
    for tag, msrc in muts.items():
        g = dict(getattr(real_fn, "__globals__", {}))
        try:
            exec(compile(msrc, f"<mut {tag}>", "exec"), g)  # noqa: S102
            mfn = g.get(real_fn.__name__)
            if not callable(mfn):
                continue
        except Exception:  # noqa: BLE001 - a mutant that won't compile is trivially "killed"
            killed += 1; continue
        for x in doctest_in:
            ok, _ = _run_prop(prop, mfn, x)
            if ok is False or ok is None:  # mutant fails the property, OR breaks it (hang/crash) = killed
                killed += 1; break
    if killed == 0:
        return {"trusted": False, "reason": f"NO TEETH: prop killed 0/{len(muts)} mutants (vacuous)"}
    return {"trusted": True, "reason": f"faithful on {len(doctest_in)} doctest inputs; killed {killed}/{len(muts)} mutants"}


# ---------------------------------------------------------------- hunt one function


def hunt_function(entry: dict, manifest: dict, models: list[str]) -> dict:
    """Author ONE property per DISTINCT MODEL FAMILY; gate each (faithful+teeth); a violation is reported
    only when a MAJORITY of the TRUSTED properties - from DIFFERENT models - agree on the same input.

    The fix to the broken same-model consensus: same-model K samples share the model's bias, so they
    hallucinate the SAME wrong contract and consensus confirms the false positive (measured: M3 ×3 all
    invented `canonicalize_name strips whitespace`). DIVERSE-model consensus breaks the shared bias - a
    spec hallucination idiosyncratic to one model is outvoted by the others; only a property MULTIPLE
    independent model families agree is violated survives. Need >=2 trusted properties from >=2 models,
    else LOW_CONFIDENCE (refuse to claim)."""
    q = entry["qualname"]
    rec = {"repo": manifest.get("target"), "qualname": q}
    real = resolve_callable(q, entry, manifest)
    if real is None:
        return {**rec, "status": "UNRESOLVABLE"}
    dt = doctest_inputs(entry)
    # PREDICATE GUARD (no LLM): a bool-returning function's correctness needs its documented CONDITION
    # ("True iff X"). Free-form authored properties universally hallucinate "should be True" - a bias
    # shared ACROSS model families, so diverse consensus can't break it (measured: is_normalized_name).
    # Refuse predicates here; they belong to the boolean_iff trusted template, not free-form authoring.
    bool_outs = []
    for x in dt[:6]:
        try:
            bool_outs.append(type(real(x)) is bool)
        except Exception:  # noqa: BLE001
            pass
    if bool_outs and all(bool_outs):
        return {**rec, "status": "LOW_CONFIDENCE", "reason": "bool predicate - refused (needs documented condition, not free-form)"}
    trusted = []  # (prop_callable, prop_src, model)
    val_reasons = []
    for m in models:  # ONE property per distinct model family
        try:
            psrc = author_property(entry, m)
            p = compile_prop(psrc)
        except Exception:  # noqa: BLE001
            continue
        if p is None:
            continue
        v = validate(p, real, dt)
        val_reasons.append(f"{m}: {v['reason']}")
        if v["trusted"]:
            trusted.append((p, psrc, m))
    rec["trusted_props"] = len(trusted)
    rec["trusted_models"] = sorted({t[2] for t in trusted})
    rec["validation"] = val_reasons
    if len({t[2] for t in trusted}) < 2:  # need >=2 DISTINCT model families
        return {**rec, "status": "LOW_CONFIDENCE"}
    # HUNT - wide input set, majority of trusted (cross-model) properties must agree on a violation
    adv = author_adversarial_inputs(entry, models[0])
    str_fuzz = fuzz_corpus([x for x in dt if isinstance(x, str)]) if any(isinstance(x, str) for x in dt) else []
    inputs, seen = [], set()
    for x in list(dt) + list(adv) + list(str_fuzz):
        try:
            k = repr(x)
        except Exception:  # noqa: BLE001
            continue
        if k not in seen:
            seen.add(k); inputs.append(x)
    need = len(trusted) // 2 + 1  # strict majority of trusted (cross-model) properties
    violations = []
    for x in inputs:
        results = [_run_prop(p, real, x) for p, _, _ in trusted]  # one eval per property per input
        flags = [r for r in results if r[0] is False]
        if len(flags) >= need:
            violations.append({"input": repr(x)[:80], "why": flags[0][1][:120],
                               "consensus": f"{len(flags)}/{len(trusted)} models"})
    rec["n_inputs"] = len(inputs)
    rec["status"] = "VIOLATION" if violations else "CONFORMANT"
    if violations:
        rec["violations"] = violations[:8]
        rec["prop_src"] = trusted[0][1]  # representative property (first trusted model)
    return rec


# ---------------------------------------------------------------- driver


def candidates(manifests: list[Path], repos: set | None) -> list[tuple[dict, dict]]:
    out = []
    for mp in manifests:
        if repos and mp.parent.name not in repos:
            continue
        m = json.loads(mp.read_text())
        for f in m["functions"]:
            if f.get("auditability") == "none" or "." in f["qualname"]:
                continue
            if f.get("deterministic") and ">>>" in (f.get("doc") or ""):
                out.append((f, m))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="authored-oracle audit - does shipped code obey its own docstring?")
    ap.add_argument("--targets", default="targets")
    ap.add_argument("--repos", default="packaging,dateutil,idna,more-itertools,markdown-it-py")
    ap.add_argument("--models", default="minimax-m3,deepseek-v4-pro,gemini-flash",
                    help="DISTINCT model families for diverse-consensus (breaks shared-bias hallucination)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default="results/authored_oracle")
    args = ap.parse_args()
    models = [m.strip() for m in args.models.split(",") if m.strip()]
    repos = set(args.repos.split(",")) if args.repos else None
    cands = candidates(sorted(Path(args.targets).glob("*/manifest.json")), repos)
    if args.limit:
        cands = cands[: args.limit]
    outdir = Path(args.out); outdir.mkdir(parents=True, exist_ok=True)
    print(f"[audit] {len(cands)} deterministic+doctested functions | diverse-consensus models={models}", flush=True)
    records, findings = [], []
    counts: dict = {}
    for i, (entry, man) in enumerate(cands, 1):
        try:
            rec = hunt_function(entry, man, models)
        except Exception as e:  # noqa: BLE001
            rec = {"repo": man.get("target"), "qualname": entry["qualname"], "status": "ERROR",
                   "detail": f"{type(e).__name__}: {e}"[:140], "tb": traceback.format_exc()[-400:]}
        records.append(rec)
        counts[rec["status"]] = counts.get(rec["status"], 0) + 1
        flag = ""
        if rec["status"] == "VIOLATION":
            findings.append(rec); flag = f" <<< {len(rec['violations'])} VIOLATION(S)"
        print(f"[{i}/{len(cands)}] {rec['status']:14s} {rec['repo']}:{rec['qualname']}{flag}", flush=True)
        (outdir / "records.json").write_text(json.dumps(records, indent=2, default=str))
    summary = {"evaluated": len(records), "counts": counts,
               "findings": [{"fn": f"{f['repo']}:{f['qualname']}", "violations": f["violations"]} for f in findings]}
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    print("\n=== SUMMARY ===")
    print(json.dumps(counts, indent=2))
    if findings:
        print(f"\n⚠ {len(findings)} function(s) with doc-vs-code VIOLATIONS (triage):")
        for f in findings:
            print(f"  {f['repo']}:{f['qualname']}")
            for v in f["violations"][:4]:
                print(f"      input={v['input'][:56]}  {v['why'][:70]}")
    else:
        print("\nNo doc-vs-code violations on the trusted properties (conformant or untrusted).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
