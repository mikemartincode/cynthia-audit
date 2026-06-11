#!/usr/bin/env python3
"""auditor/triage.py — turn the A04 candidate firehose into a credible findings report.

A04 surfaces every place the real library disagrees with a gate-GREEN oracle. But a
gate-GREEN oracle is non-vacuous, NOT necessarily spec-faithful: a cheap model can author an
oracle that kills mutants yet still encodes a wrong spec interpretation. So most A04
divergences are bad-oracle, not real bugs. This stage separates them, CONSERVATIVELY — a
false "real bug" sent to a maintainer is worse than a miss, so a candidate stays
bad-oracle/spec-ambiguity unless independent cross-checks POSITIVELY side with the oracle.

Four layered checks, cheapest first:

  1. VALIDITY (local). Re-confirm the failing input is spec-valid. If the real code raises a
     ValueError/URLParseError on it, it is an invalid-input artifact, not a divergence.

  2. CROSS-ORACLE VOTE (LLM, one per function). Author a SECOND independent oracle with a
     DIFFERENT model (deepseek-flash vs the deepseek-PRO first oracle) and mutation-gate it.
     For each candidate input, does the second oracle's answer side with the FIRST oracle
     (→ real-bug signal) or with the REAL code (→ bad-oracle)? A second oracle agreeing is
     corroboration. (Cross-family options were tried and rejected: gemini-flash produced
     truncated/prose modules that never gated, expensively; minimax-m3 hung on the large
     authoring prompt.)

  3. SPEC RE-DERIVATION (LLM, shortlist only). For candidates the vote flags as real-bug
     signal, ask deepseek-pro — blind to BOTH oracles and the real code, a different TASK from
     authoring — for the spec-correct answer to the exact input. Matches the oracle → confirms;
     matches real → downgrades.

  4. MINIMAL-IZE (local delta-debug). Shrink the failing input to the smallest that still
     diverges, so a finding is reviewable.

Both independent checks are deepseek-family. The first full run PROVED this matters: two
same-family oracles plus a same-family arbiter agreed on the same wrong spec readings (default
ports, query percent-decoding, rooted semantics) and manufactured 14 false "real-bug"s — a
100% false-positive rate. The honest conclusion is that automated cross-model agreement on a
subtle VALUE is not proof of a bug. So this tool does NOT promote value divergences to
real-bug: strong agreement makes them a HUMAN-REVIEW queue (spec-ambiguity/high). The one
self-evident case it does promote is a library CRASH on a valid input (a refusal to perform a
valid operation, not a contestable value), with corroboration. A07 still requires a human read
before any maintainer contact. "Zero real bugs" is a valid, honest outcome — the tool is a
verifier first, and here it is mostly a bad-oracle detector plus a review-queue builder.

All LLM calls go through the same hard $50 BudgetTracker as A03.

Usage:
    LITELLM_GATEWAY=... LITELLM_KEY=... \
    python auditor/triage.py --candidates results/a03-live/sweep/candidates.json \
        --records results/a03-live --manifest targets/hyperlink/manifest.json \
        --out results/a03-live/triage [--vote-model minimax-m3] [--spec-model minimax-m3] \
        [--shortlist-cap 80] [--limit N]
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import author as author_mod  # noqa: E402
from author import author_and_gate, author_best_of_n, build_prompt, call_model  # noqa: E402
from adapters import ADAPTERS  # noqa: E402
from sweep import _equal, _load_oracle, classify  # noqa: E402
from run import BudgetTracker  # noqa: E402

# Independent-check model selection (empirical, on this repo):
#   - the first oracle (A03) is deepseek-PRO; a deepseek-family vote shares its blind spots and
#     manufactured a 100% false-positive rate of value "real-bug"s (correlated error);
#   - gemini-flash authored truncated/prose modules that never gated, expensively;
#   - minimax-m3 is the only fast CROSS-FAMILY option once you author it right: STREAM it (the
#     non-stream hang was gateway buffering), turn thinking OFF (~15x faster), and run best-of-N
#     so the mutation gate selects a GREEN draft (one think-OFF draft is fragile, P(GREEN of 8)
#     ~= 90%). The blind spec arbiter stays deepseek-PRO (a different TASK/framing); it's
#     same-family as the first oracle, but the CROSS-FAMILY VOTE is what breaks the correlation.
# m3 rate = nominal budget-rail estimate (MiniMax bills credit-weighted); gemini kept for the
# optional --vote-model override.
author_mod.PRICING.setdefault("minimax-m3", (0.30, 1.20))
author_mod.PRICING.setdefault("gemini-flash", (0.30, 2.50))
author_mod.PRICING.setdefault("gemini-pro", (1.25, 10.0))

VOTE_MODEL = "minimax-m3"
SPEC_MODEL = "deepseek-v4-pro"
SHORTLIST_CAP = 80


# ---------------------------------------------------------------- loading

def _reconstruct(input_repr: str):
    """The exact failing value from its stored repr (str/tuple/int/None/bool literals)."""
    return ast.literal_eval(input_repr)


def _first_oracle(records_dir: Path):
    """qualname -> (REFERENCE_FUNC, EQUIV_KEY, oracle_path) for every GREEN A03 oracle."""
    out = {}
    for rp in sorted((records_dir / "records").glob("*.json")):
        rec = json.loads(rp.read_text())
        if not rec.get("green"):
            continue
        m = _load_oracle(rec["oracle_path"])
        out[rec["qualname"]] = (m.REFERENCE_FUNC, getattr(m, "EQUIV_KEY", None),
                                rec["oracle_path"])
    return out


# ---------------------------------------------------------------- delta-debug minimal-ize

def _smaller(x):
    """Yield candidate inputs one structural step smaller than x."""
    if isinstance(x, str):
        for i in range(len(x)):
            yield x[:i] + x[i + 1:]
    elif isinstance(x, tuple):
        for i, e in enumerate(x):
            if isinstance(e, str):
                for s in _smaller(e):
                    yield x[:i] + (s,) + x[i + 1:]


def minimalize(x, still_diverges, max_iters: int = 400):
    """Greedy ddmin-lite: shrink x while the divergence predicate holds."""
    best = x
    iters = 0
    changed = True
    while changed and iters < max_iters:
        changed = False
        for cand in _smaller(best):
            iters += 1
            if iters >= max_iters:
                break
            try:
                if still_diverges(cand):
                    best = cand
                    changed = True
                    break
            except Exception:  # noqa: BLE001 — a shrink that errors just isn't a smaller repro
                continue
    return best


# ---------------------------------------------------------------- the votes

def _answer(fn, x):
    """(ok, value, raised_valueerror). Used to compare what an oracle/impl 'says'."""
    try:
        return (True, fn(x), False)
    except ValueError:
        return (False, None, True)
    except Exception:  # noqa: BLE001
        return (False, None, False)


def cross_oracle_vote(qual, x, real_fn, first_ref, second_ref, key):
    """Does the independent second oracle side with the FIRST oracle or with the REAL code?

    Returns one of: agree_oracle | agree_real | three_way | no_second | inconclusive."""
    if second_ref is None:
        return "no_second"
    r_ok, r_val, _ = _answer(real_fn, x)
    o_ok, o_val, _ = _answer(first_ref, x)
    s_ok, s_val, _ = _answer(second_ref, x)
    if not s_ok:
        return "inconclusive"          # second oracle can't grade this input
    s_eq_o = o_ok and _equal(qual, s_val, o_val, key)
    s_eq_r = r_ok and _equal(qual, s_val, r_val, key)
    if s_eq_o and not s_eq_r:
        return "agree_oracle"          # two independent oracles agree, real differs → real-bug signal
    if s_eq_r and not s_eq_o:
        return "agree_real"            # second sides with real → first oracle was wrong
    if s_eq_o and s_eq_r:
        return "inconclusive"          # real == oracle here (no divergence on this exact value)
    return "three_way"                 # three different answers → spec-ambiguity


def _strip_think(text: str) -> str:
    """Drop <think>…</think> reasoning blocks (minimax-m3 emits them, sometimes unclosed) so
    only the model's final answer is parsed."""
    import re
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S | re.I)
    text = re.sub(r"^.*?</think>", "", text, flags=re.S | re.I)  # unclosed leading think
    return text


_SPEC_SYS = ("You are a specification analyst. Given a behavior spec and one input, state the "
             "single correct OUTPUT strictly from the spec. Do not guess at any library's "
             "implementation. Output ONLY one Python literal (the return value) on a single "
             "line, or exactly INVALID if the spec says the input must be rejected.")


def spec_rederive(entry, x, model, budget, lock):
    """Ask a blind model for the spec-correct output of the exact input. Budget-gated.
    Returns (parsed_value, raised_invalid, raw, cost) or (None, None, None, 0.0) on skip."""
    with lock:
        reservation = budget.reserve()
    if reservation is None:
        return (None, None, "budget-stop", 0.0)
    spec, _contract = build_prompt(entry)
    user = (f"{spec}\nThe function receives this single argument (Python repr):\n  {x!r}\n\n"
            "What is the spec-correct return value? One Python literal, or INVALID.")
    try:
        # reasoning models (minimax-m3) interleave <think>; budget enough tokens for the
        # reasoning AND the final one-line answer, then strip the think block before parsing.
        r = call_model(model, _SPEC_SYS, user, max_tokens=8000, timeout=180)
    except Exception as exc:  # noqa: BLE001
        with lock:
            budget.settle(reservation, 0.0)
        return (None, None, f"error: {type(exc).__name__}: {exc}", 0.0)
    with lock:
        budget.settle(reservation, r["cost"])
    raw = _strip_think(r["raw"] or "").strip()
    last = raw.splitlines()[-1].strip() if raw else ""
    if last.upper() == "INVALID" or raw.upper().endswith("INVALID"):
        return (None, True, raw, r["cost"])
    for cand in (last, raw):
        try:
            return (ast.literal_eval(cand), False, raw, r["cost"])
        except Exception:  # noqa: BLE001
            continue
    return (None, None, raw, r["cost"])  # unparseable → inconclusive


# ---------------------------------------------------------------- classification

def _is_crash_divergence(cand: dict) -> bool:
    """real raised a NON-ValueError inside the library (e.g. NotImplementedError) where the
    oracle produced a value — the library refusing a spec-valid operation."""
    return (cand["classification"] == "divergence"
            and cand["real_result"].startswith("RAISED")
            and "library raised" in cand.get("note", ""))


def classify_candidate(cand, *, valid, vote, spec_match):
    """Conservative final label + confidence.

    Hard lesson from the first all-deepseek run: two same-family oracles plus a same-family
    arbiter AGREE on the same wrong spec reading (default ports, query decoding, rooted
    semantics), manufacturing false "real-bug"s at a 100% rate. So automated agreement on a
    subtle VALUE is NOT proof of a bug — adjudicating URL semantics against the RFC needs a
    human. Therefore:
      * a VALUE divergence is NEVER auto-promoted to real-bug. Strong cross-check agreement with
        the oracle makes it a HIGH-priority human-review item (spec-ambiguity/high), not a bug.
      * a library CRASH (NotImplementedError etc. on a valid input) is the one self-evident
        case — a refusal to perform a valid operation, not a contestable value — so it promotes
        to real-bug with >=1 independent corroboration.
    bad-oracle requires positive REAL-side support; everything else is conservative default.

    spec_match ∈ {oracle, real, other, invalid, skipped}."""
    if cand["classification"] == "invalid-input" or not valid:
        return "invalid-input", "high"

    crash = _is_crash_divergence(cand)
    o_vote, o_spec = vote == "agree_oracle", spec_match == "oracle"
    r_vote, r_spec = vote == "agree_real", spec_match == "real"
    oracle_support = o_vote or o_spec
    real_support = r_vote or r_spec

    # real-side evidence dominates → the first oracle was wrong.
    if real_support and not oracle_support:
        return "bad-oracle", ("high" if (r_vote and r_spec) else "medium")
    # the ONLY automated real-bug: a library crash on a valid input, with corroboration that
    # the operation is valid (a crash leaves no value, so real_support is never set here).
    if crash:
        if oracle_support:
            return "real-bug", ("high" if (o_vote and o_spec) else "medium")
        return "spec-ambiguity", "low"  # uncorroborated crash: suspicious but unconfirmed
    # a value divergence: never a bug claim. Cross-check agreement → human-review priority.
    if o_vote and o_spec:
        return "spec-ambiguity", "high"
    if oracle_support or vote == "three_way" or spec_match == "other":
        return "spec-ambiguity", "medium"
    return "bad-oracle", "low"          # conservative default: unconfirmed divergence


# ---------------------------------------------------------------- driver

def run_triage(candidates_path: Path, records_dir: Path, manifest_path: Path, out_dir: Path,
               *, vote_model=VOTE_MODEL, spec_model=SPEC_MODEL, shortlist_cap=SHORTLIST_CAP,
               limit=0, authors_workers=4, spec_workers=8) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    cands = json.loads(candidates_path.read_text())
    if limit:
        cands = cands[:limit]
    manifest = json.loads(manifest_path.read_text())
    by_qual = {f["qualname"]: f for f in manifest["functions"]}
    target = manifest.get("target", "")
    first = _first_oracle(records_dir)
    budget = BudgetTracker(float(os.environ.get("AUDIT_BUDGET_USD", "50")))
    lock = threading.Lock()

    quals = sorted({c["qualname"] for c in cands})

    # PHASE 1 — author one independent CROSS-FAMILY second oracle per function, gated GREEN.
    # Reasoning models (minimax) author via best-of-N think-OFF (fast + gate-selected); a
    # plain coder (deepseek-flash) uses the retry-on-RED path.
    is_reasoning_vote = vote_model.startswith("minimax")
    second_dir = out_dir / "second_oracles"
    second_refs: dict[str, object] = {}
    second_meta: dict[str, dict] = {}

    def author_second(qual):
        entry = by_qual.get(qual)
        if entry is None:
            return qual, None, {"note": "not in manifest"}
        with lock:
            reservation = budget.reserve()
        if reservation is None:
            return qual, None, {"note": "budget-stop"}
        if is_reasoning_vote:
            rec = author_best_of_n(entry, vote_model, second_dir, target=target)
        else:
            rec = author_and_gate(entry, vote_model, second_dir, attempts=2, target=target)
        with lock:
            budget.settle(reservation, rec.cost)  # swap the estimate for the real cost
        meta = {"green": rec.green, "kill_rate": rec.gate.get("kill_rate"),
                "cost": round(rec.cost, 6), "oracle_path": rec.oracle_path,
                "drafts": rec.attempts}
        ref = None
        if rec.green:
            try:
                ref = _load_oracle(rec.oracle_path).REFERENCE_FUNC
            except Exception as exc:  # noqa: BLE001
                meta["note"] = f"load failed: {exc}"
        return qual, ref, meta

    t0 = time.time()
    # best-of-N already fans 8 HTTP + 4 gates PER function internally; keep the OUTER pool small
    # for the reasoning path so concurrent mutant-subprocess gates don't oversubscribe the box.
    phase1_workers = 2 if is_reasoning_vote else authors_workers
    with ThreadPoolExecutor(max_workers=phase1_workers) as pool:
        for qual, ref, meta in pool.map(author_second, quals):
            second_refs[qual] = ref
            second_meta[qual] = meta
    n_green = sum(1 for m in second_meta.values() if m.get("green"))
    print(f"[phase1] authored {len(quals)} independent {vote_model} oracles: "
          f"{n_green} GREEN | spent ${budget.spent:.3f}", flush=True)

    # PHASE 2 — per-candidate: validity, cross-oracle vote, build the re-derivation shortlist.
    enriched = []
    for c in cands:
        qual = c["qualname"]
        rec = {**c}
        try:
            x = _reconstruct(c["input"])
            rec["_x"] = x
            rec["_recon"] = True
        except Exception as exc:  # noqa: BLE001
            rec["_recon"] = False
            rec["_recon_err"] = f"{type(exc).__name__}: {exc}"
            enriched.append(rec)
            continue
        adapter = ADAPTERS.get(qual)
        fr = first.get(qual)
        if adapter is None or fr is None:
            rec["_vote"] = "no_second"
            rec["_valid"] = True
            enriched.append(rec)
            continue
        first_ref, key, _ = fr
        # validity: does the real code reject this input as invalid?
        r_ok, _r_val, r_inval = _answer(adapter, x)
        rec["_valid"] = not r_inval
        rec["_vote"] = cross_oracle_vote(qual, x, adapter, first_ref,
                                         second_refs.get(qual), key)
        enriched.append(rec)

    # shortlist for spec re-derivation: real-bug-signal candidates (vote sides with oracle, or
    # a library crash), valid, deduped by (qual, input). Capped so the run terminates cheaply.
    def _short_key(r):
        return (r["qualname"], r["input"])
    shortlist, seen = [], set()
    for r in enriched:
        if not r.get("_recon") or not r.get("_valid"):
            continue
        if r["_vote"] == "agree_oracle" or _is_crash_divergence(r):
            k = _short_key(r)
            if k in seen:
                continue
            seen.add(k)
            shortlist.append(r)
    short_capped = len(shortlist) > shortlist_cap
    shortlist = shortlist[:shortlist_cap]
    print(f"[phase2] {len(enriched)} candidates voted | re-derivation shortlist "
          f"{len(shortlist)}" + (" (CAPPED)" if short_capped else ""), flush=True)

    # PHASE 3 — blind spec re-derivation on the shortlist (parallel, budget-gated).
    spec_result: dict[tuple, dict] = {}

    def rederive(r):
        qual = r["qualname"]
        entry = by_qual.get(qual)
        x = r["_x"]
        val, inval, raw, cost = spec_rederive(entry, x, spec_model, budget, lock)
        first_ref, key, _ = first[qual]
        adapter = ADAPTERS[qual]
        ro_ok, ro_val, _ = _answer(first_ref, x)
        rr_ok, rr_val, _ = _answer(adapter, x)
        if raw in ("budget-stop", None) or (val is None and not inval):
            match = "skipped"
        elif inval:
            match = "real" if not rr_ok else "other"   # spec says invalid; real that returns is wrong
        elif ro_ok and _equal(qual, val, ro_val, key):
            match = "oracle"
        elif rr_ok and _equal(qual, val, rr_val, key):
            match = "real"
        else:
            match = "other"
        return _short_key(r), {"match": match, "answer": repr(val) if val is not None else None,
                               "invalid": inval, "raw": (raw or "")[:300]}

    if shortlist:
        with ThreadPoolExecutor(max_workers=spec_workers) as pool:
            for k, res in pool.map(rederive, shortlist):
                spec_result[k] = res
    print(f"[phase3] spec re-derivation done on {len(spec_result)} inputs | "
          f"spent ${budget.spent:.3f}", flush=True)

    # PHASE 4 — classify every candidate + minimal-ize (local).
    findings = []
    counts = {"real-bug": 0, "bad-oracle": 0, "invalid-input": 0, "spec-ambiguity": 0}
    for r in enriched:
        qual = r["qualname"]
        sk = _short_key(r)
        spec = spec_result.get(sk, {})
        spec_match = spec.get("match", "skipped")
        vote = r.get("_vote", "no_second")
        valid = r.get("_valid", True)
        cls, conf = classify_candidate(r, valid=valid, vote=vote, spec_match=spec_match)
        counts[cls] += 1

        minimal = r["input"]
        real_disp, oracle_disp = r["real_result"], r["oracle_expected"]
        if r.get("_recon") and qual in first and ADAPTERS.get(qual) is not None and cls != "invalid-input":
            first_ref, key, _ = first[qual]
            adapter = ADAPTERS[qual]
            want_crash = _is_crash_divergence(r)

            def diverges(cand, _a=adapter, _f=first_ref, _k=key, _q=qual, _crash=want_crash):
                # preserve the SAME divergence signature — a crash candidate's minimal must
                # still be a crash, not some unrelated value disagreement it wandered into.
                c = classify(_q, cand, _a, _f, _k)
                if not c or c["classification"] != "divergence":
                    return False
                is_crash = c["real_result"].startswith("RAISED") and "library raised" in c.get("note", "")
                return is_crash == _crash
            try:
                min_obj = minimalize(r["_x"], diverges)
                minimal = repr(min_obj)
                # recompute the displayed real/oracle ON the minimal input so the finding is
                # self-consistent (input, real_result, oracle_expected all describe one value).
                mc = classify(qual, min_obj, adapter, first_ref, key)
                if mc:
                    real_disp, oracle_disp = mc["real_result"], mc["oracle_expected"]
            except Exception:  # noqa: BLE001
                minimal = r["input"]

        findings.append({
            "qualname": qual,
            "minimal_input": minimal,
            "original_input": r["input"],
            "source": r.get("source"),
            "classification": cls,
            "confidence": conf,
            "real_result": real_disp,
            "oracle_expected": oracle_disp,
            "evidence": {
                "valid_input": valid,
                "a04_classification": r["classification"],
                "cross_oracle_vote": vote,
                "second_oracle_green": bool(second_meta.get(qual, {}).get("green")),
                "spec_rederivation": spec_match,
                "spec_answer": spec.get("answer"),
                "is_crash_divergence": _is_crash_divergence(r),
                "note": r.get("note", ""),
            },
        })

    # dedupe findings by (qual, minimal_input, classification); keep the highest confidence.
    _rank = {"high": 3, "medium": 2, "low": 1}
    best: dict[tuple, dict] = {}
    for f in findings:
        k = (f["qualname"], f["minimal_input"], f["classification"])
        if k not in best or _rank[f["confidence"]] > _rank[best[k]["confidence"]]:
            best[k] = f
    deduped = sorted(best.values(),
                     key=lambda f: (-_rank[f["confidence"]], f["qualname"]))

    real_bugs = [f for f in deduped if f["classification"] == "real-bug"]
    real_bugs.sort(key=lambda f: -_rank[f["confidence"]])
    # value divergences where both independent checks side with the oracle: not bug claims,
    # but the highest-value inputs for a human to adjudicate against the RFC.
    review_queue = [f for f in deduped
                    if f["classification"] == "spec-ambiguity" and f["confidence"] == "high"]
    review_queue.sort(key=lambda f: f["qualname"])

    summary = {
        "candidates_in": len(cands),
        "reconstruct_failures": sum(1 for r in enriched if not r.get("_recon")),
        "functions": len(quals),
        "second_oracles_green": n_green,
        "per_candidate_counts": counts,
        "findings_deduped": len(deduped),
        "real_bug_findings": len(real_bugs),
        "real_bug_by_confidence": {c: sum(1 for f in real_bugs if f["confidence"] == c)
                                   for c in ("high", "medium", "low")},
        "human_review_queue": len(review_queue),
        "shortlist_size": len(shortlist),
        "shortlist_capped": short_capped,
        "spent_usd": round(budget.spent, 4),
        "budget_cap_usd": budget.cap,
        "budget_stopped": budget.stopped,
        "vote_model": vote_model,
        "spec_model": spec_model,
        "elapsed_s": round(time.time() - t0, 1),
    }
    (out_dir / "findings.json").write_text(json.dumps(deduped, indent=2) + "\n")
    (out_dir / "second_oracles.json").write_text(json.dumps(second_meta, indent=2) + "\n")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary, real_bugs, review_queue


def _print_report(summary, real_bugs, review_queue):
    print("\n" + json.dumps(summary, indent=2))
    print(f"\nclassification: {summary['per_candidate_counts']}")
    print(f"deduped findings: {summary['findings_deduped']} | "
          f"real-bug: {summary['real_bug_findings']} {summary['real_bug_by_confidence']} | "
          f"human-review queue (spec-ambiguity/high): {len(review_queue)}")
    if real_bugs:
        print("\nRANKED real-bug findings (library crashes on valid inputs — A07 must verify):")
        for f in real_bugs:
            print(f"  [{f['confidence']:6s}] {f['qualname']}  input={f['minimal_input']}")
            print(f"           real={f['real_result']}  oracle={f['oracle_expected']}")
            ev = f["evidence"]
            print(f"           vote={ev['cross_oracle_vote']} spec={ev['spec_rederivation']}"
                  f" crash={ev['is_crash_divergence']}")
    else:
        print("\n0 real-bug findings — an honest, recorded outcome (the tool is a verifier first).")
    if review_queue:
        print(f"\nHUMAN-REVIEW queue — {len(review_queue)} value divergences where both "
              "independent checks side with the oracle (NOT bug claims; need RFC adjudication):")
        for f in review_queue[:15]:
            print(f"  {f['qualname']}  input={f['minimal_input']}  "
                  f"real={f['real_result']} oracle={f['oracle_expected']}")
        if len(review_queue) > 15:
            print(f"  … and {len(review_queue) - 15} more (see findings.json)")


def main() -> int:
    ap = argparse.ArgumentParser(description="triage A04 candidate divergences into findings")
    ap.add_argument("--candidates", type=Path,
                    default=Path("results/a03-live/sweep/candidates.json"))
    ap.add_argument("--records", type=Path, default=Path("results/a03-live"))
    ap.add_argument("--manifest", type=Path, default=Path("targets/hyperlink/manifest.json"))
    ap.add_argument("--out", type=Path, default=Path("results/a03-live/triage"))
    ap.add_argument("--vote-model", default=VOTE_MODEL)
    ap.add_argument("--spec-model", default=SPEC_MODEL)
    ap.add_argument("--shortlist-cap", type=int, default=SHORTLIST_CAP)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    summary, real_bugs, review_queue = run_triage(
        args.candidates, args.records, args.manifest, args.out,
        vote_model=args.vote_model, spec_model=args.spec_model,
        shortlist_cap=args.shortlist_cap, limit=args.limit)
    _print_report(summary, real_bugs, review_queue)
    if summary["budget_stopped"]:
        print(f"\nBUDGET STOP at ${summary['spent_usd']} of ${summary['budget_cap_usd']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
