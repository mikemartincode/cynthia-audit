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
import hashlib
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import author as author_mod  # noqa: E402
from author import (  # noqa: E402
    DEFAULT_BEST_OF_N, _safe_leaf, author_and_gate, author_best_of_n, build_spec, call_model,
    gate_authored,
)
from adapters import ADAPTERS  # noqa: E402
from sweep import _equal, _load_oracle, classify  # noqa: E402
from run import BudgetTracker  # noqa: E402
from spec_vectors import iter_vectors as sv_iter, lookup as sv_lookup  # noqa: E402

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


# ---------------------------------------------------------------- second-oracle salvage

def _meta_settled(meta: dict) -> bool:
    """A persisted second-oracle meta is settled iff it is GREEN or it came from a real
    authoring pass. A salvage-only RED is NOT settled: its drafts were re-gated but the
    adaptive thinking-ON fallback never ran on it — re-persisting it as final would
    permanently suppress the function's cross-oracle vote (the salvage dead-end)."""
    return bool(meta.get("green") or not meta.get("salvaged"))


def _salvage_drafts(qual: str, second_dir: Path):
    """Re-gate already-authored best-of-N drafts from a prior (interrupted) run instead of
    re-authoring — gating is cheap (batched, local), authoring is the slow part. Returns a
    GREEN meta when any draft re-gates GREEN (a settled result), the best RED meta when
    drafts exist but none gate (the caller still owes the adaptive fallback), or None when
    nothing usable is on disk (the caller authors from scratch)."""
    qhash = hashlib.sha1(qual.encode()).hexdigest()[:10]
    base = second_dir / "oracles" / f"{_safe_leaf(qual)}_{qhash}"
    if not base.is_dir():
        return None
    draft_dirs = sorted([d for d in base.glob("n*") if d.is_dir()])
    adaptive = base / "adaptive"
    if adaptive.is_dir():
        draft_dirs.append(adaptive)
    best = None
    for d in draft_dirs:
        mod = f"orc_{qhash}_{d.name}"
        if not (d / f"{mod}.py").exists():
            continue
        try:
            v = gate_authored(mod, d, cap=40)
        except Exception:  # noqa: BLE001
            continue
        op = str(d / f"{mod}.py")
        if v.get("green"):
            return {"green": True, "kill_rate": v.get("kill_rate"), "oracle_path": op,
                    "drafts": "salvaged", "salvaged": True}
        if best is None or (v.get("kill_rate") or 0) > (best.get("kill_rate") or 0):
            best = {"green": False, "kill_rate": v.get("kill_rate"), "oracle_path": op,
                    "drafts": "salvaged", "salvaged": True}
    return best  # None when no usable draft exists — that is NOT a settled RED


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
    spec = build_spec(entry)
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


def _model_family(name: str) -> str:
    """Coarse model family from a model id: deepseek-v4-pro -> deepseek, minimax-m3 -> minimax,
    gemini-flash -> gemini. Family (not exact model) is what determines correlated blind spots."""
    return ((name or "").split("-", 1)[0].lower()) or "unknown"


def spec_vector_check(qual, x, real_fn, key):
    """Compare the REAL library's output for `x` against the spec's OWN canonical vector (RFC 3986
    §5.4 reference-resolution table), when one is published for this input. Ground truth — no
    model. Returns {match: real_wrong|real_matches, expected, citation, real} or None when the
    spec publishes no vector for `x` (the only inputs we can assert a VALUE bug on)."""
    sv = sv_lookup(qual, x)
    if sv is None:
        return None
    r_ok, r_val, _ = _answer(real_fn, x)
    if not r_ok:
        # the library raised on a spec-TABLED (therefore spec-valid) input — it must return the
        # tabled value; a refusal is a divergence from the spec's own example.
        return {"match": "real_wrong", "expected": sv.expected, "citation": sv.citation,
                "real": "RAISED", "input": repr(x)}
    matches = _equal(qual, r_val, sv.expected, key)
    return {"match": ("real_matches" if matches else "real_wrong"),
            "expected": sv.expected, "citation": sv.citation,
            "real": r_val if isinstance(r_val, str) else repr(r_val), "input": repr(x)}


def classify_candidate(cand, *, valid, vote, spec_match, spec_vector=None,
                       first_family=None, vote_family=None, spec_family=None,
                       second_oracle_green=False):
    """Conservative final label + confidence.

    Hard lesson from the first all-deepseek run: two same-family oracles plus a same-family
    arbiter AGREE on the same wrong spec reading (default ports, query decoding, rooted
    semantics), manufacturing false "real-bug"s at a 100% rate. So automated agreement on a
    subtle VALUE is corroboration, NOT proof — adjudicating URL semantics needs ground truth.

    Two ways a VALUE divergence becomes assertable (E03), in order of strength:
      1. GROUND TRUTH (`spec_vector`): the spec's OWN canonical vector (RFC 3986 §5.4 table) pins
         the answer. real ≠ tabled value → real-bug/high; real == tabled value but the oracle
         differed → bad-oracle/high. No model in the loop, so no correlated-error risk.
      2. CROSS-FAMILY MAJORITY: ≥2 independent cross-family ORACLES side with the first oracle AND
         a cross-family blind arbiter agrees — i.e. ≥3 DISTINCT model families agree and none are
         correlated. 2 families alone proved insufficient on this target (the default-port
         review-queue cases where deepseek+minimax share the misreading), so the bar is 3 distinct
         families. real-bug/medium, and A07 still hand-verifies (model agreement, not ground truth).

    A library CRASH (NotImplementedError etc. on a valid input) remains the self-evident case — a
    refusal to perform a valid operation — promoting with ≥1 corroboration. Otherwise a value
    divergence with strong agreement is a HIGH-priority human-review item (spec-ambiguity/high),
    never an auto bug claim. bad-oracle needs positive REAL-side support.

    spec_match ∈ {oracle, real, other, invalid, skipped}."""
    if cand["classification"] == "invalid-input" or not valid:
        return "invalid-input", "high"

    # 1. GROUND TRUTH dominates everything — the spec's own published vector, no model involved.
    if spec_vector:
        if spec_vector["match"] == "real_wrong":
            return "real-bug", "high"
        if spec_vector["match"] == "real_matches":
            return "bad-oracle", "high"

    crash = _is_crash_divergence(cand)
    o_vote, o_spec = vote == "agree_oracle", spec_match == "oracle"
    r_vote, r_spec = vote == "agree_real", spec_match == "real"
    oracle_support = o_vote or o_spec
    real_support = r_vote or r_spec

    # real-side evidence dominates → the first oracle was wrong.
    if real_support and not oracle_support:
        return "bad-oracle", ("high" if (r_vote and r_spec) else "medium")
    # a library crash on a valid input, corroborated that the operation is valid (a crash leaves
    # no value, so real_support is never set here).
    if crash:
        if oracle_support:
            return "real-bug", ("high" if (o_vote and o_spec) else "medium")
        return "spec-ambiguity", "low"  # uncorroborated crash: suspicious but unconfirmed
    # 2. CROSS-FAMILY MAJORITY value bug: a 2nd cross-family GREEN oracle AND a cross-family blind
    # arbiter both side with the first oracle → ≥3 distinct families agree, none correlated.
    if o_vote and second_oracle_green and o_spec:
        families = {f for f in (first_family, vote_family, spec_family) if f}
        if len(families) >= 3:
            return "real-bug", "medium"   # model corroboration, not ground truth → A07 verifies
    # a value divergence below the bar: never a bug claim. Strong agreement → human-review.
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
    # the authoring model per GREEN first oracle → its family (for the cross-family majority rule).
    first_family = {}
    for rp in sorted((records_dir / "records").glob("*.json")):
        rec = json.loads(rp.read_text())
        if rec.get("green"):
            first_family[rec["qualname"]] = _model_family(rec.get("model", ""))
    vote_family = _model_family(vote_model)
    spec_family = _model_family(spec_model)
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

    def _meta_path(qual):
        return second_dir / f"_meta_{_safe_leaf(qual)}.json"

    def _ref_from_meta(meta):
        if not (meta.get("green") and meta.get("oracle_path") and Path(meta["oracle_path"]).exists()):
            return None
        try:
            return _load_oracle(meta["oracle_path"]).REFERENCE_FUNC
        except Exception:  # noqa: BLE001 — a stale/broken oracle file is treated as no-second
            return None

    def author_second(qual):
        entry = by_qual.get(qual)
        if entry is None:
            return qual, None, {"note": "not in manifest"}
        # RESUME: a settled meta (GREEN, or RED after a real authoring pass) is never
        # re-spent. A salvage-only RED falls through: its adaptive fallback never ran.
        mp = _meta_path(qual)
        if mp.exists():
            try:
                meta = {**json.loads(mp.read_text()), "resumed": True}
            except Exception:  # noqa: BLE001 — unreadable meta falls through to salvage/author
                meta = None
            if meta is not None and _meta_settled(meta):
                return qual, _ref_from_meta(meta), meta
        # SALVAGE: re-gate drafts left on disk by an interrupted run (gating is cheap,
        # authoring is the slow part). GREEN settles here; RED means the cheap drafts are
        # spent and only the adaptive fallback is still owed; None means nothing usable —
        # author from scratch.
        salv = _salvage_drafts(qual, second_dir)
        if salv is not None and salv.get("green"):
            mp.write_text(json.dumps(salv) + "\n")
            return qual, _ref_from_meta(salv), salv
        with lock:
            reservation = budget.reserve()
        if reservation is None:
            return qual, None, {"note": "budget-stop"}
        if is_reasoning_vote:
            # a salvaged-RED already spent its N fast think-OFF drafts — pay ONLY the
            # thinking-ON adaptive fallback (n=0 authors zero fast drafts).
            n = 0 if salv is not None else DEFAULT_BEST_OF_N
            rec = author_best_of_n(entry, vote_model, second_dir, target=target, n=n)
        else:
            rec = author_and_gate(entry, vote_model, second_dir, attempts=2, target=target)
        with lock:
            budget.settle(reservation, rec.cost)  # swap the estimate for the real cost
        meta = {"green": rec.green, "kill_rate": rec.gate.get("kill_rate"),
                "cost": round(rec.cost, 6), "oracle_path": rec.oracle_path,
                "drafts": rec.attempts}
        if salv is not None:
            meta["salvage_then_fallback"] = True
            if not rec.green and (salv.get("kill_rate") or 0) > (meta["kill_rate"] or 0):
                # keep the strongest oracle on record for inspection (neither is usable
                # for voting — only a GREEN ref is ever loaded).
                meta["kill_rate"], meta["oracle_path"] = salv["kill_rate"], salv["oracle_path"]
        ref = None
        if rec.green:
            try:
                ref = _load_oracle(rec.oracle_path).REFERENCE_FUNC
            except Exception as exc:  # noqa: BLE001
                meta["note"] = f"load failed: {exc}"
        mp.write_text(json.dumps(meta) + "\n")  # persist so a later run resumes, never re-spends
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
        second_green = bool(second_meta.get(qual, {}).get("green"))
        # ground-truth spec vector (RFC §5.4 table) for this exact input, if the spec publishes one
        sv = None
        if r.get("_recon") and ADAPTERS.get(qual) is not None and qual in first:
            sv = spec_vector_check(qual, r["_x"], ADAPTERS[qual], first[qual][1])
        cls, conf = classify_candidate(
            r, valid=valid, vote=vote, spec_match=spec_match, spec_vector=sv,
            first_family=first_family.get(qual), vote_family=vote_family,
            spec_family=spec_family, second_oracle_green=second_green)
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
                "second_oracle_green": second_green,
                "spec_rederivation": spec_match,
                "spec_answer": spec.get("answer"),
                "spec_vector": sv,  # GROUND TRUTH (RFC table) when present; the assertable basis
                "corroborating_families": sorted(
                    {f for f in (first_family.get(qual), vote_family, spec_family) if f}
                    if (vote == "agree_oracle" and second_green and spec_match == "oracle")
                    else []),
                "is_crash_divergence": _is_crash_divergence(r),
                "note": r.get("note", ""),
            },
        })

    # PHASE 5 — SPEC-VECTOR SWEEP (E03). Run the real library directly over the spec's OWN
    # canonical vectors (RFC 3986 §5.4 table) — ground truth, no model, no candidate needed. A
    # divergence here is assertable on the spec's own example. These augment the candidate-derived
    # findings: a real bug whose canonical-input form was never generated still surfaces.
    spec_vector_findings = []
    for qual, x, expected, citation in sv_iter():
        adapter = ADAPTERS.get(qual)
        if adapter is None or qual not in first:
            continue
        chk = spec_vector_check(qual, x, adapter, first[qual][1])
        if chk and chk["match"] == "real_wrong":
            spec_vector_findings.append({
                "qualname": qual, "minimal_input": repr(x), "original_input": repr(x),
                "source": "spec-vector", "classification": "real-bug", "confidence": "high",
                "real_result": chk["real"], "oracle_expected": repr(expected),
                "evidence": {"valid_input": True, "a04_classification": "spec-vector",
                             "spec_vector": chk, "ground_truth": citation,
                             "note": "real library output disagrees with the spec's own "
                                     f"published vector ({citation})"},
            })
    # NOTE: these are NOT A04 candidates, so they do not touch per_candidate_counts; they flow
    # into findings → deduped → real_bugs (and real_bug_by_basis['ground-truth']) on their own.
    findings.extend(spec_vector_findings)

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

    # the honest distinction (E03): ground-truth (spec-vector) and crash bugs are assertable;
    # model-corroborated value bugs are corroboration-not-proof and still need A07 hand-verify.
    def _basis(f):
        ev = f["evidence"]
        if ev.get("spec_vector") and ev["spec_vector"].get("match") == "real_wrong":
            return "ground-truth"
        if ev.get("is_crash_divergence"):
            return "crash"
        return "model-corroborated"
    real_bug_basis = {b: sum(1 for f in real_bugs if _basis(f) == b)
                      for b in ("ground-truth", "crash", "model-corroborated")}

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
        "real_bug_by_basis": real_bug_basis,
        "spec_vector_findings": len(spec_vector_findings),
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
          f"by basis: {summary.get('real_bug_by_basis', {})} | "
          f"spec-vector findings: {summary.get('spec_vector_findings', 0)} | "
          f"human-review queue (spec-ambiguity/high): {len(review_queue)}")
    if real_bugs:
        print("\nRANKED real-bug findings (ground-truth + crash are assertable; "
              "model-corroborated still needs A07 verification):")
        for f in real_bugs:
            ev = f["evidence"]
            sv = ev.get("spec_vector")
            basis = ("ground-truth" if (sv and sv.get("match") == "real_wrong")
                     else "crash" if ev.get("is_crash_divergence") else "model-corroborated")
            print(f"  [{f['confidence']:6s}] [{basis}] {f['qualname']}  "
                  f"input={f['minimal_input']}")
            print(f"           real={f['real_result']}  oracle/spec={f['oracle_expected']}")
            if basis == "ground-truth":
                print(f"           ground truth: {sv['citation']} (no model in the loop)")
            else:
                print(f"           vote={ev.get('cross_oracle_vote')} "
                      f"spec={ev.get('spec_rederivation')} crash={ev.get('is_crash_divergence')}"
                      f" families={ev.get('corroborating_families')}")
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
