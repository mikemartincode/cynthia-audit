#!/usr/bin/env python3
"""auditor/recall_rescue.py - the DECISIVE recall test (Mike's design): does a known-good oracle for a
SIMILAR function rescue a function that FAILED before?

This decouples the *mechanism* (can a worked example lift a failure) from *corpus quality* (does our
sparse corpus happen to hold a good example). We curate a BANK of verified-GREEN oracles, then for each
previously-RED function we inject the best-matched bank oracle (same shape; BEST-SHOT - same-repo
allowed, LOO deliberately dropped, because we're measuring the mechanism's CEILING, not generalization)
and author WITH vs WITHOUT it, same author, paired. The mutation gate is the sole arbiter.

  null result   -> recall is a dead end: even a perfect exemplar doesn't help -> drop the corpus bet.
  rescue lift   -> the mechanism works -> maturing the corpus (free M3 volume) is worth it.
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import glob
import json
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import author as author_mod  # noqa: E402
import coverage_exp as ce  # noqa: E402
from gate_subprocess import _gate_subprocess  # noqa: E402
from recall_strategy import _arity, shape_key as _shape_key, split_oracle  # noqa: E402

# object-typed params have no string/tuple oracle representation -> no headroom; skip them
_OBJ_PARAMS = ("node", "refnode", "stream", "treewalker", "treebuilder", "tree", "walker",
               "doc", "token", "builder", "fp", "file", "input", "iterable", "callbacks")

THINK = {"off": {"type": "disabled"}, "on": None}


def _manifest_index() -> dict:
    idx = {}
    for mp in glob.glob("targets/*/manifest.json"):
        repo = mp.split("/")[1]
        m = json.loads(open(mp).read())
        for f in m["functions"]:
            idx[(repo, f["qualname"])] = (f, m.get("target", repo))
    return idx


def build_bank(db: str) -> dict:
    """shape_key+strategy -> list of {repo, qual, strict, ref, battery} from verified-GREEN oracles,
    split into role halves and ready to inject. strict-greens sort first (highest-quality exemplars)."""
    c = sqlite3.connect(db)
    bank = collections.defaultdict(list)
    rows = c.execute("SELECT shape_key, strategy, repo, qualname, strict_green, oracle_code FROM obs "
                     "WHERE gate_green=1 AND oracle_code IS NOT NULL AND oracle_code<>''").fetchall()
    for sk, st, repo, qual, strict, code in rows:
        ref, bat = split_oracle(code)
        if ref and bat:
            bank[(sk, st)].append({"repo": repo, "qual": qual, "strict": bool(strict),
                                   "ref": ref, "battery": bat})
    for k in bank:
        bank[k].sort(key=lambda e: not e["strict"])  # strict first
    return bank


def failed_functions(db: str) -> set:
    c = sqlite3.connect(db)
    byfn = collections.defaultdict(list)
    for repo, q, g in c.execute("SELECT repo, qualname, gate_green FROM obs"):
        byfn[(repo, q)].append(g)
    return {k for k, v in byfn.items() if not any(v)}


def select_cases(failed_db: str, bank_db: str, idx: dict, limit: int) -> list[dict]:
    """Each case = a previously-RED function (from failed_db) paired with the best-matched bank oracle
    (from bank_db). CROSS-DOMAIN ONLY (exemplar from a DIFFERENT repo) - anti-memorization: a copy then
    reproduces the wrong library's behavior, which the behavioral anti-copy check catches. The model
    must transfer the METHOD, not transplant the answer. Prefer a strict exemplar.

    bank_db != failed_db lets the RED set come from one corpus (e.g. the deepseek baseline's all-RED
    functions) while the exemplars come from another (e.g. the free M3 corpus) - and when the two
    corpora cover disjoint repos, cross-domain is guaranteed by construction."""
    bank = build_bank(bank_db)
    cases = []
    for (repo, qual) in sorted(failed_functions(failed_db)):
        entry_t = idx.get((repo, qual))
        if not entry_t:
            continue
        entry, target = entry_t
        sig = (entry.get("signature", "") or "").lower()
        if _arity(entry.get("signature", "")) > 2 or any(o in sig for o in _OBJ_PARAMS):
            continue  # tractability filter: keep string/tuple-representable, low-arity funcs (headroom)
        sk = _shape_key(entry)
        for strat in ("value", "invariant", "property"):
            pool = [e for e in bank.get((sk, strat), []) if e["repo"] != repo]  # CROSS-DOMAIN
            if pool:
                ex = pool[0]
                cases.append({"repo": repo, "qual": qual, "entry": entry, "target": target,
                              "strategy": strat, "shape_key": sk,
                              "exemplar": {"reference": ex["ref"], "battery": ex["battery"]},
                              "exemplar_ref": ex["ref"],
                              "exemplar_from": f"{ex['repo']}:{ex['qual']}", "exemplar_strict": ex["strict"]})
                break
    return cases[:limit] if limit else cases


_ERR = object()


def inspect_rescue(oracle_path: Path, exemplar_ref: str) -> dict:
    """Post-check a 'rescue' for the two ways it can be fake:

    MEMORIZED - the rescued reference reproduces the (cross-domain) EXEMPLAR's behavior. Agreement is
      counted ONLY over probes where the rescued ref returns a MEANINGFUL (non-error) value; two refs
      that merely raise on the same inputs are NOT a copy (the v1 bug that false-flagged insertBefore).
    DEGENERATE - the rescued ref errors on every probe or returns a single constant: a vacuous 'oracle'
      that gate-greened on trivial structure, not a real test (the OTHER thing insertBefore was).

    A genuine rescue must be neither. Both refs already passed the gate, so in-process exec is safe."""
    try:
        nr, ne = {}, {}
        exec(compile(oracle_path.read_text(), "<rescued>", "exec"), nr)
        exec(compile(exemplar_ref, "<exemplar>", "exec"), ne)
        rf, ef = nr["ref_impl"], ne["ref_impl"]
        probes = list(nr.get("PROBE_INPUTS", []))[:20]
    except Exception as e:  # noqa: BLE001
        return {"checked": False, "note": f"{type(e).__name__}: {e}"}
    if not probes:
        return {"checked": False, "note": "no probes"}

    def call(fn, p):
        try:
            return repr(fn(p))
        except Exception:  # noqa: BLE001
            return _ERR
    r_out = [call(rf, p) for p in probes]
    e_out = [call(ef, p) for p in probes]
    meaningful = [(ro, eo) for ro, eo in zip(r_out, e_out) if ro is not _ERR]
    agree = sum(1 for ro, eo in meaningful if eo is not _ERR and ro == eo)
    agree_frac = round(agree / len(meaningful), 2) if meaningful else 0.0
    distinct = len({ro for ro in r_out if ro is not _ERR})
    return {"checked": True, "agree_frac": agree_frac, "meaningful_probes": len(meaningful),
            "distinct_outputs": distinct,
            "memorized": len(meaningful) >= 3 and agree_frac >= 0.8,  # behaves like the exemplar
            "degenerate": distinct < 2}  # all-error or single-constant => vacuous


async def _author_gate(case: dict, with_ex: bool, rep: int, model: str, thinking, run_dir: Path,
                       *, sem, gate_sem, max_tokens, timeout, gate_cap) -> dict:
    import hashlib
    entry = case["entry"]
    async with sem:
        r = await asyncio.to_thread(
            author_mod._author_independent, entry, model, author_mod._battery_model(model),
            target=case["target"], max_tokens=max_tokens, shape=case["strategy"],
            stream=ce._wants_stream(model), temperature=0.4 if rep else 0.2, thinking=thinking,
            timeout=timeout, exemplar=case["exemplar"] if with_ex else None,
            trace_meta={"case": case["qual"], "with_ex": with_ex, "rep": rep})
    if "error" in r:
        return {"error": r["error"]}
    tag = ("ex" if with_ex else "base") + f"_r{rep}"
    qh = hashlib.sha1(f"{case['repo']}:{case['qual']}".encode()).hexdigest()[:8]
    d = run_dir / "oracles" / f"{author_mod._safe_leaf(case['qual'])}_{qh}_{tag}"
    d.mkdir(parents=True, exist_ok=True)
    mod = f"orc_{tag}"
    path = d / f"{mod}.py"
    path.write_text(r["code"])
    async with gate_sem:
        v = await asyncio.to_thread(_gate_subprocess, mod, str(d), gate_cap, case["qual"])
    return {"green": bool(v.get("green")), "gate_failed": bool(v.get("gate_failed")),
            "out_tok": r["out_tok"], "path": str(path)}


async def run(cases: list[dict], model: str, thinking, run_dir: Path, *, reps: int, concurrency: int,
              max_tokens: int, timeout: int, gate_cap: int, func_concurrency: int = 3) -> dict:
    sem = asyncio.Semaphore(concurrency)
    gate_sem = asyncio.Semaphore(max(2, (os.cpu_count() or 4) - 2))
    # DEPTH-FIRST: cap functions IN FLIGHT so they COMPLETE and records trickle (early-stop yields data),
    # instead of all N progressing in lockstep and finishing only at the very end.
    func_sem = asyncio.Semaphore(func_concurrency)
    (run_dir / "oracles").mkdir(parents=True, exist_ok=True)
    (run_dir / "records").mkdir(parents=True, exist_ok=True)

    def _rec_path(case):
        return run_dir / "records" / f"{author_mod._safe_leaf(case['qual'])}.json"

    async def one(case):
      async with func_sem:  # depth-first gate
        if _rec_path(case).exists():  # RESUME: skip already-finished functions
            try:
                return json.loads(_rec_path(case).read_text())
            except Exception:  # noqa: BLE001
                pass
        async def arm(with_ex):
            res = await asyncio.gather(*[_author_gate(case, with_ex, rep, model, thinking, run_dir,
                                          sem=sem, gate_sem=gate_sem, max_tokens=max_tokens,
                                          timeout=timeout, gate_cap=gate_cap) for rep in range(reps)])
            greens = sum(1 for r in res if r.get("green"))
            return {"green_reps": greens, "covered": greens > 0, "results": res}
        base, ex = await arm(False), await arm(True)
        raw_rescued = ex["covered"] and not base["covered"]
        green_path = next((r["path"] for r in ex["results"] if r.get("green")), None)
        insp = {"checked": False}
        if raw_rescued and green_path:
            insp = await asyncio.to_thread(inspect_rescue, Path(green_path), case["exemplar_ref"])
        memorized, degenerate = insp.get("memorized", False), insp.get("degenerate", False)
        genuine = raw_rescued and not memorized and not degenerate
        rec = {**{k: case[k] for k in ("repo", "qual", "strategy", "shape_key", "exemplar_from", "exemplar_strict")},
               "base": base, "exemplar": ex, "raw_rescued": raw_rescued, "inspect": insp,
               "memorized": memorized, "degenerate": degenerate, "genuine_rescue": genuine,
               "broke": base["covered"] and not ex["covered"], "rescued_oracle": green_path}
        ce._atomic_write_json(run_dir / "records" / f"{author_mod._safe_leaf(case['qual'])}.json", rec)
        flag = ("GENUINE-RESCUE" if genuine else "MEMORIZED" if memorized else
                "DEGENERATE" if degenerate else "broke" if rec["broke"] else "")
        print(f"[{case['repo']}:{case['qual']}] base={base['green_reps']}/{reps} ex={ex['green_reps']}/{reps} "
              f"{flag} (ex<-{case['exemplar_from']}"
              + (f", agree={insp.get('agree_frac')}, distinct={insp.get('distinct_outputs')}"
                 if insp.get("checked") else "") + ")", flush=True)
        return rec

    (run_dir / "records").mkdir(parents=True, exist_ok=True)
    recs = await asyncio.gather(*[one(c) for c in cases])
    raw = [r for r in recs if r["raw_rescued"]]
    genuine = [r for r in recs if r["genuine_rescue"]]
    summary = {"model": model, "thinking": "off" if thinking else "on", "reps": reps, "cases": len(recs),
               "base_covered": sum(r["base"]["covered"] for r in recs),
               "exemplar_covered": sum(r["exemplar"]["covered"] for r in recs),
               "raw_rescues": len(raw),
               "excluded_memorized": sum(r["memorized"] for r in recs),
               "excluded_degenerate": sum(r["degenerate"] for r in recs),
               "GENUINE_rescues": len(genuine), "broke": sum(r["broke"] for r in recs),
               "genuine_fns": [f"{r['repo']}:{r['qual']} <- {r['exemplar_from']} (oracle: {r['rescued_oracle']})"
                               for r in genuine],
               "raw_breakdown": [f"{r['repo']}:{r['qual']} {'GENUINE' if r['genuine_rescue'] else 'MEMORIZED' if r['memorized'] else 'DEGENERATE' if r['degenerate'] else '?'}"
                                 for r in raw]}
    ce._atomic_write_json(run_dir / "summary.json", summary)
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="decisive recall-rescue test (curated bank)")
    ap.add_argument("--db", default="results/corpus/recall.db", help="source of the failed (all-RED) set")
    ap.add_argument("--bank-db", default=None, help="source of green exemplars (default: same as --db)")
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--model", default="minimax-m3")
    ap.add_argument("--thinking", choices=("off", "on"), default="off")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--concurrency", type=int, default=6, help="concurrent author calls (lower = less balloon)")
    ap.add_argument("--func-concurrency", type=int, default=3, help="functions in flight (depth-first)")
    ap.add_argument("--max-tokens", type=int, default=16000)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--gate-cap", type=int, default=40)
    args = ap.parse_args()
    idx = _manifest_index()
    cases = select_cases(args.db, args.bank_db or args.db, idx, args.limit)
    print(f"[recall-rescue] {len(cases)} failed functions paired with bank exemplars | "
          f"model={args.model} think={args.thinking} reps={args.reps}", flush=True)
    summary = asyncio.run(run(cases, args.model, THINK[args.thinking], args.run_dir, reps=args.reps,
                              concurrency=args.concurrency, max_tokens=args.max_tokens,
                              timeout=args.timeout, gate_cap=args.gate_cap,
                              func_concurrency=args.func_concurrency))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
