#!/usr/bin/env python3
"""auditor/coverage_exp.py - the shared author+gate engine for the coverage-recall experiment.

The whole experiment reduces to one unit of work, a CELL = (function, strategy, rep): author an
independent reference+battery oracle for `function` using oracle-shape `strategy`, gate it (STRICT,
so both gate-GREEN and strict-GREEN are recorded), and emit one result row. Every phase is a list
of cells over this engine:

  * bake-off  : functions × {value} × 1, per candidate model (attempts=1)        -> bakeoff.py
  * corpus    : basket functions × candidate_strategies × 1                       -> corpus.py
  * held-out  : held-out functions × candidate_strategies × N reps               -> holdout.py

Coverage = gate-GREEN (non-vacuity), NOT correctness (claim boundary). The mutation gate is the ONLY
trust authority - a model only AUTHORS; gate_authored decides. No model ever approves an oracle.

Concurrency mirrors run.py: authoring is I/O-bound (gateway idles minutes) -> asyncio.to_thread under
a semaphore; gating is subprocess-bound -> ProcessPoolExecutor. A HARD budget rail (run.BudgetTracker)
checks spent+reserved+estimate <= cap before every authoring dispatch and stops cleanly when the next
call could cross it (budget exhaustion is graceful degradation, not an error). Each finished cell is
checkpointed ATOMICALLY (temp + os.replace) before the next, so a kill at any instant loses <=1
in-flight cell and a re-run resumes from disk.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import author as author_mod  # noqa: E402
import frontload as fl  # noqa: E402
from author import _safe_leaf  # noqa: E402
from recall_strategy import shape_key as _shape_key  # noqa: E402
from run import BudgetTracker  # noqa: E402 - reuse the proven hard rail


def _atomic_write_json(path: Path, obj) -> None:
    """Write JSON via temp + os.replace (the seer indexer pattern): a reader never sees a partial
    file and a kill mid-write can't corrupt the checkpoint."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp{os.getpid()}")
    tmp.write_text(json.dumps(obj, indent=2) + "\n")
    os.replace(tmp, path)


@dataclass
class Cell:
    repo: str
    entry: dict
    strategy: str
    rep: int = 0

    @property
    def qualname(self) -> str:
        return self.entry["qualname"]

    @property
    def shape_key(self) -> str:
        return _shape_key(self.entry)

    @property
    def cell_id(self) -> str:
        qh = hashlib.sha1(self.qualname.encode()).hexdigest()[:10]
        return f"{_safe_leaf(self.qualname)}_{qh}_{self.strategy}_r{self.rep}"


@dataclass
class CellResult:
    repo: str
    qualname: str
    shape_key: str
    strategy: str
    rep: int
    model: str
    gate_green: bool = False
    strict_green: bool = False
    gate_failed: bool = False  # gate could not render a verdict (timeout/OOM/crash) - NOT a RED oracle
    cost: float = 0.0
    in_tok: int = 0
    out_tok: int = 0
    cache_read: int = 0
    elapsed: float = 0.0
    note: str = ""
    error: str = ""
    oracle_path: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, d: dict) -> "CellResult":
        return cls(**{k: d.get(k, getattr(cls, k, None)) for k in cls.__dataclass_fields__})


# the capped, hard-kill subprocess gate is a shared primitive (gate_subprocess.py) so author.py's
# best-of-N path can use it too without a circular import.
from gate_subprocess import GATE_TIMEOUT_S, _gate_subprocess  # noqa: E402,F401


def _wants_stream(model: str) -> bool:
    """Reasoning models the gateway BUFFERS past the read timeout when non-streamed (minimax-*) MUST
    stream - measured: minimax-m3 non-streamed timed out on ~half of bake-off cells (288s latency vs
    a 300s timeout). DeepSeek streams fine too but is kept NON-streamed so its passive prefix cache
    fires (MiniMax won't read cache on a streamed request; DeepSeek's cache is the cost lever, and
    minimax is free, so streaming costs it nothing)."""
    return model.startswith("minimax")


def _draft_temperature(draft: int) -> float:
    """Draft 0 low-temp (the deterministic best single shot, comparable to the n=1 author); later
    drafts hotter for DIVERSITY so best-of-N actually explores distinct ref+battery readings rather
    than re-sampling the same one."""
    return 0.3 if draft == 0 else 0.7


async def _run_one_cell(cell: Cell, model: str, run_dir: Path, target: str,
                        sem: asyncio.Semaphore, gate_sem: asyncio.Semaphore,
                        budget: BudgetTracker, *, max_tokens: int, gate_cap: int,
                        best_of_n: int = 1, thinking: dict | None = None,
                        front_load: bool = False) -> CellResult | None:
    """Author + gate one cell, BEST-OF-N with early-exit: author up to `best_of_n` independent
    ref+battery drafts (draft 0 cool, rest hot for diversity), gate each, STOP at the first gate-GREEN
    (the gate is the selector - that's the whole thesis). cost/tokens sum the drafts actually spent;
    the recorded verdict is the best draft (first GREEN, else highest (green,strict)). Returns None
    iff the budget stopped this cell before ANY draft. A gateway/author failure on a draft is skipped;
    only if every draft fails to author is it a RED error cell."""
    t0 = time.time()
    res = CellResult(repo=cell.repo, qualname=cell.qualname, shape_key=cell.shape_key,
                     strategy=cell.strategy, rep=cell.rep, model=model)
    bat_model = author_mod._battery_model(model)
    front = fl.frontload_block(cell.entry) if front_load else None
    oracles_dir = run_dir / "oracles" / cell.cell_id
    best = None  # (green, strict, note, module_name) - best REAL verdict only
    authored_any = False
    gate_failed_note = ""  # set if a draft authored but its gate could not render a verdict

    for draft in range(best_of_n):
        async with sem:
            reservation = budget.reserve()
            if reservation is None:
                if draft == 0:
                    return None  # budget wall before any draft - caller logs as dropped
                break  # budget exhausted mid-best-of-N - keep the best draft so far
            oracles_dir.mkdir(parents=True, exist_ok=True)
            r = await asyncio.to_thread(
                author_mod._author_independent, cell.entry, model, bat_model,
                target=target, max_tokens=max_tokens, shape=cell.strategy,
                stream=_wants_stream(model), temperature=_draft_temperature(draft),
                thinking=thinking, front_load=front,
                trace_meta={"repo": cell.repo, "strategy": cell.strategy, "rep": cell.rep,
                            "draft": draft})
        if "error" in r:
            budget.settle(reservation, 0.0)
            res.note = f"author call failed: {r['error']}"
            continue
        budget.settle(reservation, r["cost"])
        authored_any = True
        res.cost += r["cost"]
        res.in_tok += r["in_tok"]
        res.out_tok += r["out_tok"]
        res.cache_read += r.get("cache_read", 0)
        mod = f"orc_{cell.cell_id}_d{draft}"
        (oracles_dir / f"{mod}.py").write_text(r["code"])
        async with gate_sem:  # bound concurrent gates (each spawns a mutant subprocess swarm)
            verdict = await asyncio.to_thread(_gate_subprocess, mod, str(oracles_dir),
                                              gate_cap, cell.qualname)
        if verdict.get("gate_failed"):
            # the gate could not evaluate this draft (timeout/OOM/crash) - that is NOT a verdict,
            # so it must not stand in as a RED "best". Note it and move to the next draft.
            gate_failed_note = verdict.get("note", "gate failed")
            continue
        key = (bool(verdict.get("green")), bool(verdict.get("strict_green")))
        if best is None or key > best[:2]:
            best = (key[0], key[1], verdict.get("note", ""), mod)
            res.oracle_path = str(oracles_dir / f"{mod}.py")
        if key[0]:  # first gate-GREEN - the selector is satisfied, stop drafting
            break

    if not authored_any:
        res.error = res.note or "all best-of-N drafts failed to author"
        res.elapsed = time.time() - t0
        return res
    if best is None:
        # authored, but every draft's gate FAILED to render a verdict - this is a gate failure, NOT a
        # RED oracle. Bucket it as errored (excluded from coverage + recall) rather than miscount it
        # as a non-vacuous-failing oracle.
        res.gate_failed = True
        res.error = f"gate failed: {gate_failed_note}"
        res.elapsed = time.time() - t0
        return res
    res.gate_green, res.strict_green, res.note = best[0], best[1], best[2]
    res.elapsed = time.time() - t0
    return res


def _record_path(records_dir: Path, cell: Cell) -> Path:
    return records_dir / (cell.cell_id + ".json")


async def run_cells(cells: list[Cell], model: str, run_dir: Path, *, target_of: dict,
                    concurrency: int = 24, gate_cap: int = 40, max_tokens: int | None = None,
                    budget_cap: float | None = None, progress_label: str = "cells",
                    best_of_n: int = 1, thinking: dict | None = None,
                    front_load: bool = False) -> dict:
    """Fan author+gate across `cells` with bounded concurrency, a hard budget rail, and atomic
    per-cell checkpointing. `target_of` maps repo -> library name (for the spec text). Resumable:
    cells with an existing record on disk are skipped. Returns a summary dict; per-cell rows live in
    run_dir/records/. The completed-count + last-finish timestamp it writes are the monitor's signal.
    """
    records_dir = run_dir / "records"
    records_dir.mkdir(parents=True, exist_ok=True)
    max_tokens = max_tokens or author_mod.DEFAULT_MAX_TOKENS
    cap = budget_cap if budget_cap is not None else float(os.environ.get("AUDIT_BUDGET_USD", "50"))

    pending = [c for c in cells if not _record_path(records_dir, c).exists()]
    skipped = len(cells) - len(pending)
    budget = BudgetTracker(cap)
    sem = asyncio.Semaphore(concurrency)
    asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=concurrency + 4))
    # gating is subprocess-bound (each gate spawns a mutant-subprocess swarm) - bound it BELOW the
    # box's cores so concurrent gate storms don't oversubscribe. Each gate is hard-kill-timeout'd.
    gate_sem = asyncio.Semaphore(max(2, (os.cpu_count() or 4) - 2))
    done = {"n": 0, "green": 0, "strict": 0, "dropped": 0, "errors": 0}
    t0 = time.time()

    async def one(cell: Cell) -> None:
        try:
            res = await _run_one_cell(cell, model, run_dir, target_of.get(cell.repo, ""),
                                      sem, gate_sem, budget, max_tokens=max_tokens, gate_cap=gate_cap,
                                      best_of_n=best_of_n, thinking=thinking, front_load=front_load)
        except Exception as exc:  # noqa: BLE001 - one cell's surprise must never crash the gather
            res = CellResult(repo=cell.repo, qualname=cell.qualname, shape_key=cell.shape_key,
                             strategy=cell.strategy, rep=cell.rep, model=model,
                             error=f"{type(exc).__name__}: {exc}", note="cell crashed")
        if res is None:
            done["dropped"] += 1
            return
        _atomic_write_json(_record_path(records_dir, cell), res.to_dict())
        done["n"] += 1
        done["green"] += int(res.gate_green)
        done["strict"] += int(res.strict_green)
        done["errors"] += int(bool(res.error))
        # heartbeat for the stalled-progress monitor (completed-count + wall clock)
        _atomic_write_json(run_dir / "heartbeat.json",
                           {"phase": progress_label, "completed": done["n"],
                            "total": len(pending), "green": done["green"],
                            "strict": done["strict"], "dropped": done["dropped"],
                            "errors": done["errors"], "spent": round(budget.spent, 4),
                            "cap": budget.cap, "budget_stopped": budget.stopped,
                            "last_finish": time.time(), "elapsed_s": round(time.time() - t0, 1)})
        print(f"[{progress_label} {done['n']}/{len(pending)}] {cell.repo}:{cell.qualname} "
              f"[{cell.strategy} r{cell.rep}] green={res.gate_green} strict={res.strict_green} "
              f"${res.cost:.4f} | spent ${budget.spent:.2f}/{budget.cap:.0f}", flush=True)

    await asyncio.gather(*(one(c) for c in pending))

    summary = {"phase": progress_label, "model": model, "run_dir": str(run_dir),
               "cells_total": len(cells), "skipped_resumed": skipped, "completed": done["n"],
               "gate_green": done["green"], "strict_green": done["strict"],
               "errors": done["errors"], "dropped_by_budget": done["dropped"],
               "spent_usd": round(budget.spent, 4), "budget_cap_usd": budget.cap,
               "budget_stopped": budget.stopped, "elapsed_s": round(time.time() - t0, 1)}
    _atomic_write_json(run_dir / f"summary_{progress_label}.json", summary)
    return summary


def load_cell_results(run_dir: Path) -> list[CellResult]:
    """Read back every checkpointed cell record (the resumable source of truth)."""
    records_dir = run_dir / "records"
    out: list[CellResult] = []
    if not records_dir.exists():
        return out
    for p in sorted(records_dir.glob("*.json")):
        try:
            out.append(CellResult.from_dict(json.loads(p.read_text())))
        except Exception:  # noqa: BLE001 - a torn file from a hard kill: skip, the cell re-runs
            continue
    return out


def load_manifest_functions(manifest_path: Path, *, include_nondeterministic: bool = True) -> list[dict]:
    """Auditable functions from a manifest: auditability != none, and (unless excluded) including
    deterministic=False ones (which route to the stubbed_seam strategy). 'none'-basis functions are
    honestly out of scope and dropped."""
    manifest = json.loads(manifest_path.read_text())
    funcs = [f for f in manifest["functions"] if f.get("auditability") != "none"]
    if not include_nondeterministic:
        funcs = [f for f in funcs if f.get("deterministic")]
    return funcs
