#!/usr/bin/env python3
"""auditor/corpus.py - build the strategy-recall corpus across the basket, durably.

For every basket repo, author+gate EVERY candidate strategy on EVERY auditable function (TRY-ALL, not
stop-at-first-green) so each strategy's per-shape gate-GREEN rate is observed UNBIASED, then ingest
the rows into the stateless shape->strategy recall store. This is the training data the held-out
Arm3 queries (with the held-out repo excluded).

Durability (handoff §5):
  * a persisted repo QUEUE (queue.json): each repo pending/in_progress/done/failed. On restart any
    in_progress (a repo that died mid-run) -> back to pending.
  * ATOMIC per-cell checkpointing lives in coverage_exp.run_cells (temp+os.replace); a kill loses
    <=1 in-flight cell and a re-run resumes from the per-cell records on disk.
  * budget exhaustion is graceful (cells drop, run continues, every row records which model was live);
    the ONLY alarm is stalled progress (monitor.py reads run_dir/heartbeat.json).
Coverage = gate-GREEN = non-vacuity, NOT correctness. The gate is the only trust authority.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import coverage_exp as ce  # noqa: E402
from recall_strategy import StrategyRecall, candidate_strategies  # noqa: E402


# ---------------------------------------------------------------- the durable repo queue


class RepoQueue:
    """A persisted list of {name, manifest, status}. Atomic writes; in_progress->pending on load."""

    def __init__(self, path: Path):
        self.path = path
        self.repos: list[dict] = []
        if path.exists():
            self.repos = json.loads(path.read_text())["repos"]
            for r in self.repos:  # a repo caught mid-run by a kill -> retry from pending
                if r["status"] == "in_progress":
                    r["status"] = "pending"
            self._flush()

    @classmethod
    def create(cls, path: Path, entries: list[dict]) -> "RepoQueue":
        """entries: [{name, manifest}]. Existing queue is preserved (resume); new repos appended."""
        q = cls(path) if path.exists() else cls.__new__(cls)
        if not path.exists():
            q.path = path
            q.repos = []
        have = {r["name"] for r in q.repos}
        for e in entries:
            if e["name"] not in have:
                q.repos.append({"name": e["name"], "manifest": e["manifest"], "status": "pending"})
        q._flush()
        return q

    def _flush(self) -> None:
        ce._atomic_write_json(self.path, {"repos": self.repos, "updated_ts": time.time()})

    def next_pending(self) -> dict | None:
        for r in self.repos:
            if r["status"] == "pending":
                return r
        return None

    def mark(self, name: str, status: str) -> None:
        for r in self.repos:
            if r["name"] == name:
                r["status"] = status
        self._flush()

    def summary(self) -> dict:
        out: dict[str, int] = {}
        for r in self.repos:
            out[r["status"]] = out.get(r["status"], 0) + 1
        return out


# ---------------------------------------------------------------- per-repo corpus pass


def build_corpus_cells(funcs: list[dict], repo: str) -> list[ce.Cell]:
    """Every (function × candidate-strategy) cell for one repo, 1 rep (try-all)."""
    return [ce.Cell(repo=repo, entry=f, strategy=s, rep=0)
            for f in funcs for s in candidate_strategies(f)]


def _read_oracle_code(r: ce.CellResult) -> str | None:
    """The authored module text for a GREEN cell, read back from the checkpointed oracle file so it
    can serve as an exemplar (#1). Only GREEN cells carry a meaningful oracle (a RED cell's best
    draft is not a model to imitate); a missing/unreadable file degrades to None (recall just has no
    exemplar for that row)."""
    if not r.gate_green or not r.oracle_path:
        return None
    try:
        return Path(r.oracle_path).read_text()
    except OSError:
        return None


def ingest_repo(recall: StrategyRecall, results: list[ce.CellResult], repo: str) -> int:
    """Project this repo's cell results into the recall store (errored cells skipped - a failed
    authoring attempt is not evidence about a strategy's fit). GREEN cells also carry their oracle
    module text (the exemplar payload for augmented-generation recall, #1)."""
    n = 0
    for r in results:
        if r.repo != repo or r.error:
            continue
        recall.record(repo=repo, qualname=r.qualname, shape_key=r.shape_key, strategy=r.strategy,
                      model=r.model, gate_green=r.gate_green, strict_green=r.strict_green, cost=r.cost,
                      oracle_code=_read_oracle_code(r))
        n += 1
    return n


def backfill_oracle_code(recall_db: Path, run_root: Path) -> dict:
    """Re-ingest existing per-repo run records into the recall store, now carrying oracle_code, so a
    corpus built before #1 gains its exemplar payload WITHOUT re-authoring (the GREEN oracle files are
    already on disk). Idempotent: record() is INSERT OR REPLACE on the natural key, so every non-code
    column is rewritten to the same value and only oracle_code is added."""
    recall = StrategyRecall(recall_db)
    out: dict[str, int] = {}
    for repo_dir in sorted(p for p in run_root.iterdir() if p.is_dir()):
        results = ce.load_cell_results(repo_dir)
        if results:
            out[repo_dir.name] = ingest_repo(recall, results, repo_dir.name)
    return out


async def run_corpus(queue_path: Path, run_root: Path, recall_db: Path, model: str, *,
                     concurrency: int = 24, budget_cap: float | None = None,
                     include_nondeterministic: bool = True, func_limit: int = 0,
                     best_of_n: int = 1, thinking: dict | None = None,
                     front_load: bool = False) -> dict:
    queue = RepoQueue(queue_path)
    recall = StrategyRecall(recall_db)
    processed = []
    while True:
        repo = queue.next_pending()
        if repo is None:
            break
        name, manifest_path = repo["name"], Path(repo["manifest"])
        if not manifest_path.exists():
            print(f"[corpus] {name}: manifest missing ({manifest_path}) -> failed", flush=True)
            queue.mark(name, "failed")
            continue
        queue.mark(name, "in_progress")
        funcs = ce.load_manifest_functions(manifest_path,
                                           include_nondeterministic=include_nondeterministic)
        if func_limit:  # cap functions/repo for wall-clock tractability (recall aggregates per shape
            funcs = funcs[:func_limit]  # across repos, so a per-repo cap keeps shape coverage)
        target = json.loads(manifest_path.read_text()).get("target", name)
        cells = build_corpus_cells(funcs, name)
        run_dir = run_root / name
        print(f"[corpus] {name}: {len(funcs)} functions -> {len(cells)} cells", flush=True)
        try:
            summary = await ce.run_cells(cells, model, run_dir, target_of={name: target},
                                         concurrency=concurrency, budget_cap=budget_cap,
                                         progress_label=f"corpus-{name}", best_of_n=best_of_n,
                                         thinking=thinking, front_load=front_load)
            results = ce.load_cell_results(run_dir)
            ingested = ingest_repo(recall, results, name)
            queue.mark(name, "done")
            processed.append({"repo": name, "cells": len(cells), "ingested": ingested, **summary})
            print(f"[corpus] {name}: done, ingested {ingested} rows "
                  f"(gate_green {summary['gate_green']}/{summary['completed']})", flush=True)
        except Exception as exc:  # noqa: BLE001 - one repo erroring must not kill the basket
            queue.mark(name, "failed")
            print(f"[corpus] {name}: FAILED {type(exc).__name__}: {exc}", flush=True)
    report = {"queue": queue.summary(), "processed": processed, "recall_db": str(recall_db),
              "model": model, "generated_ts": time.time()}
    ce._atomic_write_json(run_root / "corpus_report.json", report)
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="build the strategy-recall corpus across the basket")
    ap.add_argument("--queue", type=Path, required=True)
    ap.add_argument("--run-root", type=Path, required=True)
    ap.add_argument("--recall-db", type=Path, required=True)
    ap.add_argument("--model", default="deepseek-v4-pro")
    ap.add_argument("--concurrency", type=int, default=24)
    ap.add_argument("--budget-cap", type=float, default=None)
    ap.add_argument("--func-limit", type=int, default=0, help="cap functions per repo (0 = all)")
    ap.add_argument("--best-of-n", type=int, default=1, help="drafts per cell, gate-selected (diversity)")
    ap.add_argument("--thinking", choices=("off", "on"), default="on",
                    help="reasoning mode (M3: 'off' = fast, robust under concurrency for long runs)")
    ap.add_argument("--front-load", action="store_true",
                    help="inject doctest anchors + edge inputs (MiniMax token/wall lever)")
    ap.add_argument("--create-from", type=Path, default=None,
                    help="JSON [{name, manifest}] to (re)seed the queue before running")
    ap.add_argument("--backfill", action="store_true",
                    help="re-ingest existing run-root records into the recall DB with oracle_code "
                         "(no authoring); for upgrading a pre-#1 corpus to carry exemplars")
    args = ap.parse_args()
    if args.backfill:
        report = backfill_oracle_code(args.recall_db, args.run_root)
        print(json.dumps({"backfilled_rows_by_repo": report}, indent=2))
        return 0
    if args.create_from:
        RepoQueue.create(args.queue, json.loads(args.create_from.read_text()))
    thinking = {"type": "disabled"} if args.thinking == "off" else None
    report = asyncio.run(run_corpus(args.queue, args.run_root, args.recall_db, args.model,
                                    concurrency=args.concurrency, budget_cap=args.budget_cap,
                                    func_limit=args.func_limit, best_of_n=args.best_of_n,
                                    thinking=thinking, front_load=args.front_load))
    print(json.dumps(report["queue"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
