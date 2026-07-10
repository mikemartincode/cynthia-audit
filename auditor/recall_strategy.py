#!/usr/bin/env python3
"""auditor/recall_strategy.py - stateless shape->strategy "recall" over the authoring corpus.

What this is (and is NOT):
  * It maps a function's coarse SHAPE to the authoring STRATEGY (oracle shape) with the highest
    gate-GREEN rate, LEARNED across repos, so a retry can try the strategy most likely to work for
    that shape FIRST instead of walking a fixed ladder.
  * It is NOT the cynthia-v3 run-history `recall` service (that keys on env_version + tool-call
    sequences). It is NOT cynthia-audit's E04 "RECALL LIFT" (that measures input-coverage = source
    lines reached, model-free). Different substrate, same English word - kept apart on purpose.

THE LOAD-BEARING PROPERTY - recall is PURE, STATELESS AGGREGATION.
  The recommendation is a pure function of the rows currently present (a `GROUP BY shape_key,
  strategy` over gate verdicts). There is NO fitted, cached, or persisted state derived from the
  corpus. That is exactly what makes the leave-one-out held-out evaluation clean: querying with
  `exclude_repo=R` is byte-identical to physically deleting R's rows and re-querying (test_recall
  asserts this). If you ever add caching/fitting, the held-out result is contaminated - don't.

Stdlib only (sqlite3). The corpus is small (a few thousand rows), so a columnar store buys nothing;
sqlite keeps the auditor stdlib-only and the leave-one-out semantics trivially exact.
"""

from __future__ import annotations

import ast
import sqlite3
import time
from pathlib import Path

# ---------------------------------------------------------------- shape_key (manifest-only)


def _arity(signature: str) -> int:
    """Count the real positional+kw-only params of a manifest signature (drop `self`, count *args
    as one). Derived from the signature string index.py already emits - index.py is untouched."""
    try:
        node = ast.parse(f"def _f{signature or '()'}: pass").body[0]
    except SyntaxError:
        return 0
    a = node.args  # type: ignore[attr-defined]
    names = [p.arg for p in (a.posonlyargs + a.args) if p.arg != "self"] + \
            [p.arg for p in a.kwonlyargs]
    return len(names) + (1 if a.vararg else 0)


def _arity_bucket(arity: int) -> str:
    return "0" if arity == 0 else "1" if arity == 1 else "2" if arity == 2 else "3+"


def shape_key(entry: dict) -> str:
    """A COARSE function shape from manifest fields ONLY (no index.py change): a stable string
    flattening (auditability, deterministic, arity_bucket, has_inverse_sibling). Coarse on purpose
    - the experiment's stated limitation (a finer key needs more corpus per cell to be non-noisy)."""
    aud = entry.get("auditability", "none")
    det = bool(entry.get("deterministic", False))
    bucket = _arity_bucket(_arity(entry.get("signature", "")))
    has_inv = bool(aud == "invariant" and "inverse pair" in (entry.get("auditability_why", "") or ""))
    return f"{aud}|det={det}|arity={bucket}|inv={has_inv}"


def candidate_strategies(entry: dict) -> list[str]:
    """The authoring strategies eligible for a function, gated by determinism. A pure function can be
    audited by a value/invariant/property oracle; an impure one needs the seam injected, so only the
    stubbed_seam rung applies (the others assume a mutatable pure reference). This is the strategy
    SET; the ladder ORDER over it is the arm's policy (fixed for Arm2, recall-driven for Arm3)."""
    if entry.get("deterministic", False):
        return ["value", "invariant", "property"]
    return ["stubbed_seam"]


# the fixed-ladder order (Arm2 / blind retry). A strategy a function isn't eligible for is skipped.
LADDER_ORDER = ("value", "invariant", "property", "stubbed_seam")


# ---------------------------------------------------------------- exemplar role-split (#1)


def split_oracle(code: str) -> tuple[str | None, str | None]:
    """Split a stored oracle module into its (reference_source, battery_source) halves.

    author._author_independent concatenates the independently-authored reference FIRST then the
    battery, and author.REFERENCE_CONTRACT pins the reference to end with `REFERENCE_NAME = "..."`
    as the last reference-role statement. So the boundary is deterministic: everything up to and
    including that assignment is the reference (with its own imports at the top); everything after is
    the battery (PROBE_INPUTS + check_impl, with its own imports). The split is by AST line number,
    not regex - the module is real Python (no_regex_for_structured_langs).

    Returns (None, None) if the module won't parse or has no REFERENCE_NAME marker. Callers MUST treat
    a None half as "no exemplar for this role" and skip injection - never cross-inject a reference
    into the battery author (that would re-couple the two independent spec reads the gate relies on).
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None, None
    split_line: int | None = None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "REFERENCE_NAME":
                    split_line = node.end_lineno  # 1-based, inclusive
    if not split_line:
        return None, None
    lines = code.splitlines()
    ref_src = "\n".join(lines[:split_line]).strip()
    bat_src = "\n".join(lines[split_line:]).strip()
    return (ref_src or None), (bat_src or None)


# ---------------------------------------------------------------- the store


class StrategyRecall:
    """sqlite-backed corpus of authoring observations + the stateless recommendation query."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS obs(
                    repo TEXT, qualname TEXT, shape_key TEXT, strategy TEXT, model TEXT,
                    gate_green INTEGER, strict_green INTEGER, cost REAL, rep INTEGER, ts REAL,
                    oracle_code TEXT,
                    PRIMARY KEY(repo, qualname, strategy, model, rep))"""
            )
            # forward migration for DBs created before exemplar-injection (#1): add the column if an
            # older obs table is missing it. oracle_code is a NULLABLE payload, never part of the key,
            # so the add is a no-op on the recall SELECTION query and the leave-one-out semantics.
            cols = {r[1] for r in c.execute("PRAGMA table_info(obs)")}
            if "oracle_code" not in cols:
                c.execute("ALTER TABLE obs ADD COLUMN oracle_code TEXT")

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.db_path)
        c.row_factory = sqlite3.Row
        return c

    def record(self, *, repo: str, qualname: str, shape_key: str, strategy: str, model: str,
               gate_green: bool, strict_green: bool, cost: float, rep: int = 0,
               ts: float | None = None, oracle_code: str | None = None) -> None:
        """Idempotent insert of one observation (delete-then-insert via INSERT OR REPLACE on the
        natural key). Re-running a repo overwrites its rows rather than double-counting.

        `oracle_code` is the authored reference+battery module text - stored ONLY so a GREEN row can
        later serve as an EXEMPLAR (augmented-generation recall, #1). It is pure payload: it never
        enters the natural key and never the strategy-SELECTION query, so adding it cannot perturb
        recommend_order or the leave-one-out aggregation."""
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO obs (repo, qualname, shape_key, strategy, model, "
                "gate_green, strict_green, cost, rep, ts, oracle_code) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (repo, qualname, shape_key, strategy, model, int(bool(gate_green)),
                 int(bool(strict_green)), float(cost), int(rep),
                 float(ts if ts is not None else time.time()), oracle_code),
            )

    def repos(self) -> list[str]:
        with self._conn() as c:
            return [r[0] for r in c.execute("SELECT DISTINCT repo FROM obs ORDER BY repo")]

    def strategy_rates(self, shape_key: str, *, exclude_repo: str | None = None,
                       model: str | None = None) -> list[dict]:
        """Per-strategy gate-GREEN rate + support for one shape - the pure GROUP BY the whole idea
        rests on. `exclude_repo` is the leave-one-out lever (≡ deleting that repo's rows)."""
        q = ("SELECT strategy, AVG(gate_green) AS rate, COUNT(*) AS n, "
             "SUM(gate_green) AS greens, AVG(strict_green) AS strict_rate "
             "FROM obs WHERE shape_key=?")
        args: list = [shape_key]
        if exclude_repo is not None:
            q += " AND repo<>?"
            args.append(exclude_repo)
        if model is not None:
            q += " AND model=?"
            args.append(model)
        q += " GROUP BY strategy ORDER BY rate DESC, n DESC, strategy"
        with self._conn() as c:
            return [dict(r) for r in c.execute(q, args).fetchall()]

    def recommend_order(self, shape_key: str, candidates: list[str], *,
                        exclude_repo: str | None = None, model: str | None = None) -> list[str]:
        """Reorder `candidates` best-first by this shape's observed gate-GREEN rate (stateless).

        Strategies with NO rows for this shape keep their original (fixed-ladder) relative order and
        fall BEHIND every strategy that does have evidence - recall never invents a preference it
        has no data for, so on a cold/sparse shape Arm3 degrades gracefully toward Arm2's order."""
        rates = {r["strategy"]: (r["rate"], r["n"])
                 for r in self.strategy_rates(shape_key, exclude_repo=exclude_repo, model=model)}
        known = [s for s in candidates if s in rates]
        unknown = [s for s in candidates if s not in rates]
        known.sort(key=lambda s: (rates[s][0], rates[s][1]), reverse=True)
        return known + unknown

    def nearest_exemplar(self, shape_key: str, strategy: str, *, role: str = "reference",
                         exclude_repo: str | None = None, model: str | None = None) -> dict | None:
        """Retrieve a GREEN, gate-passing oracle of the SAME shape+strategy to inject as a generation
        EXEMPLAR (augmented-generation recall, #1) - the half matching `role` ("reference"/"battery").

        Same leave-one-out lever as the selection query: `exclude_repo=R` is byte-identical to having
        deleted R's rows, so an exemplar for a held-out function NEVER comes from its own repo (no
        train/test leak). "Nearest" is coarse by construction - the shape_key is the only similarity
        signal the stdlib store has (no embeddings) - so among same-shape GREEN oracles it prefers the
        higher-quality (strict_green) ones, with a deterministic (repo, qualname) tiebreak so the A/B
        is reproducible. This mirrors recommend_order's documented coarse-key limitation.

        Returns {repo, qualname, strict_green, code} for the chosen role half, or None if no other-repo
        GREEN oracle of this shape exists or none yields a usable role half (then: author un-augmented).
        """
        q = ("SELECT repo, qualname, strict_green, oracle_code FROM obs "
             "WHERE shape_key=? AND strategy=? AND gate_green=1 "
             "AND oracle_code IS NOT NULL AND oracle_code<>''")
        args: list = [shape_key, strategy]
        if exclude_repo is not None:
            q += " AND repo<>?"
            args.append(exclude_repo)
        if model is not None:
            q += " AND model=?"
            args.append(model)
        q += " ORDER BY strict_green DESC, repo, qualname"  # quality-first, then deterministic
        with self._conn() as c:
            rows = c.execute(q, args).fetchall()
        for r in rows:
            ref_src, bat_src = split_oracle(r["oracle_code"])
            code = ref_src if role == "reference" else bat_src
            if code:
                return {"repo": r["repo"], "qualname": r["qualname"],
                        "strict_green": bool(r["strict_green"]), "code": code}
        return None

    # -- introspection / leave-one-out plumbing -------------------------------------------------
    def delete_repo(self, repo: str) -> int:
        with self._conn() as c:
            cur = c.execute("DELETE FROM obs WHERE repo=?", [repo])
            return cur.rowcount

    def all_shape_keys(self, *, exclude_repo: str | None = None) -> list[str]:
        q = "SELECT DISTINCT shape_key FROM obs"
        args: list = []
        if exclude_repo is not None:
            q += " WHERE repo<>?"
            args.append(exclude_repo)
        with self._conn() as c:
            return [r[0] for r in c.execute(q + " ORDER BY shape_key", args)]
