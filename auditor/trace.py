#!/usr/bin/env python3
"""auditor/trace.py — full execution trace of the audit pipeline (LLMs + gates + oracles).

The records the pipeline already writes (results/<run>/records/*.json, the oracle .py + _raw.txt
files, the sweep JSON) capture OUTCOMES. They do NOT capture the two things you'd need to ever
PREDICT an outcome from its inputs and "feed it" precomputed:

  1. the exact LLM INPUT — `call_model` saved only the response (`_raw.txt`), never the
     system+user prompt that produced it. An (prompt -> response -> verdict) corpus needs both.
  2. the per-MUTANT gate detail — the verdict names survivors/errored by tag, but not the full
     generated mutant set with each mutant's source + kill/survive verdict. That table is the
     ground truth a "will this oracle gate GREEN?" predictor would learn from.

This module is that capture, as an append-only JSONL event stream, env-gated and zero-overhead
when off. Two events cover the whole pipeline because the pipeline has exactly two LLM/gate
chokepoints:

  llm_call  — one per gateway call: {qualname, role (reference|battery|...), model, shape,
              system, user, response_raw, extracted_code, in_tok, out_tok, cost, elapsed, meta}
  gate      — one per mutation gate: {qualname, module, verdict (full dict), mutants:[{tag,
              kind, verdict, src}], equivalent_count, cap}

PROCESS SAFETY. Authoring runs in main-process threads (asyncio.to_thread); the gate runs in a
ProcessPoolExecutor. So events come from MULTIPLE processes. Rather than fight cross-process
append atomicity on large lines (prompts/mutant-sources exceed PIPE_BUF), each process writes its
OWN shard `trace.<pid>.jsonl`; `merge()` concatenates + ts-sorts them into `trace.jsonl` and emits
`trace_summary.json`. The distinct shard pids are also a free parallelism artifact.

Enable by setting AUDITOR_TRACE_DIR to a directory; everything else is automatic. Tracing NEVER
raises into the pipeline — a trace failure is swallowed, the audit run is never collateral.

CLI:
    python auditor/trace.py merge <trace_dir>     # shards -> trace.jsonl + trace_summary.json
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

_LOCK = threading.Lock()
_FH = None          # this process's shard handle (lazily opened)
_FH_PID = None      # the pid _FH belongs to (reopened after a fork)


def trace_dir() -> Path | None:
    d = os.environ.get("AUDITOR_TRACE_DIR")
    return Path(d) if d else None


def enabled() -> bool:
    return trace_dir() is not None


def _coerce(o):
    """JSON fallback: never let an exotic value abort a trace line."""
    try:
        return repr(o)
    except Exception:  # noqa: BLE001
        return f"<unreprable {type(o).__name__}>"


def emit(event: str, **fields) -> None:
    """Append one event to this process's shard. No-op when AUDITOR_TRACE_DIR is unset.
    Swallows every error — tracing is observation, it must never break the observed run."""
    d = trace_dir()
    if d is None:
        return
    try:
        rec = {"ts": round(time.time(), 6), "pid": os.getpid(), "event": event}
        rec.update(fields)
        line = json.dumps(rec, default=_coerce, ensure_ascii=False) + "\n"
        with _LOCK:
            global _FH, _FH_PID
            pid = os.getpid()
            if _FH is None or _FH_PID != pid:  # first write, or we are a forked child
                d.mkdir(parents=True, exist_ok=True)
                _FH = open(d / f"trace.{pid}.jsonl", "a", encoding="utf-8")
                _FH_PID = pid
            _FH.write(line)
            _FH.flush()
    except Exception:  # noqa: BLE001 — tracing is best-effort, never fatal
        pass


# ---------------------------------------------------------------- merge + summarize

def merge(d: Path) -> dict:
    """Concatenate every `trace.<pid>.jsonl` shard into a single ts-ordered `trace.jsonl` and
    write `trace_summary.json` (event/role/model counts, token + cost totals, gate kill stats).
    Returns the summary dict."""
    events: list[dict] = []
    shards = sorted(d.glob("trace.*.jsonl"))
    for sh in shards:
        for ln in sh.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                events.append(json.loads(ln))
            except Exception:  # noqa: BLE001 — a torn line is skipped, not fatal
                continue
    events.sort(key=lambda e: e.get("ts", 0.0))
    (d / "trace.jsonl").write_text(
        "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events), encoding="utf-8")

    llm = [e for e in events if e["event"] == "llm_call"]
    gates = [e for e in events if e["event"] == "gate"]
    by_role: dict[str, int] = {}
    by_model: dict[str, int] = {}
    for e in llm:
        by_role[e.get("role", "?")] = by_role.get(e.get("role", "?"), 0) + 1
        by_model[e.get("model", "?")] = by_model.get(e.get("model", "?"), 0) + 1
    mutants_total = sum(len(g.get("mutants", [])) for g in gates)
    survived = sum(1 for g in gates for mt in g.get("mutants", []) if mt["verdict"] == "survived")
    errored = sum(1 for g in gates for mt in g.get("mutants", []) if mt["verdict"] == "errored")
    summary = {
        "shards": [sh.name for sh in shards],
        "distinct_pids": sorted({e.get("pid") for e in events}),
        "total_events": len(events),
        "llm_calls": len(llm),
        "llm_calls_by_role": by_role,
        "llm_calls_by_model": by_model,
        "llm_in_tokens": sum(e.get("in_tok", 0) for e in llm),
        "llm_out_tokens": sum(e.get("out_tok", 0) for e in llm),
        "llm_cost_usd": round(sum(e.get("cost", 0.0) for e in llm), 4),
        "gate_runs": len(gates),
        "gate_green": sum(1 for g in gates if g.get("verdict", {}).get("green")),
        "mutants_traced": mutants_total,
        "mutants_survived": survived,
        "mutants_errored": errored,
        "mutants_killed_or_equivalent": mutants_total - survived - errored,
        "ts_span_s": round((events[-1]["ts"] - events[0]["ts"]) if events else 0.0, 1),
    }
    (d / "trace_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == "merge":
        s = merge(Path(sys.argv[2]))
        print(json.dumps(s, indent=2))
        return 0
    print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
