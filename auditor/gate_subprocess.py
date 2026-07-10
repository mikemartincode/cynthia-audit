#!/usr/bin/env python3
"""auditor/gate_subprocess.py - run ONE mutation gate in a fresh, killable, memory-capped subprocess.

The shared safe-gating primitive. Stdlib only (no import of author/coverage_exp), so BOTH
`coverage_exp` and `author.author_best_of_n` can use it without a circular import. It shells out to
`_gate_runner.py` (which imports the gate IN its own process) with:
  * a HARD process-group SIGKILL on timeout - a non-terminating reference (LLM infinite loop /
    catastrophic regex) can't wedge the caller;
  * RLIMIT_AS in the runner (see _gate_runner.py) - a MEMORY-bomb reference (allocating loop) dies at
    the cap instead of OOM-killing the host (measured: an in-process best-of-N gate grew a python
    process to 29GB and OOM-killed the box / its tmux pane).

A gate that cannot render a verdict (timeout / OOM- or rlimit-kill / crash / uncaught MemoryError) is
flagged `gate_failed=True` - that is NOT a RED oracle (RED = the gate ran and the oracle failed to kill
mutants). Callers should bucket gate_failed as an error, excluded from coverage, never counted as RED.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

GATE_RUNNER = Path(__file__).resolve().parent / "_gate_runner.py"
GATE_TIMEOUT_S = 90  # a real gate is seconds; this only catches a non-terminating reference/import

# normalized shape for a gate that produced NO verdict - carries every key real-verdict consumers read
_FAILED = {"green": False, "strict_green": False, "gate_failed": True, "kill_rate": 0.0,
           "ref_passes": False, "survivors": [], "note": ""}


def _failed(note: str) -> dict:
    d = dict(_FAILED)
    d["note"] = note
    return d


def gate_subprocess(module_name: str, oracles_dir: str, cap: int, qualname: str,
                    timeout: int = GATE_TIMEOUT_S) -> dict:
    """Gate one oracle in a fresh subprocess with a hard process-group kill on timeout. Returns the
    gate's verdict dict on success, or a `gate_failed=True` dict on timeout/crash/OOM. Never raises."""
    proc = subprocess.Popen(
        [sys.executable, str(GATE_RUNNER), module_name, oracles_dir, str(cap), qualname],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)  # kill the runner AND its mutant procs
        except ProcessLookupError:
            pass
        proc.communicate()
        return _failed(f"gate timeout >{timeout}s (non-terminating reference impl; killed group)")
    for line in out.splitlines():
        if line.startswith("VERDICT_JSON:"):
            v = json.loads(line[len("VERDICT_JSON:"):])
            # a MemoryError mid-evaluation is the gate failing to evaluate, not a verdict on the oracle
            if "memoryerror" in (v.get("note", "") or "").lower():
                v["gate_failed"] = True
            return v
    # no verdict line => the subprocess crashed / was OOM- or rlimit-killed => gate FAILED, not RED
    return _failed(f"gate subprocess failed rc={proc.returncode}: {(err or '')[-200:]}")


# back-compat alias (coverage_exp historically referenced the underscore name)
_gate_subprocess = gate_subprocess
