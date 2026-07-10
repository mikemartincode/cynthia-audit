#!/usr/bin/env python3
"""auditor/_gate_runner.py - run ONE mutation gate in a fresh, killable, MEMORY-CAPPED subprocess.

coverage_exp invokes this with a HARD timeout (process-group kill). The reason it must be a separate
process: cynthia-core's run_mutation_gate runs the oracle's `check_impl(REFERENCE_FUNC)` (the step-0
ref_passes check) and the import IN-PROCESS with no timeout - so an authored reference that doesn't
terminate (an LLM-written infinite loop / catastrophic regex) hangs the gate forever. The per-mutant
grading already runs in timeout-guarded subprocesses; this wrapper extends that hard-kill guarantee to
the ref check + import.

It ALSO caps address space (RLIMIT_AS) because the timeout does NOT stop a fast MEMORY bomb: an
LLM-authored reference with an *allocating* loop (`while True: buf.append(...)`) reaches tens of GB in
seconds - measured: a best-of-N spike grew a python process to 29GB and OOM-killed the box (the tmux
pane it ran in died). With a cap, the bomb gets MemoryError/ENOMEM at a few GB, gate_authored degrades
it to RED, and the box survives. A legitimate gate uses <500MB, so the cap only bites on bombs.
The cap is inherited by the gate's own mutant-grading child subprocesses, so they're bounded too.

Emits exactly one `VERDICT_JSON:<json>` line on stdout. Args: <module_name> <oracles_dir> <cap> <qualname>
"""

import json
import os
import resource
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from author import gate_authored  # noqa: E402

# Hard address-space cap so a memory-bomb oracle can't OOM the host (default 4GB; legit gates <500MB).
_MEM_CAP_GB = float(os.environ.get("GATE_MEM_CAP_GB", "4"))
try:
    _cap = int(_MEM_CAP_GB * 1024 ** 3)
    _soft, _hard = resource.getrlimit(resource.RLIMIT_AS)
    _ceil = _cap if _hard == resource.RLIM_INFINITY else min(_cap, _hard)
    resource.setrlimit(resource.RLIMIT_AS, (_ceil, _hard))
except (ValueError, OSError):
    pass  # best-effort - never block gating because the rlimit couldn't be set


def main() -> int:
    mod, oracles_dir, cap, qual = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    v = gate_authored(mod, Path(oracles_dir), cap=cap, qualname=qual, strict=True)
    sys.stdout.write("VERDICT_JSON:" + json.dumps(v) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
