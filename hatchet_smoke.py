#!/usr/bin/env python3
"""Worker/venv resolution proof: can the cynthia-core venv host a Hatchet worker
against the live instance? Registers one trivial task; `worker` mode runs the worker,
`run` mode pushes a task and prints the round-tripped result.

    .venv/bin/python hatchet_smoke.py worker   # (background) registers + pulls work
    .venv/bin/python hatchet_smoke.py run       # pushes audit_spike_ping(21), expects pong=42
"""
import os
import sys
from pathlib import Path

# load HATCHET_* from the V3 .env (mirror cynthia.hatchet_client._load_env)
_env_file = Path(__file__).resolve().parent / ".env"
for _line in (_env_file.read_text().splitlines() if _env_file.exists() else []):
    _line = _line.strip()
    if _line.startswith("HATCHET_") and "=" in _line:
        _k, _, _v = _line.partition("=")
        os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

from hatchet_sdk import Context, Hatchet  # noqa: E402
from pydantic import BaseModel  # noqa: E402

hatchet = Hatchet()


class PingIn(BaseModel):
    x: int


@hatchet.task(name="audit_spike_ping", input_validator=PingIn)
async def audit_spike_ping(inp: PingIn, ctx: Context) -> dict:
    # prove WHICH interpreter ran it (must be the cynthia-core venv) + that auditor imports here
    import auditor.author as A  # noqa: F401
    return {"pong": inp.x * 2, "executor_py": sys.executable, "auditor_importable": True}


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "run"
    if mode == "worker":
        w = hatchet.worker("audit-spike-worker", workflows=[audit_spike_ping])
        w.start()  # blocks
        return 0
    # run mode: blocking single-task run (NOT aio_run_many - avoids the known deadlock)
    out = audit_spike_ping.run(PingIn(x=21))
    print("ROUND-TRIP RESULT:", out)
    ok = isinstance(out, dict) and out.get("pong") == 42 and out.get("auditor_importable")
    print("RESOLVED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    raise SystemExit(main())
