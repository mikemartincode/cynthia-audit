#!/usr/bin/env python3
"""Hatchet-wrapped M3 oracle author - the spike.

Replaces the two hand-hacks (func_workers ThreadPool + global gate-lock) with platform-owned
cross-cutting concerns (north-star §2): retries + per-resource concurrency caps live on the tasks.

Two tasks, two resource profiles:
  author_draft  - network-bound. retries=3/backoff "queues the 500s" (transient gateway errors
                  re-enqueue). ConcurrencyExpression max_runs=24 caps concurrent gateway calls
                  (the HTTP-500 cascade ceiling found at fw=6).
  gate_draft    - RAM-bound mutant-subprocess swarm. ConcurrencyExpression max_runs=8 caps
                  concurrent gates to box RAM - REPLACES the manual gate-lock. Sync gate runs in
                  asyncio.to_thread (per reference_hatchet_authoring).

Retryable unit = ONE draft: a 500 on draft 7 re-authors only draft 7, never re-gates or re-authors
the rest. Driver fans out best-of-N via per-draft aio_run (NOT aio_run_many -> avoids the deadlock);
Hatchet's concurrency caps do the throttling server-side, so there is no client-side worker count to tune.

    .venv/bin/python hatchet_author.py worker                 # (background) the spike worker
    .venv/bin/python hatchet_author.py run <manifest> --limit N --shape value [--n 8]
"""
import argparse
import asyncio
import os
import statistics
import sys
import time
from pathlib import Path

# Self-sufficient env: the WORKER process (not the driver) runs the author calls, so it needs
# both HATCHET_* (client) and LITELLM_KEY (gateway auth) loaded here, not just in the launch shell.
_env_file = Path(__file__).resolve().parent / ".env"
for _line in (_env_file.read_text().splitlines() if _env_file.exists() else []):
    _line = _line.strip()
    if "=" in _line and (_line.startswith("HATCHET_") or _line.startswith("LITELLM_KEY")):
        _k, _, _v = _line.partition("=")
        os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))
# author.call_model reads LITELLM_GATEWAY (base; it appends /v1/chat/completions). Not in .env
# (which has LITELLM_URL=.../v1) - set the base here.
os.environ.setdefault("LITELLM_GATEWAY", "http://localhost:4000")

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hatchet_sdk import ConcurrencyExpression, ConcurrencyLimitStrategy, Context, Hatchet  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

hatchet = Hatchet()

_TRANSIENT = ("500", "502", "503", "504", "529", "timeout", "Timeout",
              "Connection", "ConnectionError", "Temporarily", "RemoteDisconnected")


def _is_transient(err: str) -> bool:
    return any(t in err for t in _TRANSIENT)


class AuthorIn(BaseModel):
    entry: dict
    model: str = "minimax-m3"
    shape: str = "value"
    draft: int = 0
    run_dir: str
    max_tokens: int = 8000
    temperature: float = 0.7


class GateIn(BaseModel):
    cand_dir: str
    mod: str
    qualname: str
    cap: int = 40


@hatchet.task(
    name="author_draft",
    input_validator=AuthorIn,
    execution_timeout=__import__("datetime").timedelta(minutes=5),
    retries=3,
    backoff_factor=2.0,
    concurrency=ConcurrencyExpression(
        expression="'m3-author'",  # static global key: cap ALL author calls together
        max_runs=24,               # the gateway HTTP-500 ceiling (fw=6/48 cascaded; 24 held)
        limit_strategy=ConcurrencyLimitStrategy.GROUP_ROUND_ROBIN,
    ),
)
async def author_draft(inp: AuthorIn, ctx: Context) -> dict:
    """Author ONE oracle draft (independent ref+battery, think-OFF, streamed)."""
    import hashlib

    from auditor.author import _author_independent, _battery_model

    def _do() -> dict:
        bat = _battery_model(inp.model)
        return _author_independent(inp.entry, inp.model, bat, target=inp.entry.get("target", ""),
                                   shape=inp.shape, max_tokens=inp.max_tokens,
                                   temperature=inp.temperature, stream=True,
                                   thinking={"type": "disabled"}, trace_meta={"draft": inp.draft})
    r = await asyncio.to_thread(_do)
    if "error" in r:
        if _is_transient(str(r["error"])):
            raise RuntimeError(f"transient author error (Hatchet retries): {r['error']}")
        return {"ok": False, "error": str(r["error"])[:200]}
    qh = hashlib.sha1(inp.entry["qualname"].encode()).hexdigest()[:10]
    cand_dir = Path(inp.run_dir) / f"{qh}" / f"n{inp.draft}"
    cand_dir.mkdir(parents=True, exist_ok=True)
    mod = f"orc_{qh}_n{inp.draft}"
    (cand_dir / f"{mod}.py").write_text(r["code"])
    return {"ok": True, "cand_dir": str(cand_dir), "mod": mod,
            "out_tok": r.get("out_tok", 0), "cost": r.get("cost", 0.0)}


@hatchet.task(
    name="gate_draft",
    input_validator=GateIn,
    execution_timeout=__import__("datetime").timedelta(minutes=5),
    retries=1,
    concurrency=ConcurrencyExpression(
        expression="'gate-cpu'",  # static global key: cap concurrent mutant swarms to box RAM
        max_runs=8,               # REPLACES the manual gate-lock; ~box RAM headroom
        limit_strategy=ConcurrencyLimitStrategy.GROUP_ROUND_ROBIN,
    ),
)
async def gate_draft(inp: GateIn, ctx: Context) -> dict:
    """Mutation-gate ONE authored draft (RAM-heavy; runs in a thread)."""
    from auditor.author import gate_authored

    def _do() -> dict:
        return gate_authored(inp.mod, Path(inp.cand_dir), cap=inp.cap, qualname=inp.qualname)
    v = await asyncio.to_thread(_do)
    return {"green": bool(v.get("green")), "kill_rate": float(v.get("kill_rate", 0.0)),
            "note": str(v.get("note", ""))[:120]}


async def _author_fn(entry: dict, run_dir: str, model: str, shape: str, n: int) -> dict:
    """best-of-N for one function: fan out N author_draft, gate the successes, select first GREEN."""
    q = entry["qualname"]; t0 = time.time()
    drafts = await asyncio.gather(*[
        author_draft.aio_run(AuthorIn(entry=entry, model=model, shape=shape, draft=i, run_dir=run_dir))
        for i in range(n)], return_exceptions=True)
    errs = sum(1 for d in drafts if isinstance(d, Exception) or not (isinstance(d, dict) and d.get("ok")))
    cands = [d for d in drafts if isinstance(d, dict) and d.get("ok")]
    gated = await asyncio.gather(*[
        gate_draft.aio_run(GateIn(cand_dir=c["cand_dir"], mod=c["mod"], qualname=q)) for c in cands],
        return_exceptions=True)
    verdicts = [g for g in gated if isinstance(g, dict)]
    green = any(v["green"] for v in verdicts)
    kr = max((v["kill_rate"] for v in verdicts), default=0.0)
    return {"qualname": q, "green": green, "kill_rate": kr, "drafts_ok": len(cands),
            "draft_errs": errs, "wall_s": round(time.time() - t0, 1)}


async def _run(manifest: Path, limit: int, shape: str, n: int, model: str) -> int:
    import json
    m = json.loads(manifest.read_text())
    funcs = m["functions"][:limit] if limit else m["functions"]
    for f in funcs:
        f.setdefault("target", m["target"])
    run_dir = str(Path("results") / f"hatchet-{time.strftime('%Y%m%d-%H%M%S')}")
    Path(run_dir).mkdir(parents=True, exist_ok=True)
    wall0 = time.time()
    results = await asyncio.gather(*[_author_fn(f, run_dir, model, shape, n) for f in funcs])
    total = time.time() - wall0
    g = sum(1 for r in results if r["green"])
    for r in results:
        print(f"  {r['qualname']:30} green={r['green']} kr={r['kill_rate']:.2f} "
              f"drafts_ok={r['drafts_ok']}/{n} errs={r['draft_errs']}", flush=True)
    print("=" * 64)
    print(f"Hatchet author | {m['target']} | {shape} | n={n} | funcs={len(funcs)}")
    print(f"GREEN: {g}/{len(funcs)} = {g/len(funcs):.3f}")
    print(f"TOTAL WALL: {total/60:.1f}min   (seq value=28.6min, fw=3=10.3min)")
    print(f"total draft errors (post-retry): {sum(r['draft_errs'] for r in results)}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    sub.add_parser("worker")
    rp = sub.add_parser("run")
    rp.add_argument("manifest", type=Path)
    rp.add_argument("--limit", type=int, default=0)
    rp.add_argument("--shape", default="value", choices=("value", "invariant"))
    rp.add_argument("--n", type=int, default=8)
    rp.add_argument("--model", default="minimax-m3")
    args = ap.parse_args()
    if args.mode == "worker":
        hatchet.worker("audit-author-worker", slots=100,
                       workflows=[author_draft, gate_draft]).start()
        return 0
    return asyncio.run(_run(args.manifest, args.limit, args.shape, args.n, args.model))


if __name__ == "__main__":
    raise SystemExit(main())
