#!/usr/bin/env python3
"""auditor/author.py — per-function DeepSeek oracle author + mutation-gate worker.

Generalizes the proven seed (seed/deepseek_author.py): given one manifest entry
(from auditor/index.py), build an author prompt from its intent + spec/invariant
basis, have DeepSeek author an independent oracle module, validate it with the
cynthia-core mutation gate, and return a structured ResultRecord. Retry-on-RED:
the gate, not the model, decides when to stop.

Never raises on a bad model response — a broken/truncated/contract-violating
oracle degrades to a RED record so a batch (A03) survives any single failure.

Config is ENV-ONLY (no key in any file):
    LITELLM_GATEWAY   e.g. http://host:4000   (required at call time, not import)
    LITELLM_KEY       bearer token            (required at call time)

Demo (3 manifest entries, prints + saves records):
    python auditor/author.py targets/hyperlink/manifest.json parse_host iter_pairs ...
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

# per-model gateway pricing ($/M tokens, in/out) — keep in sync with the gateway config.
PRICING = {"deepseek-v4-flash": (0.14, 0.28), "deepseek-v4-pro": (1.74, 3.48)}

DEFAULT_MODEL = "deepseek-v4-pro"
DEFAULT_ATTEMPTS = 4
DEFAULT_MAX_TOKENS = 20000  # pro is reasoning-on; 12k can truncate mid-module (measured)


# ---------------------------------------------------------------- gateway call

def _read_stream(resp) -> tuple[str, dict]:
    """Accumulate an OpenAI-compatible SSE stream into (content, usage). Streaming is what
    makes a reasoning model (minimax-m3) usable here: the gateway buffers a non-stream response
    until the whole reasoning trace finishes, which can exceed the read timeout — incremental
    delivery can't wedge."""
    content, usage = [], {}
    for raw_line in resp:
        line = raw_line.decode("utf-8", "replace").strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload == "[DONE]":
            break
        try:
            chunk = json.loads(payload)
        except Exception:  # noqa: BLE001 — keepalive / partial line
            continue
        if chunk.get("usage"):
            usage = chunk["usage"]
        choices = chunk.get("choices") or []
        if choices:
            piece = choices[0].get("delta", {}).get("content")
            if piece:
                content.append(piece)
    return "".join(content), usage


def call_model(model: str, system: str, user: str, *, max_tokens: int = DEFAULT_MAX_TOKENS,
               timeout: int = 300, temperature: float = 0.2, stream: bool = False,
               thinking: dict | None = None) -> dict:
    """One authoring call. Returns {code, raw, in_tok, out_tok, cost, elapsed}.
    Raises urllib errors upward — callers convert them to RED records.

    `stream=True` reads the response incrementally (required for reasoning models, whose
    non-stream response the gateway buffers past the timeout). `thinking={'type':'disabled'}`
    turns OFF a reasoning model's chain-of-thought — ~15x faster, but the draft is more fragile
    (callers compensate with best-of-N + the mutation gate as the selector)."""
    gateway = os.environ["LITELLM_GATEWAY"].rstrip("/") + "/v1/chat/completions"
    key = os.environ["LITELLM_KEY"]
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if thinking is not None:
        payload["thinking"] = thinking
    if stream:
        payload["stream"] = True
        payload["stream_options"] = {"include_usage": True}
    req = urllib.request.Request(gateway, data=json.dumps(payload).encode(),
                                 headers={"Authorization": f"Bearer {key}",
                                          "Content-Type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if stream:
            raw, u = _read_stream(resp)
        else:
            data = json.loads(resp.read())
            u = data.get("usage", {})
            raw = data["choices"][0]["message"]["content"]
    rin, rout = PRICING.get(model, (0.0, 0.0))
    cost = u.get("prompt_tokens", 0) / 1e6 * rin + u.get("completion_tokens", 0) / 1e6 * rout
    return {"code": extract_code(raw), "raw": raw,
            "in_tok": u.get("prompt_tokens", 0), "out_tok": u.get("completion_tokens", 0),
            "cost": cost, "elapsed": round(time.time() - t0, 1)}


def extract_code(text: str) -> str:
    """A fenced block is already delimited code — use the LONGEST one AS-IS (a non-greedy
    match can grab a partial block when a ``` appears inside a docstring). No fence: start
    at the first plausibly-code line so leading reasoning prose is dropped but a leading
    top-level assignment is kept.

    Reasoning-model output is stripped of <think>…</think> FIRST — otherwise the longest-fenced
    heuristic can grab a code snippet from inside the reasoning trace (a no-op for non-reasoning
    models, which emit no think tags)."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S | re.I)
    text = re.sub(r"^.*?</think>", "", text, flags=re.S | re.I)  # unclosed leading think
    blocks = re.findall(r"```(?:python)?\s*(.*?)```", text, re.S)
    if blocks:
        return max(blocks, key=len).strip() + "\n"
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if ln.startswith(("import ", "from ", "def ", "class ", '"""', "'''", "#!", "#")) \
                or re.match(r"^[A-Za-z_]\w*\s*[:=]", ln):
            return "\n".join(lines[i:]).strip() + "\n"
    return text.strip() + "\n"


# ---------------------------------------------------------------- prompt construction

SYSTEM_PROMPT = "You are a precise Python engineer. Output only code."

# The module contract, parameterized by reference name. The HARD rules encode the measured
# one-shot failure modes of the cheap model (forward reference, wrong-shape probes,
# module-level execution, truncation) — each otherwise caught by the gate only after a
# wasted attempt.
CONTRACT_TEMPLATE = """\
Write ONE self-contained stdlib-only Python module defining a mutation-test oracle for the
behavior specified above, conforming EXACTLY to this contract:

- `def {ref_name}(arg)`: a known-correct PURE reference implementation of the specified
  behavior, written from the SPEC above. Do NOT try to recall the library's own source —
  your implementation must be independent. It takes EXACTLY ONE positional argument; if the
  behavior needs multiple inputs, `arg` is a tuple that {ref_name} unpacks. Every helper must
  be an INNER function defined inside {ref_name}. Raise ValueError for spec-invalid inputs.
- `REFERENCE_FUNC = {ref_name}` and `REFERENCE_NAME = "{ref_name}"`.
- `PROBE_INPUTS`: a list of 8-20 inputs covering the tricky edges of the spec. Each item is
  ONE argument value (string or tuple of strings preferred) and must round-trip through
  repr() exactly.
- `def check_impl(fn)`: grades an ARBITRARY implementation `fn` (same one-argument calling
  convention) against the SPEC. Expected outcomes are HARD-CODED from the spec, or asserted
  as spec properties (round-trip, idempotence, error-on-invalid) — NEVER computed by calling
  {ref_name} (that would be circular). It MUST return a LIST of (bool, str) tuples, exactly
  one per PROBE_INPUTS item, in order. If fn raises where the spec demands an error, that is
  a PASS for that probe; if fn raises anywhere else, catch it and record a FAIL (never let
  check_impl itself raise).
- OPTIONAL `EQUIV_KEY = lambda out: ...` ONLY if check_impl grades a projection of the
  output (e.g. the sign of a comparator); omit it when you grade the full value.

HARD conformance rules (violating any one makes the module worthless):
1. `def {ref_name}` comes FIRST; every module-level assignment (REFERENCE_FUNC,
   REFERENCE_NAME, PROBE_INPUTS, EQUIV_KEY) and `def check_impl` come AFTER it — no forward
   reference.
2. PROBE_INPUTS items contain NO expected values — check_impl carries the expectations.
3. NO module-level execution: nothing runs at import except the defs and the assignments.
   Never call check_impl or {ref_name} at module level.
4. The module must import top-to-bottom with no error, stdlib only.
5. Keep it SHORT enough to finish completely — truncation is failure. Output ONLY the
   module, no prose, no fences.
"""


def _safe_leaf(qualname: str) -> str:
    return re.sub(r"\W", "_", qualname.split(".")[-1]).lower()


def build_prompt(entry: dict, target: str = "") -> tuple[str, str]:
    """(spec_text, contract_text) for one manifest entry."""
    leaf = _safe_leaf(entry["qualname"])
    ref_name = f"ref_{leaf}"
    lines = [
        f"TARGET BEHAVIOR — `{entry['qualname']}{entry['signature']}`"
        + (f" from the `{target}` library." if target else "."),
        f"INTENT: {entry['intent']}",
    ]
    doc = (entry.get("doc") or "").strip()
    if entry["auditability"] == "spec" and doc:
        lines += ["", "SPEC (the documented behavior — author your oracle from THIS):",
                  doc]
    elif entry["auditability"] == "invariant":
        lines += ["", f"UNIVERSAL INVARIANT: {entry['auditability_why']} — check_impl must "
                      "verify this invariant over the probe inputs."]
        if doc:
            lines += ["", "Documented behavior:", doc]
    if "." in entry["qualname"]:
        lines += ["", "NOTE: the original is a method. Your reference must be a standalone "
                      "pure function over plain text/tuple inputs that captures the same "
                      "specified behavior (e.g. take the object's textual form as input)."]
    spec = "\n".join(lines) + "\n"
    return spec, CONTRACT_TEMPLATE.format(ref_name=ref_name)


# ---------------------------------------------------------------- gate plumbing

def _normalize_verdict(v: object) -> dict:
    """MutationVerdict | broken-marker -> plain JSON-able dict."""
    return {
        "green": bool(getattr(v, "green", False)),
        "kill_rate": float(getattr(v, "kill_rate", 0.0)),
        "ref_passes": bool(getattr(v, "ref_passes", False)),
        "generated": int(getattr(v, "generated", 0)),
        "non_equivalent": int(getattr(v, "non_equivalent", 0)),
        "killed": int(getattr(v, "killed", 0)),
        "survivors": list(getattr(v, "survivors", []) or []),
        "note": str(getattr(v, "note", "") or ""),
    }


class _Broken:
    """RED stand-in for an oracle that won't compile/import/respect the contract."""
    green = False
    kill_rate = 0.0
    ref_passes = False

    def __init__(self, note: str):
        self.note = note


# Remote-gate offload: the mutation gate spawns a mutant-subprocess swarm that can OOM a
# RAM-tight dev box. Setting CYNTHIA_GATE_HOST=user@host ships each gate over SSH to a worker
# (cynthia-core venv + auditor/author.py at CYNTHIA_GATE_DIR, default ~/cynthia-gate) so the
# subprocess load lands on that box's cores, not the orchestrator's.
_REMOTE_GATE_PY = os.environ.get("CYNTHIA_GATE_PY", "~/cynthia-core/.venv/bin/python")
_REMOTE_GATE_DIR = os.environ.get("CYNTHIA_GATE_DIR", "~/cynthia-gate")


def _gate_remote(src_path: Path, cap: int, host: str, *, retries: int = 1) -> dict:
    """Ship one oracle module to the SSH gate worker; return its verdict dict. A worker/SSH
    failure degrades to RED (never raises) so one lost draft can't kill a best-of-N batch."""
    import subprocess  # local import: only loaded on the remote-gate path
    src = src_path.read_text()
    remote_cmd = f"{_REMOTE_GATE_PY} {_REMOTE_GATE_DIR}/remote_gate.py {cap}"
    cmd = ["ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", host, remote_cmd]
    for _ in range(retries + 1):
        try:
            p = subprocess.run(cmd, input=src, capture_output=True, text=True, timeout=200)
            if p.returncode == 0 and p.stdout.strip():
                return json.loads(p.stdout)
        except Exception:  # noqa: BLE001 — SSH/timeout/parse all retry then RED
            continue
    return _normalize_verdict(_Broken(f"remote gate failed on {host}"))


def gate_authored(module_name: str, oracles_dir: Path, *, cap: int = 40) -> dict:
    """Compile-check, import, and mutation-gate one authored oracle module.
    Any failure of the AUTHORED module degrades to a RED verdict dict, never an exception.
    With CYNTHIA_GATE_HOST set, the gate runs on that remote worker instead of locally."""
    src_path = oracles_dir / f"{module_name}.py"
    try:
        compile(src_path.read_text(), str(src_path), "exec")
    except SyntaxError as exc:
        return _normalize_verdict(_Broken(f"syntactically broken (likely truncated): {exc}"))
    host = os.environ.get("CYNTHIA_GATE_HOST")
    if host:
        return _gate_remote(src_path, cap, host)
    inserted = str(oracles_dir) not in sys.path
    if inserted:
        sys.path.insert(0, str(oracles_dir))
    try:
        try:
            importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001 — the LLM module failing to import is a RED
            return _normalize_verdict(_Broken(f"import failed: {type(exc).__name__}: {exc}"))
        from cynthia_core.mutate import run_mutation_gate
        try:
            # work_dir MUST be the oracle's own dir: the gate's subprocess drivers do
            # `import <module_name>` and resolve it via the driver script's directory.
            v = run_mutation_gate(module_name, work_dir=oracles_dir, cap=cap)
        except Exception as exc:  # noqa: BLE001 — contract violation inside check_impl is a RED
            return _normalize_verdict(_Broken(
                f"oracle violates the gate contract: {type(exc).__name__}: {exc}"))
        return _normalize_verdict(v)
    finally:
        if inserted:
            sys.path.remove(str(oracles_dir))


# ---------------------------------------------------------------- the worker

@dataclass
class ResultRecord:
    qualname: str
    model: str
    attempts: int = 0
    gate: dict = field(default_factory=dict)
    cost: float = 0.0
    tokens: dict = field(default_factory=lambda: {"in": 0, "out": 0})
    oracle_path: str = ""
    elapsed: float = 0.0
    attempt_log: list = field(default_factory=list)

    @property
    def green(self) -> bool:
        return bool(self.gate.get("green"))

    def to_dict(self) -> dict:
        return {"qualname": self.qualname, "model": self.model, "attempts": self.attempts,
                "green": self.green, "gate": self.gate, "cost": round(self.cost, 6),
                "tokens": self.tokens, "oracle_path": self.oracle_path,
                "elapsed": round(self.elapsed, 1), "attempt_log": self.attempt_log}


def author_and_gate(entry: dict, model: str = DEFAULT_MODEL, run_dir: Path = Path("results/dev"),
                    *, attempts: int = DEFAULT_ATTEMPTS, max_tokens: int = DEFAULT_MAX_TOKENS,
                    gate_cap: int = 40, target: str = "") -> ResultRecord:
    """The per-function unit: author an oracle for one manifest entry, gate it, retry on RED.
    Returns a ResultRecord in EVERY case — model/HTTP/contract failures become RED records."""
    t0 = time.time()
    qhash = hashlib.sha1(entry["qualname"].encode()).hexdigest()[:10]
    # one dir per function: the gate writes tag-named driver/mutant files into the oracle's
    # dir, so a shared dir would collide when A03 gates many functions in parallel.
    oracles_dir = run_dir / "oracles" / f"{_safe_leaf(entry['qualname'])}_{qhash}"
    oracles_dir.mkdir(parents=True, exist_ok=True)
    spec, contract = build_prompt(entry, target=target)
    rec = ResultRecord(qualname=entry["qualname"], model=model)

    for n in range(1, attempts + 1):
        rec.attempts = n
        # unique module name per qualname AND attempt — sidesteps importlib's module cache,
        # which would otherwise gate attempt 1's module again on attempt 2.
        module_name = f"orc_{qhash}_a{n}"
        try:
            r = call_model(model, SYSTEM_PROMPT, spec + "\n" + contract, max_tokens=max_tokens)
        except Exception as exc:  # noqa: BLE001 — gateway/HTTP failure is a RED attempt, not a crash
            rec.attempt_log.append({"attempt": n, "error": f"{type(exc).__name__}: {exc}"})
            rec.gate = _normalize_verdict(_Broken(f"author call failed: {type(exc).__name__}: {exc}"))
            continue
        rec.cost += r["cost"]
        rec.tokens["in"] += r["in_tok"]
        rec.tokens["out"] += r["out_tok"]
        (oracles_dir / f"{module_name}.py").write_text(r["code"])
        (oracles_dir / f"{module_name}_raw.txt").write_text(r["raw"])
        rec.oracle_path = str(oracles_dir / f"{module_name}.py")
        rec.gate = gate_authored(module_name, oracles_dir, cap=gate_cap)
        rec.attempt_log.append({"attempt": n, "green": rec.gate["green"],
                                "kill_rate": rec.gate["kill_rate"], "note": rec.gate["note"],
                                "out_tok": r["out_tok"], "cost": round(r["cost"], 6),
                                "elapsed": r["elapsed"]})
        if rec.gate["green"]:
            break
    rec.elapsed = time.time() - t0
    return rec


# ---------------------------------------------------------------- best-of-N (reasoning models)

DEFAULT_BEST_OF_N = 8


def author_best_of_n(entry: dict, model: str, run_dir: Path, *, n: int = DEFAULT_BEST_OF_N,
                     temperature: float = 0.7, max_tokens: int = 8000, gate_cap: int = 40,
                     target: str = "", call_workers: int = 8, gate_workers: int = 1,
                     adaptive_fallback: bool = True) -> ResultRecord:
    """Author an oracle from a reasoning model (minimax-m3) FAST: fire N think-OFF streaming
    drafts in parallel (diverse via temperature) and let the MUTATION GATE select a GREEN one.

    Why this shape: think-OFF makes M3 ~15x faster but its single draft is fragile (it fails the
    gate's own ref-consistency check ~75% of the time). Best-of-N turns that into a strength —
    the gate is a mechanical selector, so P(>=1 GREEN of 8) ~= 90%, at the wall-time of ONE fast
    draft instead of one ~150s reasoning call. This is the verify-the-verifier thesis applied to
    authoring: trust cheap noisy generation because a non-vacuous gate filters it.

    Returns a ResultRecord (same interface as author_and_gate) whose gate/oracle_path are the
    BEST draft (first GREEN; else highest kill_rate), and whose cost/tokens sum ALL N drafts."""
    t0 = time.time()
    qhash = hashlib.sha1(entry["qualname"].encode()).hexdigest()[:10]
    base = run_dir / "oracles" / f"{_safe_leaf(entry['qualname'])}_{qhash}"
    base.mkdir(parents=True, exist_ok=True)
    spec, contract = build_prompt(entry, target=target)
    user = spec + "\n" + contract
    rec = ResultRecord(qualname=entry["qualname"], model=model)
    rec.attempts = n

    # phase 1 — N parallel think-OFF streaming drafts. Each draft gets its OWN dir so the
    # gate's tag-named driver/mutant files never collide when phase 2 gates them in parallel.
    def _draft(i: int):
        try:
            r = call_model(model, SYSTEM_PROMPT, user, max_tokens=max_tokens, timeout=90,
                           temperature=temperature, stream=True, thinking={"type": "disabled"})
        except Exception as exc:  # noqa: BLE001 — a failed draft is just one lost ticket
            return {"i": i, "error": f"{type(exc).__name__}: {exc}"}
        cand_dir = base / f"n{i}"
        cand_dir.mkdir(exist_ok=True)
        mod = f"orc_{qhash}_n{i}"
        (cand_dir / f"{mod}.py").write_text(r["code"])
        (cand_dir / f"{mod}_raw.txt").write_text(r["raw"])
        return {"i": i, "r": r, "dir": cand_dir, "mod": mod}

    with ThreadPoolExecutor(max_workers=call_workers) as pool:
        drafts = list(pool.map(_draft, range(n)))

    candidates = []
    for d in drafts:
        if "error" in d:
            rec.attempt_log.append({"attempt": d["i"], "error": d["error"]})
            continue
        r = d["r"]
        rec.cost += r["cost"]
        rec.tokens["in"] += r["in_tok"]
        rec.tokens["out"] += r["out_tok"]
        candidates.append(d)

    # phase 2 — gate every draft. Each gate spawns a mutant-subprocess swarm, so gating N
    # drafts × an outer per-function pool can OOM a RAM-tight box (it did: the first cross-
    # family run was OOM-killed at gate_workers=3 × phase1=2). gate_workers=1 keeps the
    # concurrent-gate count at/below the level the sequential deepseek path runs safely.
    def _gate(d):
        v = gate_authored(d["mod"], d["dir"], cap=gate_cap)
        return d, v

    graded = []
    if candidates:
        with ThreadPoolExecutor(max_workers=gate_workers) as gp:
            graded = list(gp.map(_gate, candidates))

    # select: first GREEN, else highest kill_rate (the gate is the selector).
    best = None
    for d, v in graded:
        rec.attempt_log.append({"attempt": d["i"], "green": v["green"],
                                "kill_rate": v["kill_rate"], "note": v["note"],
                                "out_tok": d["r"]["out_tok"], "cost": round(d["r"]["cost"], 6)})
        if best is None or (v["green"], v["kill_rate"]) > (best[1]["green"], best[1]["kill_rate"]):
            best = (d, v)

    # escalate-on-RED net (the harness's proven fallback): if no fast draft gated GREEN, spend
    # ONE slow thinking-ON draft — near-certain GREEN — so every function gets a cross-family
    # oracle. Fast for the ~90% that best-of-N nails; the slow tail pays only on the stubborn few.
    if adaptive_fallback and (best is None or not best[1]["green"]):
        try:
            r = call_model(model, SYSTEM_PROMPT, user, max_tokens=24000, timeout=300,
                           temperature=0.2, stream=True, thinking={"type": "adaptive"})
            rec.cost += r["cost"]
            rec.tokens["in"] += r["in_tok"]
            rec.tokens["out"] += r["out_tok"]
            cand_dir = base / "adaptive"
            cand_dir.mkdir(exist_ok=True)
            mod = f"orc_{qhash}_adaptive"
            (cand_dir / f"{mod}.py").write_text(r["code"])
            (cand_dir / f"{mod}_raw.txt").write_text(r["raw"])
            v = gate_authored(mod, cand_dir, cap=gate_cap)
            rec.attempt_log.append({"attempt": "adaptive_fallback", "green": v["green"],
                                    "kill_rate": v["kill_rate"], "note": v["note"],
                                    "out_tok": r["out_tok"], "cost": round(r["cost"], 6)})
            d = {"dir": cand_dir, "mod": mod, "r": r}
            if best is None or (v["green"], v["kill_rate"]) > (best[1]["green"], best[1]["kill_rate"]):
                best = (d, v)
        except Exception as exc:  # noqa: BLE001
            rec.attempt_log.append({"attempt": "adaptive_fallback",
                                    "error": f"{type(exc).__name__}: {exc}"})

    if best is not None:
        d, v = best
        rec.gate = v
        rec.oracle_path = str(d["dir"] / f"{d['mod']}.py")
    else:
        rec.gate = _normalize_verdict(_Broken("all best-of-N drafts failed to produce a module"))
    rec.elapsed = time.time() - t0
    return rec


# ---------------------------------------------------------------- demo entrypoint

def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="author + gate oracles for named manifest functions")
    ap.add_argument("manifest", type=Path)
    ap.add_argument("qualnames", nargs="+", help="function qualnames from the manifest")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    args = ap.parse_args()
    model, attempts = args.model, args.attempts
    manifest = json.loads(args.manifest.read_text())
    by_qual = {f["qualname"]: f for f in manifest["functions"]}
    run_dir = Path("results") / f"a02-{time.strftime('%Y%m%d-%H%M%S')}"
    run_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for qual in args.qualnames:
        if qual not in by_qual:
            print(f"   !! {qual} not in manifest; skipping", file=sys.stderr)
            continue
        entry = by_qual[qual]
        print(f"== {qual} ({entry['auditability']}; model={model})")
        rec = author_and_gate(entry, model, run_dir, attempts=attempts,
                              target=manifest["target"])
        for a in rec.attempt_log:
            print(f"   attempt {a['attempt']}: " + (f"ERROR {a['error']}" if "error" in a else
                  f"green={a['green']} kill_rate={a['kill_rate']:.2f} "
                  f"out={a['out_tok']} ${a['cost']:.4f} note={a['note'][:90]!r}"))
        print(f"   -> green={rec.green} attempts={rec.attempts} total=${rec.cost:.4f}")
        records.append(rec.to_dict())
    out = run_dir / "records.json"
    out.write_text(json.dumps(records, indent=2) + "\n")
    print(f"records: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
