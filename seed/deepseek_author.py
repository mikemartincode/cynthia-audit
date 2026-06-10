#!/usr/bin/env python3
"""SEED (proven 2026-06): DeepSeek authors a spec oracle; the cynthia-core mutation gate
validates it non-vacuous; the real function is run against it.

This is the single-function pattern the parallel auditor generalizes (coreship Phase 4 / A02).
Measured: deepseek-v4-pro authored a gate-GREEN oracle for semver comparison (29/29 mutants
killed) for ~$0.032; deepseek-v4-flash authored an inconsistent one the gate caught at
ref_passes=False for ~$0.0008. Both decisions mechanical, no human read.

Config is ENV-ONLY — no secret in the file (cynthia-audit never commits keys):
    LITELLM_GATEWAY   e.g. http://host:4000   (required)
    LITELLM_KEY       the bearer token        (required)
"""

from __future__ import annotations

import importlib
import json
import os
import re
import time
import urllib.request
from pathlib import Path

GATEWAY = os.environ["LITELLM_GATEWAY"].rstrip("/") + "/v1/chat/completions"
KEY = os.environ["LITELLM_KEY"]

# per-model gateway pricing ($/M tokens, in/out) — keep in sync with the gateway config.
PRICING = {"deepseek-v4-flash": (0.14, 0.28), "deepseek-v4-pro": (1.74, 3.48)}


def author_oracle(model: str, spec: str, contract: str, *, max_tokens: int = 20000,
                  timeout: int = 240) -> dict:
    """One DeepSeek authoring call. Returns {code, in_tok, out_tok, cost, elapsed}."""
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a precise Python engineer. Output only code."},
            {"role": "user", "content": spec + "\n" + contract},
        ],
        "temperature": 0.2,
        "max_tokens": max_tokens,  # pro is reasoning-on; 4k truncates mid-thought, use >=12k
    }).encode()
    req = urllib.request.Request(GATEWAY, data=body,
                                 headers={"Authorization": f"Bearer {KEY}",
                                          "Content-Type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    u = data.get("usage", {})
    rin, rout = PRICING.get(model, (0.0, 0.0))
    cost = u.get("prompt_tokens", 0) / 1e6 * rin + u.get("completion_tokens", 0) / 1e6 * rout
    raw = data["choices"][0]["message"]["content"]
    return {"code": _extract_code(raw), "raw": raw,
            "in_tok": u.get("prompt_tokens", 0), "out_tok": u.get("completion_tokens", 0),
            "cost": cost, "elapsed": round(time.time() - t0, 1)}


def _extract_code(text: str) -> str:
    # A fenced block is already delimited code — use the LONGEST one AS-IS. Re-slicing it (the prior
    # bug) dropped legitimate leading lines like `EQUIV_KEY = ...`. Take longest because a non-greedy
    # match can grab a partial block (e.g. a ``` inside a docstring).
    blocks = re.findall(r"```(?:python)?\s*(.*?)```", text, re.S)
    if blocks:
        return max(blocks, key=len).strip() + "\n"
    # No fence: the model was told "code only", but may still prepend reasoning prose. Start at the
    # first line that is plausibly code — import/def/class/docstring/comment OR a top-level
    # assignment (so a leading `EQUIV_KEY = ...` is kept, not skipped).
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if ln.startswith(("import ", "from ", "def ", "class ", '"""', "'''", "#!", "#")) \
                or re.match(r"^[A-Za-z_]\w*\s*[:=]", ln):
            return "\n".join(lines[i:]).strip() + "\n"
    return text.strip() + "\n"


class _BrokenVerdict:
    """Graceful-degradation stand-in: a truncated/syntactically-broken oracle records RED instead
    of crashing the batch (the harness must never die on one bad DeepSeek response)."""
    green = False
    kill_rate = 0.0

    def __init__(self, note: str):
        self.note = note


def gate_oracle(module_name: str, work_dir: Path) -> object:
    """Validate an authored oracle with the cynthia-core mutation gate (must be importable
    as `module_name` from work_dir). Returns the MutationVerdict (.green, .kill_rate, .note),
    or a _BrokenVerdict if the authored module won't even compile/import (truncated output, etc.)."""
    src = (work_dir / f"{module_name}.py").read_text()
    try:
        compile(src, f"{module_name}.py", "exec")  # catch truncation before import
    except SyntaxError as exc:
        return _BrokenVerdict(f"authored module is syntactically broken (likely truncated): {exc}")
    try:
        importlib.import_module(module_name)
    except Exception as exc:  # noqa: BLE001 - import/exec failure of the LLM module is a RED, not a crash
        return _BrokenVerdict(f"authored module failed to import: {type(exc).__name__}: {exc}")
    from cynthia_core.mutate import run_mutation_gate
    try:
        return run_mutation_gate(module_name, work_dir=work_dir)
    except Exception as exc:  # noqa: BLE001 - e.g. check_impl returns a non-list => contract violation, RED
        return _BrokenVerdict(f"oracle violates the check_impl contract "
                              f"(must return list[(bool,str)]): {type(exc).__name__}: {exc}")


# semver comparison spec + contract used by the seed run — A02 parameterizes these per function.
SEMVER_SPEC = """\
Semantic Versioning precedence (semver.org §11): MAJOR.MINOR.PATCH compared numerically; build
metadata ('+...') ignored; a version WITH a prerelease has LOWER precedence than one without;
prereleases compared identifier-by-identifier (numeric compared numerically, alphanumeric
lexically ASCII, numeric < alphanumeric, more-identifiers wins when all preceding are equal).
"""
ORACLE_CONTRACT = """\
Write ONE self-contained stdlib-only Python module defining a mutation-test oracle for a
COMPARATOR, conforming EXACTLY: compare_ref(pair) (pair=(a,b) strings, returns -/0/+ ; helpers
must be INNER functions); REFERENCE_FUNC=compare_ref; REFERENCE_NAME="compare_ref"; PROBE_INPUTS
= list of (a,b) tuples covering the tricky edges; EQUIV_KEY = lambda r: (r>0)-(r<0); check_impl(fn)
grading SIGN of fn(pair) against a HARD-CODED spec-derived expected sign per pair (do NOT call
compare_ref for expected). Output ONLY the module, no prose, no fences.
HARD conformance rules (the cheap model breaks these one-shot — state them loudly):
1. Write `def compare_ref` FIRST; every module-level assignment (REFERENCE_FUNC, REFERENCE_NAME,
   PROBE_INPUTS, EQUIV_KEY) and `def check_impl` come AFTER it — no forward reference.
2. PROBE_INPUTS is a list of exactly-2-tuples `(a, b)` of strings. Do NOT put a third element
   (no expected value in the tuple); check_impl computes the expected sign itself.
3. NO module-level execution: nothing runs at import except defs and the four assignments. Do not
   call check_impl or compare_ref at module level.
4. The module must import top-to-bottom with no error. Keep it short enough to finish (it will be
   run; truncation = failure).
5. check_impl(fn) MUST return a LIST of (bool, str) tuples — EXACTLY ONE per PROBE_INPUTS pair:
   `(EQUIV_KEY(fn(pair)) == hard_coded_expected_sign, "msg")`. NEVER return a bare bool.
"""

def author_until_green(model: str, spec: str, contract: str, work_dir: Path,
                       module_name: str = "deepseek_oracle", *, attempts: int = 4) -> tuple:
    """Retry-on-RED: a cheap model is high-variance and breaks the contract one-shot (forward
    reference, wrong-arity probes, truncation — all caught by the gate as RED). Regenerate up to
    `attempts` times until the gate GREENs. Returns (verdict, total_cost, n_attempts). This is the
    realistic per-function loop A02/A03 run; the gate, not the model, decides when to stop."""
    total = 0.0
    last = None
    for n in range(1, attempts + 1):
        r = author_oracle(model, spec, contract)
        total += r["cost"]
        (work_dir / f"{module_name}.py").write_text(r["code"])
        (work_dir / f"{module_name}_raw.txt").write_text(r["raw"])
        v = gate_oracle(module_name, work_dir)
        print(f"  attempt {n}: {r['elapsed']}s out={r['out_tok']} ${r['cost']:.4f} "
              f"-> green={v.green} kill_rate={v.kill_rate:.2f} note={getattr(v, 'note', '')!r}")
        last = v
        if v.green:
            break
    return last, total, n


if __name__ == "__main__":  # smoke: author-until-green end to end
    import sys
    model = sys.argv[1] if len(sys.argv) > 1 else "deepseek-v4-pro"
    here = Path(__file__).resolve().parent
    v, cost, n = author_until_green(model, SEMVER_SPEC, ORACLE_CONTRACT, here)
    print(f"=== {model}: green={v.green} after {n} attempt(s), total ${cost:.4f} ===")
