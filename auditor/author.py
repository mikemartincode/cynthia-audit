#!/usr/bin/env python3
"""auditor/author.py - per-function DeepSeek oracle author + mutation-gate worker.

Generalizes the proven seed (seed/deepseek_author.py): given one manifest entry
(from auditor/index.py), build an author prompt from its intent + spec/invariant
basis, have DeepSeek author an independent oracle module, validate it with the
cynthia-core mutation gate, and return a structured ResultRecord. Retry-on-RED:
the gate, not the model, decides when to stop.

Never raises on a bad model response - a broken/truncated/contract-violating
oracle degrades to a RED record so a batch (A03) survives any single failure.

Config is ENV-ONLY (no key in any file):
    LITELLM_GATEWAY   e.g. http://host:4000   (required at call time, not import)
    LITELLM_KEY       bearer token            (required at call time)

Demo (3 manifest entries, prints + saves records):
    python auditor/author.py targets/hyperlink/manifest.json parse_host iter_pairs ...
"""

from __future__ import annotations

import ast
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
import trace as _trace  # noqa: E402 - the execution-trace sink (no-op unless AUDITOR_TRACE_DIR set)
from gate_subprocess import gate_subprocess as _gate_subprocess  # noqa: E402 - capped, hard-kill gate

# per-model gateway pricing ($/M tokens, in/out) - keep in sync with the gateway config.
# (input, output) USD per 1M tokens - DeepSeek's published cache-MISS + output rates.
# This is a deliberately conservative budget-rail estimate: it bills every input token at the
# miss rate, ignoring DeepSeek prefix-cache hits (which bill at ~1/120th: $0.003625/M for pro).
# The cache-accurate spend is LiteLLM's response_cost (x-litellm-response-cost) / /spend/logs -
# use those for real reporting; this dict only needs to never UNDER-count for the hard cap.
PRICING = {"deepseek-v4-flash": (0.14, 0.28), "deepseek-v4-pro": (0.435, 0.87)}

DEFAULT_MODEL = "deepseek-v4-pro"
DEFAULT_ATTEMPTS = 4
DEFAULT_MAX_TOKENS = 20000  # pro is reasoning-on; 12k can truncate mid-module (measured)


# ---------------------------------------------------------------- gateway call

def _read_stream(resp) -> tuple[str, dict]:
    """Accumulate an OpenAI-compatible SSE stream into (content, usage). Streaming is what
    makes a reasoning model (minimax-m3) usable here: the gateway buffers a non-stream response
    until the whole reasoning trace finishes, which can exceed the read timeout - incremental
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
        except Exception:  # noqa: BLE001 - keepalive / partial line
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
               thinking: dict | None = None, reasoning_effort: str | None = None,
               meta: dict | None = None) -> dict:
    """One authoring call. Returns {code, raw, in_tok, out_tok, cost, elapsed}.
    Raises urllib errors upward - callers convert them to RED records.

    `stream=True` reads the response incrementally (required for reasoning models, whose
    non-stream response the gateway buffers past the timeout). `thinking={'type':'disabled'}`
    turns OFF a reasoning model's chain-of-thought - ~15x faster, but the draft is more fragile
    (callers compensate with best-of-N + the mutation gate as the selector). `reasoning_effort`
    ('low'|'medium'|'high') is the OpenAI-style reasoning dial DeepSeek honors - the output-token
    lever for a reasoning model that can't go fully OFF (reasoning is ~97% of the spend; 'low' cuts
    it). On M3 it was measured a no-op (use `thinking` instead). Pass at most ONE of the two.

    `meta` is trace-only context (qualname, role, attempt/draft id, shape) attached to the emitted
    `llm_call` event - it never touches the request payload."""
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
    if reasoning_effort is not None:
        payload["reasoning_effort"] = reasoning_effort
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
    # Passive prefix-cache read tokens, surfaced so the bake-off can VERIFY the cache fires
    # (cache_read>0 on call 2+). LiteLLM passes the provider's count either flat
    # (cache_read_input_tokens) or in OpenAI's prompt_tokens_details.cached_tokens - read both.
    cache_read = int(u.get("cache_read_input_tokens")
                     or (u.get("prompt_tokens_details") or {}).get("cached_tokens", 0) or 0)
    out = {"code": extract_code(raw), "raw": raw,
           "in_tok": u.get("prompt_tokens", 0), "out_tok": u.get("completion_tokens", 0),
           "cache_read": cache_read,
           "cost": cost, "elapsed": round(time.time() - t0, 1)}
    if _trace.enabled():
        m = meta or {}
        _trace.emit("llm_call", qualname=m.get("qualname", ""), role=m.get("role", ""),
                    shape=m.get("shape", ""), model=model, temperature=temperature,
                    max_tokens=max_tokens, thinking=(thinking or {}).get("type", ""),
                    stream=stream, system=system, user=user, response_raw=raw,
                    extracted_code=out["code"], in_tok=out["in_tok"], out_tok=out["out_tok"],
                    cache_read=cache_read,
                    cost=round(cost, 6), elapsed=out["elapsed"],
                    meta={k: v for k, v in m.items() if k not in ("qualname", "role", "shape")})
    return out


def extract_code(text: str) -> str:
    """A fenced block is already delimited code - use the LONGEST one AS-IS (a non-greedy
    match can grab a partial block when a ``` appears inside a docstring). No fence: start
    at the first plausibly-code line so leading reasoning prose is dropped but a leading
    top-level assignment is kept.

    Reasoning-model output is stripped of <think>…</think> FIRST - otherwise the longest-fenced
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

# The reference impl's in-module name is FIXED (not per-function). Each oracle lives in its own
# module/dir, so a per-function name bought nothing - but a fixed name makes the authoring CONTRACT
# (which embeds {ref_name}) byte-identical across every function, which is what lets the passive
# prefix cache fire: the static contract block is the cacheable prefix, the per-function spec the
# dynamic suffix (see _author_independent). The gate reads REFERENCE_NAME from the module, so the
# fixed name is invisible to it.
REF_NAME = "ref_impl"

def _safe_leaf(qualname: str) -> str:
    return re.sub(r"\W", "_", qualname.split(".")[-1]).lower()


def _convention_hint(entry: dict) -> str:
    """Pin the one-argument tuple convention for multi-input functions, derived from the
    manifest signature.

    Measured (first idna run, trace_report): every convention-mismatch RED was a multi-arg
    function (4/4) and no single-arg function failed that way (0/13). Left unpinned, the
    independently-authored reference and battery each invent their OWN tuple layout, so the
    gate's cross-acceptance check fails on layout, not spec - a predictable, recoverable RED.
    Pinning the exact layout here (in the SHARED spec text both calls read) removes the
    ambiguity without coupling the two authors. Single-input functions get no hint: they have
    no measured failures and extra text is extra drift surface."""
    try:
        node = ast.parse(f"def _f{entry.get('signature', '') or '()'}: pass").body[0]
    except SyntaxError:
        return ""
    a = node.args
    allpos = a.posonlyargs + a.args
    names = [p.arg for p in allpos if p.arg != "self"] + [p.arg for p in a.kwonlyargs]
    dflt: dict[str, str] = {}
    for p, d in zip(allpos[len(allpos) - len(a.defaults):], a.defaults):
        if p.arg != "self":
            dflt[p.arg] = ast.unparse(d)
    for p, d in zip(a.kwonlyargs, a.kw_defaults):
        if d is not None:
            dflt[p.arg] = ast.unparse(d)
    is_method = "." in entry["qualname"]
    items = (["<the object's textual form>"] if is_method else []) + names
    vararg = a.vararg.arg if a.vararg else None
    if len(items) + (1 if vararg else 0) < 2:
        return ""
    tuple_disp = "(" + ", ".join(items + ([f"*{vararg}"] if vararg else [])) + ")"
    n = len(items)
    lines = ["", "CALLING CONVENTION (fixed - the reference and the battery MUST both assume "
                 "exactly this layout; do not invent another):"]
    if vararg:
        lines.append(f"`arg` is a tuple of AT LEAST {n} item(s): arg = {tuple_disp} - the "
                     f"first {n} fixed as named, then zero or more `{vararg}` values.")
    else:
        lines.append(f"`arg` is a tuple of EXACTLY {n} items, in this order: "
                     f"arg = {tuple_disp}.")
    if dflt:
        rendered = ", ".join(f"{k}={v}" for k, v in dflt.items())
        lines.append(f"Defaulted parameters ({rendered}) still occupy their slot in EVERY "
                     "probe tuple - pass the default's value explicitly (use None where the "
                     "default is a library-internal sentinel); never use a shorter tuple.")
    return "\n".join(lines)


def build_spec(entry: dict, target: str = "", shape: str = "value", *,
               convention_hint: bool = True) -> str:
    """The SPEC text for one manifest entry - the single shared input both the reference and the
    battery are authored from (independently). The reference/battery CONTRACTS live separately
    (REFERENCE_CONTRACT / BATTERY_CONTRACT); there is no combined single-call contract.

    This is the DYNAMIC (per-function) suffix of the authoring prompt; the static contract is the
    prefix (_author_independent assembles contract-first so the prefix cache fires). `shape` only
    affects the convention hint: stubbed_seam carries its own (seam, *args) convention in its
    contract, so the standard multi-arg tuple hint (which describes real args only) is suppressed
    for it."""
    lines = [
        f"TARGET BEHAVIOR - `{entry['qualname']}{entry['signature']}`"
        + (f" from the `{target}` library." if target else "."),
        f"INTENT: {entry['intent']}",
    ]
    doc = (entry.get("doc") or "").strip()
    if entry["auditability"] == "spec" and doc:
        lines += ["", "SPEC (the documented behavior - author your oracle from THIS):",
                  doc]
    elif entry["auditability"] == "invariant":
        lines += ["", f"UNIVERSAL INVARIANT: {entry['auditability_why']} - check_impl must "
                      "verify this invariant over the probe inputs."]
        if doc:
            lines += ["", "Documented behavior:", doc]
    if "." in entry["qualname"]:
        lines += ["", "NOTE: the original is a method. Your reference must be a standalone "
                      "pure function over plain text/tuple inputs that captures the same "
                      "specified behavior (e.g. take the object's textual form as input)."]
    if shape != "stubbed_seam" and convention_hint:  # stubbed_seam carries its own (seam,*args) convention
        hint = _convention_hint(entry)
        if hint:
            lines.append(hint)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- independent authoring (#1)
#
# Authoring reference + battery + probes in ONE call makes the gate's step-0 ref_passes a
# TAUTOLOGY: the model wrote both to agree, so "battery accepts reference" is guaranteed and
# proves nothing about spec fidelity. A model that misreads the spec produces a coherent WRONG
# oracle that gates GREEN. Splitting the authoring into two independent reads of the spec - a
# reference (model A) and a battery (model B, never shown the reference) - turns ref_passes into
# a real CROSS-ACCEPTANCE check: if the independent battery rejects the independent reference,
# they disagree on the spec -> mechanical ESCALATE, not a silent retry into agreement. Set
# CYNTHIA_BATTERY_MODEL to author the battery with a DIFFERENT family (breaks correlated misreads).

REFERENCE_CONTRACT = """\
Write ONE stdlib-only Python snippet defining ONLY a reference implementation of the behavior
specified below - no probes, no grader:

- `def {ref_name}(arg)`: a known-correct PURE reference, written from the SPEC. Do NOT recall the
  library's own source - implement independently. EXACTLY ONE positional argument; if the behavior
  needs multiple inputs, `arg` is a tuple {ref_name} unpacks. Every helper is an INNER function.
  Raise ValueError for spec-invalid inputs.
- `REFERENCE_FUNC = {ref_name}` and `REFERENCE_NAME = "{ref_name}"`.

HARD rules: `def {ref_name}` first, then the two assignments, nothing else at module level; no
module-level execution; stdlib only, imports at the top, imports clean. Output ONLY the code -
NO PROBE_INPUTS, NO check_impl, no prose, no fences.
"""

BATTERY_CONTRACT = """\
Write ONE stdlib-only Python snippet defining a mutation-test BATTERY for the behavior specified
below. You are NOT given the reference implementation - derive EVERY expectation from the SPEC
alone (this independence is the point):

- `PROBE_INPUTS`: 8-20 inputs covering the tricky edges of the spec. Each item is ONE argument
  value (string or tuple of strings preferred), round-trips through repr() exactly, and carries NO
  expected value.
- `def check_impl(fn)`: grades an ARBITRARY implementation `fn` (one-argument convention matching
  PROBE_INPUTS) against the SPEC. Expected outcomes are HARD-CODED from the spec, or asserted as
  spec properties (round-trip, idempotence, error-on-invalid). You have NO reference to call -
  compute expectations from the SPEC, never by grading fn against itself. Return a LIST of
  (bool, str), exactly one per PROBE_INPUTS, in order. fn raising where the spec demands an error
  is a PASS; fn raising elsewhere - catch it, record FAIL. check_impl MUST NOT raise.
- OPTIONAL `EQUIV_KEY = lambda out: ...` ONLY if check_impl grades a projection (e.g. a sign).

HARD rules: the function being graded (named `{ref_name}`) is provided SEPARATELY - assume it
exists, grade the `fn` you are handed; define NO reference implementation yourself. No module-level
execution; stdlib only, imports clean. Output ONLY the code - no reference impl, no prose, no fences.
"""


# A SECOND oracle SHAPE. The value battery hard-codes spec expectations per probe; an INVARIANT
# (metamorphic) battery instead asserts RELATIONS that hold over ALL valid inputs - round-trip
# identity (`from_text(to_text(u)) == u`), idempotence (`normalize(normalize(u)) == normalize(u)`),
# inverse-op stability. This unlocks the round-trip / stateful bug CLASS the single-call value
# oracle structurally can't see. It reuses the SAME mutation gate and the SAME independent
# reference (the reference is a correct impl regardless of how it's checked); ONLY the battery
# contract changes. A vacuous invariant (a relation that holds trivially) is caught RED by the gate
# exactly like a vacuous value battery - the verify-the-verifier guarantee generalizes for free.
INVARIANT_BATTERY_CONTRACT = """\
Write ONE stdlib-only Python snippet defining a mutation-test BATTERY that checks the behavior
specified below via METAMORPHIC INVARIANTS - relations that hold for EVERY valid input - rather
than hard-coded input->output values. You are NOT given the reference implementation; derive the
invariants from the SPEC alone (this independence is the point):

- `PROBE_INPUTS`: 8-20 valid inputs covering the tricky edges of the spec. Each item is ONE argument
  value (string or tuple of strings preferred), round-trips through repr() exactly, and carries NO
  expected value.
- `def check_impl(fn)`: grades an ARBITRARY implementation `fn` (one-argument convention matching
  PROBE_INPUTS) by asserting INVARIANTS over `fn` applied to each probe. Use relations derived from
  the spec, e.g.:
    * round-trip / identity:  for a canonical input, fn(x) == x  (or fn reconstructs x exactly);
    * idempotence:            fn(fn(x)) == fn(x);
    * inverse / structure preservation: a spec relation between input and output.
  Combine >=2 relations so the battery has TEETH: a relation that holds TRIVIALLY (fn(x) == fn(x),
  isinstance-only, etc.) is VACUOUS and the mutation gate will REJECT it. You have NO reference to
  call - compute the invariants from the SPEC, never by grading fn against itself. Return a LIST of
  (bool, str), exactly one per PROBE_INPUTS, in order. fn raising where the spec demands an error is
  a PASS; fn raising elsewhere - catch it, record FAIL. check_impl MUST NOT raise.
- OPTIONAL `EQUIV_KEY = lambda out: ...` ONLY if check_impl grades a projection.

HARD rules: the function being graded (named `{ref_name}`) is provided SEPARATELY - assume it
exists, grade the `fn` you are handed; define NO reference implementation yourself. No module-level
execution; stdlib only, imports clean. Output ONLY the code - no reference impl, no prose, no fences.
"""

# A THIRD oracle SHAPE - PROPERTY. The value battery hard-codes spec expectations per probe; the
# invariant battery asserts round-trip/idempotence/inverse relations. The property battery asserts
# RELATIONAL/ALGEBRAIC facts that hold for each input (output domain, ordering/monotonicity,
# size/bounds, membership/structure, error-on-invalid) WITHOUT needing an inverse sibling - the
# coverage rung for functions whose exact output is hard to hard-code yet whose spec still pins
# checkable properties. Same shared reference, same gate; only the battery contract changes.
PROPERTY_BATTERY_CONTRACT = """\
Write ONE stdlib-only Python snippet defining a mutation-test BATTERY that checks the behavior
specified below via SPEC PROPERTIES - relational/algebraic facts the output must satisfy for each
input - rather than a single hard-coded input->output value table. You are NOT given the reference
implementation; derive the properties from the SPEC alone (this independence is the point):

- `PROBE_INPUTS`: 8-20 inputs covering the tricky edges of the spec. Each item is ONE argument
  value (string or tuple of strings preferred), round-trips through repr() exactly, carries NO
  expected value.
- `def check_impl(fn)`: grades an ARBITRARY implementation `fn` (one-argument convention matching
  PROBE_INPUTS) by asserting SPEC PROPERTIES of `fn(x)`, e.g.:
    * output domain/type: fn(x) is always in the spec's result set / type / format;
    * ordering / monotonicity: a spec-mandated order relation between inputs is preserved in outputs;
    * bounds / size: a spec relation on the length/magnitude of the output;
    * membership / structure: the output contains / excludes spec-required substructure;
    * error-on-invalid: fn raises where the spec forbids the input.
  Combine >=2 INDEPENDENT properties with REAL discriminating power so the battery has TEETH: a
  property that holds for almost any function (isinstance-only, "is not None", len>=0) is VACUOUS and
  the mutation gate will REJECT it. You have NO reference to call - compute the properties from the
  SPEC, never by grading fn against itself. Return a LIST of (bool, str), exactly one per
  PROBE_INPUTS, in order. fn raising where the spec demands an error is a PASS; fn raising elsewhere
  - catch it, record FAIL. check_impl MUST NOT raise.
- OPTIONAL `EQUIV_KEY = lambda out: ...` ONLY if check_impl grades a projection.

HARD rules: the function being graded (named `{ref_name}`) is provided SEPARATELY - assume it
exists, grade the `fn` you are handed; define NO reference implementation yourself. No module-level
execution; stdlib only, imports clean. Output ONLY the code - no reference impl, no prose, no fences.
"""

# A FOURTH oracle SHAPE - STUBBED-SEAM, the recovery rung for deterministic=False functions. The
# function's output depends on a nondeterministic SEAM (time/random/env/IO) but is otherwise a
# deterministic function of its inputs. The reference makes that dependence EXPLICIT - it takes the
# seam value as an injected first element of the input tuple (arg = (seam, *real_inputs)) and never
# calls the real nondeterministic source - turning an impure function into a pure, mutatable one.
# PROBE_INPUTS vary the seam across a RANGE so the oracle can't memorize one seam (the strict
# memorizer/coverage closers reject a single-seam oracle). This rung needs its OWN reference contract
# (the seam-injection convention differs from the plain one); the battery is its twin.
STUBBED_SEAM_REFERENCE_CONTRACT = """\
The behavior specified below depends on a NONDETERMINISTIC SEAM (the value a clock / random draw /
environment lookup / IO read would return); its output is otherwise a deterministic function of its
inputs. Write ONE stdlib-only Python snippet defining ONLY a reference implementation that makes that
dependence EXPLICIT by taking the seam value as an injected input - no probes, no grader:

- `def {ref_name}(arg)`: a known-correct PURE reference written from the SPEC, where `arg` is a tuple
  whose FIRST element is the seam value (what the nondeterministic source would have returned) and
  the remaining elements are the function's real inputs in order: arg = (seam, <real inputs...>).
  Compute the spec's result deterministically FROM the seam and the real inputs. Do NOT call
  time/random/os/secrets/IO yourself - the seam REPLACES them. Implement independently from the SPEC
  (do not recall the library source). Every helper is an INNER function. Raise ValueError for
  spec-invalid inputs.
- `REFERENCE_FUNC = {ref_name}` and `REFERENCE_NAME = "{ref_name}"`.

HARD rules: `def {ref_name}` first, then the two assignments, nothing else at module level; no
module-level execution; NO call to time/random/os/secrets/IO (the seam stands in for all of them);
stdlib only, imports clean. Output ONLY the code - NO PROBE_INPUTS, NO check_impl, no prose, no fences.
"""
STUBBED_SEAM_BATTERY_CONTRACT = """\
The behavior specified below depends on a NONDETERMINISTIC SEAM made EXPLICIT as the FIRST element of
each input tuple: arg = (seam, <real inputs...>). Write ONE stdlib-only Python snippet defining a
mutation-test BATTERY over that injected-seam convention. You are NOT given the reference
implementation; derive every expectation from the SPEC alone:

- `PROBE_INPUTS`: 8-20 tuples (seam, <real inputs...>). VARY THE SEAM ACROSS A RANGE of >=4 distinct
  values (never one fixed seam) AND cover the tricky edges of the real inputs - an oracle that probes
  only one seam value is vacuous and the gate's coverage/memorizer closers will REJECT it. Each item
  round-trips through repr() exactly and carries NO expected value.
- `def check_impl(fn)`: grades an ARBITRARY `fn(arg)` against the SPEC, computing the expected result
  from BOTH the seam and the real inputs in each tuple (hard-coded from the spec, or asserted as a
  spec relation that must change with the seam). For at least some probes the expected result MUST
  genuinely depend on the seam, so an impl that ignores the seam FAILS. You have NO reference to call.
  Return a LIST of (bool, str), exactly one per PROBE_INPUTS, in order. fn raising where the spec
  demands an error is a PASS; fn raising elsewhere - catch it, record FAIL. check_impl MUST NOT raise.
- OPTIONAL `EQUIV_KEY = lambda out: ...` ONLY if check_impl grades a projection.

HARD rules: the function being graded (named `{ref_name}`) is provided SEPARATELY - assume it exists,
grade the `fn` you are handed; define NO reference implementation yourself. No module-level execution;
stdlib only, imports clean. Output ONLY the code - no reference impl, no prose, no fences.
"""


# Shape registries. Every entry is pre-formatted with the FIXED REF_NAME so the contract block is
# byte-identical across all functions - the stable prefix the passive cache keys on. The reference
# contract is shared across value/invariant/property (a correct impl is a correct impl); stubbed_seam
# needs its own (the seam-injection convention). Adding a shape = one entry in each map + a prompt;
# the gate is untouched. ORACLE_SHAPES is the canonical strategy-ladder order.
ORACLE_SHAPES = ("value", "invariant", "property", "stubbed_seam")

_REFERENCE_CONTRACTS = {
    "value": REFERENCE_CONTRACT.format(ref_name=REF_NAME),
    "invariant": REFERENCE_CONTRACT.format(ref_name=REF_NAME),
    "property": REFERENCE_CONTRACT.format(ref_name=REF_NAME),
    "stubbed_seam": STUBBED_SEAM_REFERENCE_CONTRACT.format(ref_name=REF_NAME),
}
_BATTERY_CONTRACTS = {
    "value": BATTERY_CONTRACT.format(ref_name=REF_NAME),
    "invariant": INVARIANT_BATTERY_CONTRACT.format(ref_name=REF_NAME),
    "property": PROPERTY_BATTERY_CONTRACT.format(ref_name=REF_NAME),
    "stubbed_seam": STUBBED_SEAM_BATTERY_CONTRACT.format(ref_name=REF_NAME),
}


def build_reference_prompt(entry: dict, target: str = "", shape: str = "value") -> tuple[str, str]:
    return (build_spec(entry, target=target, shape=shape), _REFERENCE_CONTRACTS[shape])


def build_battery_prompt(entry: dict, target: str = "", shape: str = "value") -> tuple[str, str]:
    return (build_spec(entry, target=target, shape=shape), _BATTERY_CONTRACTS[shape])


_EXEMPLAR_FRAME = {
    "reference": (
        "EXAMPLE (for STRUCTURE ONLY - a reference of the SAME oracle shape that PASSED the mutation "
        "gate for a DIFFERENT function in a DIFFERENT library). Study how it implements independently "
        "from a spec, names its single `arg`, factors helpers as inner functions, and raises on "
        "invalid input. Then write YOUR reference for the TARGET above. Do NOT copy its logic or "
        "imports - it solves a different spec; reproducing it would be wrong:"),
    "battery": (
        "EXAMPLE (for STRUCTURE ONLY - a battery of the SAME oracle shape that PASSED the mutation "
        "gate for a DIFFERENT function in a DIFFERENT library). Study how it builds discriminating, "
        "non-vacuous probes and derives expectations from the spec alone. Then write YOUR battery for "
        "the TARGET above. Do NOT copy its probes or expectations - it tests a different spec; "
        "reproducing it would be wrong. Define NO reference implementation:"),
}


def _frame_exemplar(role: str, code: str | None) -> str:
    """Wrap a retrieved exemplar half in role-specific framing, or '' when there is none. The frame
    states emphatically that the exemplar is a DIFFERENT function (so the model imitates rigor/shape,
    not content) - and for the battery role re-asserts 'define NO reference' so a stray reference in
    an example can't tempt the battery author to re-couple the two independent spec reads."""
    if not code:
        return ""
    return _EXEMPLAR_FRAME[role] + "\n\n" + code.strip()


def _author_independent(entry: dict, ref_model: str, battery_model: str, *, target: str = "",
                        max_tokens: int = DEFAULT_MAX_TOKENS, temperature: float = 0.2,
                        stream: bool = False, thinking: dict | None = None,
                        reasoning_effort: str | None = None, timeout: int = 300,
                        shape: str = "value", trace_meta: dict | None = None,
                        exemplar: dict | None = None, front_load: str | None = None,
                        convention_hint: bool = True) -> dict:
    """Author reference (ref_model) and battery (battery_model) INDEPENDENTLY, assemble one module.
    Returns {code, cost, in_tok, out_tok, raw} or {error}. Raises nothing the caller can't survive.

    The two calls run sequentially. Firing them concurrently was tried and measured NEUTRAL under
    real best-of-N load: at N=8 the 16 in-flight m3 streams are throughput-bound on the gateway, so
    one 16-wide wave costs the same wall as two 8-wide waves (AUTH 28s either way on URL.scheme).
    The concurrent variant only won in an isolated single-draft test with spare gateway capacity, so
    it was dropped - it added a cap-breach risk under run.py's fan-out for no real-load gain.

    AUGMENTED-GENERATION RECALL (#1): `exemplar`, when given, is {"reference": <ref half>, "battery":
    <battery half>} retrieved (leave-one-out clean) from a GREEN same-shape oracle for a DIFFERENT
    function - injected so the model can author past its one-shot ceiling. It rides the DYNAMIC suffix
    (after the spec), so the static contract PREFIX the passive cache keys on stays byte-identical; an
    absent half is simply not injected. Independence is preserved: each role sees only its OWN half, so
    the battery author never sees a reference and the gate's cross-acceptance check stays real."""
    spec = build_spec(entry, target=target, shape=shape, convention_hint=convention_hint)  # DYNAMIC suffix
    ref_contract = _REFERENCE_CONTRACTS[shape]             # STATIC cacheable prefix (per shape/role)
    bat_contract = _BATTERY_CONTRACTS[shape]
    ex = exemplar or {}
    ex_suffix = {"reference": _frame_exemplar("reference", ex.get("reference")),
                 "battery": _frame_exemplar("battery", ex.get("battery"))}
    base_meta = {"qualname": entry.get("qualname", ""), "shape": shape, **(trace_meta or {})}
    def _call(model, contract, role):
        # STATIC contract FIRST, DYNAMIC spec + (optional) front-load + exemplar LAST - the byte-identical
        # contract block is the passive prefix cache's hit; interleaving per-function text earlier would
        # break it. front_load (spec-derived test data) and the exemplar trail the spec in the suffix.
        user = contract + "\n\n" + spec
        if front_load:
            user += "\n\n" + front_load
        if ex_suffix[role]:
            user += "\n\n" + ex_suffix[role]
        return call_model(model, SYSTEM_PROMPT, user, max_tokens=max_tokens, timeout=timeout,
                          temperature=temperature, stream=stream, thinking=thinking,
                          reasoning_effort=reasoning_effort, meta={**base_meta, "role": role})
    try:
        rr = _call(ref_model, ref_contract, "reference")
        rb = _call(battery_model, bat_contract, "battery")
    except Exception as exc:  # noqa: BLE001 - gateway failure is a RED attempt, not a crash
        return {"error": f"{type(exc).__name__}: {exc}"}
    code = rr["code"].rstrip() + "\n\n" + rb["code"]
    return {"code": code, "raw": rr["raw"] + "\n--- battery ---\n" + rb["raw"],
            "cost": rr["cost"] + rb["cost"], "in_tok": rr["in_tok"] + rb["in_tok"],
            "out_tok": rr["out_tok"] + rb["out_tok"],
            "cache_read": rr.get("cache_read", 0) + rb.get("cache_read", 0)}


def _battery_model(ref_model: str) -> str:
    return os.environ.get("CYNTHIA_BATTERY_MODEL", ref_model)


def _is_spec_disagreement(gate: dict) -> bool:
    """A non-green verdict whose ref_passes is False: under INDEPENDENT authoring this means the
    battery rejects the reference - the two spec-reads disagree (escalate), distinct from a
    vacuous-but-self-consistent oracle (survivors)."""
    return bool(gate) and not gate.get("green") and not gate.get("ref_passes")


# ---------------------------------------------------------------- gate plumbing

def _normalize_verdict(v: object) -> dict:
    """MutationVerdict | broken-marker -> plain JSON-able dict.

    `green` is GATE-GREEN - the base operator pass (ref accepted, every non-equivalent mutant
    killed) - computed from the component fields so it means the same thing whether or not strict
    ran. (MutationVerdict.green folds the strict `loose` check INTO green when strict=True; recording
    that as `green` would silently tighten the flag every existing caller keys on. We keep `green` =
    base operator pass and expose the strict tightening as a separate `strict_green`.)
    `strict_green` additionally requires the author-blind memorizer + coverage closers to pass -
    the truer (non-example-based) quality bar. Inert (False) unless the gate ran with strict=True."""
    ref_passes = bool(getattr(v, "ref_passes", False))
    non_equivalent = int(getattr(v, "non_equivalent", 0))
    survivors = list(getattr(v, "survivors", []) or [])
    errored = list(getattr(v, "errored", []) or [])
    kill_rate = float(getattr(v, "kill_rate", 0.0))
    threshold = float(getattr(v, "threshold", 1.0))
    strict = bool(getattr(v, "strict", False))
    memorizer_survives = bool(getattr(v, "memorizer_survives", False))
    coverage_survivors = list(getattr(v, "coverage_survivors", []) or [])
    base_green = (ref_passes and non_equivalent > 0 and not survivors and not errored
                  and kill_rate >= threshold)
    strict_green = bool(base_green and strict and not memorizer_survives and not coverage_survivors)
    return {
        "green": base_green,
        "strict_green": strict_green,
        "strict": strict,
        "kill_rate": kill_rate,
        "ref_passes": ref_passes,
        "generated": int(getattr(v, "generated", 0)),
        "non_equivalent": non_equivalent,
        "killed": int(getattr(v, "killed", 0)),
        "survivors": survivors,
        "errored": errored,
        "memorizer_survives": memorizer_survives,
        "recorded_inputs": int(getattr(v, "recorded_inputs", 0)),
        "recorder_passed": bool(getattr(v, "recorder_passed", True)),
        "coverage_survivors": coverage_survivors,
        "coverage_generated": int(getattr(v, "coverage_generated", 0)),
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


def _gate_remote(src_path: Path, cap: int, host: str, *, fail_fast: bool = False,
                 retries: int = 1) -> dict:
    """Ship one oracle module to the SSH gate worker; return its verdict dict. A worker/SSH
    failure degrades to RED (never raises) so one lost draft can't kill a best-of-N batch."""
    import subprocess  # local import: only loaded on the remote-gate path
    src = src_path.read_text()
    remote_cmd = f"{_REMOTE_GATE_PY} {_REMOTE_GATE_DIR}/remote_gate.py {cap} {1 if fail_fast else 0}"
    cmd = ["ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", host, remote_cmd]
    for _ in range(retries + 1):
        try:
            p = subprocess.run(cmd, input=src, capture_output=True, text=True, timeout=200)
            if p.returncode == 0 and p.stdout.strip():
                return json.loads(p.stdout)
        except Exception:  # noqa: BLE001 - SSH/timeout/parse all retry then RED
            continue
    return _normalize_verdict(_Broken(f"remote gate failed on {host}"))


def _trace_gate(qualname: str, module_name: str, oracles_dir: Path, verdict: dict,
                cap: int) -> None:
    """Emit a `gate` trace event with the FULL per-mutant table, reconstructed exactly the way
    the gate built it: generate_mutants(dedent(getsource(REFERENCE_FUNC)), [REFERENCE_NAME], cap).
    That AST pass is pure + deterministic, so the tag set is identical to what the gate scored;
    survivors/errored are named in the verdict, the remainder is killed-or-equivalence-filtered
    (the equivalent count is generated - non_equivalent, surfaced so the label is interpretable).
    Best-effort: any reconstruction failure still emits a minimal event, never breaks the gate."""
    if not _trace.enabled():
        return
    mutants_out: list[dict] = []
    note = ""
    try:
        import inspect
        import textwrap

        from cynthia_core.mutate import generate_mutants
        orc = importlib.import_module(module_name)
        ref_src = textwrap.dedent(inspect.getsource(orc.REFERENCE_FUNC))
        ref_name = orc.REFERENCE_NAME
        muts = generate_mutants(ref_src, [ref_name], cap=cap)
        survivors = set(verdict.get("survivors") or [])
        errored = set(verdict.get("errored") or [])
        for tag, src in muts.items():
            if tag in survivors:
                vr = "survived"
            elif tag in errored:
                vr = "errored"
            else:
                vr = "killed_or_equivalent"
            mutants_out.append({"tag": tag, "kind": re.split(r"[:#]", tag)[0], "verdict": vr,
                                "src": src})
    except Exception as exc:  # noqa: BLE001 - reconstruction is best-effort
        note = f"mutant reconstruction failed: {type(exc).__name__}: {exc}"
    equiv = max(0, verdict.get("generated", 0) - verdict.get("non_equivalent", 0))
    _trace.emit("gate", qualname=qualname, module=module_name, oracle_dir=oracles_dir.name,
                cap=cap, verdict=verdict, equivalent_count=equiv, mutants=mutants_out, note=note)


def gate_authored(module_name: str, oracles_dir: Path, *, cap: int = 40,
                  fail_fast: bool = False, qualname: str = "", strict: bool = False) -> dict:
    """Compile-check, import, and mutation-gate one authored oracle module.
    Any failure of the AUTHORED module degrades to a RED verdict dict, never an exception.
    With CYNTHIA_GATE_HOST set, the gate runs on that remote worker instead of locally.
    `fail_fast` (selection contexts) stops at the first genuine survivor - much faster on RED
    drafts; keep it OFF where exact kill rates matter. `strict` additionally runs the author-blind
    memorizer + coverage closers so the verdict carries strict_green (the truer quality bar); it is
    cheap for our oracles (memorizer is in-process; coverage fires only if the oracle supplies
    EDGE_INPUTS/COVERAGE_FILLS, which authored oracles don't). `qualname` is trace-only context."""
    src_path = oracles_dir / f"{module_name}.py"
    try:
        compile(src_path.read_text(), str(src_path), "exec")
    except SyntaxError as exc:
        v = _normalize_verdict(_Broken(f"syntactically broken (likely truncated): {exc}"))
        _trace_gate(qualname, module_name, oracles_dir, v, cap)
        return v
    host = os.environ.get("CYNTHIA_GATE_HOST")
    if host:
        v = _gate_remote(src_path, cap, host, fail_fast=fail_fast)
        _trace_gate(qualname, module_name, oracles_dir, v, cap)
        return v
    inserted = str(oracles_dir) not in sys.path
    if inserted:
        sys.path.insert(0, str(oracles_dir))
    try:
        try:
            importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001 - the LLM module failing to import is a RED
            v = _normalize_verdict(_Broken(f"import failed: {type(exc).__name__}: {exc}"))
            _trace_gate(qualname, module_name, oracles_dir, v, cap)
            return v
        from cynthia_core.mutate import run_mutation_gate
        try:
            # work_dir MUST be the oracle's own dir: the gate's subprocess drivers do
            # `import <module_name>` and resolve it via the driver script's directory.
            v = run_mutation_gate(module_name, work_dir=oracles_dir, cap=cap, fail_fast=fail_fast,
                                  strict=strict)
        except Exception as exc:  # noqa: BLE001 - contract violation inside check_impl is a RED
            vd = _normalize_verdict(_Broken(
                f"oracle violates the gate contract: {type(exc).__name__}: {exc}"))
            _trace_gate(qualname, module_name, oracles_dir, vd, cap)
            return vd
        vd = _normalize_verdict(v)
        _trace_gate(qualname, module_name, oracles_dir, vd, cap)
        return vd
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
    spec_disagreement: bool = False  # independent ref/battery disagreed on the spec (escalate)

    @property
    def green(self) -> bool:
        return bool(self.gate.get("green"))

    @property
    def strict_green(self) -> bool:
        return bool(self.gate.get("strict_green"))

    def to_dict(self) -> dict:
        return {"qualname": self.qualname, "model": self.model, "attempts": self.attempts,
                "green": self.green, "strict_green": self.strict_green,
                "spec_disagreement": self.spec_disagreement,
                "gate": self.gate, "cost": round(self.cost, 6),
                "tokens": self.tokens, "oracle_path": self.oracle_path,
                "elapsed": round(self.elapsed, 1), "attempt_log": self.attempt_log}


def author_and_gate(entry: dict, model: str = DEFAULT_MODEL, run_dir: Path = Path("results/dev"),
                    *, attempts: int = DEFAULT_ATTEMPTS, max_tokens: int = DEFAULT_MAX_TOKENS,
                    gate_cap: int = 40, target: str = "", shape: str = "value",
                    strict: bool = False) -> ResultRecord:
    """The per-function unit: author an oracle for one manifest entry, gate it, retry on RED.
    Returns a ResultRecord in EVERY case - model/HTTP/contract failures become RED records.

    `shape` selects the oracle's battery contract: "value" (hard-coded spec expectations) or
    "invariant" (metamorphic relations over all valid inputs - round-trip / idempotence). Both go
    through the SAME mutation gate; the gate proves either kind non-vacuous identically.

    The reference and battery are authored in SEPARATE calls (_author_independent) so the gate's
    step-0 ref_passes is a real CROSS-ACCEPTANCE check rather than a tautology; a non-green attempt
    whose ref_passes is False is a SPEC-DISAGREEMENT - recorded distinctly and NOT retried into a
    self-consistent (possibly wrong) agreement."""
    t0 = time.time()
    qhash = hashlib.sha1(entry["qualname"].encode()).hexdigest()[:10]
    # one dir per function: the gate writes tag-named driver/mutant files into the oracle's
    # dir, so a shared dir would collide when A03 gates many functions in parallel.
    oracles_dir = run_dir / "oracles" / f"{_safe_leaf(entry['qualname'])}_{qhash}"
    oracles_dir.mkdir(parents=True, exist_ok=True)
    bat_model = _battery_model(model)
    rec = ResultRecord(qualname=entry["qualname"], model=model)

    for n in range(1, attempts + 1):
        rec.attempts = n
        # unique module name per qualname AND attempt - sidesteps importlib's module cache,
        # which would otherwise gate attempt 1's module again on attempt 2.
        module_name = f"orc_{qhash}_a{n}"
        r = _author_independent(entry, model, bat_model, target=target, max_tokens=max_tokens,
                                shape=shape, trace_meta={"attempt": n, "module": module_name})
        if "error" in r:
            rec.attempt_log.append({"attempt": n, "error": r["error"]})
            rec.gate = _normalize_verdict(_Broken(f"author call failed: {r['error']}"))
            continue
        rec.cost += r["cost"]
        rec.tokens["in"] += r["in_tok"]
        rec.tokens["out"] += r["out_tok"]
        (oracles_dir / f"{module_name}.py").write_text(r["code"])
        (oracles_dir / f"{module_name}_raw.txt").write_text(r["raw"])
        rec.oracle_path = str(oracles_dir / f"{module_name}.py")
        rec.gate = gate_authored(module_name, oracles_dir, cap=gate_cap, qualname=entry["qualname"],
                                 strict=strict)
        disagree = _is_spec_disagreement(rec.gate)
        rec.attempt_log.append({"attempt": n, "green": rec.gate["green"],
                                "strict_green": rec.gate.get("strict_green", False),
                                "shape": shape,
                                "kill_rate": rec.gate["kill_rate"], "note": rec.gate["note"],
                                "spec_disagreement": disagree,
                                "out_tok": r["out_tok"], "cost": round(r["cost"], 6)})
        if rec.gate["green"]:
            rec.spec_disagreement = False
            break
        if disagree:
            # independent reference and battery disagree on the spec - escalate, don't retry into
            # a self-consistent (possibly wrong) agreement.
            rec.spec_disagreement = True
            break
    rec.elapsed = time.time() - t0
    return rec


# ---------------------------------------------------------------- best-of-N (reasoning models)

DEFAULT_BEST_OF_N = 8


def author_best_of_n(entry: dict, model: str, run_dir: Path, *, n: int = DEFAULT_BEST_OF_N,
                     temperature: float = 0.7, max_tokens: int = 8000, gate_cap: int = 40,
                     target: str = "", call_workers: int = 8, gate_workers: int = 1,
                     adaptive_fallback: bool = True, shape: str = "value") -> ResultRecord:
    """Author an oracle from a reasoning model (minimax-m3) FAST: fire N think-OFF streaming
    drafts in parallel (diverse via temperature) and let the MUTATION GATE select a GREEN one.

    Why this shape: think-OFF makes M3 ~15x faster but its single draft is fragile - under the
    INDEPENDENT ref+battery contract it fails the gate's ref-consistency check often enough that
    ~25% of functions still find no GREEN draft in N=8 (measured on the first cross-family run).
    Best-of-N turns the cheap-but-noisy generation into a usable signal - the gate is a mechanical
    selector, so the majority GREEN in ~30s (AUTH ~28s, gate ~2s) instead of a ~150s reasoning call;
    the stubborn ~25% pay the adaptive fallback below. This is the verify-the-verifier thesis applied
    to authoring: trust cheap noisy generation because a non-vacuous gate filters it.

    The authoring phase is throughput-bound on the m3 gateway (N drafts share a fixed token rate),
    NOT latency-bound - so raising n shrinks the slow-fallback tail (P(no GREEN) drops geometrically)
    but is NOT free: more drafts add proportional authoring wall. It's a net win only because one
    avoided fallback (~200s) pays for many extra cheap drafts; tune n against the measured tail.

    Returns a ResultRecord (same interface as author_and_gate) whose gate/oracle_path are the
    BEST draft (first GREEN; else highest kill_rate), and whose cost/tokens sum ALL N drafts."""
    t0 = time.time()
    qhash = hashlib.sha1(entry["qualname"].encode()).hexdigest()[:10]
    base = run_dir / "oracles" / f"{_safe_leaf(entry['qualname'])}_{qhash}"
    base.mkdir(parents=True, exist_ok=True)
    bat_model = _battery_model(model)
    rec = ResultRecord(qualname=entry["qualname"], model=model)
    rec.attempts = n

    def _author_one(**kw) -> dict:
        # reference + battery authored in two independent think-OFF calls and assembled
        return _author_independent(entry, model, bat_model, target=target, shape=shape, **kw)

    # phase 1 - N parallel think-OFF streaming drafts. Each draft gets its OWN dir so the
    # gate's tag-named driver/mutant files never collide when phase 2 gates them in parallel.
    def _draft(i: int):
        r = _author_one(max_tokens=max_tokens, temperature=temperature, stream=True,
                        thinking={"type": "disabled"}, trace_meta={"draft": i})
        if "error" in r:
            return {"i": i, "error": r["error"]}
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

    # phase 2 - gate every draft. Each gate spawns a mutant-subprocess swarm, so gating N
    # drafts × an outer per-function pool can OOM a RAM-tight box (it did: the first cross-
    # family run was OOM-killed at gate_workers=3 × phase1=2). gate_workers=1 keeps the
    # concurrent-gate count at/below the level the sequential deepseek path runs safely.
    def _gate(d):
        # batched grading already collapses ~2 subprocesses/mutant into a few parallel chunks
        # (measured ~5-11x vs the legacy per-mutant path, byte-equal verdicts). fail_fast is left
        # OFF: its sequential-tripwire stage loses the parallelism and measured NET SLOWER than
        # plain batched-full on RED drafts (0.33s vs 0.05s on a 17-mutant vacuous oracle).
        # gate in a memory-capped, hard-kill SUBPROCESS - a memory-bomb / non-terminating reference
        # would otherwise grow THIS process (in-process gating OOM'd the box at 29GB).
        v = _gate_subprocess(d["mod"], str(d["dir"]), gate_cap, entry["qualname"])
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
    # ONE slow thinking-ON draft - near-certain GREEN - so every function gets a cross-family
    # oracle. Fast for the ~90% that best-of-N nails; the slow tail pays only on the stubborn few.
    if adaptive_fallback and (best is None or not best[1]["green"]):
        r = _author_one(max_tokens=24000, temperature=0.2, stream=True,
                        thinking={"type": "adaptive"}, trace_meta={"phase": "adaptive_fallback"})
        if "error" in r:
            rec.attempt_log.append({"attempt": "adaptive_fallback", "error": r["error"]})
        else:
            rec.cost += r["cost"]
            rec.tokens["in"] += r["in_tok"]
            rec.tokens["out"] += r["out_tok"]
            cand_dir = base / "adaptive"
            cand_dir.mkdir(exist_ok=True)
            mod = f"orc_{qhash}_adaptive"
            (cand_dir / f"{mod}.py").write_text(r["code"])
            (cand_dir / f"{mod}_raw.txt").write_text(r["raw"])
            v = _gate_subprocess(mod, str(cand_dir), gate_cap, entry["qualname"])
            rec.attempt_log.append({"attempt": "adaptive_fallback", "green": v["green"],
                                    "kill_rate": v["kill_rate"], "note": v["note"],
                                    "out_tok": r["out_tok"], "cost": round(r["cost"], 6)})
            d = {"dir": cand_dir, "mod": mod, "r": r}
            if best is None or (v["green"], v["kill_rate"]) > (best[1]["green"], best[1]["kill_rate"]):
                best = (d, v)

    if best is not None:
        d, v = best
        # independent ref/battery disagreement on the SELECTED best (non-green, ref_passes False)
        # is a spec-disagreement to escalate - distinct from a vacuous oracle.
        rec.spec_disagreement = _is_spec_disagreement(v)
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
    ap.add_argument("--shape", choices=("value", "invariant"), default="value",
                    help="oracle battery shape: value (spec expectations) or invariant (metamorphic)")
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
        print(f"== {qual} ({entry['auditability']}; model={model}; shape={args.shape})")
        rec = author_and_gate(entry, model, run_dir, attempts=attempts,
                              target=manifest["target"], shape=args.shape)
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
