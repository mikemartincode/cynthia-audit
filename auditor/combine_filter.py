#!/usr/bin/env python3
"""auditor/combine_filter.py — wire OUR precision signal over Anthropic's agentic-PBT dataset.

Anthropic's agentic-PBT (Opus 4.1) authors free-form properties and finds bugs at high recall but
44% of reports are invalid. Our finding: the false positives are LLM-invented-contract hallucinations
— the property asserts a guarantee the spec never promised (monotonicity of a quadrature method, a
stateless contract on a stateful object, a universal postcondition). Our designs avoid this BY
CONSTRUCTION (assert only docstring-grounded / trusted-template properties).

This filter operationalizes that as a precision signal over THEIR released reports: classify each
report's violated property as DOCUMENTED (the spec promises it → likely a real bug) vs ASSUMED (an
LLM-added contract the spec doesn't promise → likely a false positive). Validated against their 21
human validity labels: does our signal REJECT their 3 false positives while KEEPING the 18 valid?

The classifier is M3 (cheap) over the report text — but its OUTPUT IS MEASURED against ground-truth
human labels, never trusted on its own. If our signal separates valid from invalid on the 21, it is
an automatic precision filter for the human-triage step their pipeline requires."""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import author as author_mod  # noqa: E402

PBT = Path.home() / "projects" / "agentic-pbt"

_SYS = "You are a precise software-spec reviewer. Output ONLY a JSON object."
_PROMPT = """\
An automated tool filed this property-based-testing bug report. Judge whether the VIOLATED PROPERTY is
a guarantee the target's DOCUMENTED SPEC actually makes, or an assumption the tool ADDED that the spec
never promised.

DOCUMENTED  = the docstring/spec/standard explicitly states or directly implies this behaviour
              (e.g. "returns the input lowercased", a documented error condition, a stated invariant).
ASSUMED     = the tool imposed a general expectation the spec does NOT promise — a mathematical ideal
              the method doesn't guarantee (e.g. monotonicity of a numerical approximation), a
              stateless/deterministic contract on an object documented as stateful, or a universal
              postcondition that only holds for valid/typical inputs.

A report whose property is ASSUMED is very likely an INVALID bug (false positive).

REPORT:
{report}

Output EXACTLY: {{"property_class": "DOCUMENTED"|"ASSUMED", "reason": "<one sentence>"}}
"""


def labeled_reports() -> list[dict]:
    rows = [r for r in csv.DictReader(open(PBT / "paper/score_results_final.csv"))
            if r.get("valid", "").strip() != ""]
    out = []
    for r in rows:
        # locate the report markdown by filename leaf under paper/results
        leaf = r["file"].split("/")[-1]
        hits = list((PBT / "paper/results").rglob(leaf))
        if not hits:
            continue
        valid = r["valid"].strip().lower() in ("true", "1", "yes")
        out.append({"valid": valid, "path": hits[0], "leaf": leaf})
    return out


def classify(report_text: str, model: str) -> dict:
    r = author_mod.call_model(model, _SYS, _PROMPT.format(report=report_text[:4000]),
                              max_tokens=2000, temperature=0.0,
                              stream=model.startswith("minimax"), thinking={"type": "disabled"})
    txt = re.sub(r"<think>.*?</think>", "", r.get("raw", ""), flags=re.S | re.I)
    m = re.search(r'\{[^{}]*"property_class"[^{}]*\}', txt, re.S)
    if not m:
        return {"property_class": "?", "reason": "no json"}
    try:
        return json.loads(m.group(0))
    except Exception:  # noqa: BLE001
        return {"property_class": "?", "reason": "bad json"}


def main() -> int:
    model = sys.argv[1] if len(sys.argv) > 1 else "minimax-m3"
    reps = labeled_reports()
    print(f"[combine] {len(reps)} labeled reports (Anthropic agentic-PBT) | filter model={model}\n")
    # confusion: predicted-real (DOCUMENTED) vs actual valid
    tp = fp = tn = fn = 0
    rows = []
    for r in reps:
        cls = classify(r["path"].read_text(), model)
        pc = cls.get("property_class", "?")
        pred_real = (pc == "DOCUMENTED")
        actual_valid = r["valid"]
        if pred_real and actual_valid: tp += 1
        elif pred_real and not actual_valid: fp += 1
        elif not pred_real and not actual_valid: tn += 1
        elif not pred_real and actual_valid: fn += 1
        rows.append((actual_valid, pc, r["leaf"][:48], cls.get("reason", "")[:60]))
        flag = "✓keep" if (pred_real and actual_valid) else "✗REJECT-FP" if (not pred_real and not actual_valid) \
               else "!lost-real" if (not pred_real and actual_valid) else "·kept-FP"
        print(f"  actual={'VALID ' if actual_valid else 'INVALID'} pred={pc:10} {flag:11} {r['leaf'][:46]}")
    n_valid = sum(1 for r in reps if r["valid"]); n_inv = len(reps) - n_valid
    print(f"\n=== our filter vs their {len(reps)} labels ({n_valid} valid, {n_inv} invalid) ===")
    print(f"  caught false positives (rejected INVALID): {tn}/{n_inv}")
    print(f"  kept real bugs (kept VALID):               {tp}/{n_valid}")
    print(f"  lost real bugs (rejected VALID):           {fn}/{n_valid}")
    base_prec = round(100 * n_valid / len(reps))
    kept = tp + fp
    filt_prec = round(100 * tp / kept) if kept else 0
    print(f"\n  precision of their set:        {base_prec}% ({n_valid}/{len(reps)})")
    print(f"  precision after our filter:    {filt_prec}% ({tp}/{kept} kept are valid)")
    Path("results").mkdir(exist_ok=True)
    Path("results/combine_filter.json").write_text(json.dumps(
        {"n": len(reps), "valid": n_valid, "invalid": n_inv, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
         "base_precision": base_prec, "filtered_precision": filt_prec}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
