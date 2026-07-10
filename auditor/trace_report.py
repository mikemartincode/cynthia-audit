#!/usr/bin/env python3
"""auditor/trace_report.py - turn a raw execution trace (auditor/trace.py) into the JOINED,
predictive view: one row per (function, attempt) tying the LLM authoring calls to the gate
outcome, plus the two things you'd actually want to forecast - will an oracle gate GREEN, and
which mutants survive.

The point (Mike's framing: "see if we can foresee data and feed it"): the raw trace.jsonl is an
event log; THIS is the table a predictor learns from. Each row carries the inputs that are known
BEFORE the expensive gate runs (function basis, signature arity, prompt sizes, reference/battery
token counts) next to the outcome (green, ref_passes, kill_rate, survivors). It also CLASSIFIES
each non-green attempt by the trace's own evidence, so the dominant failure mode is legible rather
than a flat "RED":

  convention-mismatch  the independent reference + battery chose incompatible argument
                       conventions (the gate's own ref-rejection note shows an unpack/arity
                       TypeError). A HARNESS artifact on multi-arg functions, not a spec finding -
                       and the most "feedable" class: pin the tuple convention from the signature
                       arity and these recover.
  spec-disagreement    ref_passes is False for a non-arity reason: the two independent spec reads
                       genuinely differ (sometimes one is wrong, sometimes a real ambiguity).
  vacuous-survivor     ref_passes True but a mutant survived - the oracle is too weak there (the
                       gate doing its job). The surviving mutant is printed: it is the single most
                       informative training row, the exact defect a non-vacuous oracle must catch.
  broken               the authored module didn't compile/import/respect the gate contract.
  green                gated GREEN.

Read-only over a finished run's trace + records. Writes report.json + report.md next to the trace.

Usage:
    python auditor/trace_report.py results/<run>/trace
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def _arity(signature: str) -> int:
    """Positional-arg count of a manifest signature, minus self - the convention-mismatch
    predictor (a tuple-unpack oracle pair is far likelier to disagree as arity climbs)."""
    inside = signature[signature.find("(") + 1: signature.rfind(")")]
    if not inside.strip():
        return 0
    parts, depth, cur = [], 0, ""
    for ch in inside:
        if ch in "[({":
            depth += 1
        elif ch in "])}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    names = [p.split(":")[0].split("=")[0].strip() for p in parts if p.strip()]
    return len([n for n in names if n not in ("self", "cls", "") and not n.startswith("*")])


def _classify(verdict: dict) -> str:
    if verdict.get("green"):
        return "green"
    note = verdict.get("note", "")
    if not verdict.get("ref_passes"):
        # the gate's ref-rejection note tells convention-mismatch from a real spec disagreement.
        if re.search(r"unpack|positional argument|takes \d+ positional|got \d+\)", note):
            return "convention-mismatch"
        if "REJECTS its own reference" in note:
            return "spec-disagreement"
        return "broken"
    if verdict.get("survivors"):
        return "vacuous-survivor"
    return "broken"


def build(trace_dir: Path) -> dict:
    """The trace.jsonl is self-sufficient - every authoring input + gate outcome is in it; the
    per-function record files add nothing the events don't already carry, so this joins purely
    over the trace."""
    events = [json.loads(ln) for ln in (trace_dir / "trace.jsonl").read_text().splitlines()
              if ln.strip()]
    llm = [e for e in events if e["event"] == "llm_call"]
    gates = [e for e in events if e["event"] == "gate"]

    # group LLM calls by (qualname, module) -> {reference, battery}
    by_mod: dict[tuple, dict] = {}
    for e in llm:
        mod = e.get("meta", {}).get("module") or e.get("meta", {}).get("draft") \
            or e.get("meta", {}).get("phase") or ""
        by_mod.setdefault((e["qualname"], str(mod)), {})[e.get("role", "?")] = e

    rows = []
    for g in gates:
        q = g["qualname"]
        v = g["verdict"]
        mod = g.get("module", "")
        pair = by_mod.get((q, mod), {})
        ref_call, bat_call = pair.get("reference", {}), pair.get("battery", {})
        sig = ""
        # signature from the record's oracle is not stored; pull arity from the manifest-less
        # proxy: the reference prompt's user text mentions the target signature.
        # the reference prompt opens with `qualname(signature) -> ret` in backticks; capture the
        # paren group lazily, allowing a trailing return annotation before the closing backtick.
        m = re.search(r"`[\w.]+(\(.*?\))(?:\s*->|`)", ref_call.get("user", ""))
        if m:
            sig = m.group(1)
        survivors = [mt for mt in g.get("mutants", []) if mt["verdict"] == "survived"]
        rows.append({
            "qualname": q,
            "module": mod,
            "outcome": _classify(v),
            "green": bool(v.get("green")),
            "ref_passes": bool(v.get("ref_passes")),
            "kill_rate": v.get("kill_rate", 0.0),
            "mutants_generated": v.get("generated", 0),
            "non_equivalent": v.get("non_equivalent", 0),
            "equivalent": g.get("equivalent_count", 0),
            "survivors": v.get("survivors", []),
            "arity": _arity(sig) if sig else None,
            "ref_out_tok": ref_call.get("out_tok"),
            "bat_out_tok": bat_call.get("out_tok"),
            "gate_note": v.get("note", "")[:200],
            "survivor_mutants": survivors,
        })
    rows.sort(key=lambda r: (r["outcome"], r["qualname"]))

    by_outcome: dict[str, int] = {}
    for r in rows:
        by_outcome[r["outcome"]] = by_outcome.get(r["outcome"], 0) + 1
    # convention-mismatch rate vs arity - the feedable signal
    multi = [r for r in rows if r["arity"] and r["arity"] >= 2]
    single = [r for r in rows if r["arity"] == 1]
    summary = {
        "gate_attempts": len(rows),
        "distinct_functions": len({r["qualname"] for r in rows}),
        "by_outcome": by_outcome,
        "green": sum(1 for r in rows if r["green"]),
        "llm_calls": len(llm),
        "llm_out_tokens": sum(e.get("out_tok", 0) for e in llm),
        "llm_cost_usd": round(sum(e.get("cost", 0.0) for e in llm), 4),
        "mutants_total": sum(r["mutants_generated"] for r in rows),
        "survivors_total": sum(len(r["survivors"]) for r in rows),
        "multiarg_attempts": len(multi),
        "multiarg_convention_mismatch": sum(1 for r in multi if r["outcome"] == "convention-mismatch"),
        "singlearg_attempts": len(single),
        "singlearg_convention_mismatch": sum(1 for r in single if r["outcome"] == "convention-mismatch"),
    }
    return {"summary": summary, "rows": rows}


def _md(report: dict) -> str:
    s = report["summary"]
    out = ["# Trace report", "",
           f"{s['gate_attempts']} gate attempts over {s['distinct_functions']} functions · "
           f"{s['green']} GREEN · {s['llm_calls']} LLM calls · {s['llm_out_tokens']:,} output tokens · "
           f"${s['llm_cost_usd']}", "",
           "## Outcome breakdown", ""]
    for k, v in sorted(s["by_outcome"].items(), key=lambda kv: -kv[1]):
        out.append(f"- **{k}**: {v}")
    out += ["", "## The feedable signal - convention mismatch concentrates on multi-arg functions",
            "",
            f"- multi-arg (arity≥2) attempts: {s['multiarg_attempts']}, of which "
            f"{s['multiarg_convention_mismatch']} failed as convention-mismatch",
            f"- single-arg attempts: {s['singlearg_attempts']}, of which "
            f"{s['singlearg_convention_mismatch']} failed as convention-mismatch",
            "",
            "The independent reference+battery authors disagree on the tuple-unpack convention far "
            "more as argument count rises - a harness artifact (not a spec finding) that a "
            "signature-aware convention hint could feed and recover.", "",
            "## Per-function", "",
            "| function | arity | outcome | ref_passes | kill_rate | mutants | ref_tok | bat_tok |",
            "|---|---|---|---|---|---|---|---|"]
    for r in report["rows"]:
        out.append(f"| {r['qualname']} | {r['arity']} | {r['outcome']} | {r['ref_passes']} | "
                   f"{r['kill_rate']} | {r['non_equivalent']} | {r['ref_out_tok']} | {r['bat_out_tok']} |")
    surv_rows = [r for r in report["rows"] if r["survivor_mutants"]]
    if surv_rows:
        out += ["", "## Surviving mutants (the single most informative training rows)", ""]
        for r in surv_rows:
            for mt in r["survivor_mutants"]:
                out.append(f"- `{r['qualname']}` survived `{mt['tag']}` (kind {mt['kind']})")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="join a raw trace into the predictive per-function view")
    ap.add_argument("trace_dir", type=Path)
    args = ap.parse_args()
    report = build(args.trace_dir)
    (args.trace_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (args.trace_dir / "report.md").write_text(_md(report))
    s = report["summary"]
    print(json.dumps(s, indent=2))
    print(f"\nreport: {args.trace_dir/'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
