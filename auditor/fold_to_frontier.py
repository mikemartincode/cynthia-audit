#!/usr/bin/env python3
"""auditor/fold_to_frontier.py — STEP 2: prove the auto-derived obligations are real frontier gates.

For each verified (function, property) the front-end produced, emit its frontier gate (intent_obligation
.to_frontier_gate) and run it through frontier's OWN gate machinery (cynthia.services.frontier.gates
.run_gate), twice:
  * REFERENCE = the REAL shipped function (imported in the preamble)         -> gate must PASS
  * MUTANT    = a deliberately property-BREAKING variant of the same name    -> gate must go RED
A gate that passes the real code AND kills the directed mutant is, by frontier's own definition, a sound
obligation the queen can verify. This is the literal fold: front-end (cheap, auto) -> frontier (queen).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# frontier lives in cynthiaV3; the auditor venv has cynthia_core but maybe not cynthiaV3 on the path.
_V3 = Path.home() / "projects" / "cynthiaV3"
if str(_V3) not in sys.path:
    sys.path.insert(0, str(_V3))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from intent_obligation import to_frontier_gate  # noqa: E402
from cynthia.services.frontier.gates import run_gate  # noqa: E402 — frontier's real gate runner

# verified obligations from the idempotent-slice run (real packaging functions), each with a
# property-BREAKING mutant of the SAME name to prove the auto-derived gate bites.
CASES = [
    {"fn": "canonicalize_name", "prop": "idempotent",
     "import": "from packaging.utils import canonicalize_name",
     "inputs": ["Django", "oslo.concurrency", "Foo.Bar_baz"],
     "mutant": "def canonicalize_name(s):\n    return str(s).lower() + '.x'"},  # appends each call -> not idempotent
    {"fn": "canonicalize_name", "prop": "case_lower",
     "import": "from packaging.utils import canonicalize_name",
     "inputs": ["Django", "REQUESTS"],
     "mutant": "def canonicalize_name(s):\n    return str(s).upper()"},  # uppercases -> not lowercased
    {"fn": "canonicalize_version", "prop": "idempotent",
     "import": "from packaging.utils import canonicalize_version",
     "inputs": ["1.0.1", "1.0.0"],
     "mutant": "def canonicalize_version(v):\n    return str(v) + '.0'"},  # grows each call -> not idempotent
    # (normalize_pre is internal — absent from pip packaging's public utils; it must be folded against
    #  the SAME vendored commit the obligation was verified on. Version consistency matters for auditing.)
]


def main() -> int:
    ok_all = True
    with tempfile.TemporaryDirectory() as td:
        wd = Path(td)
        print(f"{'fn::property':40s} {'real=PASS':>10s} {'mutant=RED':>11s}  fold")
        for c in CASES:
            gate = to_frontier_gate(c["fn"], c["prop"], c["inputs"])
            # REFERENCE: real shipped function via preamble import, empty fill
            ref_pass, ref_detail = run_gate(c["import"], "", gate, work_dir=wd, tag=f"{c['fn']}_{c['prop']}_ref")
            # MUTANT: the property-breaking fill (no import; the def shadows)
            mut_pass, mut_detail = run_gate("", c["mutant"], gate, work_dir=wd, tag=f"{c['fn']}_{c['prop']}_mut")
            sound = ref_pass and not mut_pass  # passes real code AND kills the directed mutant
            ok_all = ok_all and sound
            print(f"  {c['fn']+'::'+c['prop']:38s} {str(ref_pass):>10s} {str(not mut_pass):>11s}  "
                  f"{'SOUND ✓' if sound else 'UNSOUND ✗'}")
            if not sound:
                print(f"      ref_detail: {ref_detail[:80]}")
                print(f"      mut_detail: {mut_detail[:80]}")
    print(f"\n=> all auto-derived obligations are sound frontier gates: {ok_all}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
