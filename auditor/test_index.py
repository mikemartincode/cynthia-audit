"""Classifier proof for auditor/index.py: known-impure shapes must classify impure
(RED side), known-pure/spec'd shapes must classify clean (GREEN side).

Run: python -m pytest auditor/test_index.py -q   (or just: python auditor/test_index.py)
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from index import classify_auditability, index_package  # noqa: E402

FIXTURE = textwrap.dedent('''
    import random
    import time as _t
    from typing import overload

    REGISTRY = {}

    def roll(n):
        """Roll a die."""
        return random.randint(1, n)

    def wraps_roll(n):
        return roll(n) + 1

    def register(name, value):
        """Register a value under a name in the module registry, replacing any
        existing entry; later lookups by other functions will observe the change."""
        REGISTRY[name] = value

    def stamp():
        return _t.time()

    def encode_thing(s):
        return s[::-1]

    def decode_thing(s):
        return s[::-1]

    def normalize_path(p):
        return p.strip("/")

    @overload
    def parse(x: str) -> int: ...

    def parse(x):
        """Parse a decimal string into an int, rejecting any non-digit characters
        and raising ValueError on empty input, per the documented grammar."""
        return int(x)

    def opaque(x):
        return x + 1
''')


def _index(tmp: Path):
    pkg = tmp / "fixture" / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "core.py").write_text(FIXTURE)
    recs = {r.qualname: r for r in index_package(tmp / "fixture", pkg)}
    return recs


def test_classifier(tmp_path: Path | None = None) -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        recs = _index(Path(td))

        # RED side - each known-impure shape is flagged, with the right reason class
        assert any("random" in r for r in recs["roll"].impure_reasons), recs["roll"]
        assert any("transitively" in r for r in recs["wraps_roll"].impure_reasons)
        assert any("enclosing-scope" in r for r in recs["register"].impure_reasons)
        assert any("time" in r for r in recs["stamp"].impure_reasons)

        # GREEN side - pure functions carry no reasons
        for name in ("encode_thing", "decode_thing", "normalize_path", "parse", "opaque"):
            assert recs[name].impure_reasons == [], (name, recs[name].impure_reasons)

        # overload stub skipped: exactly one `parse`, and it has the real body's docstring
        assert sum(1 for q in recs if q == "parse") == 1
        assert "decimal" in recs["parse"].doc

        # auditability bases
        leaves = {q.split(".")[-1] for q in recs}
        assert classify_auditability(recs["parse"], leaves)[0] == "spec"
        assert classify_auditability(recs["register"], leaves)[0] == "spec"  # basis != deterministic
        assert classify_auditability(recs["encode_thing"], leaves)[0] == "invariant"
        assert classify_auditability(recs["normalize_path"], leaves)[0] == "invariant"
        assert classify_auditability(recs["opaque"], leaves)[0] == "none"
    print("test_classifier: OK")


if __name__ == "__main__":
    test_classifier()
