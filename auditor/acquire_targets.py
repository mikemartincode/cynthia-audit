#!/usr/bin/env python3
"""auditor/acquire_targets.py — clone + index the §6 basket repos into targets/<name>/, and emit the
corpus queue. No spend (pure git + AST index). Re-runnable: an already-cloned/indexed repo is skipped.

Targets are high-invariant-density, spec-backed, pure-Python, NOT fuzzed-to-death libraries. Each is
shallow-cloned to targets/<name>/repo (gitignored) and indexed by auditor/index.py into
targets/<name>/manifest.json. The package dir is auto-detected (src/<pkg>/__init__.py or
<pkg>/__init__.py); a `package` override is given where auto-detect would miss.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

# name -> (git url, package-dir override or None for auto-detect)
TARGETS = {
    "packaging": ("https://github.com/pypa/packaging", "src/packaging"),
    "dateutil": ("https://github.com/dateutil/dateutil", "src/dateutil"),
    "email-validator": ("https://github.com/JoshData/python-email-validator", "email_validator"),
    "python-slugify": ("https://github.com/un33k/python-slugify", "slugify"),
    "markdown-it-py": ("https://github.com/executablebooks/markdown-it-py", "markdown_it"),
    "bleach": ("https://github.com/mozilla/bleach", "bleach"),
    # idna is already indexed (targets/idna); kept in the queue from disk.
    # Phase-2 expansion: more pure-Python, invariant/spec-rich, package-layout libraries.
    "more-itertools": ("https://github.com/more-itertools/more-itertools", "more_itertools"),
    "toolz": ("https://github.com/pytoolz/toolz", "toolz"),
    "boltons": ("https://github.com/mahmoud/boltons", "boltons"),
    "semver": ("https://github.com/python-semver/python-semver", "src/semver"),
    "validators": ("https://github.com/python-validators/validators", "src/validators"),
    "humanize": ("https://github.com/python-humanize/humanize", "src/humanize"),
}

HERE = Path(__file__).resolve().parent.parent  # cynthia-audit root
INDEX_PY = HERE / "auditor" / "index.py"


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def acquire_one(name: str, url: str, package: str | None) -> dict:
    tdir = HERE / "targets" / name
    repo = tdir / "repo"
    manifest = tdir / "manifest.json"
    tdir.mkdir(parents=True, exist_ok=True)
    if not repo.exists():
        print(f"[{name}] cloning {url} ...", flush=True)
        r = _run(["git", "clone", "--depth", "1", url, str(repo)])
        if r.returncode != 0:
            return {"name": name, "status": "clone_failed", "err": r.stderr[-300:]}
    commit = _run(["git", "-C", str(repo), "rev-parse", "HEAD"]).stdout.strip()
    if not manifest.exists():
        cmd = [sys.executable, str(INDEX_PY), str(repo), "--out", str(manifest)]
        if package:
            cmd += ["--package", package]
        print(f"[{name}] indexing ...", flush=True)
        r = _run(cmd)
        if r.returncode != 0 or not manifest.exists():
            return {"name": name, "status": "index_failed", "err": (r.stderr or r.stdout)[-400:]}
    m = json.loads(manifest.read_text())
    s = m["summary"]
    return {"name": name, "status": "ok", "manifest": str(manifest), "commit": commit,
            "auditable": s["auditable"], "deterministic": s["deterministic"],
            "nondeterministic": s["total_public_functions"] - s["deterministic"],
            "total_public": s["total_public_functions"], "basis": s["auditability"]}


def main() -> int:
    ap = argparse.ArgumentParser(description="clone + index the basket; emit the corpus queue")
    ap.add_argument("--queue-out", type=Path, default=HERE / "results" / "corpus" / "queue_seed.json")
    ap.add_argument("--only", nargs="*", default=None, help="subset of target names")
    args = ap.parse_args()

    names = args.only or list(TARGETS)
    results = []
    for name in names:
        url, pkg = TARGETS[name]
        results.append(acquire_one(name, url, pkg))

    # always include idna (pre-indexed) in the queue if present
    queue_entries = []
    idna_m = HERE / "targets" / "idna" / "manifest.json"
    if idna_m.exists():
        queue_entries.append({"name": "idna", "manifest": str(idna_m)})
    for r in results:
        print(f"  {r['name']:18} {r['status']:14} "
              + (f"auditable={r.get('auditable')} det={r.get('deterministic')} "
                 f"nondet={r.get('nondeterministic')} basis={r.get('basis')}"
                 if r["status"] == "ok" else r.get("err", "")[:120]), flush=True)
        if r["status"] == "ok":
            queue_entries.append({"name": r["name"], "manifest": r["manifest"]})

    args.queue_out.parent.mkdir(parents=True, exist_ok=True)
    args.queue_out.write_text(json.dumps(queue_entries, indent=2) + "\n")
    print(f"\nqueue seed ({len(queue_entries)} repos): {args.queue_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
