#!/usr/bin/env python3
"""auditor/index.py - AST-index a target repo and emit the auditable-function manifest.

Usage:
    python auditor/index.py <repo_path> [--package <dir>] [--out <manifest.json>]

Walks the target package's source, collects every PUBLIC function (module-level defs and
methods of module-level classes whose own name doesn't start with "_" - module privacy is
ignored on purpose: many libraries keep the public API in a private module and re-export),
and classifies each on the two axes the oracle author needs:

  deterministic   - an AST scan for output-affecting impurity (time/random/IO/env/global
                    state), propagated transitively through the package's internal call
                    graph to a fixpoint. Unresolvable external calls are assumed pure
                    (heuristic; the differential sweep re-checks determinism empirically).
  auditability    - what an INDEPENDENT oracle could be grounded in:
                      spec       a substantive docstring (the function documents its own
                                 behavior well enough to prompt an author against)
                      invariant  a recognized universal property: an inverse sibling in
                                 the same package (encode/decode, parse/unparse, ...) or
                                 an idempotent-by-name transform (normalize*, canonical*)
                      none       neither - honestly out of scope for this auditor

Stdlib + cynthia_core only. Rerunnable; output is deterministic for a given tree.
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------- impurity heuristics

# Modules where ANY use is output-affecting or IO (conservative).
IMPURE_MODULES = {
    "random", "secrets", "uuid", "time", "subprocess", "threading",
    "multiprocessing", "tempfile", "shutil", "requests", "httpx", "ssl",
    "select", "signal", "asyncio",
}

# (module, attr) pairs that are impure even though the module isn't blanket-impure.
IMPURE_ATTRS = {
    ("os", "environ"), ("os", "getenv"), ("os", "urandom"), ("os", "system"),
    ("os", "popen"), ("os", "getcwd"), ("os", "listdir"), ("os", "stat"),
    ("os", "remove"), ("os", "rename"), ("os", "makedirs"), ("os", "mkdir"),
    ("datetime", "now"), ("datetime", "utcnow"), ("datetime", "today"),
    ("date", "today"),
    ("sys", "stdin"), ("sys", "stdout"), ("sys", "stderr"), ("sys", "argv"),
    ("urllib", "request"),
    # socket: network/syscall surface is impure, but inet_pton/inet_ntop/htonl-family
    # are pure format converters - list the impure ones explicitly.
    ("socket", "socket"), ("socket", "create_connection"), ("socket", "getaddrinfo"),
    ("socket", "gethostbyname"), ("socket", "gethostname"), ("socket", "getfqdn"),
}

# Bare-name calls that are impure regardless of origin.
IMPURE_CALLS = {"open", "input", "print", "exec", "eval", "compile", "globals", "vars"}

# Container-mutation methods: calling one on an enclosing-scope (module-level) name is a
# global-state write - e.g. a register_*() function appending to a module registry.
MUTATOR_METHODS = {"add", "append", "extend", "insert", "remove", "discard", "pop",
                   "clear", "update", "setdefault", "popitem", "sort", "reverse"}

# Names that, when imported from an impure module, carry the impurity.
PURE_EXCEPTIONS = {
    ("socket", "inet_pton"), ("socket", "inet_ntop"), ("socket", "inet_aton"),
    ("socket", "inet_ntoa"), ("socket", "htons"), ("socket", "htonl"),
    ("socket", "ntohs"), ("socket", "ntohl"), ("socket", "AddressFamily"),
}

# ---------------------------------------------------------------- auditability heuristics

SPEC_MIN_DOC_WORDS = 15  # a docstring this substantive can ground an author prompt

INVERSE_STEMS = [
    ("encode", "decode"), ("quote", "unquote"), ("parse", "unparse"),
    ("serialize", "deserialize"), ("dumps", "loads"), ("dump", "load"),
    ("pack", "unpack"), ("escape", "unescape"), ("compress", "decompress"),
    ("to_text", "from_text"), ("to_bytes", "from_bytes"),
]
IDEMPOTENT_PREFIXES = ("normalize", "canonical")


@dataclass
class FuncRecord:
    module: str               # path relative to repo root
    module_name: str          # dotted module name within the package
    qualname: str             # ClassName.method or function name
    signature: str
    span: tuple[int, int]
    doc: str
    impure_reasons: list[str] = field(default_factory=list)
    calls: set[tuple[str, str]] = field(default_factory=set)  # resolved (module_name, qualname)
    public: bool = True

    @property
    def key(self) -> tuple[str, str]:
        return (self.module_name, self.qualname)


def _humanize(name: str) -> str:
    return name.replace("_", " ").strip()


def _intent(rec: FuncRecord) -> str:
    if rec.doc:
        first = rec.doc.strip().splitlines()[0].strip()
        if first:
            return first
    base = rec.qualname.split(".")[-1]
    return f"{_humanize(base)} (no docstring)"


def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = ast.unparse(node.args)
    ret = f" -> {ast.unparse(node.returns)}" if node.returns else ""
    return f"({args}){ret}"


class _BodyScan(ast.NodeVisitor):
    """Direct (non-transitive) impurity + intra-package call collection for one function."""

    def __init__(self, imports: "_Imports", own_class: str | None, module_name: str,
                 local_funcs: set[str], local_methods: dict[str, set[str]],
                 local_names: set[str]):
        self.imports = imports
        self.own_class = own_class
        self.module_name = module_name
        self.local_funcs = local_funcs          # module-level function names in this module
        self.local_methods = local_methods      # class -> method names in this module
        self.local_names = local_names          # params + names bound inside the function
        self.reasons: list[str] = []
        self.calls: set[tuple[str, str]] = set()

    # -- impurity ---------------------------------------------------------------
    def visit_Global(self, node: ast.Global) -> None:
        self.reasons.append(f"global statement: {', '.join(node.names)}")

    def visit_Call(self, node: ast.Call) -> None:
        fn = node.func
        if isinstance(fn, ast.Name):
            name = fn.id
            if name in IMPURE_CALLS:
                self.reasons.append(f"call to {name}()")
            origin = self.imports.origins.get(name)
            if origin:
                mod, orig_name = origin
                if (mod, orig_name) in PURE_EXCEPTIONS:
                    pass
                elif mod in IMPURE_MODULES or (mod, orig_name) in IMPURE_ATTRS:
                    self.reasons.append(f"call to {mod}.{orig_name}")
                elif mod.startswith("."):
                    pass  # intra-package import; resolved at link time
            if name in self.local_funcs:
                self.calls.add((self.module_name, name))
        elif isinstance(fn, ast.Attribute):
            base = fn.value
            if isinstance(base, ast.Name):
                mod = self.imports.module_aliases.get(base.id)
                if mod:
                    if (mod, fn.attr) in PURE_EXCEPTIONS:
                        pass
                    elif mod in IMPURE_MODULES:
                        self.reasons.append(f"call to {mod}.{fn.attr}")
                    elif (mod, fn.attr) in IMPURE_ATTRS:
                        self.reasons.append(f"call to {mod}.{fn.attr}")
                elif base.id == "self" and self.own_class:
                    if fn.attr in self.local_methods.get(self.own_class, set()):
                        self.calls.add((self.module_name, f"{self.own_class}.{fn.attr}"))
                elif base.id in self.local_methods:  # ClassName.method(...)
                    if fn.attr in self.local_methods[base.id]:
                        self.calls.add((self.module_name, f"{base.id}.{fn.attr}"))
                if (fn.attr in MUTATOR_METHODS and mod is None
                        and base.id not in self.local_names
                        and base.id not in self.local_methods):
                    self.reasons.append(
                        f"mutation of enclosing-scope name: {base.id}.{fn.attr}()")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # X[k] = v  /  del X[k]  where X is not function-local -> global-state write
        if isinstance(node.ctx, (ast.Store, ast.Del)) and isinstance(node.value, ast.Name):
            name = node.value.id
            if name not in self.local_names:
                self.reasons.append(f"mutation of enclosing-scope name: {name}[...]")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # non-call attribute reads like os.environ[...]
        if isinstance(node.value, ast.Name):
            mod = self.imports.module_aliases.get(node.value.id)
            if mod and (mod, node.attr) in IMPURE_ATTRS:
                self.reasons.append(f"read of {mod}.{node.attr}")
        self.generic_visit(node)

    # don't descend into nested defs/lambdas' default args twice; nested defs share fate
    # (they execute inside the function), so descending is correct - keep generic_visit.


class _Imports:
    def __init__(self, tree: ast.Module):
        self.origins: dict[str, tuple[str, str]] = {}   # local name -> (module, original)
        self.module_aliases: dict[str, str] = {}        # alias -> top-level module
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.module_aliases[a.asname or a.name.split(".")[0]] = a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                top = f".{mod}" if node.level else mod.split(".")[0]
                for a in node.names:
                    self.origins[a.asname or a.name] = (top, a.name)


def _local_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Parameters + every name bound inside the function (assigns, loop/with targets,
    walrus, comprehension vars, nested defs). Anything else a bare name refers to is
    enclosing-scope (module or closure) state."""
    a = node.args
    names = {p.arg for p in a.args + a.posonlyargs + a.kwonlyargs}
    if a.vararg:
        names.add(a.vararg.arg)
    if a.kwarg:
        names.add(a.kwarg.arg)
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            names.add(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n is not node:
            names.add(n.name)
    return names


def _is_overload(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for d in node.decorator_list:
        if (isinstance(d, ast.Name) and d.id == "overload") or \
           (isinstance(d, ast.Attribute) and d.attr == "overload"):
            return True
    return False


def _is_test_path(p: Path) -> bool:
    parts = {q.lower() for q in p.parts}
    return bool(parts & {"test", "tests"}) or p.name.startswith(("test_", "conftest"))


def index_package(repo: Path, package_dir: Path) -> list[FuncRecord]:
    records: list[FuncRecord] = []
    intra_links: dict[tuple[str, str], set[tuple[str, str]]] = {}
    # module_name -> (local function names, class -> methods), for cross-module linking
    module_tables: dict[str, tuple[set[str], dict[str, set[str]]]] = {}
    trees: dict[str, tuple[ast.Module, Path]] = {}

    for py in sorted(package_dir.rglob("*.py")):
        if _is_test_path(py.relative_to(package_dir)):
            continue
        rel_mod = ".".join(py.relative_to(package_dir).with_suffix("").parts)
        module_name = package_dir.name if rel_mod == "__init__" else f"{package_dir.name}.{rel_mod}"
        try:
            tree = ast.parse(py.read_text(), filename=str(py))
        except SyntaxError as exc:  # py2-only files etc. - skip loudly
            print(f"  [skip] {py}: {exc}", file=sys.stderr)
            continue
        trees[module_name] = (tree, py)
        funcs = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        methods: dict[str, set[str]] = {}
        for n in tree.body:
            if isinstance(n, ast.ClassDef):
                methods[n.name] = {m.name for m in n.body
                                   if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
        module_tables[module_name] = (funcs, methods)

    for module_name, (tree, py) in trees.items():
        imports = _Imports(tree)
        funcs, methods = module_tables[module_name]
        rel = str(py.relative_to(repo))

        def scan(node: ast.FunctionDef | ast.AsyncFunctionDef, qualname: str,
                 own_class: str | None) -> None:
            if _is_overload(node):
                return  # typing stub, not a real body
            scanner = _BodyScan(imports, own_class, module_name, funcs, methods,
                                _local_names(node))
            for stmt in node.body:
                scanner.visit(stmt)
            doc = ast.get_docstring(node) or ""
            leaf = qualname.split(".")[-1]
            public = not leaf.startswith("_") and not (own_class or "").startswith("_")
            rec = FuncRecord(module=rel, module_name=module_name, qualname=qualname,
                             signature=_signature(node), span=(node.lineno, node.end_lineno or node.lineno),
                             doc=doc, impure_reasons=sorted(set(scanner.reasons)),
                             calls=scanner.calls, public=public)
            records.append(rec)
            intra_links[rec.key] = scanner.calls

        for n in tree.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scan(n, n.name, None)
            elif isinstance(n, ast.ClassDef):
                for m in n.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        scan(m, f"{n.name}.{m.name}", n.name)

    # transitive impurity: fixpoint over the intra-package call graph
    by_key = {r.key: r for r in records}
    changed = True
    while changed:
        changed = False
        for rec in records:
            if rec.impure_reasons:
                continue
            for callee_key in intra_links.get(rec.key, ()):
                callee = by_key.get(callee_key)
                if callee and callee.impure_reasons:
                    rec.impure_reasons.append(f"transitively impure via {callee.qualname}")
                    changed = True
                    break
    return records


def _has_inverse(name: str, all_names: set[str]) -> str | None:
    low = name.lower()
    for a, b in INVERSE_STEMS:
        if a in low:
            partner = low.replace(a, b)
            if partner != low and any(partner == n.lower() for n in all_names):
                return f"inverse pair with {partner}"
        if b in low:
            partner = low.replace(b, a)
            if partner != low and any(partner == n.lower() for n in all_names):
                return f"inverse pair with {partner}"
    return None


def classify_auditability(rec: FuncRecord, all_leaf_names: set[str]) -> tuple[str, str]:
    """Returns (basis, why)."""
    if len(rec.doc.split()) >= SPEC_MIN_DOC_WORDS:
        return "spec", f"docstring of {len(rec.doc.split())} words"
    leaf = rec.qualname.split(".")[-1]
    inv = _has_inverse(leaf, all_leaf_names)
    if inv:
        return "invariant", inv
    if leaf.lower().startswith(IDEMPOTENT_PREFIXES):
        return "invariant", "idempotent-by-name transform"
    return "none", "no substantive docstring, no recognized universal invariant"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repo", type=Path)
    ap.add_argument("--package", type=Path, default=None,
                    help="package dir inside the repo (auto-detected if omitted)")
    ap.add_argument("--out", type=Path, default=None,
                    help="manifest path (default: <repo>/../manifest.json)")
    args = ap.parse_args()

    repo: Path = args.repo.resolve()
    if args.package:
        package_dir = (repo / args.package).resolve()
    else:
        candidates = [p.parent for p in repo.glob("src/*/__init__.py")] or \
                     [p.parent for p in repo.glob("*/__init__.py")
                      if not _is_test_path(p.parent.relative_to(repo))]
        if not candidates:
            print("no package found; pass --package", file=sys.stderr)
            return 1
        package_dir = candidates[0]

    commit = ""
    try:
        commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        pass

    records = index_package(repo, package_dir)
    public = [r for r in records if r.public]
    all_leaf_names = {r.qualname.split(".")[-1] for r in records}

    out_funcs = []
    counts = {"spec": 0, "invariant": 0, "none": 0}
    det_auditable = 0
    for rec in sorted(public, key=lambda r: (r.module, r.span[0])):
        basis, why = classify_auditability(rec, all_leaf_names)
        counts[basis] += 1
        deterministic = not rec.impure_reasons
        if deterministic and basis != "none":
            det_auditable += 1
        out_funcs.append({
            "module": rec.module,
            "qualname": rec.qualname,
            "signature": rec.signature,
            "span": list(rec.span),
            "deterministic": deterministic,
            "impure_reasons": rec.impure_reasons,
            "auditability": basis,
            "auditability_why": why,
            "intent": _intent(rec),
            "doc": rec.doc,  # full docstring - the spec text the oracle author prompts against
        })

    manifest = {
        "target": package_dir.name,
        "repo_path": str(repo),
        "commit": commit,
        "package_dir": str(package_dir.relative_to(repo)),
        "indexer": "auditor/index.py",
        "functions": out_funcs,
        "summary": {
            "total_public_functions": len(out_funcs),
            "auditability": counts,
            "deterministic": sum(1 for f in out_funcs if f["deterministic"]),
            "auditable": det_auditable,
        },
    }

    out_path = args.out or repo.parent / "manifest.json"
    out_path.write_text(json.dumps(manifest, indent=2) + "\n")

    s = manifest["summary"]
    print(f"target: {manifest['target']} @ {commit[:12]}")
    print(f"public functions: {s['total_public_functions']}")
    print(f"  basis spec:      {counts['spec']}")
    print(f"  basis invariant: {counts['invariant']}")
    print(f"  basis none:      {counts['none']}   (honestly out of scope)")
    print(f"deterministic:     {s['deterministic']}")
    print(f"AUDITABLE (deterministic AND spec|invariant): {s['auditable']}")
    print(f"manifest: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
