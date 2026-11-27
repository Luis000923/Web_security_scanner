#!/usr/bin/env python3
"""Deterministic AST duplicate guard (stdlib only, no LLM).

Three modes, all read-only:

``--lookup "<query>"``
    Before writing a helper: rank existing functions by name/doc/signature
    overlap with the query (from ``.context/symbols.json`` when present, a
    live AST walk otherwise) and print a compact (<= ~150 token) answer.

``--scan``
    Whole-repo clone report. Type 1/2 clones share a hash of the normalised
    AST (docstring dropped, locals/args renamed positionally, attributes and
    globals kept). Type 3 clones are pairs whose AST-token 4-gram shingles
    have Jaccard similarity >= ``--threshold``. Same-name functions repeated
    across modules are listed separately as review candidates.

``--check-diff``
    Only functions touched by ``git diff`` (plus untracked files) are compared
    against the rest of the index. A match that already existed at the base
    revision is not reported, so pre-existing debt never blocks a commit.
    Exit 0 = clean, 2 = new duplicate (reuse the reported symbol), 1 = error.

``--hook``
    Claude Code ``PreToolUse`` hook (``.claude/settings.json``): reads the
    tool payload on stdin and, only for a Bash ``git commit``, runs
    ``--check-diff --staged``; exit 2 blocks the commit. Failures exit 0.

Suppressions: a ``# dup-guard: ignore`` comment on the ``def`` line (or on
the line right above it / its decorators), or an entry in
``tools/dup_allowlist.json``::

    {"groups": [{"members": ["path.py::Qual", "other.py::Qual"],
                 "reason": "why these must stay separate"}]}
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
import zlib
from collections import defaultdict
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import context_packer as cp  # noqa: E402

DEFAULT_MIN_LINES = 8
DEFAULT_THRESHOLD = 0.85
DEFAULT_ALLOWLIST = "tools/dup_allowlist.json"
SHINGLE_K = 4
LOOKUP_LIMIT = 5
LOOKUP_DOC_CHARS = 60
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DUPLICATE = 2

_IGNORE_RE = re.compile(r"#\s*dup-guard:\s*ignore\b")
_WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
# Plugin-contract method names: same name across testers is the interface,
# not a copy-paste accident.
_CONTRACT_NAMES = frozenset({"run", "test", "check", "scan", "detect", "execute", "analyze"})
_PLUGIN_DIRS = ("vulnerability_testers/", "plugins/")
_ENTRYPOINT_NAMES = frozenset({"main", "build_parser", "parse_args", "cli"})

FuncNode = ast.FunctionDef | ast.AsyncFunctionDef


# ---------------------------------------------------------------------------
# AST fingerprinting
# ---------------------------------------------------------------------------


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


def _local_names(func: FuncNode) -> set[str]:
    """Arguments plus every name the function itself binds."""
    names: set[str] = set()
    a = func.args
    for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg):
        if arg is not None:
            names.add(arg.arg)
    for node in ast.walk(func):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
    return names


class _Normalizer(ast.NodeTransformer):
    """Rename locals/args to ``_v<n>`` by first occurrence (Type-2 clones)."""

    def __init__(self, local: set[str]) -> None:
        self.local = local
        self.mapping: dict[str, str] = {}

    def _rename(self, name: str) -> str:
        if name not in self.local:
            return name
        if name not in self.mapping:
            self.mapping[name] = f"_v{len(self.mapping)}"
        return self.mapping[name]

    def visit_Name(self, node: ast.Name) -> ast.Name:
        node.id = self._rename(node.id)
        return node

    def visit_arg(self, node: ast.arg) -> ast.arg:
        node.arg = self._rename(node.arg)
        node.annotation = None
        return node

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.ExceptHandler:
        if node.name:
            node.name = self._rename(node.name)
        self.generic_visit(node)
        return node


def _normalized(func: FuncNode) -> ast.Module:
    clone = ast.parse(ast.unparse(func)).body[0]
    assert isinstance(clone, (ast.FunctionDef, ast.AsyncFunctionDef))  # nosec B101
    local = _local_names(clone)
    clone.name = "_f"
    clone.decorator_list = []
    clone.returns = None
    clone.body = _strip_docstring(clone.body) or [ast.Pass()]
    return ast.Module(body=[_Normalizer(local).visit(clone)], type_ignores=[])


def _tokens(node: ast.AST) -> Iterator[str]:
    """Pre-order AST token stream used for Type-3 shingling."""
    yield type(node).__name__
    if isinstance(node, ast.Attribute):
        yield "." + node.attr
    elif isinstance(node, ast.Name):
        yield node.id if not node.id.startswith("_v") else "_v"
    elif isinstance(node, ast.Constant):
        yield type(node.value).__name__
    for child in ast.iter_child_nodes(node):
        yield from _tokens(child)


def _gram(tokens: Sequence[str]) -> int:
    # zlib.crc32 is stable across processes (str hash() is salted).
    return zlib.crc32("\x1f".join(tokens).encode("utf-8"))


def _shingles(tokens: Sequence[str]) -> frozenset[int]:
    if len(tokens) < SHINGLE_K:
        return frozenset({_gram(tokens)})
    return frozenset(_gram(tokens[i : i + SHINGLE_K]) for i in range(len(tokens) - SHINGLE_K + 1))


def logical_lines(func: FuncNode) -> int:
    """Distinct source lines that start a statement, docstring excluded."""
    lines: set[int] = set()
    for stmt in _strip_docstring(func.body):
        for node in ast.walk(stmt):
            if isinstance(node, ast.stmt):
                lines.add(node.lineno)
    return len(lines)


@dataclass(frozen=True)
class FuncRecord:
    """One function or method with its clone fingerprints."""

    path: str
    qualname: str
    lineno: int
    end_lineno: int
    logical: int
    signature: str
    doc: str
    exact: str
    shingles: frozenset[int] = field(repr=False, compare=False)
    is_test: bool = False
    ignored: bool = False

    @property
    def key(self) -> str:
        return f"{self.path}::{self.qualname}"

    @property
    def name(self) -> str:
        return self.qualname.rsplit(".", 1)[-1]

    @property
    def span(self) -> int:
        return self.end_lineno - self.lineno + 1


def _has_ignore(lines: list[str], func: FuncNode) -> bool:
    first = min([func.lineno, *(d.lineno for d in func.decorator_list)])
    lo = max(first - 2, 0)
    return any(_IGNORE_RE.search(line) for line in lines[lo : func.lineno])


def _walk_funcs(body: list[ast.stmt], prefix: str) -> Iterator[tuple[str, FuncNode]]:
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qual = f"{prefix}{node.name}"
            yield qual, node
            yield from _walk_funcs(node.body, f"{qual}.")
        elif isinstance(node, ast.ClassDef):
            yield from _walk_funcs(node.body, f"{prefix}{node.name}.")
        elif isinstance(node, (ast.If, ast.Try)):
            yield from _walk_funcs(node.body, prefix)
            yield from _walk_funcs(node.orelse, prefix)


def records_from_source(path: str, source: str) -> list[FuncRecord]:
    """Fingerprint every function in ``source``; syntax errors yield ``[]``."""
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError):
        return []
    lines = source.splitlines()
    is_test = cp.is_test_path(path)
    out: list[FuncRecord] = []
    for qual, func in _walk_funcs(tree.body, ""):
        norm = _normalized(func)
        digest = hashlib.sha256(ast.dump(norm, include_attributes=False).encode()).hexdigest()
        out.append(
            FuncRecord(
                path=path,
                qualname=qual,
                lineno=func.lineno,
                end_lineno=func.end_lineno or func.lineno,
                logical=logical_lines(func),
                signature=f"{func.name}({cp.format_arguments(func.args, False)})",
                doc=(ast.get_docstring(func) or "").strip().split("\n", 1)[0],
                exact=digest[:16],
                shingles=_shingles(list(_tokens(norm.body[0]))),
                is_test=is_test,
                ignored=_has_ignore(lines, func),
            )
        )
    return out


def jaccard(a: frozenset[int], b: frozenset[int]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------


def load_allowlist(root: Path, rel: str) -> list[frozenset[str]]:
    """Return allowlisted member sets; a missing file is an empty list."""
    try:
        path = cp.safe_resolve(root, rel)
    except cp.PackerError:
        return []
    if not path.is_file():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    groups = raw.get("groups", []) if isinstance(raw, dict) else []
    out: list[frozenset[str]] = []
    for group in groups:
        members = group.get("members") if isinstance(group, dict) else None
        if isinstance(members, list) and all(isinstance(m, str) for m in members):
            out.append(frozenset(members))
    return out


def is_allowed(keys: Iterable[str], allow: list[frozenset[str]]) -> bool:
    wanted = set(keys)
    return any(wanted <= group for group in allow)


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


@dataclass
class DupGroup:
    """A cluster of clones (``exact`` / ``near``) or same-name functions."""

    kind: str
    similarity: float
    members: list[FuncRecord]

    @property
    def savable_lines(self) -> int:
        spans = sorted(m.span for m in self.members)
        return sum(spans[:-1])

    @property
    def risk(self) -> str:
        """Heuristic refactor risk: Bajo / Medio / Alto."""
        paths = {m.path for m in self.members}
        tops = {p.split("/", 1)[0] for p in paths}
        names = {m.name for m in self.members}
        in_plugins = any(any(d in p for d in _PLUGIN_DIRS) for p in paths)
        methods = any("." in m.qualname for m in self.members)
        if self.kind == "name" or (in_plugins and (names & _CONTRACT_NAMES)):
            return "Alto"
        if len(tops) > 1 or self.kind == "near" or (in_plugins and methods):
            return "Medio"
        return "Bajo"

    def to_json(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "similarity": round(self.similarity, 3),
            "risk": self.risk,
            "savable_lines": self.savable_lines,
            "members": [
                {"symbol": m.key, "lines": f"{m.lineno}-{m.end_lineno}", "logical": m.logical}
                for m in self.members
            ],
        }


def collect_records(root: Path, include_tests: bool) -> list[FuncRecord]:
    snap = cp.Snapshot(root)
    files = [f for f in snap.python_files() if include_tests or not cp.is_test_path(f)]
    out: list[FuncRecord] = []
    for path, source in sorted(snap.read_many(files).items()):
        out.extend(records_from_source(path, source))
    return out


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        self.parent[self.find(a)] = self.find(b)


def near_pairs(
    recs: Sequence[FuncRecord], threshold: float
) -> Iterator[tuple[FuncRecord, FuncRecord, float]]:
    """Yield (a, b, jaccard) with jaccard >= threshold and distinct exact hash."""
    ordered = sorted(recs, key=lambda r: len(r.shingles))
    for i, a in enumerate(ordered):
        size_a = len(a.shingles)
        for b in ordered[i + 1 :]:
            if size_a < threshold * len(b.shingles):
                break  # Jaccard <= |a| / |b| < threshold for every later b
            if a.exact == b.exact:
                continue
            score = jaccard(a.shingles, b.shingles)
            if score >= threshold:
                yield a, b, score


def scan(
    records: Sequence[FuncRecord],
    min_lines: int,
    threshold: float,
    allow: list[frozenset[str]],
) -> list[DupGroup]:
    """Group clones; allowlisted/ignored members and tiny functions are skipped."""
    big = [r for r in records if r.logical >= min_lines and not r.ignored]
    by_key = {r.key: r for r in big}
    groups: list[DupGroup] = []

    by_hash: dict[str, list[FuncRecord]] = defaultdict(list)
    for rec in big:
        by_hash[rec.exact].append(rec)
    exact_keys: set[str] = set()
    for members in by_hash.values():
        if len(members) > 1 and not is_allowed((m.key for m in members), allow):
            groups.append(DupGroup("exact", 1.0, members))
            exact_keys.update(m.key for m in members)

    uf = _UnionFind()
    pair_score: dict[tuple[str, str], float] = {}
    for a, b, score in near_pairs(big, threshold):
        if is_allowed((a.key, b.key), allow):
            continue
        uf.union(a.key, b.key)
        pair_score[(a.key, b.key)] = score
    clusters: dict[str, list[FuncRecord]] = defaultdict(list)
    for key in list(uf.parent):
        clusters[uf.find(key)].append(by_key[key])
    for members in clusters.values():
        keys = {m.key for m in members}
        if len(members) > 1 and not keys <= exact_keys:
            sim = min(s for (x, y), s in pair_score.items() if x in keys and y in keys)
            groups.append(DupGroup("near", sim, sorted(members, key=lambda m: m.key)))

    clustered = {m.key for g in groups for m in g.members}
    by_name: dict[str, list[FuncRecord]] = defaultdict(list)
    for rec in big:
        # Same-name *methods* are polymorphism (plugin/adapter contracts), and
        # every CLI has its own main(); only module-level helpers count here.
        if "." in rec.qualname or rec.name in _ENTRYPOINT_NAMES or rec.key in clustered:
            continue
        by_name[rec.name].append(rec)
    for members in by_name.values():
        if len({m.path for m in members}) > 1 and not is_allowed((m.key for m in members), allow):
            sim = min(
                jaccard(x.shingles, y.shingles) for x in members for y in members if x is not y
            )
            groups.append(DupGroup("name", sim, members))

    order = {"exact": 0, "near": 1, "name": 2}
    groups.sort(key=lambda g: (order[g.kind], -g.savable_lines, g.members[0].key))
    return groups


def render_table(groups: Sequence[DupGroup], top: int) -> str:
    rows = ["| # | tipo | sim | riesgo | ahorrables | miembros |", "|---|---|---|---|---|---|"]
    for i, g in enumerate(groups[:top], 1):
        members = "<br>".join(f"{m.key}:{m.lineno}-{m.end_lineno}" for m in g.members)
        rows.append(
            f"| {i} | {g.kind} | {g.similarity:.2f} | {g.risk} | {g.savable_lines} | {members} |"
        )
    summary: dict[str, int] = defaultdict(int)
    for g in groups:
        summary[g.kind] += 1
    rows.append("")
    rows.append(
        "grupos: "
        + " ".join(f"{k}={summary.get(k, 0)}" for k in ("exact", "near", "name"))
        + f" ahorrables(exact+near)={sum(g.savable_lines for g in groups if g.kind != 'name')}"
    )
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


def words(text: str) -> list[str]:
    """Split snake_case / CamelCase / free text into lowercase, de-pluralised words."""
    out: list[str] = []
    for raw in _WORD_RE.findall(text):
        w = raw.lower()
        if len(w) > 3 and w.endswith("s") and not w.endswith("ss"):
            w = w[:-1]
        out.append(w)
    return out


@dataclass(frozen=True)
class LookupHit:
    path: str
    lineno: int
    qualname: str
    signature: str
    doc: str
    score: float


def _symbol_rows(root: Path) -> Iterator[tuple[str, int, str, str, str]]:
    ctx = root / ".context" / "symbols.json"
    if ctx.is_file():
        data = json.loads(ctx.read_text(encoding="utf-8"))
        for path, info in sorted(data.get("files", {}).items()):
            for sym in info.get("symbols", []):
                if sym.get("kind") in ("function", "method", "async_function", "class"):
                    yield (
                        path,
                        int(sym["lineno"]),
                        str(sym["qualname"]),
                        str(sym.get("signature", "")),
                        str(sym.get("doc", "")),
                    )
        return
    for rec in collect_records(root, include_tests=False):
        yield rec.path, rec.lineno, rec.qualname, rec.signature, rec.doc


def lookup(root: Path, query: str, limit: int = LOOKUP_LIMIT) -> list[LookupHit]:
    """Rank existing symbols by word overlap with ``query``."""
    q = set(words(query))
    if not q:
        return []
    hits: list[LookupHit] = []
    for path, lineno, qual, sig, doc in _symbol_rows(root):
        if cp.is_test_path(path):
            continue
        name_w = set(words(qual.rsplit(".", 1)[-1]))
        ctx_w = set(words(qual)) | set(words(Path(path).stem))
        doc_w = set(words(doc)) | set(words(sig))
        score = 3.0 * len(q & name_w) + 1.0 * len(q & ctx_w) + 0.5 * len(q & doc_w)
        if not q & (name_w | ctx_w | doc_w):
            continue
        if q <= name_w:
            score += 2.0
        if score > 0:
            hits.append(LookupHit(path, lineno, qual, sig, doc, score))
    hits.sort(key=lambda h: (-h.score, h.path, h.lineno))
    return hits[:limit]


def render_lookup(hits: Sequence[LookupHit]) -> str:
    if not hits:
        return "sin coincidencias: puedes crear la función (anota por qué no reutilizas)."
    lines = []
    for h in hits:
        doc = cp._short(h.doc, LOOKUP_DOC_CHARS) if h.doc else ""
        sig = h.signature if h.signature.startswith(h.qualname.rsplit(".", 1)[-1]) else h.qualname
        lines.append(f"{h.path}:{h.lineno} {sig}" + (f" — {doc}" if doc else ""))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Check diff
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    new: FuncRecord
    existing: FuncRecord
    kind: str
    similarity: float

    def render(self) -> str:
        return (
            f"{self.new.key}:{self.new.lineno} duplica {self.existing.key}:"
            f"{self.existing.lineno} ({self.kind}, sim={self.similarity:.2f}) "
            f"-> reutiliza {self.existing.qualname}"
        )


def _match(a: FuncRecord, b: FuncRecord, threshold: float) -> tuple[str, float] | None:
    if a.exact == b.exact:
        return "exact", 1.0
    score = jaccard(a.shingles, b.shingles)
    return ("near", score) if score >= threshold else None


def changed_records(
    root: Path, base: str, staged: bool, include_tests: bool
) -> tuple[list[FuncRecord], set[str]]:
    """Functions whose span touches an added line, plus all in untracked files."""
    args = ["diff", "--unified=0", "--no-color", "--no-ext-diff"]
    args += ["--cached", cp.validate_rev(base)] if staged else [cp.validate_rev(base)]
    diff = cp.run_git(root, [*args, "--", "*.py"]).decode("utf-8", errors="replace")
    touched: dict[str, set[int]] = {
        f.path: f.added_lines for f in cp.parse_unified_diff(diff) if f.new_path
    }
    if not staged:
        untracked = cp.run_git(root, ["ls-files", "-z", "--others", "--exclude-standard"])
        for rel in untracked.decode("utf-8", errors="replace").split("\0"):
            if rel.endswith(".py") and not cp.is_excluded(rel):
                touched[rel] = set(range(1, 1_000_000))
    paths = {p for p in touched if include_tests or not cp.is_test_path(p)}
    sources: dict[str, str]
    if staged:
        sources = {
            p: cp.run_git(root, ["show", f":{p}"]).decode("utf-8", errors="replace")
            for p in sorted(paths)
        }
    else:
        sources = cp.Snapshot(root).read_many(paths)
    out: list[FuncRecord] = []
    for path, source in sources.items():
        lines = touched[path]
        for rec in records_from_source(path, source):
            if any(rec.lineno <= ln <= rec.end_lineno for ln in lines):
                out.append(rec)
    return out, paths


def check_diff(
    root: Path,
    base: str,
    staged: bool,
    min_lines: int,
    threshold: float,
    allow: list[frozenset[str]],
    include_tests: bool,
) -> list[Finding]:
    """New duplicates introduced by the diff (pre-existing pairs are ignored)."""
    changed, paths = changed_records(root, base, staged, include_tests)
    candidates = [r for r in changed if r.logical >= min_lines and not r.ignored]
    if not candidates:
        return []
    cand_keys = {r.key for r in candidates}
    corpus = [
        r
        for r in collect_records(root, include_tests)
        if r.key not in cand_keys and r.logical >= min_lines and not r.ignored
    ]
    base_src = cp.Snapshot(root, rev=base).read_many(paths)
    base_recs = {r.key: r for p, s in base_src.items() for r in records_from_source(p, s)}
    findings: list[Finding] = []
    for new in candidates:
        best: Finding | None = None
        for old in corpus:
            hit = _match(new, old, threshold)
            if hit is None or is_allowed((new.key, old.key), allow):
                continue
            prior = base_recs.get(new.key)
            if prior is not None and _match(prior, old, threshold) is not None:
                continue  # already duplicated before this change
            if best is None or hit[1] > best.similarity:
                best = Finding(new, old, hit[0], hit[1])
        if best is not None:
            findings.append(best)
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--lookup", metavar="QUERY", help="find existing functions to reuse")
    mode.add_argument("--scan", action="store_true", help="whole-repo duplicate report")
    mode.add_argument("--check-diff", action="store_true", help="block new duplicates in git diff")
    mode.add_argument(
        "--hook", action="store_true", help="Claude Code PreToolUse hook (blocks git commit)"
    )
    ap.add_argument("--base", default="HEAD", help="diff base revision (default HEAD)")
    ap.add_argument("--staged", action="store_true", help="check the index instead of the worktree")
    ap.add_argument("--min-lines", type=int, default=DEFAULT_MIN_LINES)
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--allowlist", default=DEFAULT_ALLOWLIST)
    ap.add_argument("--include-tests", action="store_true", help="also index tests/")
    ap.add_argument("--top", type=int, default=10, help="groups shown by --scan")
    ap.add_argument("--limit", type=int, default=LOOKUP_LIMIT, help="hits shown by --lookup")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    return ap


_GIT_COMMIT_RE = re.compile(r"(?:^|[;&|(\s])git\s+(?:-C\s+\S+\s+)?commit\b")


def run_hook(stdin_text: str, args: argparse.Namespace) -> int:
    """PreToolUse hook: on ``git commit``, exit 2 (block) on new staged duplicates.

    Any parse/git failure exits 0: the guard must never wedge the session.
    """
    try:
        payload = json.loads(stdin_text or "{}")
    except ValueError:
        return EXIT_OK
    tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
    command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
    if not isinstance(command, str) or not _GIT_COMMIT_RE.search(command):
        return EXIT_OK
    try:
        root = cp.find_repo_root(Path.cwd())
        findings = check_diff(
            root,
            "HEAD",
            True,
            args.min_lines,
            args.threshold,
            load_allowlist(root, args.allowlist),
            args.include_tests,
        )
    except (cp.PackerError, OSError, ValueError) as exc:
        print(f"dup_guard hook: omitido ({exc})", file=sys.stderr)
        return EXIT_OK
    if not findings:
        return EXIT_OK
    for f in findings:
        print(f.render(), file=sys.stderr)
    print(
        "dup_guard: commit bloqueado. Reutiliza el símbolo existente, o justifica con "
        "'# dup-guard: ignore -- <motivo>' / tools/dup_allowlist.json (skill reuse-before-write).",
        file=sys.stderr,
    )
    return EXIT_DUPLICATE


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.hook:
        return run_hook(sys.stdin.read(), args)
    try:
        root = cp.find_repo_root(Path.cwd())
        allow = load_allowlist(root, args.allowlist)
        if args.lookup is not None:
            hits = lookup(root, args.lookup, args.limit)
            if args.json:
                print(json.dumps([h.__dict__ for h in hits], ensure_ascii=False))
            else:
                print(render_lookup(hits))
            return EXIT_OK
        if args.scan:
            groups = scan(
                collect_records(root, args.include_tests), args.min_lines, args.threshold, allow
            )
            if args.json:
                print(json.dumps([g.to_json() for g in groups], ensure_ascii=False, indent=1))
            else:
                print(render_table(groups, args.top))
            return EXIT_OK
        findings = check_diff(
            root,
            args.base,
            args.staged,
            args.min_lines,
            args.threshold,
            allow,
            args.include_tests,
        )
    except (cp.PackerError, OSError, json.JSONDecodeError) as exc:
        print(f"dup_guard: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "new": f.new.key,
                        "existing": f.existing.key,
                        "line": f.existing.lineno,
                        "kind": f.kind,
                        "similarity": round(f.similarity, 3),
                    }
                    for f in findings
                ],
                ensure_ascii=False,
            )
        )
    else:
        for f in findings:
            print(f.render())
        print(f"dup-check: {'FAIL' if findings else 'OK'} ({len(findings)} duplicados nuevos)")
    return EXIT_DUPLICATE if findings else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
