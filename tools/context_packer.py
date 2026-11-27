#!/usr/bin/env python3
"""Deterministic AST context packer for agent workflows (L0 -> L1 -> L2).

Modes
-----
``--mode l0``
    Repo map. Writes ``.context/repomap.md`` (paths, classes, typed
    signatures, key imports; no bodies) and ``.context/symbols.json`` (full
    symbol index with line spans and call names, used by L1).
``--mode l1``
    Context bundle for a change: the unified diff (or a list of symbols /
    files) plus the signatures and call-site slices of 1-hop callers and the
    signatures of 1-hop callees, resolved through the AST call graph.
``--mode budget``
    Same bundle as ``l1`` but measured against the full-file baseline of every
    file involved and pruned by priority until it is ``<= --max-ratio``
    (default 0.60). Exits with code 3 when no pruning level fits.

Priority (kept longest -> pruned first): diff hunks > typed signatures >
tracebacks > caller slices > docstrings / comments / low-relevance blocks.

Only the standard library is required. ``tiktoken`` (cl100k_base) is used when
importable and its encoding loads offline; otherwise a conservative,
deterministic heuristic counts tokens. The tokenizer name is recorded in every
output so numbers are reproducible per backend.

Security: files come from ``git ls-files`` (honours ``.gitignore`` and
``.git/info/exclude``); every path is resolved and must stay inside the repo
root; VCS/venv/cache dirs and secret-looking files are never read; git runs
without a shell and with validated revisions; obvious secrets are redacted
from bundle output.

Exit codes: 0 ok, 1 stale (``--check``), 2 input/usage error, 3 over budget.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

SCHEMA_VERSION = 1
CONTEXT_DIRNAME = ".context"
REPOMAP_NAME = "repomap.md"
SYMBOLS_NAME = "symbols.json"
BUNDLE_NAME = "bundle.md"
DEFAULT_MAX_RATIO = 0.60
# The heuristic over-counts code slightly more than prose, which can make a
# bundle look a few percent cheaper than under cl100k (measured: 0.1685 vs
# 0.1733 on a 20-file diff). Enforce a tighter limit when it is in use.
HEURISTIC_RATIO_MARGIN = 0.95
GIT_TIMEOUT_S = 60
MAX_TEXT_BYTES = 2_000_000

EXIT_OK = 0
EXIT_STALE = 1
EXIT_INPUT = 2
EXIT_OVER_BUDGET = 3

# Directory names never traversed, wherever they appear in a path.
EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        ".tox",
        ".nox",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        CONTEXT_DIRNAME,
        "worktrees",
        "site-packages",
        "build",
        "dist",
    }
)

# Secret-looking file names (matched on the final path component only, so a
# module such as ``credential_exposure_tester_async.py`` is still indexed).
_SECRET_NAME_RE = re.compile(
    r"""(?ix)
    ^\.env(?:\..*)?$
    | \.(?:pem|key|p12|pfx|jks|keystore|kdbx|ovpn|asc|gpg)$
    | ^id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$
    | ^\.(?:netrc|pgpass|pypirc|npmrc)$
    | ^credentials?(?:\.(?:json|ya?ml|toml|ini|cfg|txt))?$
    | ^secrets?\.(?:json|ya?ml|toml|ini|cfg|env|txt)$
    | \.secrets?$
    """
)

# Accepts refs like HEAD, HEAD~2, main, origin/main, abc123^, A..B, A...B.
_SAFE_REV_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/~^@{}-]{0,199}$")

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED PRIVATE KEY]",
    ),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED AWS KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[REDACTED API KEY]"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "[REDACTED JWT]",
    ),
    (
        re.compile(
            r"(?i)(\b(?:authorization|proxy-authorization)\b\s*[:=]\s*[\"']?\s*(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]{8,}"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)(\b\w*(?:api[_-]?key|secret|passw(?:or)?d|access[_-]?key|auth[_-]?token)\w*\b[\"']?\s*[:=]\s*[\"'])([^\"'\s]{8,})([\"'])"
        ),
        r"\1[REDACTED]\3",
    ),
)

_STDLIB = frozenset(getattr(sys, "stdlib_module_names", ()))


class PackerError(Exception):
    """Input, git or path-safety failure (exit code 2)."""


# ---------------------------------------------------------------------------
# Token counting
# ---------------------------------------------------------------------------

_HEUR_RE = re.compile(r"[A-Za-z]+|[0-9]+|\s+|[^A-Za-z0-9\s]")


def heuristic_tokens(text: str) -> int:
    """Conservative BPE-like estimate (over-counts cl100k on code).

    Letter runs cost ceil(len/4), digit runs ceil(len/3), every other
    non-space character costs 1 and each newline costs 1 (plus 1 for a
    trailing indentation run longer than one char).
    """
    total = 0
    for match in _HEUR_RE.finditer(text):
        chunk = match.group(0)
        head = chunk[0]
        if head.isascii() and head.isalpha():
            total += (len(chunk) + 3) // 4
        elif head.isascii() and head.isdigit():
            total += (len(chunk) + 2) // 3
        elif head.isspace():
            newlines = chunk.count("\n")
            tail = len(chunk) - chunk.rfind("\n") - 1 if newlines else len(chunk)
            total += newlines + (1 if tail > 1 else 0)
        else:
            total += 1
    return total


class TokenCounter:
    """``tiktoken`` when available offline, deterministic heuristic otherwise."""

    def __init__(self, backend: str = "auto") -> None:
        self._encode: Callable[[str], int] | None = None
        self.name = "heuristic-v1"
        if backend not in ("auto", "tiktoken", "heuristic"):
            raise PackerError(f"unknown tokenizer backend: {backend}")
        if backend == "heuristic":
            return
        try:
            module = importlib.import_module("tiktoken")
            encoding = module.get_encoding("cl100k_base")
        except Exception as exc:  # ImportError, or no offline BPE file
            if backend == "tiktoken":
                raise PackerError(f"tiktoken unavailable: {type(exc).__name__}") from exc
            return

        def _count(text: str) -> int:
            return len(encoding.encode(text, disallowed_special=()))

        self._encode = _count
        self.name = "tiktoken:cl100k_base"

    def count(self, text: str) -> int:
        if self._encode is not None:
            return self._encode(text)
        return heuristic_tokens(text)


# ---------------------------------------------------------------------------
# Path safety and git access
# ---------------------------------------------------------------------------


def is_excluded(rel: str) -> bool:
    """True for VCS/venv/cache paths and secret-looking file names."""
    parts = Path(rel).parts
    if not parts:
        return True
    if any(part in EXCLUDED_PARTS for part in parts):
        return True
    return bool(_SECRET_NAME_RE.search(parts[-1]))


def safe_resolve(root: Path, user_path: str) -> Path:
    """Resolve ``user_path`` and refuse anything outside ``root`` or excluded."""
    if not user_path or "\x00" in user_path:
        raise PackerError("empty or invalid path")
    real_root = root.resolve()
    raw = Path(user_path)
    candidate = (raw if raw.is_absolute() else real_root / raw).resolve()
    if candidate != real_root and real_root not in candidate.parents:
        raise PackerError(f"path escapes repository root: {user_path}")
    rel = candidate.relative_to(real_root).as_posix()
    if rel != "." and is_excluded(rel):
        raise PackerError(f"path is excluded (vcs/venv/cache/secret): {user_path}")
    return candidate


def validate_rev(rev: str) -> str:
    if not _SAFE_REV_RE.match(rev):
        raise PackerError(f"invalid git revision: {rev!r}")
    return rev


def _git_exe() -> str:
    exe = shutil.which("git")
    if not exe:
        raise PackerError("git executable not found on PATH")
    return exe


def run_git(root: Path, args: Sequence[str], *, stdin: bytes | None = None) -> bytes:
    """Run git without a shell; raise PackerError on non-zero exit."""
    cmd = [_git_exe(), "-C", str(root), "-c", "core.quotepath=off", *args]
    try:
        proc = subprocess.run(  # nosec B603
            cmd,
            input=stdin,
            capture_output=True,
            timeout=GIT_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PackerError(f"git {args[0]} timed out") from exc
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()[:300]
        raise PackerError(f"git {args[0]} failed: {err}")
    return proc.stdout


def find_repo_root(start: Path) -> Path:
    out = run_git(start, ["rev-parse", "--show-toplevel"])
    return Path(out.decode("utf-8").strip()).resolve()


class Snapshot:
    """Read-only view of the repo at a revision (``None`` = working tree)."""

    def __init__(self, root: Path, rev: str | None = None) -> None:
        self.root = root.resolve()
        self.rev = validate_rev(rev) if rev else None
        self._files: list[str] | None = None

    def list_files(self) -> list[str]:
        if self._files is None:
            if self.rev is None:
                raw = run_git(
                    self.root,
                    ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                )
            else:
                raw = run_git(
                    self.root, ["ls-tree", "-r", "-z", "--name-only", "--full-tree", self.rev]
                )
            names = {n for n in raw.decode("utf-8", errors="replace").split("\0") if n}
            kept: list[str] = []
            for name in sorted(names):
                if is_excluded(name):
                    continue
                if self.rev is None:
                    try:
                        path = safe_resolve(self.root, name)
                    except PackerError:
                        continue  # symlink escaping the root, etc.
                    if not path.is_file():
                        continue  # tracked but deleted in the worktree
                kept.append(name)
            self._files = kept
        return list(self._files)

    def python_files(self) -> list[str]:
        return [f for f in self.list_files() if f.endswith(".py")]

    def read_many(self, rels: Iterable[str]) -> dict[str, str]:
        wanted = sorted({r for r in rels if not is_excluded(r)})
        if self.rev is None:
            return self._read_worktree(wanted)
        return self._read_rev(wanted)

    def _read_worktree(self, rels: list[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for rel in rels:
            try:
                path = safe_resolve(self.root, rel)
            except PackerError:
                continue
            if not path.is_file() or path.stat().st_size > MAX_TEXT_BYTES:
                continue
            data = path.read_bytes()
            if b"\0" in data[:4096]:
                continue  # binary
            out[rel] = data.decode("utf-8", errors="replace")
        return out

    def _read_rev(self, rels: list[str]) -> dict[str, str]:
        if not rels:
            return {}
        req = "".join(f"{self.rev}:{rel}\n" for rel in rels).encode("utf-8")
        raw = run_git(self.root, ["cat-file", "--batch"], stdin=req)
        out: dict[str, str] = {}
        pos = 0
        for rel in rels:
            nl = raw.index(b"\n", pos)
            header = raw[pos:nl].split()
            pos = nl + 1
            if len(header) < 3 or header[-1] == b"missing":
                continue
            size = int(header[2])
            blob = raw[pos : pos + size]
            pos += size + 1
            if header[1] != b"blob" or size > MAX_TEXT_BYTES or b"\0" in blob[:4096]:
                continue
            out[rel] = blob.decode("utf-8", errors="replace")
        return out


# ---------------------------------------------------------------------------
# AST extraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Symbol:
    qualname: str
    name: str
    kind: str  # class | function | async_function | method | async_method
    lineno: int
    end_lineno: int
    signature: str
    doc: str = ""
    decorators: tuple[str, ...] = ()
    calls: tuple[str, ...] = ()  # "name" (direct) or ".attr" (attribute call)


@dataclass
class FileIndex:
    path: str
    module: str
    sha256: str
    lines: int
    tokens: int
    imports: tuple[str, ...] = ()
    symbols: tuple[Symbol, ...] = ()
    error: str | None = None


def module_name(path: str) -> str:
    parts = list(Path(path).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def is_test_path(path: str) -> bool:
    parts = Path(path).parts
    return bool(parts) and (
        parts[0] == "tests" or parts[-1].startswith("test_") or parts[-1] == "conftest.py"
    )


def _short(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _fmt_arg(arg: ast.arg, default: ast.expr | None, sep_default: bool) -> str:
    out = arg.arg
    if arg.annotation is not None:
        out += f": {_short(ast.unparse(arg.annotation), 60)}"
    if default is not None:
        val = ast.unparse(default)
        val = val if len(val) <= 24 else "..."
        out += f" = {val}" if (arg.annotation is not None or sep_default) else f"={val}"
    return out


def format_arguments(args: ast.arguments, drop_first: bool) -> str:
    positional = [*args.posonlyargs, *args.args]
    defaults: list[ast.expr | None] = [None] * (len(positional) - len(args.defaults))
    defaults += list(args.defaults)
    rendered: list[str] = []
    for idx, (arg, default) in enumerate(zip(positional, defaults, strict=True)):
        if idx == 0 and drop_first:
            if idx + 1 == len(args.posonlyargs):
                rendered.append("/")
            continue
        rendered.append(_fmt_arg(arg, default, False))
        if args.posonlyargs and idx + 1 == len(args.posonlyargs):
            rendered.append("/")
    if args.vararg is not None:
        rendered.append("*" + _fmt_arg(args.vararg, None, False))
    elif args.kwonlyargs:
        rendered.append("*")
    for arg, kw_default in zip(args.kwonlyargs, args.kw_defaults, strict=True):
        rendered.append(_fmt_arg(arg, kw_default, False))
    if args.kwarg is not None:
        rendered.append("**" + _fmt_arg(args.kwarg, None, False))
    return ", ".join(rendered)


def _call_names(node: ast.AST) -> tuple[str, ...]:
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add("." + func.attr)
    return tuple(sorted(names))


def _first_doc_line(node: ast.AST) -> str:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return ""
    doc = ast.get_docstring(node, clean=True)
    if not doc:
        return ""
    return _short(doc.strip().splitlines()[0], 100)


def _decorators(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> tuple[str, ...]:
    out = []
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        out.append(_short(ast.unparse(target), 40))
    return tuple(out)


def _stmt_children(node: ast.stmt) -> list[list[ast.stmt]]:
    """Statement lists nested in module-level if/try blocks."""
    blocks: list[list[ast.stmt]] = []
    for attr in ("body", "orelse", "finalbody"):
        value = getattr(node, attr, None)
        if isinstance(value, list):
            blocks.append([s for s in value if isinstance(s, ast.stmt)])
    for handler in getattr(node, "handlers", []) or []:
        blocks.append(list(handler.body))
    return blocks


_CONTAINER_TYPES: tuple[type[ast.stmt], ...] = tuple(
    t for t in (ast.If, ast.Try, getattr(ast, "TryStar", None)) if isinstance(t, type)
)


def _collect_symbols(body: list[ast.stmt], prefix: str, in_class: bool, out: list[Symbol]) -> None:
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decos = _decorators(node)
            drop_first = (
                in_class
                and "staticmethod" not in decos
                and bool(node.args.posonlyargs or node.args.args)
                and (node.args.posonlyargs or node.args.args)[0].arg in ("self", "cls", "mcs")
            )
            sig = f"{node.name}({format_arguments(node.args, drop_first)})"
            if node.returns is not None:
                sig += f" -> {_short(ast.unparse(node.returns), 60)}"
            kind = ("async_" if isinstance(node, ast.AsyncFunctionDef) else "") + (
                "method" if in_class else "function"
            )
            start = min([node.lineno, *(d.lineno for d in node.decorator_list)])
            out.append(
                Symbol(
                    qualname=prefix + node.name,
                    name=node.name,
                    kind=kind,
                    lineno=start,
                    end_lineno=node.end_lineno or node.lineno,
                    signature=sig,
                    doc=_first_doc_line(node),
                    decorators=decos,
                    calls=_call_names(node),
                )
            )
        elif isinstance(node, ast.ClassDef):
            bases = [_short(ast.unparse(b), 40) for b in node.bases]
            bases += [f"{k.arg}={_short(ast.unparse(k.value), 30)}" for k in node.keywords if k.arg]
            start = min([node.lineno, *(d.lineno for d in node.decorator_list)])
            out.append(
                Symbol(
                    qualname=prefix + node.name,
                    name=node.name,
                    kind="class",
                    lineno=start,
                    end_lineno=node.end_lineno or node.lineno,
                    signature=f"{node.name}({', '.join(bases)})" if bases else node.name,
                    doc=_first_doc_line(node),
                    decorators=_decorators(node),
                )
            )
            _collect_symbols(node.body, prefix + node.name + ".", True, out)
        elif _CONTAINER_TYPES and isinstance(node, _CONTAINER_TYPES):
            for block in _stmt_children(node):
                _collect_symbols(block, prefix, in_class, out)


def _resolve_imports(tree: ast.Module, module: str, is_package: bool) -> tuple[str, ...]:
    found: set[str] = set()
    package = module if is_package else module.rpartition(".")[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base_parts = package.split(".") if package else []
                keep = len(base_parts) - (node.level - 1)
                base = ".".join(base_parts[: max(keep, 0)])
                mod = ".".join(p for p in (base, node.module or "") if p)
            else:
                mod = node.module or ""
            if mod:
                found.add(mod)
            for alias in node.names:
                if alias.name != "*":
                    found.add(f"{mod}.{alias.name}" if mod else alias.name)
    return tuple(sorted(found))


def index_file(path: str, source: str, counter: TokenCounter) -> FileIndex:
    module = module_name(path)
    info = FileIndex(
        path=path,
        module=module,
        sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
        lines=source.count("\n") + (0 if source.endswith("\n") or not source else 1),
        tokens=counter.count(source),
    )
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError) as exc:
        info.error = f"{type(exc).__name__} at line {getattr(exc, 'lineno', 0) or 0}"
        return info
    symbols: list[Symbol] = []
    _collect_symbols(tree.body, "", False, symbols)
    info.symbols = tuple(symbols)
    info.imports = _resolve_imports(tree, module, Path(path).name == "__init__.py")
    return info


@dataclass
class RepoIndex:
    files: dict[str, FileIndex]
    tokenizer: str

    @property
    def digest(self) -> str:
        h = hashlib.sha256(f"schema={SCHEMA_VERSION};tok={self.tokenizer}\n".encode())
        for path in sorted(self.files):
            h.update(f"{path}\0{self.files[path].sha256}\n".encode())
        return h.hexdigest()

    def def_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for fi in self.files.values():
            if is_test_path(fi.path):
                continue
            for sym in fi.symbols:
                counts[sym.name] = counts.get(sym.name, 0) + 1
        return counts


def build_index(snapshot: Snapshot, counter: TokenCounter) -> RepoIndex:
    files = snapshot.python_files()
    sources = snapshot.read_many(files)
    return RepoIndex(
        files={p: index_file(p, sources[p], counter) for p in sorted(sources)},
        tokenizer=counter.name,
    )


# ---------------------------------------------------------------------------
# L0: repo map
# ---------------------------------------------------------------------------

_KIND_TAG = {
    "class": "C",
    "function": "F",
    "async_function": "aF",
    "method": "M",
    "async_method": "aM",
}


def key_imports(fi: FileIndex, limit: int = 12) -> list[str]:
    """Non-stdlib imports collapsed to module granularity."""
    mods: set[str] = set()
    for imp in fi.imports:
        top = imp.split(".")[0]
        if top in _STDLIB or top == "__future__":
            continue
        mods.add(imp)
    # Drop "pkg.mod.name" when "pkg.mod" is also present.
    collapsed = sorted(m for m in mods if m.rpartition(".")[0] not in mods)
    return collapsed[:limit] + ([f"+{len(collapsed) - limit}"] if len(collapsed) > limit else [])


def render_symbol_line(sym: Symbol) -> str:
    depth = sym.qualname.count(".")
    decos = [d.split(".")[-1] for d in sym.decorators]
    deco = (" @" + ",".join(decos)) if decos else ""
    return f"{'  ' * depth}{_KIND_TAG[sym.kind]} {sym.signature}{deco}"


def render_repomap(index: RepoIndex, include_tests: bool = False) -> str:
    out = [
        "# Repo map (L0)",
        f"<!-- tools/context_packer.py --mode l0 | schema {SCHEMA_VERSION} | "
        f"tokenizer {index.tokenizer} | inputs {index.digest[:16]} | generated, do not edit -->",
        "Legend: C class, F function, M method, a=async, @decorators. Bodies omitted.",
        "Need code? `--mode l1 --symbols path::Qual` (L1) before reading a whole file (L2).",
        "",
    ]
    for path in sorted(index.files):
        fi = index.files[path]
        if is_test_path(path) and not include_tests:
            continue
        out.append(f"## {path} ({fi.lines}L)")
        if fi.error:
            out.append(f"! parse error: {fi.error}")
        imps = key_imports(fi)
        if imps:
            out.append("imports: " + ", ".join(imps))
        out.extend(render_symbol_line(s) for s in fi.symbols)
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def symbols_payload(index: RepoIndex, include_tests: bool = False) -> dict[str, object]:
    return {
        "schema": SCHEMA_VERSION,
        "include_tests": include_tests,
        "tokenizer": index.tokenizer,
        "inputs_sha256": index.digest,
        "files": {p: asdict(index.files[p]) for p in sorted(index.files)},
    }


def context_dir(root: Path) -> Path:
    path = (root / CONTEXT_DIRNAME).resolve()
    if path.parent != root.resolve():
        raise PackerError("context dir resolves outside repo root")
    return path


def resolve_output(root: Path, ctx: Path, user_path: str | None) -> Path:
    """Bundles may only be written inside ``.context/`` (never over sources)."""
    if not user_path:
        return ctx / BUNDLE_NAME
    raw = Path(user_path)
    candidate = (raw if raw.is_absolute() else root.resolve() / raw).resolve()
    if ctx not in candidate.parents or candidate.suffix not in (".md", ".txt"):
        raise PackerError(f"--out must be a .md/.txt file inside {CONTEXT_DIRNAME}/: {user_path}")
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate


def write_text_atomic(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def l0_stats(
    index: RepoIndex, repomap: str, counter: TokenCounter, include_tests: bool
) -> dict[str, object]:
    scope = [fi for p, fi in index.files.items() if include_tests or not is_test_path(p)]
    raw = sum(fi.tokens for fi in scope)
    mapped = counter.count(repomap)
    return {
        "mode": "l0",
        "tokenizer": counter.name,
        "files": len(scope),
        "symbols": sum(len(fi.symbols) for fi in scope),
        "parse_errors": sorted(fi.path for fi in scope if fi.error),
        "raw_tokens": raw,
        "repomap_tokens": mapped,
        "ratio": round(mapped / raw, 4) if raw else 0.0,
        "inputs_sha256": index.digest,
    }


def run_l0(
    root: Path, counter: TokenCounter, include_tests: bool, check: bool
) -> tuple[int, dict[str, object]]:
    index = build_index(Snapshot(root), counter)
    ctx = context_dir(root)
    sym_path = ctx / SYMBOLS_NAME
    if check:
        try:
            stored = json.loads(sym_path.read_text(encoding="utf-8")).get("inputs_sha256")
        except (OSError, ValueError):
            stored = None
        fresh = stored == index.digest
        return (EXIT_OK if fresh else EXIT_STALE), {"mode": "l0", "fresh": fresh}
    repomap = render_repomap(index, include_tests)
    _write_l0(ctx, index, include_tests, repomap)
    return EXIT_OK, l0_stats(index, repomap, counter, include_tests)


def _write_l0(ctx: Path, index: RepoIndex, include_tests: bool, repomap: str) -> None:
    ctx.mkdir(exist_ok=True)
    gitignore = ctx / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text("# generated by tools/context_packer.py\n*\n", encoding="utf-8")
    write_text_atomic(ctx / REPOMAP_NAME, repomap)
    payload = symbols_payload(index, include_tests)
    write_text_atomic(
        ctx / SYMBOLS_NAME, json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    )


def _file_index_from_json(raw: dict[str, object]) -> FileIndex:
    syms = raw.get("symbols")
    imports = raw.get("imports")
    if not isinstance(syms, list) or not isinstance(imports, list):
        raise TypeError("malformed file entry")
    symbols = tuple(
        Symbol(
            qualname=str(d["qualname"]),
            name=str(d["name"]),
            kind=str(d["kind"]),
            lineno=int(d["lineno"]),
            end_lineno=int(d["end_lineno"]),
            signature=str(d["signature"]),
            doc=str(d.get("doc", "")),
            decorators=tuple(str(x) for x in d.get("decorators", [])),
            calls=tuple(str(x) for x in d.get("calls", [])),
        )
        for d in syms
        if isinstance(d, dict)
    )
    err = raw.get("error")
    return FileIndex(
        path=str(raw["path"]),
        module=str(raw["module"]),
        sha256=str(raw["sha256"]),
        lines=int(str(raw["lines"])),
        tokens=int(str(raw["tokens"])),
        imports=tuple(str(x) for x in imports),
        symbols=symbols,
        error=None if err is None else str(err),
    )


def load_index(ctx: Path, counter: TokenCounter) -> tuple[RepoIndex, bool] | None:
    """Stored index, or None when missing/corrupt/other schema or tokenizer."""
    try:
        data = json.loads((ctx / SYMBOLS_NAME).read_text(encoding="utf-8"))
        if data.get("schema") != SCHEMA_VERSION or data.get("tokenizer") != counter.name:
            return None
        files = {p: _file_index_from_json(f) for p, f in data["files"].items()}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    return RepoIndex(files=files, tokenizer=counter.name), bool(data.get("include_tests"))


def run_l0_incremental(
    root: Path, counter: TokenCounter, paths: Sequence[str]
) -> tuple[int, dict[str, object]]:
    """Re-index only ``paths`` on top of the stored index (full build if none).

    Byte-identical to a full ``--mode l0`` run whenever the other files have
    not changed since the stored index was written (``--check`` detects the
    case where they have).
    """
    ctx = context_dir(root)
    loaded = load_index(ctx, counter)
    if loaded is None:
        code, stats = run_l0(root, counter, include_tests=False, check=False)
        stats["incremental"] = False
        return code, stats
    index, include_tests = loaded
    real_root = root.resolve()
    rels: set[str] = set()
    for user_path in paths:
        try:
            rel = safe_resolve(root, user_path).relative_to(real_root).as_posix()
        except PackerError:
            continue
        if rel.endswith(".py"):
            rels.add(rel)
    if not rels:
        return EXIT_OK, {"mode": "l0", "incremental": True, "updated": []}
    listed = run_git(
        root,
        ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", *sorted(rels)],
    )
    indexable = {n for n in listed.decode("utf-8", errors="replace").split("\0") if n}
    sources = Snapshot(root).read_many(sorted(indexable))
    updated = _apply_updates(index, counter, sources, sorted(rels))
    _write_l0(ctx, index, include_tests, render_repomap(index, include_tests))
    return EXIT_OK, {"mode": "l0", "incremental": True, "updated": updated}


def _apply_updates(
    index: RepoIndex, counter: TokenCounter, sources: dict[str, str], rels: Sequence[str]
) -> list[str]:
    """Re-index ``rels`` present in ``sources``; drop the ones that are gone."""
    updated: list[str] = []
    for rel in rels:
        if rel in sources:
            index.files[rel] = index_file(rel, sources[rel], counter)
            updated.append(rel)
        elif index.files.pop(rel, None) is not None:
            updated.append(rel)  # deleted, or now ignored/excluded
    index.files = dict(sorted(index.files.items()))
    return updated


def stale_paths(root: Path, index: RepoIndex) -> tuple[list[str], dict[str, str]]:
    """Paths whose content differs from ``index`` (added, changed or removed).

    Cheap: one ``git ls-files`` plus a sha256 per file; no AST work.
    """
    current = Snapshot(root).python_files()
    sources = Snapshot(root).read_many(current)
    stale = {
        rel
        for rel, text in sources.items()
        if rel not in index.files
        or index.files[rel].sha256 != hashlib.sha256(text.encode("utf-8")).hexdigest()
    }
    stale |= set(index.files) - set(sources)
    return sorted(stale), {rel: sources[rel] for rel in stale if rel in sources}


def run_l0_sync(
    root: Path, counter: TokenCounter, write: bool = True
) -> tuple[int, dict[str, object]]:
    """Bring ``.context/`` up to date re-indexing only stale files.

    With ``write=False`` it is a fast freshness check (exit 1 when stale).
    """
    ctx = context_dir(root)
    loaded = load_index(ctx, counter)
    if loaded is None:
        if not write:
            return EXIT_STALE, {"mode": "l0", "fresh": False, "reason": "no usable index"}
        code, stats = run_l0(root, counter, include_tests=False, check=False)
        stats["incremental"] = False
        return code, stats
    index, include_tests = loaded
    stale, sources = stale_paths(root, index)
    if not write:
        return (EXIT_STALE if stale else EXIT_OK), {
            "mode": "l0",
            "fresh": not stale,
            "stale": stale,
        }
    if stale:
        _apply_updates(index, counter, sources, stale)
        _write_l0(ctx, index, include_tests, render_repomap(index, include_tests))
    return EXIT_OK, {"mode": "l0", "incremental": True, "updated": stale}


# ---------------------------------------------------------------------------
# Diff parsing
# ---------------------------------------------------------------------------

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass
class DiffFile:
    old_path: str | None = None
    new_path: str | None = None
    added_lines: set[int] = field(default_factory=set)
    removed_at: set[int] = field(default_factory=set)

    @property
    def path(self) -> str:
        return self.new_path or self.old_path or ""

    @property
    def status(self) -> str:
        if self.old_path is None:
            return "added"
        if self.new_path is None:
            return "deleted"
        return "renamed" if self.old_path != self.new_path else "modified"

    def touched_lines(self) -> set[int]:
        return self.added_lines | self.removed_at


def _strip_prefix(path: str) -> str | None:
    path = path.split("\t")[0].strip()
    if path == "/dev/null":
        return None
    if path.startswith('"') and path.endswith('"'):
        path = path[1:-1]
    return path[2:] if path[:2] in ("a/", "b/") else path


def parse_unified_diff(text: str) -> list[DiffFile]:
    files: list[DiffFile] = []
    current: DiffFile | None = None
    in_header = False
    new_ln = 0
    for line in text.splitlines():
        if line.startswith("diff --git "):
            current = DiffFile()
            files.append(current)
            in_header = True
            continue
        if current is None:
            if line.startswith("--- "):  # diff without "diff --git" lines
                current = DiffFile()
                files.append(current)
                in_header = True
            else:
                continue
        if in_header:
            if line.startswith("--- "):
                current.old_path = _strip_prefix(line[4:])
            elif line.startswith("+++ "):
                current.new_path = _strip_prefix(line[4:])
            elif line.startswith("@@"):
                in_header = False
            elif line.startswith(("rename from ", "rename to ")):
                key, _, value = line.partition(" from " if " from " in line else " to ")
                if "from" in key:
                    current.old_path = value.strip()
                else:
                    current.new_path = value.strip()
            if in_header:
                continue
        match = _HUNK_RE.match(line)
        if match:
            new_ln = int(match.group(3))
            continue
        if line.startswith("+"):
            current.added_lines.add(new_ln)
            new_ln += 1
        elif line.startswith("-"):
            current.removed_at.add(max(new_ln, 1))
        elif line.startswith("\\"):
            continue
        elif line.startswith("diff --git"):
            continue
        else:
            new_ln += 1
    # Binary/mode-only entries without ---/+++ lines: recover the path.
    return [f for f in files if f.path]


def trim_diff_context(diff: str, level: str) -> str:
    """``full`` keep; ``code`` drop blank/comment context; ``none`` drop all context."""
    if level == "full":
        return diff
    kept: list[str] = []
    in_hunk = False
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            in_hunk = False
        elif line.startswith("@@"):
            in_hunk = True
        elif in_hunk and line.startswith(" "):
            body = line[1:].strip()
            if level == "none" or not body or body.startswith("#"):
                continue
        kept.append(line)
    return "\n".join(kept) + "\n"


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


# ---------------------------------------------------------------------------
# L1: bundle construction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SymRef:
    path: str
    symbol: Symbol | None  # None = module-level change

    @property
    def label(self) -> str:
        if self.symbol is None:
            return f"{self.path}::<module>"
        return f"{self.path}::{self.symbol.qualname}"


@dataclass(frozen=True)
class CallerRef:
    ref: SymRef
    target: str  # called qualname(s), comma-separated
    sites: tuple[tuple[int, str], ...]  # (lineno, source line)
    same_file: bool


@dataclass
class Bundle:
    diff: str
    diff_files: list[DiffFile]
    changed: list[SymRef]
    callers: list[CallerRef]
    callees: list[SymRef]
    tests: list[str]
    traceback: str
    involved: set[str]
    notes: list[str]
    changed_files: set[str] = field(default_factory=set)


def innermost_symbol(fi: FileIndex, line: int) -> Symbol | None:
    best: Symbol | None = None
    for sym in fi.symbols:
        if sym.lineno <= line <= sym.end_lineno:
            if best is None or (sym.end_lineno - sym.lineno) < (best.end_lineno - best.lineno):
                best = sym
    return best


def _imports_target(caller: FileIndex, owner: FileIndex, top_name: str) -> bool:
    return owner.module in caller.imports or f"{owner.module}.{top_name}" in caller.imports


def _call_sites(
    lines: list[str], sym: Symbol, name: str, limit: int = 3
) -> tuple[tuple[int, str], ...]:
    pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(name)}\s*\(")
    hits = [
        ln
        for ln in range(sym.lineno, min(sym.end_lineno, len(lines)) + 1)
        if pattern.search(lines[ln - 1])
    ][:limit]
    keep: set[int] = set()
    for ln in hits:
        keep.update(
            x for x in (ln - 1, ln, ln + 1) if sym.lineno <= x <= min(sym.end_lineno, len(lines))
        )
    return tuple((ln, lines[ln - 1]) for ln in sorted(keep))


def find_callers(
    index: RepoIndex,
    target: SymRef,
    sources: dict[str, list[str]],
    def_counts: dict[str, int],
    limit: int,
) -> tuple[list[CallerRef], int]:
    """1-hop callers of ``target`` (signature + call-site slice)."""
    sym = target.symbol
    if sym is None:
        return [], 0
    owner = index.files[target.path]
    name = sym.name
    top_name = sym.qualname.split(".")[0]
    if name == "__init__" and "." in sym.qualname:
        name = sym.qualname.split(".")[-2]  # instantiation of the class
    elif name.startswith("__") and name.endswith("__"):
        return [], 0
    is_method = sym.kind.endswith("method")
    found: list[CallerRef] = []
    for path in sorted(index.files):
        fi = index.files[path]
        same = path == target.path
        if is_test_path(target.path) and not same:
            continue  # test helpers: only same-file callers are meaningful
        if is_test_path(path) and not is_test_path(target.path):
            continue  # tests are listed separately
        imports = same or _imports_target(fi, owner, top_name)
        for cand in fi.symbols:
            if cand.kind == "class" or (same and cand.qualname == sym.qualname):
                continue
            direct = name in cand.calls and not (is_method and name == sym.name)
            attr = ("." + name) in cand.calls
            if not (direct or attr):
                continue
            if not (imports or (attr and def_counts.get(name, 0) <= 2)):
                continue
            lines = sources.get(path)
            if lines is None:
                continue
            sites = _call_sites(lines, cand, name)
            if not sites:
                continue
            found.append(CallerRef(SymRef(path, cand), sym.qualname, sites, same))
    found.sort(
        key=lambda c: (not c.same_file, c.ref.path, c.ref.symbol.lineno if c.ref.symbol else 0)
    )
    return _spread_by_file(found, limit), max(len(found) - limit, 0)


def _spread_by_file(callers: list[CallerRef], limit: int) -> list[CallerRef]:
    """Pick up to ``limit`` callers round-robin across files (same file first).

    A plain prefix would spend the whole cap on the first file and hide every
    other dependent module; file coverage matters more than call-site count.
    """
    if len(callers) <= limit:
        return callers
    by_file: dict[str, list[CallerRef]] = {}
    for c in callers:  # already ordered: same file first, then path, line
        by_file.setdefault(c.ref.path, []).append(c)
    queues = list(by_file.values())
    picked: list[CallerRef] = []
    depth = 0
    while len(picked) < limit:
        layer = [q[depth] for q in queues if len(q) > depth]
        if not layer:
            break
        picked.extend(layer[: limit - len(picked)])
        depth += 1
    order = {id(c): i for i, c in enumerate(callers)}
    return sorted(picked, key=lambda c: order[id(c)])


def find_callees(
    index: RepoIndex, target: SymRef, def_counts: dict[str, int], limit: int
) -> list[SymRef]:
    sym = target.symbol
    if sym is None:
        return []
    owner = index.files[target.path]
    cls_prefix = sym.qualname.rpartition(".")[0]
    out: dict[str, SymRef] = {}
    for call in sym.calls:
        attr = call.startswith(".")
        name = call[1:] if attr else call
        matches: list[SymRef] = []
        for path in sorted(index.files):
            fi = index.files[path]
            if is_test_path(path) and not is_test_path(target.path):
                continue
            same = path == target.path
            for cand in fi.symbols:
                if cand.name != name or cand.qualname == sym.qualname:
                    continue
                top = cand.qualname.split(".")[0]
                if attr:
                    in_class = bool(cls_prefix) and cand.qualname == f"{cls_prefix}.{name}"
                    ok = (
                        in_class
                        or same
                        or def_counts.get(name, 0) <= 2
                        or ("." not in cand.qualname and _imports_target(owner, fi, top))
                    )
                else:
                    ok = "." not in cand.qualname and (same or _imports_target(owner, fi, top))
                if ok:
                    matches.append(SymRef(path, cand))
        for ref in matches[:3]:
            out.setdefault(ref.label, ref)
    return [out[k] for k in sorted(out)][:limit]


def find_tests(index: RepoIndex, targets: list[SymRef], limit: int = 12) -> list[str]:
    names: set[str] = set()
    for t in targets:
        if t.symbol is None:
            continue
        n = t.symbol.name
        if n == "__init__" and "." in t.symbol.qualname:
            n = t.symbol.qualname.split(".")[-2]
        if not (n.startswith("__") and n.endswith("__")):
            names.add(n)
    hits: set[str] = set()
    for path, fi in index.files.items():
        if not is_test_path(path):
            continue
        for sym in fi.symbols:
            if sym.kind == "class":
                continue
            if any(n in sym.calls or ("." + n) in sym.calls for n in names):
                hits.add(f"{path}::{sym.qualname}")
    return sorted(hits)[:limit]


def resolve_symbol_specs(index: RepoIndex, specs: Sequence[str]) -> list[SymRef]:
    """``path::Qual``, ``module:Qual`` or bare ``Qual`` (all matches)."""
    refs: list[SymRef] = []
    for spec in specs:
        if "::" in spec:
            path, _, qual = spec.partition("::")
            file_hits = [index.files[path]] if path in index.files else []
        elif ":" in spec:
            mod, _, qual = spec.partition(":")
            file_hits = [fi for fi in index.files.values() if fi.module == mod]
        else:
            qual = spec
            file_hits = list(index.files.values())
        matched = [
            SymRef(fi.path, s)
            for fi in sorted(file_hits, key=lambda f: f.path)
            for s in fi.symbols
            if s.qualname == qual
        ]
        if not matched:
            raise PackerError(f"symbol not found: {spec}")
        refs.extend(matched)
    return refs


def load_diff(root: Path, args: argparse.Namespace) -> tuple[str, str | None]:
    """Return (diff text, revision whose tree is the new side or None)."""
    common = ["diff", "--no-color", "--no-ext-diff", "--no-textconv", "--unified=3", "-M"]
    if args.diff_file:
        path = safe_resolve(root, args.diff_file)
        return path.read_text(encoding="utf-8", errors="replace"), None
    if args.range:
        rng = validate_rev(args.range)
        new_rev = rng.split("..")[-1].lstrip(".") or "HEAD"
        return run_git(root, [*common, rng, "--"]).decode("utf-8", errors="replace"), validate_rev(
            new_rev
        )
    if args.staged:
        return run_git(root, [*common, "--cached", "--"]).decode("utf-8", errors="replace"), None
    base = validate_rev(args.base or "HEAD")
    text = run_git(root, [*common, base, "--"]).decode("utf-8", errors="replace")
    # Untracked .py files are part of the change too: append them as additions.
    untracked = run_git(root, ["ls-files", "-z", "--others", "--exclude-standard", "--", "*.py"])
    for rel in sorted(n for n in untracked.decode("utf-8", errors="replace").split("\0") if n):
        if is_excluded(rel):
            continue
        try:
            path = safe_resolve(root, rel)
        except PackerError:
            continue
        if not path.is_file() or path.stat().st_size > MAX_TEXT_BYTES:
            continue
        body = path.read_text(encoding="utf-8", errors="replace").splitlines()
        text += f"diff --git a/{rel} b/{rel}\nnew file mode 100644\n--- /dev/null\n+++ b/{rel}\n"
        text += f"@@ -0,0 +1,{len(body)} @@\n" + "".join(f"+{ln}\n" for ln in body)
    return text, None


def read_traceback(root: Path, spec: str | None) -> str:
    if not spec:
        return ""
    if spec == "-":
        data = sys.stdin.read(MAX_TEXT_BYTES)
    else:
        path = safe_resolve(root, spec)
        if not path.is_file() or path.stat().st_size > MAX_TEXT_BYTES:
            raise PackerError(f"traceback file unreadable or too large: {spec}")
        data = path.read_text(encoding="utf-8", errors="replace")
    return data.strip("\n")


def build_bundle(
    root: Path, args: argparse.Namespace, counter: TokenCounter
) -> tuple[Bundle, RepoIndex, Snapshot]:
    diff_text = ""
    new_rev: str | None = None
    use_diff = not (args.symbols or args.files)
    if use_diff:
        diff_text, new_rev = load_diff(root, args)
        if not diff_text.strip():
            raise PackerError("empty diff: nothing to pack")
    if not use_diff and args.at:
        new_rev = validate_rev(args.at)
    snapshot = Snapshot(root, new_rev)
    index = build_index(snapshot, counter)
    def_counts = index.def_counts()
    notes: list[str] = []

    diff_files = parse_unified_diff(diff_text) if diff_text else []
    changed: list[SymRef] = []
    seen: set[str] = set()

    def _add(ref: SymRef) -> None:
        if ref.label not in seen:
            seen.add(ref.label)
            changed.append(ref)

    for df in diff_files:
        if df.new_path is None or not df.new_path.endswith(".py"):
            continue
        fi = index.files.get(df.new_path)
        if fi is None:
            notes.append(f"not indexed (excluded or unreadable): {df.new_path}")
            continue
        for line in sorted(df.touched_lines()):
            sym = innermost_symbol(fi, line)
            _add(SymRef(fi.path, sym))
    if args.symbols:
        for ref in resolve_symbol_specs(index, args.symbols):
            _add(ref)
    if args.files:
        for spec in args.files:
            rel = safe_resolve(root, spec).relative_to(root.resolve()).as_posix()
            fi = index.files.get(rel)
            if fi is None:
                raise PackerError(f"not an indexed python file: {spec}")
            for sym in fi.symbols:
                if "." not in sym.qualname or not sym.name.startswith("_"):
                    _add(SymRef(fi.path, sym))

    involved: set[str] = {df.new_path for df in diff_files if df.new_path}
    involved |= {ref.path for ref in changed}
    source_lines = {p: s.splitlines() for p, s in snapshot.read_many(index.files).items()}

    callers: list[CallerRef] = []
    for ref in changed:
        hits, dropped = find_callers(index, ref, source_lines, def_counts, args.max_callers)
        callers.extend(hits)
        if dropped:
            notes.append(f"{dropped} more callers of {ref.label} omitted (cap {args.max_callers})")
    merged: dict[str, CallerRef] = {}
    for c in callers:
        if c.ref.label in seen:
            continue  # already shown as a changed symbol
        prev = merged.get(c.ref.label)
        if prev is None:
            merged[c.ref.label] = c
        elif c.target not in prev.target.split(", "):
            sites = tuple(sorted(set(prev.sites) | set(c.sites)))
            merged[c.ref.label] = replace(prev, target=f"{prev.target}, {c.target}", sites=sites)
    unique_callers = sorted(
        merged.values(),
        key=lambda c: (not c.same_file, c.ref.path, c.ref.symbol.lineno if c.ref.symbol else 0),
    )

    callee_map: dict[str, SymRef] = {}
    for ref in changed:
        for callee in find_callees(index, ref, def_counts, args.max_callees):
            if callee.label not in seen:
                callee_map.setdefault(callee.label, callee)
    callees = [callee_map[k] for k in sorted(callee_map)][: args.max_callees]

    involved |= {c.ref.path for c in unique_callers} | {c.path for c in callees}
    bundle = Bundle(
        diff=redact(diff_text),
        diff_files=diff_files,
        changed=changed,
        callers=unique_callers,
        callees=callees,
        tests=find_tests(index, changed),
        traceback=redact(read_traceback(root, args.traceback)),
        involved=involved,
        notes=notes,
        changed_files={df.new_path for df in diff_files if df.new_path} | {r.path for r in changed},
    )
    return bundle, index, snapshot


# ---------------------------------------------------------------------------
# Rendering + budget
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RenderOpts:
    level: int = 0
    docstrings: bool = True
    slices: bool = True
    slice_comments: bool = True
    max_callers: int = 10_000
    max_callees: int = 10_000
    traceback_tail: int = 10_000
    diff_context: str = "full"  # full | code | none
    callee_sigs: bool = True
    label: str = "full bundle"


def pruning_ladder() -> list[RenderOpts]:
    """Progressively cheaper renderings; priority order documented in module doc."""
    base = RenderOpts()
    steps: list[tuple[str, dict[str, object]]] = [
        ("drop docstrings", {"docstrings": False}),
        ("drop comment/blank lines in caller slices", {"slice_comments": False}),
        ("keep top-8 callers / top-10 callees", {"max_callers": 8, "max_callees": 10}),
        ("traceback tail 30 lines", {"traceback_tail": 30}),
        ("drop caller slices (signatures only)", {"slices": False}),
        ("keep top-4 callers / top-5 callees", {"max_callers": 4, "max_callees": 5}),
        ("drop blank/comment diff context", {"diff_context": "code"}),
        ("drop all diff context lines", {"diff_context": "none"}),
        ("traceback tail 10 lines", {"traceback_tail": 10}),
        ("drop callee signatures", {"callee_sigs": False, "max_callees": 0}),
        ("keep top-2 callers", {"max_callers": 2}),
    ]
    ladder = [base]
    current = base
    for idx, (label, changes) in enumerate(steps, start=1):
        current = replace(current, level=idx, label=label, **changes)  # type: ignore[arg-type]
        ladder.append(current)
    return ladder


def _sig_line(ref: SymRef, opts: RenderOpts) -> str:
    if ref.symbol is None:
        return f"- `{ref.path}` module-level change"
    sym = ref.symbol
    line = f"- `{ref.path}:{sym.lineno}-{sym.end_lineno}` {_KIND_TAG[sym.kind]} {sym.qualname.rpartition('.')[0] + '.' if '.' in sym.qualname else ''}{sym.signature}"
    if opts.docstrings and sym.doc:
        line += f" — {sym.doc}"
    return line


def render_bundle(bundle: Bundle, opts: RenderOpts, mode: str, tokenizer: str) -> str:
    out = [
        "# Context bundle (L1)",
        f"<!-- tools/context_packer.py | mode {mode} | tokenizer {tokenizer} | "
        f"prune level {opts.level} -->",
        f"Scope: {len(bundle.changed)} changed symbol(s), {len(bundle.callers)} caller(s), "
        f"{len(bundle.callees)} callee(s), {len(bundle.involved)} file(s) involved.",
        "",
    ]
    if bundle.diff.strip():
        out += [
            "## 1. Diff",
            "```diff",
            trim_diff_context(bundle.diff, opts.diff_context).rstrip(),
            "```",
            "",
        ]
    if bundle.changed:
        # Symbols of newly added files are already verbatim in the diff:
        # list them by name only (lossless, avoids paying for them twice).
        added: set[str] = {
            df.new_path for df in bundle.diff_files if df.status == "added" and df.new_path
        }
        out.append("## 2. Changed symbols (typed signatures)")
        out += [_sig_line(r, opts) for r in bundle.changed if r.path not in added]
        for path in sorted(added & {r.path for r in bundle.changed}):
            names = [r.symbol.qualname for r in bundle.changed if r.path == path and r.symbol]
            out.append(f"- `{path}` new file, full source in diff: {', '.join(names)}")
        out.append("")
    if bundle.traceback:
        tb = bundle.traceback.splitlines()
        if len(tb) > opts.traceback_tail:
            tb = [
                f"... ({len(tb) - opts.traceback_tail} lines trimmed)",
                *tb[-opts.traceback_tail :],
            ]
        out += ["## 3. Traceback", "```", *tb, "```", ""]
    callers = bundle.callers[: opts.max_callers]
    if callers:
        out.append("## 4. Callers (1 hop)")
        for c in callers:
            out.append(_sig_line(c.ref, opts) + f"  → calls `{c.target}`")
            if opts.slices:
                sites = [
                    (ln, src)
                    for ln, src in c.sites
                    if opts.slice_comments or (src.strip() and not src.strip().startswith("#"))
                ]
                if sites:
                    out.append("```python")
                    out += [f"{ln:>5}| {src}" for ln, src in sites]
                    out.append("```")
        if len(bundle.callers) > len(callers):
            out.append(f"- … {len(bundle.callers) - len(callers)} lower-priority caller(s) pruned")
        out.append("")
    callees = bundle.callees[: opts.max_callees] if opts.callee_sigs else []
    if callees:
        out.append("## 5. Callees (1 hop, signatures)")
        out += [_sig_line(r, opts) for r in callees]
        out.append("")
    if bundle.tests:
        files = sorted({t.split("::")[0] for t in bundle.tests})
        names = sorted({t.split("::")[-1].split(".")[-1] for t in bundle.tests})
        out.append("## 6. Tests referencing changed symbols")
        out += [f"- {t}" for t in bundle.tests]
        out.append(f'Scoped run: `pytest {" ".join(files)} -k "{" or ".join(names)}"`')
        out.append("")
    if bundle.notes:
        out.append("## Notes")
        out += [f"- {n}" for n in bundle.notes]
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def baseline_tokens(
    bundle: Bundle, snapshot: Snapshot, counter: TokenCounter, scope: str = "changed"
) -> int:
    """Tokens of the 'traditional' load: the diff plus files read in full.

    ``changed`` (default, strictest): only the files the change touches.
    ``involved``: also every caller/callee file the bundle references.
    """
    files = bundle.changed_files if scope == "changed" else bundle.involved
    sources = snapshot.read_many(files)
    return counter.count(bundle.diff) + sum(counter.count(text) for text in sources.values())


def pack(
    bundle: Bundle,
    snapshot: Snapshot,
    counter: TokenCounter,
    mode: str,
    max_ratio: float,
    baseline_scope: str = "auto",
) -> tuple[str, dict[str, object], int]:
    if baseline_scope == "auto":
        baseline_scope = "changed" if bundle.diff.strip() else "involved"
    baseline = baseline_tokens(bundle, snapshot, counter, baseline_scope)
    limit = max_ratio * (HEURISTIC_RATIO_MARGIN if counter.name.startswith("heuristic") else 1.0)
    ladder = pruning_ladder() if mode == "budget" else [RenderOpts()]
    text = ""
    tokens = 0
    chosen = ladder[0]
    for opts in ladder:
        chosen = opts
        text = render_bundle(bundle, opts, mode, counter.name)
        tokens = counter.count(text)
        if mode != "budget" or (baseline and tokens <= limit * baseline):
            break
    ratio = round(tokens / baseline, 4) if baseline else None
    within = bool(baseline) and tokens <= limit * baseline
    stats: dict[str, object] = {
        "mode": mode,
        "tokenizer": counter.name,
        "baseline_tokens": baseline,
        "baseline_scope": baseline_scope,
        "bundle_tokens": tokens,
        "ratio": ratio,
        "max_ratio": max_ratio,
        "effective_max_ratio": round(limit, 4),
        "within_budget": within,
        "prune_level": chosen.level,
        "prune_label": chosen.label,
        "files_involved": len(bundle.involved),
        "changed_symbols": len(bundle.changed),
        "callers": len(bundle.callers),
        "callees": len(bundle.callees),
        "tests": len(bundle.tests),
    }
    code = EXIT_OK if (mode != "budget" or within) else EXIT_OVER_BUDGET
    return text, stats, code


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="context_packer",
        description="Deterministic AST context packer (L0 repo map, L1 diff bundle, token budget).",
    )
    p.add_argument("--mode", choices=("l0", "l1", "budget"), required=True)
    p.add_argument("--root", default=".", help="any path inside the git repository")
    p.add_argument("--tokenizer", choices=("auto", "tiktoken", "heuristic"), default="auto")
    p.add_argument("--include-tests", action="store_true", help="l0: also map tests/ in repomap.md")
    p.add_argument(
        "--check", action="store_true", help="l0: exit 1 if .context/ is stale, write nothing"
    )
    p.add_argument(
        "--paths",
        nargs="+",
        help="l0: incremental update of only these files on top of the stored index",
    )
    p.add_argument(
        "--sync",
        action="store_true",
        help="l0: re-index only files whose sha256 changed since the stored index",
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--base", help="diff working tree against REF (default HEAD)")
    src.add_argument("--range", help="commit range A..B (new side read at B)")
    src.add_argument("--staged", action="store_true", help="diff the index against HEAD")
    src.add_argument("--diff-file", help="read a unified diff from a file inside the repo")
    p.add_argument(
        "--symbols", nargs="+", help="path::Qual | module:Qual | Qual (instead of a diff)"
    )
    p.add_argument("--files", nargs="+", help="focus files (public symbols) instead of a diff")
    p.add_argument("--at", help="with --symbols/--files: read the tree at this revision")
    p.add_argument("--traceback", help="file with an error traceback, or - for stdin")
    p.add_argument("--max-ratio", type=float, default=DEFAULT_MAX_RATIO)
    p.add_argument(
        "--baseline",
        choices=("auto", "changed", "involved"),
        default="auto",
        help="budget baseline: diff + changed files (strict), + caller/callee files, or "
        "auto (changed for diffs, involved for --symbols/--files)",
    )
    p.add_argument("--max-callers", type=int, default=15)
    p.add_argument("--max-callees", type=int, default=20)
    p.add_argument(
        "--out",
        help=f"bundle path inside the repo (default {CONTEXT_DIRNAME}/{BUNDLE_NAME}); - = stdout",
    )
    p.add_argument("--json", action="store_true", help="print stats as JSON on stdout")
    p.add_argument("--quiet", action="store_true")
    return p


def _emit(stats: dict[str, object], as_json: bool, quiet: bool) -> None:
    if as_json:
        print(json.dumps(stats, sort_keys=True))
    elif not quiet:
        print(" ".join(f"{k}={v}" for k, v in sorted(stats.items())), file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if not 0.0 < args.max_ratio <= 1.0:
            raise PackerError("--max-ratio must be in (0, 1]")
        if args.max_callers < 0 or args.max_callees < 0:
            raise PackerError("--max-callers/--max-callees must be >= 0")
        root = find_repo_root(Path(args.root).resolve())
        counter = TokenCounter(args.tokenizer)
        if args.mode == "l0" and args.paths and not args.check:
            code, stats = run_l0_incremental(root, counter, args.paths)
            _emit(stats, args.json, args.quiet)
            return code
        if args.mode == "l0" and (args.sync or args.check):
            code, stats = run_l0_sync(root, counter, write=not args.check)
            _emit(stats, args.json, args.quiet)
            return code
        if args.mode == "l0":
            code, stats = run_l0(root, counter, args.include_tests, args.check)
            _emit(stats, args.json, args.quiet)
            return code
        bundle, _index, snapshot = build_bundle(root, args, counter)
        text, stats, code = pack(
            bundle, snapshot, counter, args.mode, args.max_ratio, args.baseline
        )
        if args.out == "-":
            sys.stdout.write(text)
        else:
            ctx = context_dir(root)
            ctx.mkdir(exist_ok=True)
            out_path = resolve_output(root, ctx, args.out)
            write_text_atomic(out_path, text)
            stats["out"] = out_path.relative_to(root).as_posix()
        _emit(stats, args.json, args.quiet)
        return code
    except PackerError as exc:
        print(f"context_packer: error: {exc}", file=sys.stderr)
        return EXIT_INPUT


if __name__ == "__main__":
    sys.exit(main())
