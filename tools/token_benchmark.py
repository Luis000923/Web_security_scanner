#!/usr/bin/env python3
"""Reproducible token benchmark: traditional context vs L0/L1 + micro-skill.

Traditional pipeline (baseline)
    static context (``AGENTS.md``, plus Obsidian notes with ``--vault``)
    + every file the task touches, read in full (+ the diff for reviews).
Optimized pipeline
    the L0 repo-map section or the L1 ``--mode budget`` bundle from
    ``tools/context_packer.py`` + the single micro-skill the task loads.

Each scenario is pinned to a commit of this repository so the numbers do not
drift as ``HEAD`` moves. In a clone without those commits each scenario falls
back to the same task at ``HEAD`` and, when that is impossible too (shallow
clone, tarball), to a deterministic synthetic git fixture; the ``source``
column says which one ran, so a run never reports SKIPPED
(``--portable head|synthetic`` forces a source). A scenario passes when both the full ratio and the
files-only ratio (static context excluded) are ``<= --max-ratio`` (default
0.60) **and** its information-recall oracle is 1.0:

* context load: every class/function/method name found by an independent
  ``ast`` walk of the full files appears in the optimized context;
* bounded modification: every non-test file that calls the symbol according
  to a plain regex search appears in the bundle;
* code review: every ``+``/``-`` line of the diff and every changed path
  appears in the bundle.

``--gates`` also runs ``pytest``, ``ruff`` and ``mypy`` with the project
virtualenv. Every run appends one JSON line to ``.context/metrics.jsonl``.
Exit code 0 only when every scenario (and gate, if run) passes.
"""

from __future__ import annotations

import argparse
import ast
import datetime as _dt
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import context_packer as cp  # noqa: E402

PINNED_REV = "4ac3fdd"
GATE_TIMEOUT_S = 1800


@dataclass(frozen=True)
class Scenario:
    name: str
    kind: str  # context | modify | review
    skill: str
    description: str
    rev: str = PINNED_REV
    prefix: str = ""
    symbol: str = ""
    diff_range: str = ""


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        name="context-load:core",
        kind="context",
        skill="context-navigation",
        description="Understand web_security_scanner/core/ (architecture question)",
        prefix="web_security_scanner/core/",
    ),
    Scenario(
        name="modify:confirm_double_oracle",
        kind="modify",
        skill="scoped-testing",
        description="Change a base-tester method used by 8 testers",
        symbol=(
            "web_security_scanner/modules/vulnerability_testers/base_tester_async.py"
            "::VulnerabilityTester.confirm_double_oracle"
        ),
    ),
    Scenario(
        name="modify:mask_secrets",
        kind="modify",
        skill="scoped-testing",
        description="Change the report secret-masking helper",
        symbol="web_security_scanner/utils/validation.py::mask_secrets",
    ),
    Scenario(
        name="review:69a4252",
        kind="review",
        skill="diff-code-review",
        description="Review a 20-file refactor (probe() returns url)",
        diff_range="69a4252~1..69a4252",
    ),
    Scenario(
        name="review:9cdf7f2",
        kind="review",
        skill="diff-code-review",
        description="Review a 4-file dedupe refactor",
        diff_range="9cdf7f2~1..9cdf7f2",
    ),
    Scenario(
        name="review:f937b78-new-module",
        kind="review",
        skill="diff-code-review",
        description="Review a new 814-line module + tests (worst case: all additions)",
        diff_range="f937b78~1..f937b78",
    ),
)


@dataclass
class Result:
    name: str
    kind: str
    description: str
    skill: str
    baseline_tokens: int = 0
    baseline_files_tokens: int = 0
    optimized_tokens: int = 0
    optimized_core_tokens: int = 0
    ratio: float = 0.0
    files_only_ratio: float = 0.0
    recall: float = 0.0
    recall_detail: str = ""
    baseline_files: int = 0
    passed: bool = False
    source: str = "pinned"  # pinned | head | synthetic
    notes: list[str] = field(default_factory=list)


def _rev_exists(root: Path, rev: str) -> bool:
    try:
        cp.run_git(root, ["rev-parse", "--verify", "--quiet", f"{cp.validate_rev(rev)}^{{commit}}"])
    except cp.PackerError:
        return False
    return True


def _skill_text(root: Path, skill: str) -> str:
    path = cp.safe_resolve(root, f".claude/skills/{skill}/SKILL.md")
    return path.read_text(encoding="utf-8")


def static_context(root: Path, static: Sequence[str], vault: str | None) -> str:
    """Traditional always-loaded context: AGENTS.md (+ optional vault notes)."""
    parts: list[str] = []
    for rel in static:
        try:
            path = cp.safe_resolve(root, rel)
        except cp.PackerError:
            continue
        if path.is_file():
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
    if vault:
        vroot = Path(vault).expanduser().resolve()
        for note in sorted(vroot.rglob("*.md")):
            if vroot not in note.parents or any(
                p.startswith(".") for p in note.relative_to(vroot).parts
            ):
                continue
            name = note.name.lower()
            if name.startswith("wss") or "web security scanner" in name:
                parts.append(note.read_text(encoding="utf-8", errors="replace"))
    return "\n\n".join(parts)


def _ast_names(source: str) -> set[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    names: set[str] = set()

    def visit(body: list[ast.stmt]) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.add(node.name)
            elif isinstance(node, ast.ClassDef):
                names.add(node.name)
                visit(node.body)
            elif isinstance(node, (ast.If, ast.Try)):
                visit(node.body)
                visit(node.orelse)
                if isinstance(node, ast.Try):
                    visit(node.finalbody)
                    for handler in node.handlers:
                        visit(handler.body)

    visit(tree.body)
    return names


def _ratio(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def run_context(root: Path, sc: Scenario, counter: cp.TokenCounter, static: str) -> Result:
    res = Result(sc.name, sc.kind, sc.description, sc.skill)
    snap = cp.Snapshot(root, sc.rev)
    files = [f for f in snap.python_files() if f.startswith(sc.prefix)]
    sources = snap.read_many(files)
    index = cp.RepoIndex(
        files={p: cp.index_file(p, sources[p], counter) for p in sorted(sources)},
        tokenizer=counter.name,
    )
    repomap = cp.render_repomap(index)
    skill = _skill_text(root, sc.skill)
    res.baseline_files = len(sources)
    res.baseline_files_tokens = sum(counter.count(t) for t in sources.values())
    res.baseline_tokens = res.baseline_files_tokens + counter.count(static)
    res.optimized_core_tokens = counter.count(repomap)
    res.optimized_tokens = res.optimized_core_tokens + counter.count(skill)
    missing: list[str] = []
    total = 0
    for path, text in sorted(sources.items()):
        section = repomap.split(f"## {path} (", 1)[-1].split("\n## ", 1)[0]
        for name in sorted(_ast_names(text)):
            total += 1
            if not re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", section):
                missing.append(f"{path}::{name}")
    res.recall = _ratio(total - len(missing), total) if total else 1.0
    res.recall_detail = f"{total - len(missing)}/{total} AST symbols present in L0"
    res.notes += missing[:5]
    return res


def _bundle(root: Path, argv: list[str], counter: cp.TokenCounter) -> tuple[str, dict[str, object]]:
    args = cp.build_parser().parse_args(["--mode", "budget", *argv])
    bundle, _index, snapshot = cp.build_bundle(root, args, counter)
    text, stats, _code = cp.pack(bundle, snapshot, counter, "budget", args.max_ratio, args.baseline)
    return text, stats


def run_modify(root: Path, sc: Scenario, counter: cp.TokenCounter, static: str) -> Result:
    res = Result(sc.name, sc.kind, sc.description, sc.skill)
    owner, _, qual = sc.symbol.partition("::")
    name = qual.split(".")[-1]
    snap = cp.Snapshot(root, sc.rev)
    all_py = snap.python_files()
    sources = snap.read_many(all_py)
    pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(name)}\s*\(")
    callers = sorted(
        p for p, t in sources.items() if p != owner and not cp.is_test_path(p) and pattern.search(t)
    )
    read_full = [owner, *callers]
    res.baseline_files = len(read_full)
    res.baseline_files_tokens = sum(counter.count(sources[p]) for p in read_full if p in sources)
    res.baseline_tokens = res.baseline_files_tokens + counter.count(static)
    text, stats = _bundle(root, ["--symbols", sc.symbol, "--at", sc.rev], counter)
    skill = _skill_text(root, sc.skill)
    res.optimized_core_tokens = counter.count(text)
    res.optimized_tokens = res.optimized_core_tokens + counter.count(skill)
    missing = [p for p in callers if p not in text]
    found_owner = f"{owner}:" in text
    total = len(callers) + 1
    res.recall = _ratio(total - len(missing) - (0 if found_owner else 1), total)
    res.recall_detail = (
        f"{len(callers) - len(missing)}/{len(callers)} grep-caller files + target signature "
        f"({'yes' if found_owner else 'NO'}); bundle prune level {stats['prune_level']}"
    )
    res.notes += missing[:5]
    return res


def run_review(root: Path, sc: Scenario, counter: cp.TokenCounter, static: str) -> Result:
    res = Result(sc.name, sc.kind, sc.description, sc.skill)
    rng = cp.validate_rev(sc.diff_range)
    diff = cp.run_git(
        root,
        ["diff", "--no-color", "--no-ext-diff", "--no-textconv", "--unified=3", "-M", rng, "--"],
    ).decode("utf-8", errors="replace")
    new_rev = rng.split("..")[-1]
    changed = [f.new_path for f in cp.parse_unified_diff(diff) if f.new_path]
    sources = cp.Snapshot(root, new_rev).read_many(changed)
    res.baseline_files = len(sources)
    res.baseline_files_tokens = counter.count(diff) + sum(
        counter.count(t) for t in sources.values()
    )
    res.baseline_tokens = res.baseline_files_tokens + counter.count(static)
    text, stats = _bundle(root, ["--range", rng], counter)
    skill = _skill_text(root, sc.skill)
    res.optimized_core_tokens = counter.count(text)
    res.optimized_tokens = res.optimized_core_tokens + counter.count(skill)
    bundle_lines = set(text.splitlines())
    oracle = [
        ln
        for ln in cp.redact(diff).splitlines()
        if ln[:1] in "+-" and not ln.startswith(("+++ ", "--- "))
    ]
    missing = [ln for ln in oracle if ln not in bundle_lines]
    missing_paths = [p for p in changed if p not in text]
    total = len(oracle) + len(changed)
    res.recall = _ratio(total - len(missing) - len(missing_paths), total) if total else 1.0
    res.recall_detail = (
        f"{len(oracle) - len(missing)}/{len(oracle)} +/- diff lines, "
        f"{len(changed) - len(missing_paths)}/{len(changed)} paths; prune level {stats['prune_level']}"
    )
    res.notes += (missing_paths + missing)[:5]
    return res


def _scenario_revs(sc: Scenario) -> list[str]:
    if sc.kind != "review":
        return [sc.rev]
    old, _, new = sc.diff_range.partition("..")
    return [new, old]


def _symbol_exists(root: Path, rev: str, spec: str, counter: cp.TokenCounter) -> bool:
    path, _, qual = spec.partition("::")
    src = cp.Snapshot(root, rev).read_many([path]).get(path)
    if src is None:
        return False
    return any(s.qualname == qual for s in cp.index_file(path, src, counter).symbols)


def head_variant(
    root: Path, sc: Scenario, counter: cp.TokenCounter, ordinal: int = 0
) -> Scenario | None:
    """Same task re-targeted at ``HEAD`` (clone without the pinned commits).

    Reviews use the ``ordinal``-th most recent commit touching ``*.py`` so
    several review scenarios never collapse onto the same diff.
    """
    if not _rev_exists(root, "HEAD"):
        return None
    if sc.kind == "context":
        files = [f for f in cp.Snapshot(root, "HEAD").python_files() if f.startswith(sc.prefix)]
        return replace(sc, rev="HEAD") if files else None
    if sc.kind == "modify":
        return replace(sc, rev="HEAD") if _symbol_exists(root, "HEAD", sc.symbol, counter) else None
    try:
        log = cp.run_git(
            root, ["log", f"-{ordinal + 1}", "--no-merges", "--format=%H", "HEAD", "--", "*.py"]
        )
    except cp.PackerError:
        return None
    shas = log.decode().split()
    sha = shas[ordinal] if len(shas) > ordinal else ""
    if not sha or not _rev_exists(root, f"{sha}~1"):
        return None  # shallow clone: no parent to diff against
    return replace(sc, name=f"{sc.kind}:head-{sha[:7]}", diff_range=f"{sha[:12]}~1..{sha[:12]}")


# Deterministic synthetic project used when neither the pinned commits nor a
# usable HEAD exist (fresh shallow clone, exported tarball, CI sandbox).
_SYNTH_CORE = '''\
"""Synthetic core module (generated by tools/token_benchmark.py)."""

from __future__ import annotations


def normalize(payload: str, *, lower: bool = True) -> str:
    """Normalise a raw payload before matching."""
    text = payload.strip()
    return text.lower() if lower else text


class Matcher:
    """Match normalised payloads against a signature list."""

    def __init__(self, signatures: list[str]) -> None:
        self.signatures = [normalize(s) for s in signatures]

    def match(self, payload: str) -> bool:
        probe = normalize(payload)
        return any(sig in probe for sig in self.signatures)
''' + "".join(
    f'''

def encode_variant_{i}(payload: str, rounds: int = {i + 1}) -> str:
    """Encoding variant {i}: apply a reversible transform ``rounds`` times."""
    # Each round rotates the payload and swaps case to defeat naive filters.
    out = payload
    for _ in range(rounds):
        out = out[1:] + out[:1]
        out = out.swapcase()
    return out
'''
    for i in range(30)
)


def _synth_module(idx: int) -> str:
    funcs = "".join(
        f'''

def step_{idx}_{j}(value: str, limit: int = {j + 3}) -> list[str]:
    """Pipeline step {j} of module {idx}: split, filter and normalise."""
    # Chunk the value so later steps can stream it.
    chunks = [value[k : k + limit] for k in range(0, len(value), limit)]
    kept = [c for c in chunks if c.strip()]
    return [normalize(c) for c in kept]
'''
        for j in range(18)
    )
    return (
        f'"""Synthetic pipeline module {idx}."""\n\nfrom __future__ import annotations\n\n'
        f"from synth.core import Matcher, normalize\n{funcs}\n\n"
        f"def run_{idx}(payloads: list[str]) -> int:\n"
        f"    matcher = Matcher(['alert(', 'union select'])\n"
        f"    return sum(1 for p in payloads if matcher.match(normalize(p)))\n"
    )


def _git_commit(root: Path, message: str) -> None:
    ident = ["-c", "user.name=bench", "-c", "user.email=bench@example.invalid"]
    cp.run_git(root, ["add", "-A"])
    cp.run_git(root, [*ident, "-c", "commit.gpgsign=false", "commit", "-q", "-m", message])


def build_synthetic_repo(dest: Path, real_root: Path) -> Path:
    """Create the synthetic git repo (two commits) and copy the real skills."""
    (dest / "synth").mkdir(parents=True)
    (dest / "synth" / "__init__.py").write_text("", encoding="utf-8")
    (dest / "synth" / "core.py").write_text(_SYNTH_CORE, encoding="utf-8")
    for idx in range(6):
        (dest / "synth" / f"mod_{idx}.py").write_text(_synth_module(idx), encoding="utf-8")
    for skill in ("context-navigation", "scoped-testing", "diff-code-review"):
        target = dest / ".claude" / "skills" / skill
        target.mkdir(parents=True)
        (target / "SKILL.md").write_text(_skill_text(real_root, skill), encoding="utf-8")
    cp.run_git(dest, ["init", "-q"])
    _git_commit(dest, "synthetic: initial")
    core = dest / "synth" / "core.py"
    core.write_text(
        core.read_text(encoding="utf-8").replace(
            "    text = payload.strip()\n", "    text = payload.strip().replace('\\x00', '')\n"
        ),
        encoding="utf-8",
    )
    _git_commit(dest, "synthetic: strip NUL bytes in normalize")
    return dest


SYNTHETIC: dict[str, Scenario] = {
    "context": Scenario(
        "context-load:synthetic",
        "context",
        "context-navigation",
        "synthetic",
        "HEAD",
        prefix="synth/",
    ),
    "modify": Scenario(
        "modify:synthetic",
        "modify",
        "scoped-testing",
        "synthetic",
        "HEAD",
        symbol="synth/core.py::normalize",
    ),
    "review": Scenario(
        "review:synthetic", "review", "diff-code-review", "synthetic", diff_range="HEAD~1..HEAD"
    ),
}


def _finish(res: Result, max_ratio: float, source: str) -> Result:
    res.source = source
    res.ratio = _ratio(res.optimized_tokens, res.baseline_tokens)
    res.files_only_ratio = _ratio(res.optimized_core_tokens, res.baseline_files_tokens)
    res.passed = res.ratio <= max_ratio and res.files_only_ratio <= max_ratio and res.recall == 1.0
    return res


def run_scenarios(
    root: Path,
    counter: cp.TokenCounter,
    static: str,
    max_ratio: float,
    portable: str = "auto",
) -> list[Result]:
    """Run every scenario: pinned commit -> HEAD variant -> synthetic fixture.

    ``portable``: ``auto`` (fallback only when needed), ``head`` (skip the
    pinned commits) or ``synthetic`` (fixture only). Never returns SKIPPED.
    """
    runners = {"context": run_context, "modify": run_modify, "review": run_review}
    results: list[Result] = []
    pending: list[Scenario] = []
    for sc in SCENARIOS:
        chosen: tuple[Scenario, str] | None = None
        if portable == "auto" and all(_rev_exists(root, r) for r in _scenario_revs(sc)):
            chosen = (sc, "pinned")
        elif portable in ("auto", "head"):
            ordinal = sum(1 for s in SCENARIOS[: SCENARIOS.index(sc)] if s.kind == sc.kind)
            variant = head_variant(root, sc, counter, ordinal if sc.kind == "review" else 0)
            chosen = (variant, "head") if variant else None
        if chosen is None:
            pending.append(sc)
            continue
        target, source = chosen
        results.append(_finish(runners[sc.kind](root, target, counter, static), max_ratio, source))
    if pending:
        with tempfile.TemporaryDirectory(prefix="token-bench-") as tmp:
            synth_root = build_synthetic_repo(Path(tmp) / "repo", root)
            for kind in sorted({sc.kind for sc in pending}, key=list(SYNTHETIC).index):
                sc = SYNTHETIC[kind]
                res = runners[kind](synth_root, sc, counter, static)
                results.append(_finish(res, max_ratio, "synthetic"))
    return results


# ---------------------------------------------------------------------------
# Quality gates
# ---------------------------------------------------------------------------


def find_venv_python(root: Path) -> Path | None:
    candidates = [root / ".venv" / "bin" / "python"]
    try:
        common = cp.run_git(root, ["rev-parse", "--path-format=absolute", "--git-common-dir"])
        candidates.append(Path(common.decode().strip()).parent / ".venv" / "bin" / "python")
    except cp.PackerError:
        pass
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def _run_gate(root: Path, argv: list[str]) -> tuple[bool, str]:
    try:
        proc = subprocess.run(  # nosec B603
            argv, cwd=root, capture_output=True, text=True, timeout=GATE_TIMEOUT_S, check=False
        )
    except subprocess.TimeoutExpired:
        return False, "timeout"
    lines = [ln for ln in (proc.stdout + proc.stderr).splitlines() if ln.strip()]
    summary = lines[-1] if lines else ""
    summary = re.sub(r" in [0-9.]+s(?: \([0-9:]+\))?", "", summary)  # drop timings
    return proc.returncode == 0, summary.strip("= ").strip()


def run_gates(root: Path, python: Path) -> dict[str, dict[str, object]]:
    py = str(python)
    tools = ["tools/context_packer.py", "tools/token_benchmark.py", "tools/context_hook.py"]
    plan = {
        "pytest": [py, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
        "ruff": [py, "-m", "ruff", "check", "."],
        "mypy": [py, "-m", "mypy"],
        "mypy_strict_tools": [py, "-m", "mypy", "--strict", "--python-version", "3.10", *tools],
    }
    out: dict[str, dict[str, object]] = {}
    for name, argv in plan.items():
        ok, summary = _run_gate(root, argv)
        out[name] = {"ok": ok, "summary": summary}
    return out


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def render_table(results: list[Result], tokenizer: str, max_ratio: float) -> str:
    rows = [
        f"Token benchmark | tokenizer {tokenizer} | threshold <= {max_ratio:.0%} | pinned {PINNED_REV}",
        "",
        "| scenario | source | skill | baseline | optimized | % | files-only % | recall | result |",
        "|---|---|---|---:|---:|---:|---:|---|---|",
    ]
    for r in results:
        rows.append(
            f"| {r.name} | {r.source} | {r.skill} | {r.baseline_tokens} | {r.optimized_tokens} | "
            f"{r.ratio:.1%} | {r.files_only_ratio:.1%} | {r.recall:.0%} ({r.recall_detail}) | "
            f"{'PASS' if r.passed else 'FAIL'} |"
        )
    if results:
        base = sum(r.baseline_tokens for r in results)
        opt = sum(r.optimized_tokens for r in results)
        rows.append(f"| **total** | | | {base} | {opt} | {_ratio(opt, base):.1%} | | | |")
    return "\n".join(rows)


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="token_benchmark", description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--tokenizer", choices=("auto", "tiktoken", "heuristic"), default="auto")
    ap.add_argument("--max-ratio", type=float, default=cp.DEFAULT_MAX_RATIO)
    ap.add_argument(
        "--static",
        nargs="*",
        default=["CLAUDE.md", "AGENTS.md"],
        help="baseline static context files (missing ones are skipped)",
    )
    ap.add_argument("--vault", help="Obsidian vault dir: add WSS* notes to the static baseline")
    ap.add_argument("--gates", action="store_true", help="also run pytest, ruff and mypy")
    ap.add_argument(
        "--no-metrics", action="store_true", help="do not append to .context/metrics.jsonl"
    )
    ap.add_argument(
        "--portable",
        choices=("auto", "head", "synthetic"),
        default="auto",
        help="auto: pinned commits, else HEAD, else synthetic fixture; "
        "head/synthetic force that source",
    )
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        root = cp.find_repo_root(Path(args.root).resolve())
        counter = cp.TokenCounter(args.tokenizer)
        static = static_context(root, args.static, args.vault)
        results = run_scenarios(root, counter, static, args.max_ratio, args.portable)
    except cp.PackerError as exc:
        print(f"token_benchmark: error: {exc}", file=sys.stderr)
        return 2

    gates: dict[str, dict[str, object]] = {}
    if args.gates:
        python = find_venv_python(root)
        if python is None:
            gates = {"setup": {"ok": False, "summary": "no .venv/bin/python found"}}
        else:
            gates = run_gates(root, python)

    kinds = {r.kind for r in results}
    ok = (
        len(results) >= 3
        and kinds == {"context", "modify", "review"}
        and all(r.passed for r in results)
        and all(g["ok"] for g in gates.values())
    )
    report = {
        "tokenizer": counter.name,
        "max_ratio": args.max_ratio,
        "pinned_rev": PINNED_REV,
        "static_context_tokens": counter.count(static),
        "scenarios": [asdict(r) for r in results],
        "gates": gates,
        "passed": ok,
    }
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=1))
    else:
        print(render_table(results, counter.name, args.max_ratio))
        for name, gate in gates.items():
            print(f"GATE {name}: {'OK' if gate['ok'] else 'FAIL'} — {gate['summary']}")
        print(f"RESULT: {'PASS' if ok else 'FAIL'} ({len(results)} scenarios run)")

    if not args.no_metrics:
        ctx = cp.context_dir(root)
        ctx.mkdir(exist_ok=True)
        if not (ctx / ".gitignore").exists():
            (ctx / ".gitignore").write_text("*\n", encoding="utf-8")
        head = cp.run_git(root, ["rev-parse", "HEAD"]).decode().strip()
        line = {
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "head": head,
        }
        line.update(report)
        with (ctx / "metrics.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, sort_keys=True) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
