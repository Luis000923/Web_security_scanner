"""Tests for tools/context_packer.py (L0 repo map, L1 bundle, token budget).

Every test builds a throwaway git repository under ``tmp_path`` so results do
not depend on the state of this checkout. Assertion messages are in Spanish
by repo convention (``tests/``).
"""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tools import context_packer as cp

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git no disponible")

# Unrelated, realistic-size code so token ratios are not dominated by the
# bundle's fixed header (real modules in this repo are hundreds of lines).
FILLER = "".join(
    f"""

def unrelated_{i}(payload: str, retries: int = 3) -> list[str]:
    \"\"\"Unrelated helper number {i}, never called by the code under test.\"\"\"
    # Normalise the payload before splitting it into chunks.
    chunks = [payload[j : j + 8] for j in range(0, len(payload), 8)]
    if retries <= 0:
        return []
    return [c.strip().lower() for c in chunks if c]
"""
    for i in range(25)
)


CORE = (
    '''\
from __future__ import annotations

import os


def helper(x: int, *, scale: float = 2.0) -> float:
    """Scale x by a factor."""
    return x * scale


class Engine:
    """Toy engine."""

    def __init__(self, n: int) -> None:
        self.n = n

    async def run(self, url: str) -> dict[str, int]:
        # internal comment
        return {"v": int(helper(self.n))}
'''
    + FILLER
)

USE = """\
from pkg.core import Engine, helper


def caller_a() -> float:
    return helper(3)


async def caller_b(url: str) -> None:
    eng = Engine(1)
    await eng.run(url)
"""

TEST_CORE = """\
from pkg.core import helper


def test_helper() -> None:
    assert helper(1) == 2.0
"""


def _git(root: Path, *args: str) -> str:
    proc = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "pkg").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (root / "pkg" / "core.py").write_text(CORE, encoding="utf-8")
    (root / "pkg" / "use.py").write_text(USE + FILLER, encoding="utf-8")
    (root / "tests" / "test_core.py").write_text(TEST_CORE, encoding="utf-8")
    (root / ".gitignore").write_text("ignored.py\n", encoding="utf-8")
    (root / "ignored.py").write_text("def nope() -> None: ...\n", encoding="utf-8")
    (root / ".env").write_text("API_KEY=supersecretvalue\n", encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "add", "pkg", "tests", ".gitignore")
    _git(root, "commit", "-q", "-m", "init")
    return root


def _run(root: Path, *argv: str) -> tuple[int, dict[str, object]]:
    code = cp.main(["--root", str(root), "--tokenizer", "heuristic", "--json", *argv])
    return code, {}


def _stats(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    out = capsys.readouterr().out.strip().splitlines()
    return json.loads(out[-1])


# --------------------------------------------------------------------------- #
# L0
# --------------------------------------------------------------------------- #


def test_l0_mapa_con_firmas_tipadas(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _ = _run(repo, "--mode", "l0")
    stats = _stats(capsys)
    assert code == cp.EXIT_OK
    repomap = (repo / ".context" / "repomap.md").read_text(encoding="utf-8")
    assert "F helper(x: int, *, scale: float = 2.0) -> float" in repomap
    assert "aM run(url: str) -> dict[str, int]" in repomap, "self debe omitirse en métodos"
    assert "## pkg/use.py" in repomap
    assert "ignored.py" not in repomap, "un archivo en .gitignore no debe indexarse"
    assert "tests/test_core.py" not in repomap, "tests fuera del mapa por defecto"
    assert "return x * scale" not in repomap, "L0 no debe incluir cuerpos"
    assert stats["files"] == 3
    assert isinstance(stats["ratio"], float) and stats["ratio"] < 0.5


def test_l0_symbols_json_tiene_llamadas_y_tests(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(repo, "--mode", "l0")
    capsys.readouterr()
    data = json.loads((repo / ".context" / "symbols.json").read_text(encoding="utf-8"))
    assert data["schema"] == cp.SCHEMA_VERSION
    syms = {s["qualname"]: s for s in data["files"]["pkg/core.py"]["symbols"]}
    assert "helper" in syms["Engine.run"]["calls"]
    assert "tests/test_core.py" in data["files"], "symbols.json indexa también los tests"
    assert (repo / ".context" / ".gitignore").read_text(encoding="utf-8").strip().endswith("*")


def test_l0_es_determinista(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _run(repo, "--mode", "l0")
    first = (
        (repo / ".context" / "repomap.md").read_bytes(),
        (repo / ".context" / "symbols.json").read_bytes(),
    )
    _run(repo, "--mode", "l0")
    second = (
        (repo / ".context" / "repomap.md").read_bytes(),
        (repo / ".context" / "symbols.json").read_bytes(),
    )
    capsys.readouterr()
    assert first == second, "dos ejecuciones sobre el mismo árbol deben ser idénticas byte a byte"


def test_l0_check_detecta_obsolescencia(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _run(repo, "--mode", "l0")
    assert (
        cp.main(["--root", str(repo), "--tokenizer", "heuristic", "--mode", "l0", "--check"]) == 0
    )
    (repo / "pkg" / "core.py").write_text(CORE + "\n\ndef extra() -> None: ...\n", encoding="utf-8")
    assert (
        cp.main(["--root", str(repo), "--tokenizer", "heuristic", "--mode", "l0", "--check"])
        == cp.EXIT_STALE
    )
    capsys.readouterr()


def test_l0_tolera_errores_de_sintaxis(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "pkg" / "broken.py").write_text("def roto(:\n", encoding="utf-8")
    code, _ = _run(repo, "--mode", "l0")
    stats = _stats(capsys)
    assert code == cp.EXIT_OK
    assert stats["parse_errors"] == ["pkg/broken.py"]


# --------------------------------------------------------------------------- #
# Path safety
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "bad",
    ["../outside.py", "/etc/passwd", ".git/config", ".env", "pkg/../../x.py", ".venv/lib/a.py"],
)
def test_safe_resolve_rechaza_rutas_peligrosas(repo: Path, bad: str) -> None:
    with pytest.raises(cp.PackerError):
        cp.safe_resolve(repo, bad)


def test_safe_resolve_rechaza_symlink_fuera_del_repo(repo: Path, tmp_path: Path) -> None:
    target = tmp_path / "fuera.py"
    target.write_text("x = 1\n", encoding="utf-8")
    (repo / "pkg" / "link.py").symlink_to(target)
    with pytest.raises(cp.PackerError):
        cp.safe_resolve(repo, "pkg/link.py")
    assert "pkg/link.py" not in cp.Snapshot(repo).list_files()


@pytest.mark.parametrize(
    ("name", "excluded"),
    [
        ("web_security_scanner/modules/credential_exposure_tester_async.py", False),
        ("pkg/core.py", False),
        (".env.local", True),
        ("deploy/id_rsa", True),
        ("certs/server.pem", True),
        ("config/credentials.json", True),
        ("a/__pycache__/x.py", True),
    ],
)
def test_is_excluded(name: str, excluded: bool) -> None:
    assert cp.is_excluded(name) is excluded


@pytest.mark.parametrize("rev", ["--output=/tmp/x", "a;b", "a b", "$(id)", ""])
def test_validate_rev_rechaza_inyeccion(rev: str) -> None:
    with pytest.raises(cp.PackerError):
        cp.validate_rev(rev)


def test_out_fuera_de_context_rechazado(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "pkg" / "core.py").write_text(
        CORE.replace("x * scale", "x * scale + 0"), encoding="utf-8"
    )
    code = cp.main(["--root", str(repo), "--mode", "l1", "--out", "pkg/core.py"])
    assert code == cp.EXIT_INPUT, "--out nunca debe poder sobrescribir código fuente"
    assert "x * scale + 0" in (repo / "pkg" / "core.py").read_text(encoding="utf-8")
    capsys.readouterr()


# --------------------------------------------------------------------------- #
# Diff parsing
# --------------------------------------------------------------------------- #


def test_parse_diff_mapea_lineas_nuevas() -> None:
    diff = (
        "diff --git a/m.py b/m.py\n"
        "--- a/m.py\n"
        "+++ b/m.py\n"
        "@@ -1,4 +1,4 @@\n"
        " a = 1\n"
        "--- this removed line starts with two dashes\n"
        "+b = 2\n"
        " c = 3\n"
        "diff --git a/n.py b/n.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/n.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+x = 1\n"
        "+y = 2\n"
    )
    files = cp.parse_unified_diff(diff)
    assert [f.path for f in files] == ["m.py", "n.py"]
    assert files[0].added_lines == {2}
    assert files[0].old_path == "m.py", "una línea '--- ' dentro de un hunk no es cabecera"
    assert files[1].status == "added" and files[1].added_lines == {1, 2}


def test_trim_diff_context() -> None:
    diff = "@@ -1,3 +1,3 @@\n # comment\n x = 1\n-y = 1\n+y = 2\n\n"
    assert " x = 1" in cp.trim_diff_context(diff, "code")
    assert " # comment" not in cp.trim_diff_context(diff, "code")
    none = cp.trim_diff_context(diff, "none")
    assert " x = 1" not in none and "+y = 2" in none and "-y = 1" in none


# --------------------------------------------------------------------------- #
# L1 / budget
# --------------------------------------------------------------------------- #


def test_l1_funcion_modificada_trae_callers_y_tests(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "pkg" / "core.py").write_text(
        CORE.replace("x * scale", "x * scale * 1"), encoding="utf-8"
    )
    code, _ = _run(repo, "--mode", "l1")
    stats = _stats(capsys)
    bundle = (repo / ".context" / "bundle.md").read_text(encoding="utf-8")
    assert code == cp.EXIT_OK
    assert "+    return x * scale * 1" in bundle
    assert "F helper(x: int, *, scale: float = 2.0) -> float" in bundle
    assert "pkg/use.py" in bundle and "caller_a" in bundle, "falta el caller directo"
    assert "return helper(3)" in bundle, "falta el slice del sitio de llamada"
    assert "tests/test_core.py::test_helper" in bundle
    assert 'pytest tests/test_core.py -k "test_helper"' in bundle
    assert stats["changed_symbols"] == 1


def test_l1_metodo_modificado_trae_caller_por_atributo(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "pkg" / "core.py").write_text(
        CORE.replace('{"v": int(helper(self.n))}', '{"v": int(helper(self.n)) + 1}'),
        encoding="utf-8",
    )
    _run(repo, "--mode", "l1")
    capsys.readouterr()
    bundle = (repo / ".context" / "bundle.md").read_text(encoding="utf-8")
    assert "Engine.run" in bundle
    assert "caller_b" in bundle and "await eng.run(url)" in bundle
    assert "## 5. Callees" in bundle and "helper(" in bundle.split("## 5. Callees")[1]


def test_l1_por_simbolo_sin_diff(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _ = _run(repo, "--mode", "l1", "--symbols", "pkg/core.py::Engine.__init__")
    stats = _stats(capsys)
    bundle = (repo / ".context" / "bundle.md").read_text(encoding="utf-8")
    assert code == cp.EXIT_OK and stats["callers"] == 1
    assert "eng = Engine(1)" in bundle, "__init__ se resuelve como instanciación de la clase"
    assert "## 1. Diff" not in bundle


def test_l1_simbolo_inexistente_es_error(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = cp.main(["--root", str(repo), "--mode", "l1", "--symbols", "NoExiste"])
    assert code == cp.EXIT_INPUT
    assert "symbol not found" in capsys.readouterr().err


def test_l1_incluye_archivos_nuevos_sin_trackear(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "pkg" / "nuevo.py").write_text(
        "def fresh(a: str) -> str:\n    return a\n", encoding="utf-8"
    )
    _run(repo, "--mode", "l1")
    capsys.readouterr()
    bundle = (repo / ".context" / "bundle.md").read_text(encoding="utf-8")
    assert "+++ b/pkg/nuevo.py" in bundle and "+def fresh(a: str) -> str:" in bundle


def test_diff_vacio_es_error(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cp.main(["--root", str(repo), "--mode", "l1"]) == cp.EXIT_INPUT
    capsys.readouterr()


def test_range_lee_el_lado_nuevo_en_la_revision(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "pkg" / "core.py").write_text(
        CORE.replace("x * scale", "x * scale * 7"), encoding="utf-8"
    )
    _git(repo, "commit", "-q", "-am", "change")
    # Dirty the worktree with something unrelated: --range must ignore it.
    (repo / "pkg" / "core.py").write_text(
        CORE.replace("def helper", "def renamed"), encoding="utf-8"
    )
    code, _ = _run(repo, "--mode", "budget", "--range", "HEAD~1..HEAD")
    stats = _stats(capsys)
    bundle = (repo / ".context" / "bundle.md").read_text(encoding="utf-8")
    assert code == cp.EXIT_OK
    assert "x * scale * 7" in bundle and "F helper(" in bundle and "renamed" not in bundle
    assert stats["within_budget"] is True


def test_budget_respeta_ratio_y_poda_por_prioridad(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "pkg" / "core.py").write_text(
        CORE.replace("x * scale", "x * scale * 1"), encoding="utf-8"
    )
    code, _ = _run(repo, "--mode", "budget", "--max-ratio", "0.6")
    stats = _stats(capsys)
    assert code == cp.EXIT_OK and stats["within_budget"] is True
    assert isinstance(stats["ratio"], float) and stats["ratio"] <= 0.6
    # An impossible budget must fail loudly instead of shipping an oversized bundle.
    code = cp.main(
        [
            "--root",
            str(repo),
            "--tokenizer",
            "heuristic",
            "--json",
            "--mode",
            "budget",
            "--max-ratio",
            "0.01",
        ]
    )
    stats = _stats(capsys)
    assert code == cp.EXIT_OVER_BUDGET and stats["within_budget"] is False
    assert stats["prune_level"] == len(cp.pruning_ladder()) - 1
    bundle = (repo / ".context" / "bundle.md").read_text(encoding="utf-8")
    assert "+    return x * scale * 1" in bundle, "el diff (+/-) nunca se poda"


def test_escalera_de_poda_es_monotona(repo: Path) -> None:
    (repo / "pkg" / "core.py").write_text(
        CORE.replace("x * scale", "x * scale * 1"), encoding="utf-8"
    )
    parser = cp.build_parser()
    args = parser.parse_args(["--mode", "budget", "--traceback", "tb.txt"])
    (repo / "tb.txt").write_text("\n".join(f"frame {i}" for i in range(80)), encoding="utf-8")
    counter = cp.TokenCounter("heuristic")
    bundle, _, _ = cp.build_bundle(repo, args, counter)
    sizes = [
        counter.count(cp.render_bundle(bundle, o, "budget", counter.name))
        for o in cp.pruning_ladder()
    ]
    assert sizes == sorted(sizes, reverse=True), f"cada nivel debe costar <= el anterior: {sizes}"
    assert "frame 79" in cp.render_bundle(bundle, cp.pruning_ladder()[-1], "budget", counter.name)


# --------------------------------------------------------------------------- #
# Tokens, signatures, redaction
# --------------------------------------------------------------------------- #


def test_heuristic_tokens() -> None:
    assert cp.heuristic_tokens("") == 0
    assert cp.heuristic_tokens("def f(x):\n    return x\n") == cp.heuristic_tokens(
        "def f(x):\n    return x\n"
    )
    assert cp.heuristic_tokens("a" * 400) == 100
    assert cp.heuristic_tokens("x = 1") < cp.heuristic_tokens("x = 1\ny = 2")


def test_token_counter_backend_invalido() -> None:
    with pytest.raises(cp.PackerError):
        cp.TokenCounter("bogus")
    assert cp.TokenCounter("heuristic").name == "heuristic-v1"


def test_format_arguments_cubre_todas_las_formas() -> None:
    fn = ast.parse(
        "def f(a, /, b: int = 1, *args: str, c, d: bool = False, **kw: object): ..."
    ).body[0]
    assert isinstance(fn, ast.FunctionDef)
    assert (
        cp.format_arguments(fn.args, drop_first=False)
        == "a, /, b: int = 1, *args: str, c, d: bool = False, **kw: object"
    )
    m = ast.parse("def g(self, *, k=3): ...").body[0]
    assert isinstance(m, ast.FunctionDef)
    assert cp.format_arguments(m.args, drop_first=True) == "*, k=3"


def test_redact_oculta_secretos() -> None:
    text = (
        'api_key = "abcd1234efgh5678"\n'
        "Authorization: Bearer abcdefghijklmnop\n"
        "AKIAABCDEFGHIJKLMNOP\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n"
    )
    out = cp.redact(text)
    assert "abcd1234efgh5678" not in out
    assert "abcdefghijklmnop" not in out
    assert "AKIAABCDEFGHIJKLMNOP" not in out
    assert "MIIE" not in out
    assert 'api_key = "[REDACTED]"' in out


def test_archivo_nuevo_no_duplica_firmas(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "pkg" / "nuevo.py").write_text(
        "def fresh(a: str) -> str:\n    return a\n\n\ndef other(b: int) -> int:\n    return b\n",
        encoding="utf-8",
    )
    _run(repo, "--mode", "l1")
    capsys.readouterr()
    bundle = (repo / ".context" / "bundle.md").read_text(encoding="utf-8")
    assert "`pkg/nuevo.py` new file, full source in diff: fresh, other" in bundle
    assert "+def fresh(a: str) -> str:" in bundle, "la firma sigue presente, dentro del diff"


def test_baseline_changed_es_mas_estricto_que_involved(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "pkg" / "core.py").write_text(
        CORE.replace("x * scale", "x * scale * 1"), encoding="utf-8"
    )
    _run(repo, "--mode", "l1", "--baseline", "changed")
    strict = _stats(capsys)
    _run(repo, "--mode", "l1", "--baseline", "involved")
    loose = _stats(capsys)
    assert strict["baseline_scope"] == "changed" and loose["baseline_scope"] == "involved"
    assert isinstance(strict["baseline_tokens"], int) and isinstance(loose["baseline_tokens"], int)
    assert strict["baseline_tokens"] < loose["baseline_tokens"]


# --------------------------------------------------------------------------- #
# Hook
# --------------------------------------------------------------------------- #


def _hook(payload: str) -> subprocess.CompletedProcess[str]:
    hook = Path(__file__).resolve().parents[1] / "tools" / "context_hook.py"
    return subprocess.run(
        ["python3", str(hook)], input=payload, capture_output=True, text=True, check=False
    )


def test_hook_regenera_tras_editar_py(repo: Path) -> None:
    payload = json.dumps(
        {"cwd": str(repo), "tool_input": {"file_path": str(repo / "pkg" / "core.py")}}
    )
    proc = _hook(payload)
    assert proc.returncode == 0
    assert (repo / ".context" / "repomap.md").is_file()


@pytest.mark.parametrize(
    "payload",
    [
        "no-json",
        "[]",
        '{"tool_input": {"file_path": "README.md"}}',
        '{"tool_input": {"file_path": "/etc/x.py"}}',
    ],
)
def test_hook_nunca_bloquea(repo: Path, payload: str) -> None:
    proc = _hook(payload)
    assert proc.returncode == 0, "el hook nunca debe romper la edición del usuario"
    assert not (repo / ".context").exists()


# --------------------------------------------------------------------------- #
# Benchmark
# --------------------------------------------------------------------------- #


def test_benchmark_escenarios_en_repo_de_juguete(repo: Path) -> None:
    from tools import token_benchmark as tb

    (repo / "pkg" / "core.py").write_text(
        CORE.replace("x * scale", "x * scale * 3"), encoding="utf-8"
    )
    _git(repo, "commit", "-q", "-am", "change")
    skills = repo / ".claude" / "skills"
    for name in ("context-navigation", "scoped-testing", "diff-code-review"):
        (skills / name).mkdir(parents=True)
        (skills / name / "SKILL.md").write_text(f"# {name}\nshort skill\n", encoding="utf-8")
    counter = cp.TokenCounter("heuristic")
    static = "static context\n" * 50
    ctx = tb.run_context(
        repo,
        tb.Scenario("c", "context", "context-navigation", "", rev="HEAD", prefix="pkg/"),
        counter,
        static,
    )
    mod = tb.run_modify(
        repo,
        tb.Scenario("m", "modify", "scoped-testing", "", rev="HEAD", symbol="pkg/core.py::helper"),
        counter,
        static,
    )
    rev = tb.run_review(
        repo,
        tb.Scenario("r", "review", "diff-code-review", "", diff_range="HEAD~1..HEAD"),
        counter,
        static,
    )
    assert ctx.recall == 1.0 and "helper" not in ctx.notes
    assert mod.recall == 1.0, f"caller de pkg/use.py ausente: {mod.notes}"
    assert rev.recall == 1.0, f"líneas del diff perdidas: {rev.notes}"
    for res in (ctx, mod, rev):
        assert 0 < res.optimized_tokens < res.baseline_tokens
    table = tb.render_table([ctx], counter.name, 0.6)
    assert "| c | pinned | context-navigation |" in table


def test_benchmark_ast_names_independiente() -> None:
    from tools import token_benchmark as tb

    src = "class A:\n    def m(self): ...\n\nif True:\n    def f(): ...\n"
    assert tb._ast_names(src) == {"A", "m", "f"}
    assert tb._ast_names("def roto(:") == set()


# --------------------------------------------------------------------------- #
# Incremental L0 / sync
# --------------------------------------------------------------------------- #


def _l0_bytes(repo: Path) -> tuple[bytes, bytes]:
    ctx = repo / ".context"
    return (ctx / "repomap.md").read_bytes(), (ctx / "symbols.json").read_bytes()


def test_incremental_identico_a_rebuild_completo(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(repo, "--mode", "l0")
    (repo / "pkg" / "core.py").write_text(
        CORE + "\n\ndef extra(z: int) -> int:\n    return z\n", encoding="utf-8"
    )
    (repo / "pkg" / "nuevo.py").write_text("def fresh() -> None: ...\n", encoding="utf-8")
    code, _ = _run(repo, "--mode", "l0", "--paths", "pkg/core.py", "pkg/nuevo.py")
    stats = _stats(capsys)
    assert code == cp.EXIT_OK and stats["incremental"] is True
    assert stats["updated"] == ["pkg/core.py", "pkg/nuevo.py"]
    incremental = _l0_bytes(repo)
    _run(repo, "--mode", "l0")
    capsys.readouterr()
    assert incremental == _l0_bytes(repo), "incremental y completo deben coincidir byte a byte"


def test_incremental_elimina_archivos_borrados(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(repo, "--mode", "l0")
    (repo / "pkg" / "use.py").unlink()
    _run(repo, "--mode", "l0", "--paths", "pkg/use.py")
    stats = _stats(capsys)
    assert stats["updated"] == ["pkg/use.py"]
    assert "## pkg/use.py" not in (repo / ".context" / "repomap.md").read_text(encoding="utf-8")


def test_incremental_ignora_rutas_fuera_o_ignoradas(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(repo, "--mode", "l0")
    _run(repo, "--mode", "l0", "--paths", "ignored.py", "../fuera.py", "README.md")
    stats = _stats(capsys)
    assert stats["updated"] == []
    assert "ignored.py" not in (repo / ".context" / "repomap.md").read_text(encoding="utf-8")


def test_sync_reindexa_solo_lo_cambiado(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _run(repo, "--mode", "l0")
    capsys.readouterr()
    (repo / "pkg" / "use.py").write_text(USE + FILLER + "\n# touched\n", encoding="utf-8")
    assert (
        cp.main(
            ["--root", str(repo), "--tokenizer", "heuristic", "--json", "--mode", "l0", "--check"]
        )
        == cp.EXIT_STALE
    )
    assert _stats(capsys)["stale"] == ["pkg/use.py"]
    _run(repo, "--mode", "l0", "--sync")
    assert _stats(capsys)["updated"] == ["pkg/use.py"]
    assert (
        cp.main(["--root", str(repo), "--tokenizer", "heuristic", "--mode", "l0", "--check"])
        == cp.EXIT_OK
    )
    synced = _l0_bytes(repo)
    _run(repo, "--mode", "l0")
    capsys.readouterr()
    assert synced == _l0_bytes(repo)


def test_sync_sin_indice_hace_build_completo(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(repo, "--mode", "l0", "--sync")
    stats = _stats(capsys)
    assert stats["incremental"] is False and (repo / ".context" / "symbols.json").is_file()


def test_indice_corrupto_fuerza_rebuild(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / ".context").mkdir()
    (repo / ".context" / "symbols.json").write_text("{no json", encoding="utf-8")
    assert cp.load_index(repo / ".context", cp.TokenCounter("heuristic")) is None
    _run(repo, "--mode", "l0", "--paths", "pkg/core.py")
    assert _stats(capsys)["incremental"] is False


def test_hook_stop_sincroniza(repo: Path) -> None:
    proc = _hook(json.dumps({"cwd": str(repo), "hook_event_name": "Stop"}))
    assert proc.returncode == 0
    assert (repo / ".context" / "symbols.json").is_file()


def test_tope_de_callers_reparte_por_archivo() -> None:
    sym = cp.Symbol("f", "f", "function", 1, 2, "f()")
    callers = [
        cp.CallerRef(
            cp.SymRef(f"m{i}.py", cp.Symbol(f"c{j}", f"c{j}", "function", j, j, "c()")),
            "f",
            (),
            False,
        )
        for i in range(4)
        for j in range(1, 6)
    ]
    picked = cp._spread_by_file(callers, 6)
    assert len(picked) == 6
    assert {c.ref.path for c in picked} == {"m0.py", "m1.py", "m2.py", "m3.py"}
    assert sym.name == "f"


# --------------------------------------------------------------------------- #
# Benchmark portability
# --------------------------------------------------------------------------- #


def test_benchmark_sintetico_nunca_skipped() -> None:
    from tools import token_benchmark as tb

    root = Path(__file__).resolve().parents[1]
    static = tb.static_context(root, ["CLAUDE.md", "AGENTS.md"], None)
    results = tb.run_scenarios(root, cp.TokenCounter("heuristic"), static, 0.6, "synthetic")
    assert {r.kind for r in results} == {"context", "modify", "review"}
    assert all(r.source == "synthetic" for r in results)
    assert all(r.passed for r in results), [(r.name, r.ratio, r.recall, r.notes) for r in results]


def test_benchmark_head_reviews_no_se_repiten(repo: Path) -> None:
    from tools import token_benchmark as tb

    for n in range(3):
        (repo / "pkg" / "core.py").write_text(CORE + f"\n# rev {n}\n", encoding="utf-8")
        _git(repo, "commit", "-q", "-am", f"rev {n}")
    review = tb.Scenario("r", "review", "diff-code-review", "", diff_range="x..y")
    counter = cp.TokenCounter("heuristic")
    ranges = {tb.head_variant(repo, review, counter, k).diff_range for k in range(3)}  # type: ignore[union-attr]
    assert len(ranges) == 3
