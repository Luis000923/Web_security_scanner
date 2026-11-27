"""Tests for tools/dup_guard.py (AST duplicate guard)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tools import dup_guard as dg

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git no disponible")

ORIGINAL = '''\
def normalize_headers(headers, default="text/html"):
    """Lower-case header names and pick the content type."""
    result = {}
    for key, value in headers.items():
        name = key.strip().lower()
        if not name:
            continue
        result[name] = str(value).strip()
    ctype = result.get("content-type", default)
    if ";" in ctype:
        ctype = ctype.split(";", 1)[0]
    return result, ctype.lower()
'''

# Type 2 clone: same structure, every local and argument renamed.
RENAMED = '''\
def tidy_hdrs(hdrs, fallback="text/html"):
    """Different docstring, same body."""
    out = {}
    for k, v in hdrs.items():
        n = k.strip().lower()
        if not n:
            continue
        out[n] = str(v).strip()
    ct = out.get("content-type", fallback)
    if ";" in ct:
        ct = ct.split(";", 1)[0]
    return out, ct.lower()
'''

# Type 3 clone: one extra statement.
NEAR = """\
def headers_with_type(headers, default="text/html"):
    result = {}
    for key, value in headers.items():
        name = key.strip().lower()
        if not name:
            continue
        result[name] = str(value).strip()
    ctype = result.get("content-type", default)
    if ";" in ctype:
        ctype = ctype.split(";", 1)[0]
    ctype = ctype.strip()
    return result, ctype.lower()
"""

UNRELATED = '''\
def count_vowels(text):
    """Count vowels in text."""
    total = 0
    for ch in text:
        if ch in "aeiou":
            total += 1
        elif ch == " ":
            continue
        else:
            total += 0
    return total
'''

TINY = """\
def getter(obj):
    return obj.value
"""


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


@pytest.fixture()
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "r"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "core.py").write_text(ORIGINAL + "\n\n" + UNRELATED, encoding="utf-8")
    (root / "pkg" / "small.py").write_text(TINY, encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "init")
    monkeypatch.chdir(root)
    return root


def _rec(src: str, path: str = "pkg/x.py") -> dg.FuncRecord:
    return dg.records_from_source(path, src)[0]


# --- fingerprints ----------------------------------------------------------


def test_renombrar_locales_no_cambia_el_hash_exacto() -> None:
    assert _rec(ORIGINAL).exact == _rec(RENAMED).exact


def test_casi_duplicado_supera_el_umbral_y_no_es_exacto() -> None:
    a, b = _rec(ORIGINAL), _rec(NEAR)
    assert a.exact != b.exact
    assert dg.jaccard(a.shingles, b.shingles) >= dg.DEFAULT_THRESHOLD


def test_codigo_no_relacionado_queda_por_debajo_del_umbral() -> None:
    a, b = _rec(ORIGINAL), _rec(UNRELATED)
    assert dg.jaccard(a.shingles, b.shingles) < 0.5


def test_lineas_logicas_ignoran_el_docstring() -> None:
    assert _rec(ORIGINAL).logical == 10
    assert _rec(TINY).logical == 1


def test_comentario_de_exclusion_marca_ignored() -> None:
    src = "# dup-guard: ignore -- adapter contract\n" + ORIGINAL
    assert _rec(src).ignored
    assert not _rec(ORIGINAL).ignored


def test_sintaxis_invalida_no_rompe() -> None:
    assert dg.records_from_source("pkg/bad.py", "def (:\n") == []


def test_metodos_y_funciones_anidadas_tienen_qualname() -> None:
    src = "class A:\n    def m(self):\n        def inner():\n            return 1\n        return inner\n"
    quals = [r.qualname for r in dg.records_from_source("pkg/a.py", src)]
    assert quals == ["A.m", "A.m.inner"]


# --- scan ------------------------------------------------------------------


def test_scan_agrupa_exactos_y_casi_duplicados() -> None:
    recs = [_rec(ORIGINAL, "a/x.py"), _rec(RENAMED, "a/y.py"), _rec(NEAR, "a/z.py")]
    groups = dg.scan(recs, dg.DEFAULT_MIN_LINES, dg.DEFAULT_THRESHOLD, [])
    kinds = sorted(g.kind for g in groups)
    assert kinds == ["exact", "near"]
    exact = next(g for g in groups if g.kind == "exact")
    assert exact.risk == "Bajo"
    assert exact.savable_lines == _rec(ORIGINAL).span


def test_scan_respeta_min_lines() -> None:
    recs = [_rec(TINY, "a/x.py"), _rec(TINY, "a/y.py")]
    assert dg.scan(recs, dg.DEFAULT_MIN_LINES, dg.DEFAULT_THRESHOLD, []) == []
    assert dg.scan(recs, 1, dg.DEFAULT_THRESHOLD, [])[0].kind == "exact"


def test_scan_respeta_allowlist() -> None:
    recs = [_rec(ORIGINAL, "a/x.py"), _rec(RENAMED, "a/y.py")]
    allow = [frozenset({"a/x.py::normalize_headers", "a/y.py::tidy_hdrs"})]
    assert dg.scan(recs, dg.DEFAULT_MIN_LINES, dg.DEFAULT_THRESHOLD, allow) == []


def test_riesgo_alto_para_contratos_de_plugin() -> None:
    group = dg.DupGroup(
        "exact",
        1.0,
        [
            _rec("class T:\n" + _indent(ORIGINAL.replace("normalize_headers", "run")), p)
            for p in ("m/vulnerability_testers/a.py", "m/vulnerability_testers/b.py")
        ],
    )
    assert group.risk == "Alto"


def test_mismo_nombre_solo_para_funciones_de_modulo() -> None:
    renamed_unrelated = UNRELATED.replace("count_vowels", "normalize_headers")
    recs = [_rec(ORIGINAL, "a/x.py"), _rec(renamed_unrelated, "b/y.py")]
    groups = dg.scan(recs, dg.DEFAULT_MIN_LINES, dg.DEFAULT_THRESHOLD, [])
    assert [g.kind for g in groups] == ["name"]
    assert groups[0].risk == "Alto"


def _indent(src: str) -> str:
    return "".join("    " + line if line.strip() else line for line in src.splitlines(True))


def test_render_table_resume_conteos() -> None:
    recs = [_rec(ORIGINAL, "a/x.py"), _rec(RENAMED, "a/y.py")]
    out = dg.render_table(dg.scan(recs, 8, 0.85, []), 10)
    assert "| 1 | exact |" in out
    assert "exact=1 near=0 name=0" in out


# --- allowlist file ----------------------------------------------------------


def test_load_allowlist_ignora_entradas_invalidas(repo: Path) -> None:
    (repo / "tools").mkdir()
    (repo / "tools" / "dup_allowlist.json").write_text(
        json.dumps({"groups": [{"members": ["a::f", "b::g"], "reason": "x"}, {"members": 3}]}),
        encoding="utf-8",
    )
    assert dg.load_allowlist(repo, dg.DEFAULT_ALLOWLIST) == [frozenset({"a::f", "b::g"})]
    assert dg.load_allowlist(repo, "no/existe.json") == []
    assert dg.load_allowlist(repo, "../../fuera.json") == []


# --- lookup ------------------------------------------------------------------


def test_words_parte_snake_camel_y_plurales() -> None:
    assert dg.words("maskSecrets parse_URL headers") == ["mask", "secret", "parse", "url", "header"]


def test_lookup_encuentra_la_funcion_por_palabras(repo: Path) -> None:
    hits = dg.lookup(repo, "normalize header")
    assert hits[0].qualname == "normalize_headers"
    assert "pkg/core.py:1 normalize_headers(" in dg.render_lookup(hits)


def test_lookup_sin_coincidencias(repo: Path) -> None:
    assert dg.lookup(repo, "zzz quux") == []
    assert "sin coincidencias" in dg.render_lookup([])


def test_lookup_salida_compacta(repo: Path) -> None:
    out = dg.render_lookup(dg.lookup(repo, "normalize headers count vowels text"))
    assert len(out.split()) < 120  # ~150 tokens budget


# --- check-diff --------------------------------------------------------------


def test_check_diff_limpio_sin_cambios(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert dg.main(["--check-diff"]) == dg.EXIT_OK
    assert "dup-check: OK" in capsys.readouterr().out


def test_check_diff_detecta_clon_nuevo_en_archivo_sin_trackear(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "pkg" / "new.py").write_text(RENAMED, encoding="utf-8")
    assert dg.main(["--check-diff"]) == dg.EXIT_DUPLICATE
    out = capsys.readouterr().out
    assert "pkg/new.py::tidy_hdrs" in out and "pkg/core.py::normalize_headers" in out


def test_check_diff_detecta_clon_en_archivo_modificado(repo: Path) -> None:
    core = repo / "pkg" / "small.py"
    core.write_text(TINY + "\n\n" + NEAR, encoding="utf-8")
    findings = dg.check_diff(repo, "HEAD", False, 8, 0.85, [], False)
    assert [(f.new.qualname, f.kind) for f in findings] == [("headers_with_type", "near")]


def test_check_diff_staged(repo: Path) -> None:
    (repo / "pkg" / "new.py").write_text(RENAMED, encoding="utf-8")
    assert dg.check_diff(repo, "HEAD", True, 8, 0.85, [], False) == []
    _git(repo, "add", "pkg/new.py")
    assert len(dg.check_diff(repo, "HEAD", True, 8, 0.85, [], False)) == 1


def test_check_diff_ignora_duplicado_preexistente(repo: Path) -> None:
    (repo / "pkg" / "dup.py").write_text(RENAMED, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "debt")
    # Touch the pre-existing clone without changing its structure.
    (repo / "pkg" / "dup.py").write_text(RENAMED + "\n# touched\n", encoding="utf-8")
    assert dg.check_diff(repo, "HEAD", False, 8, 0.85, [], False) == []


def test_check_diff_respeta_allowlist_y_comentario(repo: Path) -> None:
    (repo / "pkg" / "new.py").write_text("# dup-guard: ignore\n" + RENAMED, encoding="utf-8")
    assert dg.check_diff(repo, "HEAD", False, 8, 0.85, [], False) == []
    (repo / "pkg" / "new.py").write_text(RENAMED, encoding="utf-8")
    allow = [frozenset({"pkg/new.py::tidy_hdrs", "pkg/core.py::normalize_headers"})]
    assert dg.check_diff(repo, "HEAD", False, 8, 0.85, allow, False) == []


def test_check_diff_excluye_tests_por_defecto(repo: Path) -> None:
    (repo / "tests").mkdir()
    (repo / "tests" / "test_x.py").write_text(RENAMED, encoding="utf-8")
    assert dg.check_diff(repo, "HEAD", False, 8, 0.85, [], False) == []
    assert len(dg.check_diff(repo, "HEAD", False, 8, 0.85, [], True)) == 1


def test_check_diff_json(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "pkg" / "new.py").write_text(RENAMED, encoding="utf-8")
    assert dg.main(["--check-diff", "--json"]) == dg.EXIT_DUPLICATE
    data = json.loads(capsys.readouterr().out)
    assert data[0]["existing"] == "pkg/core.py::normalize_headers"
    assert data[0]["kind"] == "exact"


def test_base_invalida_devuelve_error(repo: Path) -> None:
    assert dg.main(["--check-diff", "--base", "$(rm -rf /)"]) == dg.EXIT_ERROR


# --- CLI ---------------------------------------------------------------------


def test_scan_json_cli(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "pkg" / "new.py").write_text(RENAMED, encoding="utf-8")
    assert dg.main(["--scan", "--json"]) == dg.EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data[0]["kind"] == "exact"
    assert {m["symbol"] for m in data[0]["members"]} == {
        "pkg/core.py::normalize_headers",
        "pkg/new.py::tidy_hdrs",
    }


def test_lookup_cli(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert dg.main(["--lookup", "count vowels"]) == dg.EXIT_OK
    assert "count_vowels" in capsys.readouterr().out


def test_el_repo_real_no_tiene_clones_exactos_sin_justificar() -> None:
    root = Path(__file__).resolve().parents[1]
    recs = dg.collect_records(root, include_tests=False)
    allow = dg.load_allowlist(root, dg.DEFAULT_ALLOWLIST)
    exact = [g for g in dg.scan(recs, 8, 0.85, allow) if g.kind == "exact"]
    assert exact == [], [m.key for g in exact for m in g.members]


# --- hook --------------------------------------------------------------------


def _hook(command: str) -> int:
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    return dg.run_hook(payload, dg.build_parser().parse_args(["--hook"]))


def test_hook_ignora_comandos_que_no_son_commit(repo: Path) -> None:
    (repo / "pkg" / "new.py").write_text(RENAMED, encoding="utf-8")
    _git(repo, "add", "pkg/new.py")
    assert _hook("git status && pytest -q") == dg.EXIT_OK
    assert _hook("echo 'git commitment'") == dg.EXIT_OK
    assert dg.run_hook("no es json", dg.build_parser().parse_args(["--hook"])) == dg.EXIT_OK


def test_hook_bloquea_commit_con_duplicado_staged(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "pkg" / "new.py").write_text(RENAMED, encoding="utf-8")
    assert _hook("git commit -m x") == dg.EXIT_OK  # not staged yet
    _git(repo, "add", "pkg/new.py")
    assert _hook("git add -A && git commit -m x") == dg.EXIT_DUPLICATE
    assert "commit bloqueado" in capsys.readouterr().err
    assert _hook("git -C . commit -qm x") == dg.EXIT_DUPLICATE


def test_allowlist_real_apunta_a_simbolos_existentes_con_motivo() -> None:
    root = Path(__file__).resolve().parents[1]
    raw = json.loads((root / dg.DEFAULT_ALLOWLIST).read_text(encoding="utf-8"))
    existing = {r.key for r in dg.collect_records(root, include_tests=False)}
    for group in raw["groups"]:
        assert len(group["reason"].strip()) >= 20, group
        assert len(group["members"]) >= 2, group
        missing = set(group["members"]) - existing
        assert not missing, missing
