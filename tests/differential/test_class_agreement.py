# Tests for the class-agreement metric.
#
# Qué mide esto, y por qué existe una métrica aparte
# ------------------------------------------------------------------
# `precision` y `recall` no preguntan *qué* vulnerabilidad encontró el
# escáner: preguntan si encontró algo. En OWASP Benchmark cada caso de prueba
# declara por separado (a) si es vulnerable y (b) de qué clase es vulnerable.
# Ignorar (b) permite que un hallazgo de inyección LDAP sobre un endpoint de
# path traversal cuente como acierto completo. Medido sobre las 338
# instancias del subconjunto: 182 instancias vulnerables detectadas, pero
# solo 143 con la clase esperada reportada. Publicar 0.9381 de recall sin
# decir eso es publicar la mitadavorable del número.
#
# Estos tests fijan cuatro propiedades:
#   1. La clase se normaliza en ambos lados (`vulnerabilities.sql_injection`
#      y `SQLInjection` son la misma clase; una diferencia de escritura no es
#      un desacuerdo sobre la vulnerabilidad).
#   2. Una clase desconocida nunca cuenta como acierto, en ninguna dirección.
#   3. Una fuente SIN etiquetas de clase devuelve `None`, nunca 1.0 y nunca
#      0.0 -- "no responde" no es "responde bien".
#   4. `precision`/`recall` siguen disponibles sin calificar: la métrica
#      estricta se añade, no sustituye.

import json

import pytest

from web_security_scanner.core.benchmark_ground_truth import (
    load_json_ground_truth,
    load_owasp_benchmark,
)
from web_security_scanner.core.ieee_metrics import (
    Finding,
    GroundTruth,
    compute_metrics,
    render_console_summary,
    render_latex,
    render_markdown,
)
from web_security_scanner.core.vuln_classes import (
    CANONICAL_CLASSES,
    canonical_class,
    class_matches,
)

# ---- vocabulario ------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        # Vocabulario del escáner (como viaja en el informe).
        ("vulnerabilities.sql_injection", "sqli"),
        ("vulnerabilities.nosql_injection", "nosqli"),
        ("vulnerabilities.ldap_injection", "ldapi"),
        ("vulnerabilities.xss", "xss"),
        ("vulnerabilities.command_injection", "cmdi"),
        ("vulnerabilities.path_traversal", "pathtraver"),
        # Vocabulario del CSV de OWASP Benchmark.
        ("sqli", "sqli"),
        ("pathtraver", "pathtraver"),
        ("ldapi", "ldapi"),
        ("cmdi", "cmdi"),
        # Vocabulario de tablas JSON escritas a mano.
        ("SQLInjection", "sqli"),
        ("XSS", "xss"),
        ("PathTraversal", "pathtraver"),
        ("CommandInjection", "cmdi"),
        ("LDAPInjection", "ldapi"),
        ("command-injection", "cmdi"),
        ("Command Injection", "cmdi"),
        ("LDAPi", "ldapi"),
        # Vacíos y desconocidos.
        ("", None),
        ("   ", None),
        ("vulnerabilities.missing_header", None),
        ("totally-made-up", None),
    ],
)
def test_canonical_class_normalises_both_vocabularies(raw, expected):
    """Una diferencia de escritura no puede ser un desacuerdo de clase."""
    assert canonical_class(raw) == expected


def test_canonical_class_unknown_is_never_a_wildcard():
    """Lo desconocido no puede coincidir con nada.

    Si `None` se tratara como comodín, la métrica SUBIRÍA cuando el informe
    se vuelve más vago. Es la dirección equivocada para una medida de acuerdo.
    """
    assert canonical_class("missing_header") is None
    assert not class_matches("missing_header", "sqli")
    # Tampoco al revés: una etiqueta esperada inútil no convierte un
    # hallazgo en un acierto.
    assert not class_matches("vulnerabilities.sql_injection", "nonsense-class")


def test_class_matches_requires_both_sides():
    assert class_matches("vulnerabilities.xss", "XSS")
    assert not class_matches("vulnerabilities.xss", "sqli")


def test_bare_blind_is_not_mapped():
    """`blind` es igual un XSS ciego que un SQLi ciego.

    Mapearlo a una de las dos clases haría que este módulo eligiera por el
   Ground truth qué clase encontró el escáner, que es exactamente lo que la
    métrica tiene que *medir*.
    """
    assert canonical_class("blind") is None


def test_canonical_classes_are_published():
    """El conjunto canónico se publica para que un informe declare qué clases
    eran puntuables sin duplicar la tabla."""
    assert {"sqli", "nosqli", "xss", "pathtraver", "cmdi", "ldapi"} <= CANONICAL_CLASSES
    # Todo nombre canónico se normaliza a sí mismo: la idempotencia es lo que
    # permite componer `canonical_class(canonical_class(x))` sin sorpresas.
    for name in CANONICAL_CLASSES:
        assert canonical_class(name) == name


# ---- aritmética -------------------------------------------------------------


def _labelled_gt() -> GroundTruth:
    """4 vulnerables (3 con etiqueta de clase) + 2 benignos.

    ``/d`` is a vulnerable instance the labels do not name a class for, so it
    exercises the "unlabelled" branch: it counts for recall and is excluded
    from the class-agreement population.
    """
    return GroundTruth(
        instances=(
            (("/a", ""), True, "sqli"),
            (("/b", ""), True, "xss"),
            (("/c", ""), True, "sqli"),
            (("/d", ""), True, "crypto"),
            (("/e", ""), False, "safe"),
            (("/f", ""), False, "safe"),
        ),
        name="t",
        expected_class={
            ("/a", ""): "sqli",
            ("/b", ""): "xss",
            ("/c", ""): "sqli",
        },
    )


def test_class_matched_recall_credits_only_the_right_class():
    """/a_sqli correcto, /b_xss detectado pero reportado como SQLi, /c y /d sin aviso.

    recall (cualquier clase) = 2/4. recall_class_matched = 1/3, sobre las 3
    instancias que sí llevan etiqueta de clase. La diferencia es exactamente
    "detectó el endpoint pero nombró otra vulnerabilidad".
    """
    gt = _labelled_gt()
    findings = [
        Finding(url="/a", vulnerability_type="vulnerabilities.sql_injection"),
        Finding(url="/b", vulnerability_type="vulnerabilities.sql_injection"),
    ]
    r = compute_metrics(findings, gt)

    assert r.recall == pytest.approx(2 / 4)
    assert r.recall_class_matched == pytest.approx(1 / 3)
    assert r.class_labelled_instances == 3
    assert r.tp_class_matched_instances == 1


def test_class_matched_is_never_above_its_unqualified_twin():
    """Invariante que un lector necesita poder dar por cierta sin recalcular."""
    gt = _labelled_gt()
    findings = [
        Finding(url="/a", vulnerability_type="vulnerabilities.sql_injection"),
        Finding(url="/b", vulnerability_type="vulnerabilities.command_injection"),
        Finding(url="/c", vulnerability_type="vulnerabilities.xss"),
        Finding(url="/e", vulnerability_type="vulnerabilities.xss"),  # benigno
    ]
    r = compute_metrics(findings, gt)

    assert r.precision_class_matched <= r.precision
    assert r.recall_class_matched <= r.recall
    assert r.f1_class_matched <= r.f1


def test_unknown_reported_class_is_a_mismatch_not_a_match():
    """Un tipo fuera del vocabulario resta; no suma y tampoco es neutro.

    Es el caso que un `missing_header` o un nombre de clase mal escrito
    producirían. Contarlo como acierto haría que la métrica dependiera de cómo
    se llama el hallazgo.
    """
    gt = _labelled_gt()
    findings = [Finding(url="/a", vulnerability_type="vulnerabilities.missing_header")]
    r = compute_metrics(findings, gt)

    assert r.recall == pytest.approx(1 / 4)          # detectado, da igual la clase
    assert r.recall_class_matched == pytest.approx(0.0)
    assert r.claims_unknown_class == 1


def test_unclassifiable_expected_label_leaves_the_population():
    """Una etiqueta esperada ilegible saca la instancia de la población.

    Contarla como fallo de clase convertiría una errata del ground truth en
    un hallazgo en contra del escáner, y la tasa caería sin que nadie pudiera
    decir por qué.
    """
    gt = GroundTruth(
        instances=((("/a", ""), True, "sqli"),),
        name="t",
        expected_class={("/a", ""): "no-such-class"},
    )
    r = compute_metrics(
        [Finding(url="/a", vulnerability_type="vulnerabilities.sql_injection")], gt
    )

    assert r.recall == pytest.approx(1.0)
    assert r.class_labelled_instances == 0
    assert r.claims_unlabelled_class == 1
    # Sin población puntuable la pregunta no tiene respuesta: None, no 1.0.
    assert r.precision_class_matched is None
    assert r.recall_class_matched is None
    assert r.f1_class_matched is None


def test_unlabelled_source_returns_none_not_one():
    """La propiedad que más se viola por descuido.

    Una fuente sin clases que devuelve 1.0 aparenta haber confirmado algo que
    nunca se preguntó. Y 0.0 aparenta un escáner que acierta siempre en clase.
    Ambas son mentira; `None` es la ausencia de dato.
    """
    gt = GroundTruth(
        instances=((("/a", ""), True, "sqli"), (("/e", ""), False, "safe")),
        name="t",
    )
    r = compute_metrics(
        [Finding(url="/a", vulnerability_type="vulnerabilities.xss")], gt
    )

    assert r.has_class_labels is False
    assert r.precision_class_matched is None
    assert r.recall_class_matched is None
    assert r.f1_class_matched is None
    # ...y las tasas no calificadas siguen ahí, porque la detección sí se midió.
    assert r.precision == pytest.approx(1.0)
    assert r.recall == pytest.approx(1.0)


def test_f1_class_matched_is_the_harmonic_mean():
    gt = _labelled_gt()
    r = compute_metrics(
        [
            Finding(url="/a", vulnerability_type="vulnerabilities.sql_injection"),
            Finding(url="/b", vulnerability_type="vulnerabilities.xss"),
            Finding(url="/c", vulnerability_type="vulnerabilities.ldap_injection"),
        ],
        gt,
    )
    p, rc = r.precision_class_matched, r.recall_class_matched
    assert p is not None and rc is not None
    assert r.f1_class_matched == pytest.approx(2 * p * rc / (p + rc))


def test_repeated_claims_on_one_instance_count_once_for_recall():
    """Varias afirmaciones en el mismo endpoint no compran recall de clase.

    Es el mismo argumento que sostiene el desdoblamiento afirmación/instancia:
    una vulnerabilidad no se recuerda tres veces porque tres testers la
    detecten. Aquí se comprueba del lado de las clases.
    """
    gt = GroundTruth(
        instances=((("/a", "id"), True, "sqli"),),
        name="t",
        expected_class={("/a", "id"): "sqli"},
    )
    findings = [
        Finding(url=f"/a?id={i}", parameter="id",
                vulnerability_type="vulnerabilities.sql_injection")
        for i in range(4)
    ]

    def _resolve(f):
        return [("/a", "id"), f.key]

    r = compute_metrics(findings, gt, key_resolver=_resolve)
    assert r.tp == 4                        # 4 afirmaciones
    assert r.tp_instances == 1              # 1 instancia
    assert r.tp_class_matched == 4
    assert r.tp_class_matched_instances == 1
    assert r.recall_class_matched == pytest.approx(1.0)


# ---- exportación ------------------------------------------------------------


def test_rates_and_to_dict_expose_the_class_figures():
    gt = _labelled_gt()
    r = compute_metrics(
        [Finding(url="/a", vulnerability_type="vulnerabilities.sql_injection")], gt
    )
    rates = r.rates()
    for key in ("precision_class_matched", "recall_class_matched", "f1_class_matched"):
        assert key in rates

    counts = r.to_dict()["counts"]
    assert counts["has_class_labels"] is True
    assert counts["class_labelled_instances"] == 3
    assert counts["tp_class_matched"] == 1
    assert counts["tp_class_matched_instances"] == 1
    assert counts["claims_unknown_class"] == 0
    assert counts["claims_unlabelled_class"] == 0
    # json-serializable de punta a punta, como exige el contrato de write_results
    json.dumps(r.to_dict())


def test_renderers_mention_class_agreement_both_ways():
    gt = _labelled_gt()
    labelled = compute_metrics(
        [Finding(url="/a", vulnerability_type="vulnerabilities.sql_injection")], gt
    )
    plain_gt = GroundTruth(instances=gt.instances, name="t")
    plain = compute_metrics(
        [Finding(url="/a", vulnerability_type="vulnerabilities.sql_injection")], plain_gt
    )

    for render in (render_markdown, render_latex, render_console_summary):
        with_labels = render(labelled)
        without = render(plain)
        assert "class" in with_labels.lower()
        # Sin etiquetas, los tres tienen que decirlo en vez de omitirlo: una
        # tabla que se calla deja que el lector suponga que no importaba.
        assert "n/a" in without.lower() or "no class" in without.lower()
        assert "class" in without.lower()


def test_console_summary_pairs_class_rates_with_their_twins():
    """La cifra estricta se imprime junto a la que corrige, no en otro bloque."""
    gt = _labelled_gt()
    out = render_console_summary(
        compute_metrics(
            [Finding(url="/a", vulnerability_type="vulnerabilities.sql_injection")], gt
        )
    )
    assert "class agreement" in out.lower()
    assert "0.3333" in out   # 1 de 3 instancias con la clase esperada
    assert "0.5000" in out   # 2 de 3 detectadas, cualquier clase


# ---- cargadores -------------------------------------------------------------


def test_json_loader_reads_expected_class(tmp_path):
    table = tmp_path / "gt.json"
    table.write_text(json.dumps({
        "name": "toy",
        "instances": [
            {"url": "/a?x=1", "param": "x", "vulnerable": True,
             "expected_class": "SQLInjection"},
            {"url": "/b", "param": "", "vulnerable": False, "category": "info"},
        ],
    }), encoding="utf-8")
    gt = load_json_ground_truth(table)

    # La clave conserva la query: es la identidad de la instancia tal como la
    # nombra la tabla. La reconciliación con el informe (que trae la query con
    # el payload dentro) la hace `json_key_resolver`, no el cargador.
    assert gt.expected_class == {("/a?x=1", "x"): "SQLInjection"}
    # Un `category` libre ("info") no es una clase, así que no etiqueta.
    assert ("/b", "") not in gt.expected_class


def test_json_loader_falls_back_to_category_and_then_type(tmp_path):
    """Un `category` que es una clase real sirve; `safe` no sirve de nada."""
    table = tmp_path / "gt.json"
    table.write_text(json.dumps([
        {"url": "/a", "vulnerable": True, "category": "xss"},
        {"url": "/b", "vulnerable": True, "category": "safe"},
        {"url": "/c", "vulnerable": True, "type": "CommandInjection"},
        {"url": "/d", "vulnerable": True, "category": "info"},
        {"url": "/e", "vulnerable": False, "type": "SQLInjection"},
    ]), encoding="utf-8")
    gt = load_json_ground_truth(table)

    # /b, /d y /e no aportan etiqueta utilizable; /e además es benigno.
    assert set(gt.expected_class) == {("/a", ""), ("/c", "")}
    # Sin `category` explícita, la clase canónica alimenta la tabla por categoría.
    by_key = {key: cat for key, _vuln, cat in gt.instances}
    assert by_key[("/a", "")] == "xss"
    assert by_key[("/c", "")] == "cmdi"


def test_benchmark_loader_reads_the_category_column(tmp_path):
    csv_path = tmp_path / "expectedresults.csv"
    csv_path.write_text(
        "# test name,category,real vulnerability,cwe\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,sqli,false,89\n"
        "BenchmarkTest00003,pathtraver,true,22\n",
        encoding="utf-8",
    )
    gt, index = load_owasp_benchmark(csv_path)

    assert len(gt.instances) == 3
    # Solo las instancias vulnerables llevan etiqueta: un caso seguro no tiene
    # clase que esperar y solo podría ser un fallo.
    assert gt.expected_class == {
        ("/BenchmarkTest00001", ""): "sqli",
        ("/BenchmarkTest00003", ""): "pathtraver",
    }
    assert index["BenchmarkTest00001"] == "/BenchmarkTest00001"


def test_benchmark_loader_without_category_column_still_scores(tmp_path):
    """Una tabla v1.0 sin `category` se carga igual, sin acuerdo de clase.

    Devolver None en vez de inventar clases es lo que permite que la
    afirmación "el ground truth no lleva clases" sea una observación y no una
    suposición.
    """
    csv_path = tmp_path / "expectedresults.csv"
    csv_path.write_text(
        "# test name,real vulnerability\n"
        "BenchmarkTest00001,true\n"
        "BenchmarkTest00002,false\n",
        encoding="utf-8",
    )
    gt, _index = load_owasp_benchmark(csv_path)

    assert gt.expected_class == {}
    r = compute_metrics(
        [Finding(url="/BenchmarkTest00001", vulnerability_type="vulnerabilities.xss")],
        gt,
    )
    assert r.recall == pytest.approx(1.0)
    assert r.recall_class_matched is None
