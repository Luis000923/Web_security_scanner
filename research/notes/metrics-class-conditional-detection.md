# Detección condicionada por clase de vulnerabilidad

> **Nota de alcance.** Esto **no** es una hipótesis pre-registrada. Es un
> resultado post-hoc de la tarea de métricas (P/R/F1) que se me asignó fuera de
> los tracks A/B/C. No se puede usar como evidencia confirmatoria en el paper:
> la métrica se construyó *después* de ver estos números. Se documenta porque
> cualquier cifra de recall que se publique sin esto está incompleta.

## Corrida

```
scripts/evaluate.py "https://127.0.0.1:8443/benchmark/" \
  --ground-truth /tmp/opencode/tb/ground_truth.json \
  --target-list /tmp/opencode/tb/targets.json \
  --profile intense --max-payloads 60 --no-map \
  --global-seed 1337 --no-verify-ssl --allow-private-redirects \
  -o /tmp/opencode/final2 --basename main
```

Ground truth: 338 instancias (194 vulnerables / 144 benignas), todas con etiqueta
de clase. Artefactos: `main.json`, `main.md`, `main.tex`, `main.report.json`.
Perfil `intense`, sin truncación por presupuesto de tiempo (186 326 requests,
419 s). Cobertura 1.0000 — ningún punto sin medir.

## Cifras

| Convención | P | R | F1 |
|---|---:|---:|---:|
| cualquier clase (`precision`/`recall`) | 0.9779 | 0.9381 | 0.9576 |
| clase concordante (`*_class_matched`) | 0.4669 | 0.8711 | 0.6079 |

Las dos filas son **la misma corrida**. La diferencia son 185 afirmaciones
sobre instancias vulnerables que nombran una clase que no es la del ground
truth. Ninguna cuenta como FP bajo la convención "cualquier clase", porque el
flag por caso de OWASP Benchmark es un booleano por caso, no por clase.

## Detección por clase esperada (194 instancias vulnerables)

| Clase esperada |detectadas con su clase | ratio |
|---|---:|---:|
| sqli | 65/65 | 1.000 |
| ldapi | 6/6 | 1.000 |
| xss | 60/68 | 0.882 |
| pathtraver | 26/30 | 0.867 |
| cmdi | 12/25 | 0.480 |

12 instancias sin ningún hallazgo, **todas cmdi**. 13 instancias detectadas solo
con la clase equivocada: 8 xss, 4 pathtraver, 1 cmdi.

## De dónde salen los 185 claims de clase equivocada

| Reportado como | claims sobre instancias de otra clase |
|---|---:|
| nosqli | 79 (28 pathtraver, 22 sqli, 16 xss, 13 cmdi) |
| sqli | 75 (28 pathtraver, 28 xss, 13 cmdi, 6 ldapi) |
| ldapi | 31 (16 pathtraver, 8 xss, 7 cmdi) |

Causa raíz: la rama diferencial de los tres testers acepta "la respuesta
difiere > 10 % con un payload de operador". Sobre las plantillas rígidas de
Benchmark la línea base de un endpoint GET es minúscula, así que **cualquier**
cambio de longitud la dispara — y un path traversal que resuelve a un
directorio inexistente, o un parámetro de sesión que deja de ser válido, cambian
la respuesta tanto como un operador NoSQL. El guard de reflexión que ya está
en NoSQL/LDAP (`decode_reflected`) filtra la reflexión escapada; **no** filtra
una diferencia real causada por otro mecanismo. Por eso el guard necesario no
es suficiente: hace falta un **control** (un payload sintácticamente equivalente
que un motor NoSQL no debería distinguir) para probar causalidad.

Eso es exactamente el mecanismo que `core/param_semantics.py` +
`evidence_kind` existen para y que sigue muerto (2 de 25 testers emiten
`evidence_kind`; ver AGENTS.md §1.4 y la skill `track-b-evidence-semantics`).
**No lo he tocado**: `base_tester_async.py` tiene un refactor sin commitear y
AGENTS.md lo marca intocable sin claim explícito.

## Reproducir

```
python scripts/evaluate.py --from-report /tmp/opencode/final2/main.report.json \
  --ground-truth /tmp/opencode/tb/ground_truth.json \
  -o /tmp/opencode/final2 --basename main
```

`--from-report` es el camino de reproducibilidad: no re-escanea, no necesita
target, y da el mismo número que la corrida en vivo.
