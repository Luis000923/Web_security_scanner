# Metodología de entrenamiento y alineación del agente de IA

Este documento formaliza la metodología de investigación con la que se
construye el **agente de triaje asesor** del escáner (`ai_module/`). El agente
es un modelo de lenguaje abierto (*open-weight*) especializado en la taxonomía
de ciberseguridad del proyecto, no un modelo de propósito general consultado por
*prompt*. Su construcción se organiza como un **ciclo de entrenamiento modular
en tres fases** metodológicas, cada una con un artefacto verificable y un
criterio de aceptación explícito.

> **Neutralidad de plataforma.** Toda la metodología es agnóstica al acelerador
> de cómputo. El entrenamiento se ejecuta sobre **infraestructura de aceleración
> de hardware estándar** con **escalado dinámico de parámetros** que selecciona
> la capacidad del modelo base y la ruta de cuantización en función de la
> **memoria de cómputo disponible** en el entorno, sin dependencia de una
> arquitectura, un fabricante ni un modelo de acelerador concretos. El ciclo se
> reproduce sobre entornos de cómputo heterogéneos sin modificar la metodología.

El objetivo de diseño es **asimétrico**: maximizar la supresión de falsos
positivos heurísticos minimizando, por encima de todo, el falso *negativo* —que
un juicio del modelo descarte una vulnerabilidad real.

---

## Fase 1 — Preparación y saneamiento del conjunto de datos

Transforma la telemetría cruda del escáner (una fila JSONL por sonda) en un
conjunto de instrucciones supervisadas, curado y balanceado, mediante una
tubería de cuatro etapas: **ingesta y enriquecimiento → limpieza → estructuración
→ balanceo con partición estratificada** (`ai_module/dataset_generator.py`).

- **Volumen y cobertura.** **1 786 instancias de triaje** que cubren las cuatro
  clases de vulnerabilidad de mayor incidencia: inyección SQL (SQLi), inyección
  de comandos (*command injection*), *cross-site scripting* (XSS) y *path
  traversal*.
- **Balanceo.** Distribución equilibrada entre los tres veredictos de la
  taxonomía (`TRUE_POSITIVE` / `FALSE_POSITIVE` / `UNCERTAIN`), con submuestreo
  de la clase mayoritaria hasta un equilibrio ≈ 1:1:1.
- **Partición estratificada 90/10** (1 608 entrenamiento / 178 validación) que
  conserva las tres clases en la validación.

### Salvaguardas contra el aprendizaje espurio

1. **Depuración semántica de parámetros (`param_semantics.py`).** Los puntos de
   inyección cuya función es de *control de flujo* —parámetros de redirección o
   destino de URL como `next`, `redirect_uri`, `return_to`— se identifican
   explícitamente. La aplicación valida el valor de esos parámetros antes de
   usarlo, de modo que cualquier divergencia de respuesta que no vaya acompañada
   de **evidencia dura** (firma de error del intérprete, oráculo temporal
   confirmado, ejecución observada) se explica por esa validación y no por una
   inyección. El etiquetado **fuerza esos casos a `FALSE_POSITIVE`**, eliminando
   la clase de falso positivo heurístico —*la etiqueta es errónea mientras la
   evidencia parece plausible*— que más contamina a un clasificador descendente
   (el caso arquetípico es el parámetro `next` de los flujos de *login*).
2. **Anonimización anti-fuga.** La entrada que ve el modelo expone solo un
   *endpoint* y un nombre de parámetro genéricos; la ruta original —que en el
   banco de referencia codifica la clase y el veredicto— se conserva únicamente
   en metadatos privados. La deduplicación opera sobre la **clave observable**
   (entrada anonimizada + latencia discretizada en cubetas), evitando que la
   variación de milisegundos filtre una instancia casi idéntica a través de la
   frontera entrenamiento/validación.
3. **Contraste de evidencia.** Cada veredicto sintetizado se verifica contra el
   mismo evaluador de evidencia que emplea la ruta real; los casos cuya
   evidencia no discrimina su etiqueta pretendida se **descartan** en lugar de
   mal etiquetarse.

**Artefacto:** manifiesto de curación `data/curation.json` (filas descartadas,
recuento de deduplicación, balance de clases, tamaños de partición).

---

## Fase 2 — Alineación y cuantización (QLoRA)

Especializa un modelo base *open-weight* sobre la taxonomía mediante
*fine-tuning* eficiente en parámetros, evitando el coste de un ajuste completo
(`ai_module/train_qlora.py`).

| Componente | Valor |
|------------|-------|
| Cuantización de pesos base | **NF4 de 4 bits** con doble cuantización |
| Rango de la adaptación (`r`) | **32** |
| Escala (`lora_alpha`) | **64** (razón estándar `α = 2r`) |
| *Dropout* de LoRA | 0.05 |
| Módulos objetivo | **7** — atención completa (`q,k,v,o`) + MLP (`gate,up,down`) |
| Selección del modelo base | escalado dinámico según memoria disponible |

- **Estabilidad numérica.** El modelo base se carga cuantizado (NF4, 4 bits) y
  el gradiente actualiza únicamente adaptadores de bajo rango (LoRA) sobre los
  pesos congelados. El cómputo se realiza en precisión de punto flotante
  extendida mientras el almacenamiento se mantiene cuantizado, preservando la
  estabilidad sin la huella de memoria de un ajuste completo.
- **Módulos objetivo completos.** Los adaptadores se insertan sobre las siete
  proyecciones lineales del bloque *transformer* —las cuatro de atención y las
  tres del bloque *feed-forward*—, no solo sobre la atención.
- **Restricción de dominio (alineación).** La alineación inyecta una minoría
  (≈ 10 %) de instancias de ruido conversacional cuya salida objetivo es un
  centinela de rechazo fijo. Tras el ajuste, cualquier entrada que no sea un
  hallazgo de triaje o una petición de síntesis de *payloads* colapsa a ese
  centinela, que la capa de inferencia interpreta como veredicto `RESTRICTED` y
  descarta. El agente conserva su competencia analítica dentro del dominio y
  carece de la superficie de comportamiento de asistente general.

**Artefacto:** adaptador LoRA entrenado (opcionalmente fusionado a un modelo de
precisión completa para servir).

---

## Fase 3 — Validación y evaluación de seguridad

Somete el adaptador a una evaluación de aceptación **independiente del
entrenamiento**, orientada a la mitigación de alucinaciones
(`ai_module/evaluate_golden.py`, `ai_module/structured_inference.py`,
`ai_module/security_metrics.py`).

1. **Conjunto de validación disjunto (*Golden Set*).** Conjunto curado a mano,
   *disjunto* del corpus de entrenamiento, de vulnerabilidades políglotas
   (verdaderos positivos) y escenarios adversarios de falso positivo (páginas de
   bloqueo de WAF, reflexión codificada como entidades, *jitter* de latencia,
   respuestas cacheadas, páginas de error independientes de la entrada). Se
   evalúa con el **mismo cliente asíncrono** que el escáner usa en producción,
   de modo que se mide el comportamiento desplegado y no el ajuste al corpus.
2. **Decodificación estructurada.** La generación se restringe a un esquema
   tipado (fuente única de verdad, compartida por las etiquetas de
   entrenamiento y las restricciones del servidor). Con enmascaramiento de
   *logits* guiado por gramática el modelo **no puede** emitir un token no
   conforme; cuando esa restricción no está disponible, la salida se valida y
   repara contra el esquema y, si resulta irreparable, se adopta el veredicto
   seguro `UNCERTAIN` en lugar de propagar una respuesta malformada.
3. **Métricas estrictas por clase.** La entropía cruzada no informa sobre si el
   modelo pasaría por alto una vulnerabilidad real, por lo que se reportan
   métricas de seguridad explícitas:

   | Métrica | Definición |
   |---------|------------|
   | **FNR** *(gobernante)* | `P(pred = FALSE_POSITIVE | oro = TRUE_POSITIVE)` |
   | Tasa de degradación | `P(pred = UNCERTAIN | oro = TRUE_POSITIVE)` |
   | Cobertura `FALSE_POSITIVE` | `P(pred = FALSE_POSITIVE | oro = FALSE_POSITIVE)` |
   | Exactitud de rechazo | fracción de ruido conversacional correctamente rechazada |
   | Exactitud (3 clases) | concordancia global, de referencia |
   | Tasa de error | inferencias fallidas, aisladas y **nunca** plegadas en las métricas de clasificación |

La **tasa de falsos negativos (FNR)** es la magnitud gobernante por su coste
asimétrico. El adaptador solo se promueve a producción si supera los umbrales
fijados sobre estas métricas: la evaluación funciona como **puerta de aceptación
(*gate*)**, no como un mero informe.

**Artefacto:** informe JSON de la evaluación *Golden Set* con el desglose por
clase y categoría.

---

## Integración con el escáner

El agente es la **capa asesora por defecto** sobre las heurísticas
deterministas y es estrictamente **consultivo**:

- **Triaje** — cada candidato heurístico, con su evidencia estructurada, se
  clasifica en la taxonomía; un `FALSE_POSITIVE` por encima de un umbral de
  confianza descarta el hallazgo, el resto solo se anota.
- **Síntesis de *payloads*** — cuando la lista estática de un parámetro se agota
  sin acierto, el agente propone vectores de confirmación adaptados a las
  defensas observadas (sujetos al filtro de *payloads* destructivos).
- **Degradación transparente** — si el *backend* de inferencia no responde, el
  escaneo continúa sobre el motor determinista con una sola advertencia. El
  agente **nunca** es un punto de fallo.

Véase el paper (`paper/submission/sections/03b_ia_alineacion.tex`) para la
formalización académica de esta metodología.
