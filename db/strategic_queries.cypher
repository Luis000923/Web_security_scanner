// ============================================================
// EL CEREBRO — Knowledge Graph Neo4j
// FASE 1.2: Query Estratégica — Correlación CVE crítico -> cadena hasta activo de alto valor
// ============================================================

// Disparado por evento: CTI Agent insertó nueva Vulnerability crítica.
// Parámetro esperado: $cve_id
//
// Busca: ¿esa CVE afecta una tecnología presente en mi grafo? ¿desde qué host de entrada?
// ¿existe ruta de movimiento lateral hasta un host crown_jewel?
//
// Lectura táctica del resultado: si objetivo_alto_valor no es nulo, el Estratega tiene
// justificación cuantitativa (EPSS + distancia de grafo) para escalar esa CVE de "hallazgo"
// a "cadena de ataque priorizada" — disparador para abrir un ticket en la cola HITL (Fase 2)
// antes de tocar el entryPoint.

MATCH (newVuln:Vulnerability {cve: $cve_id})
WHERE newVuln.criticidad = "Alta"

// 1. ¿Esa vulnerabilidad afecta alguna tecnología YA presente en mi superficie de ataque?
MATCH (tech:Technology)-[:AFFECTED_BY]->(newVuln)
MATCH (entryHost:Host)-[:RUNS]->(tech)
MATCH (entryHost)-[:HAS_ENDPOINT]->(entryPoint:Endpoint)

// 2. Técnica MITRE asociada (para que el Fuzzer sepa qué clase de payload generar)
OPTIONAL MATCH (newVuln)-[:MAPS_TO]->(entryTTP:TTP)

// 3. Ruta de movimiento lateral desde el host de entrada hasta un activo crítico,
//    combinando adyacencia de red y reutilización de credenciales (hasta 4 saltos)
OPTIONAL MATCH path = (entryHost)-[:NETWORK_ADJACENT_TO|CREDENTIAL_REUSE*1..4]->(target:Host)
WHERE target.value_tier = "crown_jewel"

RETURN
    entryHost.ip         AS host_entrada,
    entryPoint.url        AS punto_entrada,
    tech.name             AS tecnologia_vulnerable,
    newVuln.cve           AS cve,
    newVuln.epss_score    AS probabilidad_explotacion,
    entryTTP.technique_id AS mitre_ttp,
    target.ip             AS objetivo_alto_valor,
    length(path)          AS saltos_movimiento_lateral,
    [n IN nodes(path) | n.ip] AS ruta_completa
ORDER BY probabilidad_explotacion DESC, saltos_movimiento_lateral ASC
LIMIT 5;
