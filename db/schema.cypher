// ============================================================
// EL CEREBRO — Knowledge Graph Neo4j
// FASE 1.1: Esquema de inicialización (constraints, índices, seed de ejemplo)
// ============================================================

// ============================================================
// CONSTRAINTS DE UNICIDAD (crean índice de backing automáticamente)
// ============================================================

CREATE CONSTRAINT host_ip_unique IF NOT EXISTS
FOR (h:Host) REQUIRE h.ip IS UNIQUE;

CREATE CONSTRAINT endpoint_url_unique IF NOT EXISTS
FOR (e:Endpoint) REQUIRE e.url IS UNIQUE;

// Technology se identifica por nombre+versión (CPE-like), no por nombre solo,
// porque "Apache 2.4.49" y "Apache 2.4.57" son nodos de riesgo distintos.
CREATE CONSTRAINT technology_cpe_unique IF NOT EXISTS
FOR (t:Technology) REQUIRE t.cpe IS UNIQUE;

CREATE CONSTRAINT vuln_cve_unique IF NOT EXISTS
FOR (v:Vulnerability) REQUIRE v.cve IS UNIQUE;

CREATE CONSTRAINT ttp_id_unique IF NOT EXISTS
FOR (t:TTP) REQUIRE t.technique_id IS UNIQUE;

CREATE CONSTRAINT credential_hash_unique IF NOT EXISTS
FOR (c:Credential) REQUIRE c.value_hash IS UNIQUE;

// ============================================================
// ÍNDICES ADICIONALES (para propiedades de filtro frecuente, no unicidad)
// ============================================================

CREATE INDEX vuln_criticidad_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.criticidad);
CREATE INDEX vuln_epss_idx       IF NOT EXISTS FOR (v:Vulnerability) ON (v.epss_score);
CREATE INDEX host_value_tier_idx IF NOT EXISTS FOR (h:Host) ON (h.value_tier);
CREATE INDEX ttp_tactic_idx      IF NOT EXISTS FOR (t:TTP) ON (t.tactic);

// ============================================================
// PROPIEDADES CLAVE POR NODO (documentación de esquema, ejemplo de creación)
// ============================================================

// Host: activo físico/lógico. value_tier marca objetivos de alto valor
// (ej. "crown_jewel", "standard", "unknown") — usado por el Estratega para priorizar rutas.
MERGE (h:Host {ip: "10.0.4.12"})
SET h.hostname   = "db-prod-01.internal",
    h.os         = "Linux",
    h.value_tier = "crown_jewel",
    h.first_seen = datetime(),
    h.last_seen  = datetime();

// Endpoint: superficie HTTP concreta
MERGE (e:Endpoint {url: "https://app.target.com/api/v1/invoices/{id}"})
SET e.method        = "GET",
    e.auth_required = true,
    e.discovered_at = datetime();

// Technology: stack identificado (fingerprint de Recon/API-RE Agent)
MERGE (t:Technology {cpe: "cpe:2.3:a:apache:http_server:2.4.49"})
SET t.name = "Apache HTTP Server", t.version = "2.4.49";

// Vulnerability: hallazgo propio o ingerido por el CTI Agent
MERGE (v:Vulnerability {cve: "CVE-2021-41773"})
SET v.criticidad  = "Alta",
    v.cvss_score  = 9.8,
    v.epss_score  = 0.94,
    v.published_at = date("2021-10-05"),
    v.source      = "CTI_AGENT_TAXII_FEED";

// TTP: técnica MITRE ATT&CK asociada
MERGE (ttp:TTP {technique_id: "T1190"})
SET ttp.name = "Exploit Public-Facing Application", ttp.tactic = "Initial Access";

// Credential: material capturado/reutilizable (para pivote lateral)
MERGE (c:Credential {value_hash: "sha256:9f2a..."})
SET c.type = "ssh_key", c.captured_from = "10.0.4.12";

// ============================================================
// RELACIONES TIPADAS
// ============================================================

MATCH (h:Host {ip:"10.0.4.12"}), (e:Endpoint {url:"https://app.target.com/api/v1/invoices/{id}"})
MERGE (h)-[:HAS_ENDPOINT]->(e);

MATCH (h:Host {ip:"10.0.4.12"}), (t:Technology {cpe:"cpe:2.3:a:apache:http_server:2.4.49"})
MERGE (h)-[:RUNS]->(t);

MATCH (t:Technology {cpe:"cpe:2.3:a:apache:http_server:2.4.49"}), (v:Vulnerability {cve:"CVE-2021-41773"})
MERGE (t)-[:AFFECTED_BY]->(v);

MATCH (v:Vulnerability {cve:"CVE-2021-41773"}), (ttp:TTP {technique_id:"T1190"})
MERGE (v)-[:MAPS_TO]->(ttp);

// Movimiento lateral: relación descubierta por Recon (confianza de red, credenciales compartidas)
MATCH (a:Host {ip:"10.0.4.12"}), (b:Host {ip:"10.0.4.50"})
MERGE (a)-[:NETWORK_ADJACENT_TO {trust_level:"high", discovered_via:"internal_scan"}]->(b);
