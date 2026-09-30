"""
FASE 9 — Telemetría de Infraestructura Docker.

Se conecta al socket local de Docker (`/var/run/docker.sock`, vía la
librería oficial `docker`) para recolectar, en el momento de generar el
informe de engagement, el estado real de los contenedores del laboratorio
(Neo4j, OWASP Benchmark, etc.): metadatos (nombre/imagen/estado) y
estadísticas instantáneas de rendimiento (CPU %, memoria, red).

Diseño fail-safe: si el daemon de Docker no está disponible (socket
inaccesible, permisos, entorno CI sin Docker) ninguna función lanza —
devuelven listas/estructuras vacías y el ReportingAgent documenta la
telemetría como "no disponible" en vez de romper el pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

try:
    import docker
    from docker.errors import DockerException
except ImportError:  # pragma: no cover - el SDK es una dependencia opcional
    docker = None  # type: ignore[assignment]
    DockerException = Exception  # type: ignore[misc,assignment]

try:
    import matplotlib

    matplotlib.use("Agg")  # backend sin display, requerido en servidores/CI
    import matplotlib.pyplot as plt
except ImportError:  # pragma: no cover - la visualización es opcional
    plt = None  # type: ignore[assignment]


@dataclass
class ContainerInfo:
    container_id: str
    name: str
    image: str
    status: str


@dataclass
class ContainerStats:
    name: str
    cpu_percent: float
    mem_usage_mb: float
    mem_limit_mb: float
    mem_percent: float
    net_rx_mb: float
    net_tx_mb: float


def _get_client() -> docker.DockerClient | None:
    if docker is None:
        return None
    try:
        client = docker.from_env()
        client.ping()
        return client
    except DockerException:
        return None


def list_containers() -> list[ContainerInfo]:
    """Lista los contenedores activos visibles en el socket local."""
    client = _get_client()
    if client is None:
        return []

    infos = []
    for container in client.containers.list():
        image_tags = container.image.tags
        infos.append(
            ContainerInfo(
                container_id=container.short_id,
                name=container.name,
                image=image_tags[0] if image_tags else container.image.short_id,
                status=container.status,
            )
        )
    return infos


def _cpu_percent(stats: dict) -> float:
    cpu_stats = stats.get("cpu_stats", {})
    precpu_stats = stats.get("precpu_stats", {})

    cpu_delta = cpu_stats.get("cpu_usage", {}).get("total_usage", 0) - precpu_stats.get(
        "cpu_usage", {}
    ).get("total_usage", 0)
    system_delta = cpu_stats.get("system_cpu_usage", 0) - precpu_stats.get("system_cpu_usage", 0)
    online_cpus = cpu_stats.get("online_cpus") or len(
        cpu_stats.get("cpu_usage", {}).get("percpu_usage") or [1]
    )

    if system_delta <= 0 or cpu_delta < 0:
        return 0.0
    return (cpu_delta / system_delta) * online_cpus * 100.0


def _network_totals(stats: dict) -> tuple[float, float]:
    networks = stats.get("networks") or {}
    rx = sum(iface.get("rx_bytes", 0) for iface in networks.values())
    tx = sum(iface.get("tx_bytes", 0) for iface in networks.values())
    return rx / (1024 * 1024), tx / (1024 * 1024)


def get_container_stats() -> list[ContainerStats]:
    """
    Obtiene una foto instantánea (`stats(stream=False)`) de CPU/memoria/red
    para cada contenedor activo. Cada llamada bloquea brevemente (~1s por
    contenedor, coste inherente a `stream=False` de la API de Docker).
    """
    client = _get_client()
    if client is None:
        return []

    results = []
    for container in client.containers.list():
        try:
            raw = container.stats(stream=False)
        except DockerException:
            continue

        mem_stats = raw.get("memory_stats", {})
        mem_usage = mem_stats.get("usage", 0)
        mem_limit = mem_stats.get("limit", 0) or 1
        # `usage` incluye cache de páginas; se resta para reflejar consumo real
        # de la aplicación, siguiendo la misma convención que `docker stats`.
        mem_usage -= mem_stats.get("stats", {}).get("cache", 0)

        rx_mb, tx_mb = _network_totals(raw)

        results.append(
            ContainerStats(
                name=container.name,
                cpu_percent=round(_cpu_percent(raw), 2),
                mem_usage_mb=round(mem_usage / (1024 * 1024), 2),
                mem_limit_mb=round(mem_limit / (1024 * 1024), 2),
                mem_percent=round((mem_usage / mem_limit) * 100.0, 2) if mem_limit else 0.0,
                net_rx_mb=round(rx_mb, 2),
                net_tx_mb=round(tx_mb, 2),
            )
        )
    return results


def get_network_topology() -> dict[str, list[str]]:
    """Mapa red Docker -> nombres de contenedores conectados a ella."""
    client = _get_client()
    if client is None:
        return {}

    topology: dict[str, list[str]] = {}
    for network_summary in client.networks.list():
        # `networks.list()` no rellena "Containers" en las versiones recientes
        # de la API de Docker; hay que reobtener cada red por nombre/ID para
        # que el campo venga poblado.
        network = client.networks.get(network_summary.id)
        containers = network.attrs.get("Containers") or {}
        names = [info.get("Name", cid[:12]) for cid, info in containers.items()]
        if names:
            topology[network.name] = names
    return topology


def render_resource_usage_chart(stats: list[ContainerStats], output_path: Path) -> Path | None:
    """
    Genera un gráfico de barras agrupadas (CPU % / Memoria %) por contenedor
    y lo guarda como PNG en `output_path`. Devuelve None si matplotlib no
    está disponible o no hay estadísticas que graficar (no rompe el informe).
    """
    if plt is None or not stats:
        return None

    names = [s.name for s in stats]
    cpu = [s.cpu_percent for s in stats]
    mem = [s.mem_percent for s in stats]

    x = range(len(names))
    width = 0.35

    fig, ax = plt.subplots(figsize=(max(6, len(names) * 1.6), 4.5))
    ax.bar([i - width / 2 for i in x], cpu, width, label="CPU %", color="#e74c3c")
    ax.bar([i + width / 2 for i in x], mem, width, label="Memoria %", color="#3498db")

    ax.set_ylabel("Porcentaje de uso")
    ax.set_title("Consumo de recursos por contenedor (Docker)")
    ax.set_xticks(list(x))
    ax.set_xticklabels(names, rotation=20, ha="right")
    ax.legend()
    fig.tight_layout()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=120)
    plt.close(fig)
    return output_path


def render_network_topology_chart(topology: dict[str, list[str]], output_path: Path) -> Path | None:
    """
    Genera un diagrama simple de topología (redes Docker -> contenedores
    conectados) como PNG en `output_path`. Devuelve None si matplotlib no
    está disponible o no hay topología que graficar.
    """
    if plt is None or not topology:
        return None

    fig, ax = plt.subplots(figsize=(8, max(3, len(topology) * 1.5)))
    y_labels = []
    for row, (network_name, containers) in enumerate(topology.items()):
        y_labels.append(network_name)
        for col, container_name in enumerate(containers):
            ax.scatter(col, row, s=400, color="#2ecc71", zorder=2)
            ax.annotate(
                container_name,
                (col, row),
                textcoords="offset points",
                xytext=(0, 12),
                ha="center",
                fontsize=8,
            )

    ax.set_yticks(range(len(y_labels)))
    ax.set_yticklabels(y_labels)
    ax.set_xticks([])
    ax.set_title("Topología de red de contenedores (Docker)")
    ax.set_xlim(-0.5, max((len(v) for v in topology.values()), default=1) - 0.5 + 0.5)
    ax.set_ylim(-0.7, len(y_labels) - 1 + 0.7)
    fig.tight_layout()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=120)
    plt.close(fig)
    return output_path
