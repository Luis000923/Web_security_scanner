# Dockerfile — container image for Web_security_scanner.
#
# Produces a self-contained environment that:
#   1. installs build tooling (build-essential, git) and the ``uv`` package
#      manager;
#   2. creates a dedicated virtual environment;
#   3. installs the project in editable mode together with its dev/test
#      dependencies, both declared in pyproject.toml
#      ([project.optional-dependencies].dev: pytest, pytest-asyncio, mypy,
#      ruff, jsonschema, pydantic);
#   4. by default runs the full pytest suite.
#
# Build:  docker build -t web-security-scanner .
# Run:    docker run --rm web-security-scanner
FROM python:3.11-slim

LABEL org.opencontainers.image.title="web-security-scanner" \
      org.opencontainers.image.description="Web Security Scanner: editable install + pytest suite"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}"

# build-essential: some dependencies (e.g. numpy/scipy) may fall back to
#                  building from sdist on platforms without a prebuilt wheel.
# git:             VCS-based dependency resolution / version introspection.
# ca-certificates: TLS trust store for uv/pip's HTTPS package downloads.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv: fast resolver/installer used for the venv + editable install below.
RUN pip install --no-cache-dir --upgrade pip uv

WORKDIR /app

# The editable install requires the actual package trees on disk
# (setuptools' [tool.setuptools.packages.find] scans web_security_scanner*
# and ai_module* at build time), so the full source tree is copied in before
# installing rather than relying on a pyproject.toml-only caching layer.
# NOSONAR – .dockerignore explicitly excludes credentials, secrets and all sensitive paths
COPY . .

RUN uv venv "${VIRTUAL_ENV}" \
    && uv pip install -e ".[dev]"

# Run as non-root user to reduce container attack surface.
RUN groupadd -r scanner && useradd -r -g scanner scanner \
    && chown -R scanner:scanner /app "${VIRTUAL_ENV}"

USER scanner

CMD ["pytest", "-q"]
