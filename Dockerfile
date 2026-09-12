# Dockerfile — reproducible Artifact Evaluation (AE) image for
# Web_security_scanner.
#
# Produces a self-contained environment that:
#   1. installs build tooling (build-essential, git) and the ``uv`` package
#      manager;
#   2. creates a dedicated virtual environment;
#   3. installs the project in editable mode together with its dev/test
#      dependencies, both declared in pyproject.toml
#      ([project.optional-dependencies].dev: pytest, pytest-asyncio, mypy,
#      ruff, jsonschema, pydantic);
#   4. by default runs the full pytest suite followed by the paper's
#      statistical-analysis script (tools/analyze_results.py) against the
#      testbed artifacts checked into the repository
#      (testbed/experiment_results.csv, testbed/ground_truth.json — the raw
#      per-run telemetry under testbed/results/ is gitignored and not part
#      of the image) — reproducing the reported headline numbers with no
#      network access and no live scan target required.
#
# Build:  docker build -t web-security-scanner-ae .
# Run:    docker run --rm web-security-scanner-ae
FROM python:3.11-slim

LABEL org.opencontainers.image.title="web-security-scanner-ae" \
      org.opencontainers.image.description="Artifact Evaluation image: editable install + pytest suite + tools/analyze_results.py"

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
COPY . .

RUN uv venv "${VIRTUAL_ENV}" \
    && uv pip install -e ".[dev]"

# Default entrypoint: reproduce the artifact's headline results — the full
# test suite, then the paper's statistical analysis. --no-figures skips
# matplotlib rendering, which is not needed to verify the reported numbers.
CMD ["sh", "-c", "pytest -q && python tools/analyze_results.py --no-figures"]
