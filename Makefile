# Makefile — Artifact Evaluation (AE) entry points for Web_security_scanner.
#
# Everything below is safe to run from a fresh clone: `make test` and
# `make evaluate` use the project's own virtual environment on the host,
# while `make docker-build`/`make docker-run` reproduce the exact same audit
# inside the self-contained image built from ./Dockerfile.
#
#   make            # == make all: full test suite + statistical analysis
#   make docker-run # the same audit, but fully containerized

.PHONY: all test evaluate docker-build docker-run clean

# Override on the command line if the project venv lives elsewhere, e.g.
# `make test PYTHON=python3`.
PYTHON      ?= .venv/bin/python
IMAGE_NAME  ?= web-security-scanner-ae

all: test evaluate ## Run the full test suite, then the statistical analysis.

test: ## Run the complete pytest suite.
	$(PYTHON) -m pytest

evaluate: ## Run the paper's statistical analysis (tools/analyze_results.py), figures skipped.
	$(PYTHON) tools/analyze_results.py --no-figures

docker-build: ## Build the reproducible Artifact Evaluation Docker image.
	docker build -t $(IMAGE_NAME) .

docker-run: ## Run the full audit (tests + analysis) inside an ephemeral container.
	docker run --rm $(IMAGE_NAME)

clean: ## Remove pytest/mypy/ruff caches and build/compilation artifacts.
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist ./*.egg-info
	find . -type d -name "__pycache__" -exec rm -rf {} +
