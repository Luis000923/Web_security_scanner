# Makefile — Artifact Evaluation (AE) entry points for Web_security_scanner.
#
# Everything below is safe to run from a fresh clone: `make test` and
# `make evaluate` use the project's own virtual environment on the host,
# while `make docker-build`/`make docker-run` reproduce the exact same audit
# inside the self-contained image built from ./Dockerfile.
#
#   make            # == make all: full test suite + statistical analysis
#   make docker-run # the same audit, but fully containerized

.PHONY: all test evaluate docker-build docker-run clean context context-check bench

# Override on the command line if the project venv lives elsewhere, e.g.
# `make test PYTHON=python3`.
PYTHON      ?= .venv/bin/python
IMAGE_NAME  ?= web-security-scanner-ae

all: test evaluate ## Run the full test suite, then the statistical analysis.

test: ## Run the complete pytest suite.
	$(PYTHON) -m pytest

evaluate: ## Run the paper's statistical analysis (tools/analyze_results.py), figures skipped.
	@test -f tools/analyze_results.py || { \
		echo "error: tools/analyze_results.py not found on this branch ($$(git rev-parse --abbrev-ref HEAD))." >&2; \
		echo "  The statistical-analysis pipeline (tools/, testbed/, paper/) lives on" >&2; \
		echo "  feat/ai-triage-mainline, not on main -- see AGENTS.md section 1.3." >&2; \
		echo "  Run this from that branch/worktree, e.g.:" >&2; \
		echo "    git worktree add ../wss-eval feat/ai-triage-mainline && make -C ../wss-eval evaluate" >&2; \
		exit 1; \
	}
	$(PYTHON) tools/analyze_results.py --no-figures

context: ## Regenerate the L0 repo map (.context/repomap.md + symbols.json).
	python3 tools/context_packer.py --mode l0

context-check: ## Exit 1 if .context/ is stale.
	python3 tools/context_packer.py --mode l0 --check

bench: ## Token benchmark (traditional vs L0/L1 + micro-skill) with quality gates.
	$(PYTHON) tools/token_benchmark.py --gates

docker-build: ## Build the reproducible Artifact Evaluation Docker image.
	docker build -t $(IMAGE_NAME) .

docker-run: ## Run the full audit (tests + analysis) inside an ephemeral container.
	docker run --rm $(IMAGE_NAME)

clean: ## Remove pytest/mypy/ruff caches and build/compilation artifacts.
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist ./*.egg-info
	find . -type d -name "__pycache__" -exec rm -rf {} +
