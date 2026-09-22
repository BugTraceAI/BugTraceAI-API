# BugTraceAI-API Makefile — dev / audit / test / build commands.
#
# Run `make help` for a full list.

PY     := .venv/bin/python
PIP    := .venv/bin/pip
PYTEST := .venv/bin/pytest
RUFF   := .venv/bin/ruff

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: install
install: ## Install Python deps into the venv.
	$(PIP) install -r requirements.txt
	$(PIP) install ruff pytest pytest-asyncio

.PHONY: test
test: ## Run the full test suite.
	$(PYTEST) tests/ -v

.PHONY: test-fast
test-fast: ## Run tests, stop on first failure.
	$(PYTEST) tests/ -x

.PHONY: lint
lint: ## Run ruff on lib/ and tools/ (no external deps).
	$(RUFF) check lib/ tools/ orchestrator.py api_server.py main.py mcp_server.py

.PHONY: lint-fix
lint-fix: ## Run ruff with --fix on lib/ and tools/.
	$(RUFF) check --fix lib/ tools/ orchestrator.py api_server.py main.py mcp_server.py

.PHONY: callgraph
callgraph: ## Regenerate tools/callgraph.json (static analysis).
	$(PY) tools/callgraph.py build --path . --out tools/callgraph.json

.PHONY: callgraph-html
callgraph-html: callgraph ## Also render tools/callgraph.html viewer.
	$(PY) tools/callgraph.py html --path tools/callgraph.json --out tools/callgraph.html

.PHONY: callgraph-stats
callgraph-stats: callgraph ## Show callgraph stats summary.
	$(PY) tools/callgraph.py stats --path tools/callgraph.json

.PHONY: callgraph-dead
callgraph-dead: callgraph ## List dead (unreachable) symbols.
	$(PY) tools/callgraph.py dead --path tools/callgraph.json --limit 50

.PHONY: audit
audit: lint test callgraph-stats callgraph-dead ## Full audit: lint + test + callgraph summary + dead code.
	@echo "✓ Audit complete"

.PHONY: clean-pyc
clean-pyc: ## Remove __pycache__ dirs.
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

.PHONY: clean
clean: clean-pyc ## Remove caches and build artifacts.
	rm -rf .pytest_cache .ruff_cache tools/callgraph.json tools/callgraph.html
