# KingSec - developer task shortcuts (thin wrappers over the toolchain).
# Assumes 'uv' as the environment manager. Swap the runner if you freeze another.

.DEFAULT_GOAL := help
.PHONY: help install lint fmt type arch sec test cov check clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n",$$1,$$2}'

install: ## Create the venv, sync runtime + dev deps, install git hooks
	uv sync --all-groups
	uv run pre-commit install

lint: ## Static linting (Ruff)
	uv run ruff check .

fmt: ## Auto-format the codebase (Ruff)
	uv run ruff format .

type: ## Strict static type check (mypy)
	uv run mypy

arch: ## Enforce hexagonal boundaries (import-linter)
	uv run lint-imports

sec: ## Security scans (SAST + dependency audit)
	uv run bandit -q -r src
	uv run pip-audit

test: ## Run the test suite
	uv run pytest

cov: ## Run tests with coverage
	uv run pytest --cov

check: lint type arch sec test ## Run every quality gate (mirrors CI)

clean: ## Remove caches and build artifacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov dist build .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
