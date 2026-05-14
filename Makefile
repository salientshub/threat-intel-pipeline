# =============================================================================
# Threat Intelligence Pipeline — Makefile
# =============================================================================
# Convenience targets for corporate development workflow.
# Usage:  make install | make test | make lint | make run | make clean
# =============================================================================

PYTHON   ?= python3
VENV     := venv
PIP      := $(VENV)/bin/pip
PYTEST   := $(VENV)/bin/pytest
BLACK    := $(VENV)/bin/black
FLAKE8   := $(VENV)/bin/flake8

.PHONY: help install test lint format run clean

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Create venv and install all dependencies
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

test: ## Run pytest with coverage report
	$(PYTEST) tests/ -v --tb=short --cov=core --cov=utils --cov-report=term-missing

lint: ## Run flake8 and black --check
	$(FLAKE8) core/ utils/ config/ main.py tests/ --max-line-length=88 --extend-ignore=E203,W503
	$(BLACK) --check core/ utils/ config/ main.py tests/

format: ## Auto-format code with black
	$(BLACK) core/ utils/ config/ main.py tests/

run: ## Execute the full CTI pipeline
	$(VENV)/bin/python main.py

clean: ## Remove venv, caches, logs, and build artefacts
	rm -rf $(VENV) __pycache__ .pytest_cache htmlcov .coverage
	rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
