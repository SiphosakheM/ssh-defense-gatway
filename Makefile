PYTHON ?= python3
VENV_DIR ?= .venv
PY = $(VENV_DIR)/bin/python
PIP = $(VENV_DIR)/bin/pip
PYTEST = $(VENV_DIR)/bin/pytest

.PHONY: venv install test test-root clean

venv: ## Create the virtualenv and install runtime + dev dependencies
	$(PYTHON) -m venv $(VENV_DIR)
	$(PIP) install -r requirements-dev.txt

install: ## Install dependencies into an existing virtualenv
	$(PIP) install -r requirements-dev.txt

test: venv ## Run the non-root test suite
	$(PYTEST) tests/ -v

test-root: venv ## Run the full suite incl. iptables/systemd tests (needs root)
	sudo -E $(PYTEST) tests/ -v

clean: ## Remove the virtualenv and all test/build artifacts
	rm -rf $(VENV_DIR) .pytest_cache logs/*.log logs/defense_state.json
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete