VENV ?= .venv
PYTHON := $(VENV)/bin/python

# Default PYTHONPATH for running from project root
PYTHONPATH := $(CURDIR)

test:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest -q

test-examples:
	@echo "test-examples: not implemented"
	exit 2

bench:
	@echo "bench: not implemented"
	exit 2

.PHONY: test test-examples bench
