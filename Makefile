PYTHON ?= python
PIP ?= pip
PYTEST ?= pytest

.PHONY: run install test test-unit test-integration clean

run:
	$(PYTHON) main.py

install:
	$(PIP) install -r requirements.txt
	$(PIP) install pytest

test:
	PYTHONPATH=$(CURDIR) $(PYTEST) backend/Tests

test-unit:
	PYTHONPATH=$(CURDIR) PYTHONPATH=. $(PYTEST) backend/Tests/Unit_tests 

test-integration:
	PYTHONPATH=$(CURDIR) $(PYTEST) backend/Tests/Integration_tests 

clean:
	rm -rf .pytest_cache
