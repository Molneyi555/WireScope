PYTHON ?= python3
TYPECHECK_TARGETS = wirescope/models.py wirescope/artifacts.py wirescope/redact.py wirescope/public_suffix.py wirescope/tracker.py wirescope/assessment.py wirescope/budget.py wirescope/session.py wirescope/session_report.py wirescope/lifecycle.py wirescope/rules.py wirescope/baseline.py wirescope/manifest.py scripts/normalize_sdist.py

.PHONY: test check lint typecheck package benchmark ci doctor

test:
	PYTHONPYCACHEPREFIX=/private/tmp/wirescope-pycache $(PYTHON) -m unittest discover -s tests -v

check:
	PYTHONPYCACHEPREFIX=/private/tmp/wirescope-pycache $(PYTHON) -m compileall -q wirescope tests scripts

lint:
	$(PYTHON) -m ruff check wirescope tests scripts

typecheck:
	$(PYTHON) -m mypy $(TYPECHECK_TARGETS)

package:
	$(PYTHON) -m build
	$(PYTHON) scripts/normalize_sdist.py dist/*.tar.gz
	$(PYTHON) -m twine check dist/*.whl dist/*.tar.gz

benchmark:
	PYTHONPYCACHEPREFIX=/private/tmp/wirescope-pycache $(PYTHON) -m benchmarks.benchmark_core --quick

ci: lint typecheck check test package

doctor:
	./bin/wirescope doctor
