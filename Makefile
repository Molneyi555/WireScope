.PHONY: test check doctor

test:
	PYTHONPYCACHEPREFIX=/private/tmp/wirescope-pycache python3 -m unittest discover -s tests -v

check:
	PYTHONPYCACHEPREFIX=/private/tmp/wirescope-pycache python3 -m py_compile wirescope/*.py tests/*.py

doctor:
	./bin/wirescope doctor

