.PHONY: check test e2e

# Windows venvs use Scripts/python.exe, POSIX venvs use bin/python.
PY := $(if $(wildcard .venv/Scripts/python.exe),.venv/Scripts/python.exe,.venv/bin/python)
# Inside the repo so it works on both platforms and stays ignored via .local*/.
BASETEMP ?= .local-pytest-basetemp

check:
	$(PY) tools/gate.py
	$(PY) -m pytest -q --basetemp=$(BASETEMP)

test:
	$(PY) -m pytest -q --basetemp=$(BASETEMP)

# Real Chromium acceptance; dependencies stay outside the repository.
e2e:
	$(PY) tools/browser_e2e.py
