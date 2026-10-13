.PHONY: install lint typecheck test test-target demo check-policy
install:
	python -m pip install -e ".[dev]"
lint:
	ruff check src tests target-app

typecheck:
	mypy --strict src/sentinel

test:
	python -m pytest -q tests

test-target:
	PYTHONPATH=target-app python -m pytest -q target-app/test_app.py

check-policy:
	sentinel check-policy

demo: check-policy test
	python -m sentinel.cli triage --advisory CVE-2020-14343 --package PyYAML --repository local/sentinel-demo --change-type major --path target-app/app.py
