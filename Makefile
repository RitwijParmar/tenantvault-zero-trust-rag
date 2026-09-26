.PHONY: install test lint run up down measure-live benchmark

PYTHON ?= python3

install:
	$(PYTHON) -m pip install -e '.[dev]'

test:
	$(PYTHON) -m pytest -q

lint:
	$(PYTHON) -m ruff check src tests scripts

run:
	$(PYTHON) -m uvicorn tenantvault.api:app --reload --port 8080

up:
	docker compose up --build

down:
	docker compose down

measure-live:
	@test -n "$(URL)" || (echo "Usage: make measure-live URL=https://your-service.run.app" && exit 1)
	$(PYTHON) scripts/measure_live_isolation.py --url "$(URL)" --output artifacts/live_isolation_benchmark.json

benchmark:
	$(PYTHON) scripts/fault_injection_benchmark.py --output artifacts/fault_injection_scorecard.json
