.PHONY: install test lint run up down

install:
	pip install -e '.[dev]'

test:
	pytest -q

lint:
	ruff check src tests

run:
	uvicorn tenantvault.api:app --reload --port 8080

up:
	docker compose up --build

down:
	docker compose down
