.PHONY: help install dev lint format type test test-offline cov migrate lab-up lab-down clean

help:
	@echo "RedPrompt make targets:"
	@echo "  install       Install the package"
	@echo "  dev           Install with dev + api extras and pre-commit hooks"
	@echo "  lint          Run ruff"
	@echo "  format        Run black + ruff --fix"
	@echo "  type          Run mypy"
	@echo "  test          Run the full pytest suite"
	@echo "  test-offline  Run the stdlib unittest core harness (no heavy deps)"
	@echo "  cov           Run tests with coverage"
	@echo "  migrate       Apply Alembic migrations"
	@echo "  lab-up        Start the local vulnerable lab (docker compose)"
	@echo "  lab-down      Stop the lab"

install:
	pip install -e .

dev:
	pip install -e ".[dev,api]"
	pre-commit install

lint:
	ruff check src tests

format:
	black src tests
	ruff check --fix src tests

type:
	mypy src

test:
	pytest

test-offline:
	PYTHONPATH=src python -m unittest discover -s tests_offline -v

cov:
	pytest --cov=redprompt --cov-report=term-missing --cov-report=xml

migrate:
	alembic upgrade head

lab-up:
	docker compose -f redprompt-lab/docker-compose.yml up -d --build

lab-down:
	docker compose -f redprompt-lab/docker-compose.yml down -v

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov coverage.xml *.db
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
