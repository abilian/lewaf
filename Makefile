.PHONY: all test build format check lint clean docs docs-serve

all:
	uv run pytest
	@make lint


check: lint

lint:
	uv run ruff check src tests
	uv run ruff format --check
	uv run pyrefly check src
	uv run ty check src
	uv run mypy src


format:
	uv run ruff format .
	uv run ruff check --fix src tests
	uv run ruff format .

test:
	uv run pytest

test-cov:
	uv run pytest --cov=lewaf --cov-report=html --cov-report=term tests

build: clean
	uv build

clean:
	rm -rf .pytest_cache .ruff_cache dist build __pycache__ .mypy_cache \
		.coverage htmlcov .coverage.* *.egg-info site

publish: build
	uv publish

docs:
	uv run mkdocs build

docs-serve:
	uv run mkdocs serve
