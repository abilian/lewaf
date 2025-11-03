.PHONY: all test build format check lint clean

all:
	uv run ruff check .
	uv run pytest
	uv run ruff format . --check
	uv run pyrefly check src


check: lint

lint:
	ruff check .
	ruff format . --check
	pyrefly check src
	

format:
	ruff format .
	ruff check . --fix
	ruff format .

test:
	uv run pytest

build: clean
	uv build

clean:
	rm -rf .pytest_cache .ruff_cache dist build __pycache__ .mypy_cache .coverage htmlcov .coverage.* *.egg-info

publish: build
	uv publish
