PYTHON ?= python3
VENV := .venv
BIN := $(VENV)/bin
PORT ?= 8000

.PHONY: install run check lint typecheck test docker-up docker-down
install: $(VENV)/.installed

$(VENV)/.installed: requirements-dev.lock pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --require-hashes -r requirements-dev.lock
	$(BIN)/python -m pip install --no-deps --no-build-isolation -e .
	touch $@

run: install
	$(BIN)/python -m flask --app posture:create_app --no-debug run --host 127.0.0.1 --port $(PORT) --no-reload --no-debugger

lint:
	$(BIN)/ruff check posture tests scripts
	$(BIN)/ruff format --check posture tests scripts

typecheck:
	$(BIN)/mypy posture

test:
	$(BIN)/pytest

check: lint typecheck test

docker-up:
	docker compose up --build

docker-down:
	docker compose down
