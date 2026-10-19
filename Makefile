.PHONY: dev lint test splits eval-dev summarize-dev

MODEL ?= qwen3:8b

dev:
	uv sync --locked

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy

test:
	uv run pytest

# Regenerating must be a no-op: the split is frozen (tests/unit/test_splits.py).
splits:
	uv run python -m taintwall.eval.splits

# Needs a model server; default is Ollama on localhost:11434 (see README).
eval-dev:
	uv run python -m taintwall.eval.run_agentdojo --split dev --model $(MODEL)
	uv run python -m taintwall.eval.run_agentdojo summarize --split dev --model $(MODEL)

summarize-dev:
	uv run python -m taintwall.eval.run_agentdojo summarize --split dev --model $(MODEL)
