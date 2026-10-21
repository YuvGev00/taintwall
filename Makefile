.PHONY: serve loadtest dev lint test splits r1 eval-dev summarize-dev dataset audit

MODEL ?= qwen3:8b

dev:
	uv sync --locked

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy

test:
	uv run pytest

# L1 detector data: streams seeds from the HF Hub, writes data/ (gitignored) and the
# committed sample, then runs the contamination audit on the full set before any training.
dataset:
	uv run --group training python -m training.build_dataset
	uv run --group training python -m training.contamination_audit data/train.jsonl data/dev.jsonl data/test.jsonl --report training/audit_report.json

# Contamination audit on the committed sample only (no network); this is what CI runs.
audit:
	uv run --group training python -m training.contamination_audit training/sample/sample.jsonl

# Regenerating must be a no-op: the split is frozen (tests/unit/test_splits.py).
splits:
	uv run python -m taintwall.eval.splits

# R1 hijacked-agent replay: no model, no API key, seconds. DEFENSE=none|...
DEFENSE ?= none
r1:
	uv run python -m taintwall.eval.replay --split dev --defense $(DEFENSE)
	uv run python -m taintwall.eval.replay --split test --defense $(DEFENSE)

# Needs a model server; default is Ollama on localhost:11434 (see README).
eval-dev:
	uv run python -m taintwall.eval.run_agentdojo --split dev --model $(MODEL)
	uv run python -m taintwall.eval.run_agentdojo summarize --split dev --model $(MODEL)

summarize-dev:
	uv run python -m taintwall.eval.run_agentdojo summarize --split dev --model $(MODEL)

serve:
	uv run uvicorn taintwall.api.app:app --port 8000

# Needs `make serve` running; see results/LOADTEST.md.
loadtest:
	uv run locust -f loadtest/locustfile.py --headless -u 200 -r 50 -t 75s --host http://localhost:8000
