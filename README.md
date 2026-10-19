# taintwall

**A runtime firewall for tool-using LLM agents.** It is measured on [AgentDojo](https://github.com/ethz-spylab/agentdojo).

[![ci](https://github.com/YuvGev00/taintwall/actions/workflows/ci.yml/badge.svg)](https://github.com/YuvGev00/taintwall/actions/workflows/ci.yml)

LLM agents read emails, files and web pages through tools. Any of that content can carry hidden instructions. This attack is called *indirect prompt injection*: "send the March statement to this IBAN", buried inside a transaction note.

taintwall sits between the agent and its tools and defends in two layers:

| Layer | What it does | Guarantee |
|---|---|---|
| **L1: detector** | A fine-tuned classifier scores every tool result and redacts likely injections | Probabilistic, tuned to ≤1% false positives |
| **L2: taint policy** | Tracks where every value came from. Blocks side-effecting tool calls (send money, send email, share file) whose sensitive arguments appear *only* in untrusted tool output | Deterministic for the flows it encodes, at a measured utility cost |

> **Status: week 1 of 10.** The harness, frozen splits and CI are in place. Defenses and results come next. The full plan is in [SPEC.md](SPEC.md).

## Results

*Pending.* The first runs will use a hosted model endpoint. Every number will be reported on the **held-out test split**, with 95% bootstrap confidence intervals.

| Model | Defense | Benign utility ↑ | Utility under attack ↑ | Attack success ↓ | p95 overhead |
|---|---|---|---|---|---|
| — | none | — | — | — | — |
| — | spotlighting (AgentDojo built-in) | — | — | — | — |
| — | ProtectAI detector (AgentDojo built-in) | — | — | — | — |
| — | **taintwall L1 + L2** | — | — | — | — |

## Evaluation protocol

- **Benchmark:** AgentDojo `v1.2.2`: 4 suites (workspace, travel, banking, slack), 97 user tasks, 35 injection tasks, and the `important_instructions` attack.
- **Frozen split on both axes:** user tasks *and* injection tasks are split 30/70 dev/test with a salted hash.
  - Dev pairs are dev users × dev injections (87 pairs).
  - Test pairs are test users × test injections (461 pairs).
  - Thresholds and policies are tuned on dev only, so test numbers measure attacks the defense has never seen.
  - The split is committed in [`eval/splits.json`](eval/splits.json), and CI fails if it ever changes.
- **Metrics:**
  - Benign utility: tasks solved with no attack.
  - Utility under attack: user task still solved while under attack.
  - Attack success rate: the injection goal was executed.
  - Latency overhead per tool call.
  - Defenses run on the same pairs, so comparisons are paired.
- **Detector training data never includes AgentDojo text.** A contamination audit (8-gram overlap) enforces this in CI.

## Findings so far

These are from building the harness. Details and the reasoning behind each are in [DECISIONS.md](DECISIONS.md).

- **AgentDojo 0.1.35 never sends `temperature=0`.** The request uses `temperature or NOT_GIVEN`, and `0.0` is falsy, so runs silently use the server's default sampling. taintwall's LLM element sends it explicitly, and a test pins this.
- **The `important_instructions` attack raises an error for models it doesn't know.** It addresses the model by name. taintwall registers new models' names, which keeps the attack text identical to the paper's.
- **Workspace injection tasks 6–13 (added in v1.2) ship with empty ground truths.** AgentDojo's own `suite.check()` reports them as failing. Their security checks are real, so live attack-success numbers on them remain valid.
- **Qwen3-8B (local, Ollama) needs its reasoning mode on.** With thinking off, it describes a plan and stops without calling a tool (0/2 on a smoke test). With thinking on, it solved 2/3 at about 70 s per episode on an M2 Pro. That is fine for spot checks but too slow and too hot for full runs.

## Quickstart

```bash
uv sync
make lint test          # ruff, mypy --strict, unit tests, ground-truth replays (no LLM needed)
```

Run the benchmark on the dev split against any OpenAI-compatible endpoint:

```bash
export TAINTWALL_BASE_URL=https://<provider>/v1 TAINTWALL_API_KEY=...
uv run python -m taintwall.eval.run_agentdojo --provider openai-compatible \
    --model <model-id> --prose-name "<Name the attack should use>" --split dev
uv run python -m taintwall.eval.run_agentdojo summarize --provider openai-compatible --model <model-id> --split dev
```

Or run locally with Ollama. Start it with a 16K context first, because the default 4K silently truncates AgentDojo prompts:

```bash
OLLAMA_CONTEXT_LENGTH=16384 ollama serve &
ollama pull qwen3:8b
uv run python -m taintwall.eval.run_agentdojo --split dev --suite banking
```

The runner writes per-suite pass/fail counts to `results/<run>/<split>/<suite>.json`. Raw traces go to `runs/` (gitignored) and are cached, so interrupted runs resume where they stopped.

## Repository layout

```
src/taintwall/
  adapters/agentdojo.py   pipeline builder for any model (L1/L2 plug in here)
  eval/splits.py          frozen dev/test split generator
  eval/run_agentdojo.py   benchmark runner → raw counts
eval/splits.json          the committed split
tests/unit/               split, adapter
tests/groundtruth/        AgentDojo ground-truth replays (zero cost, deterministic)
SPEC.md                   full design and 10-week plan
DECISIONS.md              dated decision log
```

## Roadmap

- [x] Week 1: harness, frozen split, CI
- [ ] Baseline numbers on a hosted model (no defense plus 2 AgentDojo built-ins)
- [ ] Indirect-injection dataset and contamination audit
- [ ] Fine-tuned detector (ModernBERT), published on Hugging Face
- [ ] Detection service (FastAPI) and end-to-end L1 results
- [ ] Taint policy (L2) and ground-truth policy tests
- [ ] Ablations, frozen config, full test-split runs with paired statistics
- [ ] Traces, load test, demo, write-up

## License

Apache-2.0
