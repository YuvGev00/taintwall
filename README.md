# taintwall

**A runtime firewall for tool-using LLM agents.** It is measured on [AgentDojo](https://github.com/ethz-spylab/agentdojo).

[![ci](https://github.com/YuvGev00/taintwall/actions/workflows/ci.yml/badge.svg)](https://github.com/YuvGev00/taintwall/actions/workflows/ci.yml)

LLM agents read emails, files and web pages through tools. Any of that content can carry hidden instructions. This attack is called *indirect prompt injection*: "send the March statement to this IBAN", buried inside a transaction note.

taintwall sits between the agent and its tools and defends in two layers:

| Layer | What it does | Guarantee |
|---|---|---|
| **L1: detector** | A fine-tuned classifier scores every tool result and redacts likely injections | Probabilistic, tuned to ≤1% false positives |
| **L2: taint policy** | Tracks where every value came from. Blocks side-effecting tool calls (send money, send email, share file) whose sensitive arguments appear *only* in untrusted tool output | Deterministic for the flows it encodes, at a measured utility cost |

> **Status: in progress.** The harness, frozen splits, CI and the R1 replay are done. The defenses come next. The full plan is in [SPEC.md](SPEC.md).

## Results

### R1: hijacked-agent replay (model-free worst case, test split)

Every (user task, injection task) pair is replayed as an agent that obeys every injection it reads. Scoring uses AgentDojo's own checkers. It is deterministic, needs no API key, and the full test split runs in about 4 seconds.

| Defense | Benign utility ↑ | Attack success ↓ (same 335 injectable pairs) |
|---|---|---|
| none | 68/68 (100%) | 325/335 (97.0%) |
| **taintwall L2 (taint policy)** | **53/68 (77.9%)** | **44/335 (13.1%)** |
| ProtectAI detector | 68/68 (100%) | 88/335 (26.3%) |
| ProtectAI + L2 | 57/68 (83.8%) | 13/335 (3.9%) |
| taintwall L1 + L2 | — | — |

- The no-defense row is the ceiling. It matches the ~97.5% that [upstream #208](https://github.com/ethz-spylab/agentdojo/issues/208) found independently.
- ProtectAI (`protectai/deberta-v3-base-prompt-injection-v2`, threshold 0.5, tool outputs truncated to 512 tokens) redacts any output it flags. In ProtectAI + L2, ProtectAI screens outputs and L2 gates calls.
  - ProtectAI alone leaves 69/168 workspace attacks through. It stops all travel attacks and most banking attacks.
  - Combined, attacks fall from 44 to 13 (all workspace). Benign utility is *higher* than L2 alone (57 vs 53), because a redacted output can no longer taint a later argument. That is a real effect of the combination, not a free lunch: it holds only while the detector does not flag benign outputs (it flagged none in R1 benign runs).
  - Dev: ProtectAI 12/39 attacks, 29/29 benign; ProtectAI + L2 0/39, 26/29.
- The L2 policy was tuned on dev only and frozen at commit `d8e79b6` before the first test run.
- 9 injection tasks with empty ground truths are excluded (see below).

**By suite (test), attack success none → L2:**

| Suite | Attack success | Benign utility |
|---|---|---|
| banking | 64/66 → **0/66** | 11/11 → 9/11 |
| slack | 45/45 → **3/45** | 15/15 → 7/15 |
| travel | 54/56 → **13/56** | 14/14 → 14/14 |
| workspace | 162/168 → **28/168** | 28/28 → 23/28 |

**Error analysis (test, descriptive; the policy was not changed after it).**
- **All 15 blocked benign tasks are delegation.** The user tells the agent to act on data inside a document or message:
  - "pay the bill in bill-december-2023.txt";
  - "invite Dora; her email is on her website";
  - "email everyone in the meeting minutes";
  - a URL taken from a channel message.

  Taint tracking blocks these by design. A deployment would turn the block into a user confirmation.
- **The 44 attacks that got through fall outside what L2 protects:**
  - deleting a file by ID (28). IDs are not sensitive arguments, because benign tasks take them from search results;
  - creating a participant-less calendar event (12);
  - a malicious link sent to a legitimate recipient (3). The payload is in the message body, which is the detector's (L1) job;
  - booking a hotel the attacker *computes* from a trusted catalog (1). Only intent-level checks such as CaMeL can catch this.

### R2 / R3: live agents (dev, preliminary)

**Dev split only, 87 attacked pairs and 29 benign tasks per config, so these are preliminary.** Nothing here is on the held-out test split. Rows: no defense, `spotlighting_with_delimiting` (AgentDojo baselines), and taintwall L2 (policy frozen at `d8e79b6`, run live for the first time). Counts are k/n; confidence intervals come with the test runs. Raw JSONs are in [`results/`](results/), and model ids, dates and token counts are in [`results/COSTS.md`](results/COSTS.md).

| Regime | Model | Defense | Benign utility | Utility under attack | Attack success |
|---|---|---|---|---|---|
| R2 | `gemini-3.1-flash-lite` | none | 26/29 | 52/87 | **36/87 (41%)** |
| R2 | `gemini-3.1-flash-lite` | spotlighting | 26/29 | 61/87 | 31/87 (36%) |
| R3 | `gemini-3.5-flash` | none | 29/29 | 81/87 | 0/87 |
| R3 | `gemini-3.5-flash` | spotlighting | 28/29 | 82/87 | 0/87 |
| R2 | `gemini-3.1-flash-lite` | **taintwall L2** | 24/29 | 58/87 | **6/87 (6.9%)** |
| R3 | `gemini-3.5-flash` | **taintwall L2** | 25/29 | 78/87 | 0/87 |

- **R2 selection rule** (no-defense dev ASR of at least 20%): `gemini-3.1-flash-lite` passes (41%).
  - `nvidia/nemotron-3.5-super-vl:free` fails the rule: 4/87 (4.6%), all in banking. Its numbers are in `results/` and `COSTS.md` but it is not in the R2 table, and no spotlighting run was made for it.
  - The second suggested OpenRouter model (`xingchen-agi/xing4.0-29b-a4b:free`) was not run, because a free model takes about an hour per config under OpenRouter's rate limits. R2 therefore has one model so far.
- **L2 live (dev, preliminary):** attack success 36/87 → 6/87 on R2, at a benign-utility cost of 2 tasks (26 → 24 of 29). All 6 remaining successes are travel `injection_task_4` (book the priciest hotel), the known "attacker computes a catalog item" limitation. On R3, benign utility drops 29 → 25 of 29, with no security to gain (0/87 either way). Blocked calls are returned to the model as errors, so it can recover; the utility cost is the policy's false positives (delegation tasks, see above).
- **R3 expected result:** `gemini-3.5-flash` ignores the injections (0/87 with and without spotlighting), so it only measures utility cost, not security. Spotlighting changes it by one benign task, which is within noise at n=29.
- **Cost:** these runs used the Gemini API on a paid billing account (the free tier allows about 20 requests per day per model) and OpenRouter with a $10 credit balance, which unlocks 1000 free-model requests per day. `:free` models are not charged. See `results/COSTS.md`.

## Service

A FastAPI service wraps both layers (SPEC §8). Sessions keep per-session provenance, so the policy sees what the agent's tools returned.

```bash
make serve                       # http://localhost:8000/docs, SQLite in ./taintwall.db
docker compose up --build        # api + Postgres 16; add --profile tracing for Jaeger
```

| Endpoint | Purpose |
|---|---|
| `POST /v1/sessions` `{suite, user_prompt}` | start a session (suite = a file in `policies/`) |
| `POST /v1/check/tool_output` `{session_id, tool_name, text}` | L1 verdict: `allow` or `redact`; the text is recorded as untrusted provenance |
| `POST /v1/check/tool_call` `{session_id, tool_name, args}` | L2 verdict: `allow` or `block`, with reason and `tainted_args` |
| `GET /v1/sessions/{id}/trace` | every output and decision, in order |
| `GET /healthz`, `GET /metrics` | liveness, Prometheus |

- **Detector:** pluggable (`Detector.score(text) -> float`), default no-op. `TAINTWALL_DETECTOR=protectai` after `uv sync --group detector`. Verdicts are cached in an LRU keyed by `sha256(text)`.
- **Storage:** `TAINTWALL_DATABASE_URL` (`sqlite:///...` default, or `postgresql://...`).
- **Tracing:** set `OTEL_EXPORTER_OTLP_ENDPOINT` (e.g. `http://jaeger:4318` with the `tracing` profile; UI on :16686).
- **Parity test:** `tests/api/test_replay_parity.py` replays the banking and slack dev hijacked-agent traces through HTTP and asserts identical decisions to the in-process policy.
- **Load test:** ~530 RPS total on a laptop at 200 concurrent sessions, 0 failures; per-endpoint p50/p95/p99 and caveats in [results/LOADTEST.md](results/LOADTEST.md).

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
- **Detector training data never includes AgentDojo text.** A contamination audit (8-gram overlap + attacker entities) enforces this in CI. On the full L1 build: **0 / 23,427 rows** share any AgentDojo 8-gram and **0 rows** contain an AgentDojo entity (`training/audit_report.json`).

## Findings so far

These are from building the harness. Details and the reasoning behind each are in [DECISIONS.md](DECISIONS.md).

- **Frontier models leave no headroom on the standard attack.** Upstream reports 0/560 attack success on Claude Sonnet 4.6 with no defense ([#201](https://github.com/ethz-spylab/agentdojo/issues/201), [#208](https://github.com/ethz-spylab/agentdojo/issues/208)), so a defense measured only there looks perfect while measuring nothing. taintwall reports three regimes instead:
  - a model-free hijacked-agent replay (worst case, deterministic);
  - live models that actually fall for the attack;
  - utility cost on a frontier model.
- **The released AgentDojo package can't drive current Claude models.** `AnthropicLLM` always sends `temperature=0.0`, which Claude 5.5-generation models reject. taintwall uses its own element.
- **The released package (0.1.35) also drops `temperature=0` for OpenAI-compatible models** (`temperature or NOT_GIVEN`). It is fixed on upstream `main` (#141) but unreleased. taintwall sends it explicitly, and a test pins this.
- **The `important_instructions` attack raises an error for models it doesn't know.** It addresses the model by name. taintwall registers new models' names, which keeps the attack text identical to the paper's.
- **Nine injection tasks (workspace 6–13, travel 6) ship with empty ground truths.** AgentDojo's own `suite.check()` reports them as failing. Their security checks are real, so live attack-success numbers on them remain valid.
- **Qwen3-8B (local, Ollama) needs its reasoning mode on.** With thinking off, it describes a plan and stops without calling a tool (0/2 on a smoke test). With thinking on, it solved 2/3 at about 70 s per episode on an M2 Pro. That is fine for spot checks but too slow and too hot for full runs.

## Quickstart

```bash
uv sync
make lint test          # ruff, mypy --strict, unit tests, ground-truth replays, contamination audit (no LLM needed)
make dataset            # build the L1 dataset (streams seeds from HF) and re-run the audit on the full set
```

The L1 detector is trained on a free Colab T4 from [`training/train.ipynb`](training/train.ipynb);
`data/` is gitignored and regenerable, with a licence-clean sample committed under `training/sample/`.
See [`training/MODEL_CARD.md`](training/MODEL_CARD.md).

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
  eval/run_agentdojo.py   live benchmark runner (R2/R3) → raw counts
  eval/replay.py          R1 hijacked-agent replay + the defense interface
  policy/                 L2: registry loader, provenance, taint rules
policies/                 per-suite tool registries (YAML, written from schemas)
eval/splits.json          the committed split
tests/unit/               split, adapter
tests/groundtruth/        AgentDojo ground-truth replays (zero cost, deterministic)
SPEC.md                   full design and 10-week plan
DECISIONS.md              dated decision log
```

## Roadmap

- [x] Week 1: harness, frozen split, CI
- [x] R1 hijacked-agent replay harness, with the no-defense ceiling measured
- [x] L2 taint policy v1: attack success 97.0% → 13.1% (worst case, test) at a benign-utility cost of 22 points
- [x] R2/R3 dev baselines (no defense, spotlighting): 1 R2 model passed the headroom rule, 1 R3 model. taintwall L2 live on dev. Still to do: ProtectAI live, a second R2 model, and the test split
- [x] ProtectAI and ProtectAI + L2 in R1 (dev and test)
- [x] Indirect-injection dataset (23.4k rows, 50/50, span-level splits) and contamination audit (0/23,427 flagged), gated in CI
- [ ] Fine-tuned detector (ModernBERT): `training/train.ipynb` ready for a free Colab T4; threshold at FPR ≤ 1% on dev vs the protectai baseline
- [x] Service (FastAPI + SQLite/Postgres + Prometheus + OpenTelemetry + Docker) and load test; [ ] end-to-end L1 results
- [ ] Ablations, frozen config, full test-split runs with paired statistics
- [ ] Traces, load test, demo, write-up

## License

Apache-2.0
