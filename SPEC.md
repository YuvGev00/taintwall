# taintwall — build spec

> Working name (free on PyPI as of 2026-10-19; 2 small GitHub repos use it). Rename freely.
> Status: spec only, nothing built yet. Owner: Yuval. Target: 10 weeks × ~12–15 h/week.

## 1. Pitch (the sentence you say in an interview)

**taintwall is a runtime firewall for tool-using LLM agents.** It stops *indirect prompt injection* — malicious instructions hidden in emails, files, or web pages that an agent reads through its tools — with two layers: an **ML detector** I fine-tuned on tool outputs, and a **provenance (taint-tracking) policy** that refuses side-effecting tool calls whose sensitive arguments came only from untrusted data. I measured it end-to-end on **AgentDojo** (ETH Zurich's agent-security benchmark) against published baselines, reporting attack-success rate, the utility it costs, and latency overhead.

Why this project: it hits the three things junior AI-engineer postings ask for (Python + LLM agents + evals), adds real ML training and a real backend service, and it lands in the space where 20+ Israeli startups (Zenity, Noma, Lasso, Pillar, Onyx, …) are hiring.

## 2. Goals and non-goals

**Goals**
1. Reproduce AgentDojo baseline numbers (no defense + 2 built-in defenses) for 2 models.
2. Ship a fine-tuned injection detector specialised for *tool outputs* (not chat jailbreaks), published on Hugging Face with a model card.
3. Ship a provenance policy engine that gives a *structural* guarantee for the flows it covers.
4. Wrap both in a deployable HTTP service with traces, a load test and CI.
5. Report honest results: held-out test split, confidence intervals, error taxonomy, and what still gets through.

**Non-goals** (write these into the README too — it shows judgment)
- Direct jailbreaks typed by the user, model-weight attacks, DoS.
- Beating CaMeL or other research systems. You compare to them in prose, not in a leaderboard fight.
- A general agent framework. taintwall plugs into an existing agent loop.

## 3. Threat model

- **Trusted:** the system prompt, the user's request, and the tool *schemas*.
- **Untrusted:** every tool *result* (email bodies, file contents, web pages, reviews, Slack messages, transaction notes).
- **Attacker:** controls some untrusted data and wants the agent to perform an *injection task* (for example, send money to their IBAN, or forward an email to their address) while the user asked for something else.
- **Success for the defense:** the injection task does not happen (security) and the user's task still completes (utility).

## 4. Architecture

```
            user request (trusted)
                   │
   ┌───────────────▼────────────────┐
   │        Agent loop (LLM)        │◄──────────────┐
   └───────────────┬────────────────┘               │
                   │ proposed tool call             │ tool result
                   ▼                                │ (maybe redacted)
   ┌────────────────────────────────┐   ┌───────────┴─────────────┐
   │ L2  Policy guard (taint check) │   │ L1  Detector (ML)       │
   │ side-effect tool? sensitive    │   │ classify each tool      │
   │ args traceable to trusted src? │   │ result; redact if       │
   │ → allow / block + reason       │   │ injection               │
   └───────────────┬────────────────┘   └───────────▲─────────────┘
                   │ allowed call                   │ raw result
                   ▼                                │
              ┌──────────┐  provenance store records │
              │  Tools   │──every untrusted string ──┘
              └──────────┘
```

All decisions go through the **taintwall service** (FastAPI). The AgentDojo adapter calls it over HTTP, so the benchmark exercises the real service. An in-process mode exists for fast dev runs.

### L1 — Detector (the ML part)
- **Model:** fine-tune `answerdotai/ModernBERT-base` (149M params, Apache-2.0). Baseline ablation: `microsoft/deberta-v3-small` (MIT).
- **The gap you are filling:** public prompt-injection datasets are mostly *direct* chat prompts ("ignore previous instructions…"). Agent attacks arrive *inside* realistic documents. Off-the-shelf detectors either miss them or flag benign emails that contain imperatives ("please transfer the files by Friday"). Your dataset targets exactly that.
- **Data:**
  - **Direct-injection seed (permissive licenses):** `deepset/prompt-injections` (Apache-2.0, <1K rows), `Lakera/gandalf_ignore_instructions` (MIT), `reshabhs/SPML_Chatbot_Prompt_Injection` (MIT), `jackhhao/jailbreak-classification` (Apache-2.0). `xTRam1/safe-guard-prompt-injection` has no license tag, so skip it or ask the author.
  - **Synthetic indirect set (your contribution):** take benign *carrier* documents (emails, calendar invites, reviews, README snippets, bank-statement notes), then inject payloads at random positions with varied formatting (plain text, markdown, HTML comments, quoted replies, base64-ish noise).
  - **Hard negatives:** benign carriers full of imperatives, payment details and URLs. This is what keeps the false-positive rate down.
  - **Target size:** about 20–40K examples with a 50/50 class balance and stratified splits.
- **Contamination audit (your edge, so make it a CI check):** nothing from AgentDojo may enter training. A script computes 8-gram overlap between the training set and every AgentDojo injection-task goal and attack template, and fails CI above a tiny threshold. Put the audit result in the README.
- **Threshold:** pick it on the dev split to hit **FPR ≤ 1% on benign tool outputs**, because false positives destroy utility. Report TPR at that FPR, plus AUROC.
- **Evaluation, in three rings:**
  1. Held-out synthetic test set (in-distribution).
  2. Out-of-distribution, eval only: BIPIA (`microsoft/BIPIA`; licence says NOASSERTION, so evaluate and cite but don't redistribute) and InjecAgent (`uiuc-kang-lab/InjecAgent`, MIT).
  3. End-to-end on AgentDojo (never seen in training).
- **Baselines:** `protectai/deberta-v3-base-prompt-injection-v2` (this is what AgentDojo's built-in `transformers_pi_detector` uses) and `meta-llama/Llama-Prompt-Guard-2-86M` (gated, manual approval, so **request access in week 1**).
- **Compute:** free Colab or Kaggle T4. CPU inference for the service; export to ONNX if latency needs it.

### L2 — Policy guard (the systems part)
- **Tool registry** (`policies/<suite>.yaml`), written from **tool schemas only**, never from benchmark results:
  ```yaml
  send_money:
    side_effect: external        # none | write | external
    sensitive_args: [recipient, amount]
  send_email:
    side_effect: external
    sensitive_args: [recipients, cc, bcc]
  read_file:
    side_effect: none
  ```
- **Provenance store:** every string the agent receives is tagged `trusted` (user prompt) or `untrusted` (tool result id). Normalise values (lowercase emails, strip spaces from IBANs, canonicalise URLs).
- **Rule v1:** a call to a `write`/`external` tool is blocked if any sensitive argument value appears **only** in untrusted sources and not in the user's request. The block returns a tool *error* message ("Blocked by policy: recipient came from untrusted content"), so the agent can recover and keep doing the user's task instead of crashing.
- **Known, measured limitation:** some legitimate tasks require using data from a file (for example, "pay the bill in bill.txt"). Rule v1 blocks those. Count them, list them in the README, and discuss the fix used in production systems (user confirmation, or CaMeL-style capability flows — see `google-research/camel-prompt-injection`, Apache-2.0). This trade-off discussion is interview gold.

## 5. AgentDojo integration (verified against agentdojo 0.1.35)

Facts checked in the installed package:
- Benchmark version `v1.2.2` has 4 suites: workspace (40 user tasks × 14 injection tasks), travel (20 × 7), banking (16 × 9), slack (21 × 5). That is **97 user tasks** and **949 (user, injection) pairs per attack**.
- Built-in defenses: `tool_filter` (OpenAI models only), `transformers_pi_detector`, `spotlighting_with_delimiting`, `repeat_user_prompt`.
- Attacks include `important_instructions` (the standard strong one) and `tool_knowledge`.
- The `ModelsEnum` is dated (newest entries are 2025-era). Build your LLM element directly instead of using the CLI: `OpenAILLM(openai.OpenAI(base_url=..., api_key=...), model)` works with any OpenAI-compatible endpoint (Ollama, OpenRouter, vLLM), and `AnthropicLLM(Anthropic(), model)` covers Claude.

Adapter sketch (`src/taintwall/adapters/agentdojo.py`):
```python
from agentdojo.agent_pipeline import (
    AgentPipeline,
    InitQuery,
    OpenAILLM,
    PromptInjectionDetector,
    SystemMessage,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections
from agentdojo.task_suite.load_suites import get_suite


class TaintwallDetector(PromptInjectionDetector):
    def __init__(self, client):  # client = HTTP client to the taintwall service
        super().__init__(mode="message", raise_on_injection=False)
        self.client = client

    def detect(self, tool_output: str) -> tuple[bool, float]:
        r = self.client.check_tool_output(tool_output)
        return r.is_injection, r.score


class PolicyGuardedExecutor(ToolsExecutor):
    # Override query(): for each tool_call in messages[-1]["tool_calls"], ask the
    # service /v1/check/tool_call; if blocked, append a ChatToolResultMessage with
    # error="Blocked by policy: ..." (same pattern ToolsExecutor uses for invalid
    # tools), otherwise delegate to the normal execution path. Also record every
    # tool result in the provenance store.
    ...


def build_pipeline(llm, client, use_detector=True, use_policy=True):
    executor = PolicyGuardedExecutor(client) if use_policy else ToolsExecutor()
    loop_elems = [executor] + ([TaintwallDetector(client)] if use_detector else []) + [llm]
    p = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm, ToolsExecutionLoop(loop_elems)])
    p.name = f"{llm.model}-taintwall"
    return p


suite = get_suite("v1.2.2", "banking")
attack = load_attack("important_instructions", suite, pipeline)
results = benchmark_suite_with_injections(
    pipeline, suite, attack, logdir=..., force_rerun=False, user_tasks=TEST_SPLIT["banking"], benchmark_version="v1.2.2"
)
```
Check the exact `ChatToolResultMessage` fields against `agentdojo/agent_pipeline/tool_execution.py` when you implement it.

**Gotcha:** attacks like `important_instructions` address the model by name. They call `get_model_name_from_pipeline()`, which searches `pipeline.name` for a key in `agentdojo.attacks.base_attacks.MODEL_NAMES` and fails with `pipeline.name = None`. For any model newer than the enum, add `MODEL_NAMES["<your-model-id>"] = "<Prose Name>"` at startup, before `load_attack`. Write down that you did so, because it keeps the attack identical to the paper's.

## 6. Metrics and statistics

| Metric | Definition |
|---|---|
| **BU**: benign utility | % of user tasks solved, no attack |
| **UA**: utility under attack | % of (user, injection) pairs where the user task is still solved |
| **ASR**: attack success rate | % of *delivered* pairs where the injection task is executed (R1 rule, §7) |
| Overhead | added latency per tool call, p50/p95 (service-side and end-to-end) |
| Cost | $ and tokens per 100 episodes |
| Detector | AUROC, TPR @ FPR=1%, F1, per-carrier-type breakdown |

**Statistics (do this properly, because most projects don't):**
- **Dev/test split:** per suite, hash user-task ids into **30% dev / 70% test** once, commit the split file, and never change it. Tune thresholds and policy on dev only, and report test only.
- **Paired design:** every defense runs on the *same* pairs, so compare defenses with a **paired bootstrap** (resample pairs) or **McNemar's test**, not independent CIs.
- 95% bootstrap CIs on every number in the results table.
- Run 3 seeds or temperature 0 where the provider allows it; note any nondeterminism.

## 7. Experiment design: three evaluation regimes (revised 2026-10-20)

**Why revised.** Recent frontier models almost never fall for AgentDojo's standard attack. That leaves a defense nothing to stop, so "0% ASR with my defense" means nothing on those models. Evidence:
- [Upstream #201](https://github.com/ethz-spylab/agentdojo/issues/201): workspace v1.2.2 + `important_instructions` on claude-sonnet-4-6 gave **0/560** attack success with no defense.
- [Upstream #208](https://github.com/ethz-spylab/agentdojo/issues/208): Haiku 4.5 and Sonnet 4.5 both gave **0.0%** on banking.

Every claim must therefore come from a regime where the undefended attack actually succeeds.

| Regime | What it measures | Models | Cost |
|---|---|---|---|
| **R1: hijacked-agent replay** (primary security metric for L2) | For each (user, injection) pair, replay the user task's ground-truth calls, then the attacker's ground-truth calls, through the defense. AgentDojo's checkers score utility and attack success. This is the worst case: an agent that obeys every injection. | none (model-free) | $0, deterministic, runs in CI |
| **R2: live agents with headroom** (main live table) | BU / UA / ASR on agents that *do* fall for the attack. **Selection rule:** run no-defense on dev first, and keep only models with no-defense ASR ≥ 20%. | free OpenRouter models with tool calling (e.g. `nvidia/nemotron-3.5-super-vl:free`, `xingchen-agi/xing4.0-29b-a4b:free`); local Ollama for spot checks | $0 |
| **R3: frontier utility cost** | What the defense costs a strong model: BU and UA with vs. without the defense. ASR is reported but expected to be ~0, and that is stated explicitly. | Gemini Flash (free tier, via the OpenAI-compatible endpoint); optional claude-haiku-5-5 from existing credit | $0 (optional ~$10–20) |

**R1 accounting rule (credit: #208).** Run the attacker phase only when a tool result in the user phase actually delivered the injection text. Count pairs where the injection was never delivered as *not attacked* and leave them out of the denominator. Otherwise a defense that blocks the delivery gets scored as a successful attack.

**Excluded injection tasks.** Nine of the 35 injection tasks have empty ground truths (8 in workspace, 1 in travel). They are excluded from R1 and reported separately in R2/R3.

**Configs** (run on every regime where they apply):

| Config | R1 | R2 dev | R2 test | R3 |
|---|---|---|---|---|
| no defense | ✓ | ✓ | ✓ | ✓ |
| spotlighting_with_delimiting | — (prompt-only) | ✓ | ✓ | ✓ |
| protectai detector (built-in) | ✓ (as a filter) | ✓ | ✓ | ✓ |
| taintwall L1 only | ✓ | ✓ | — | — |
| taintwall L2 only | ✓ | ✓ | — | — |
| **taintwall L1 + L2** | ✓ | ✓ | ✓ | ✓ |

**Attack:** `important_instructions` for the main tables and `tool_knowledge` as a robustness row. Stretch: one adaptive attack registered via `register_attack`.

**Budget control:**
1. Before any full run, run 20 episodes, log tokens, extrapolate the cost, and write it to `results/COSTS.md`.
2. Set a provider spending limit.
3. Use `force_rerun=False` so crashed runs resume.

**$0 by default (decided 2026-10-20).**
- Every regime runs on free tiers. Gemini and OpenRouter both expose OpenAI-compatible APIs, so they run through the existing `openai-compatible` provider with no code change:
  - Gemini: `TAINTWALL_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/`, which supports tools and `reasoning_effort` (minimal…high).
  - OpenRouter: `https://openrouter.ai/api/v1`.
- Claude is an optional comparison row from existing credit.
- Free tiers are rate-limited, so runs are longer. Rely on `force_rerun=False` resumes and overnight runs.
- `:free` model lists change over time, so every result records the exact model id and run date.
- No Sonnet-class headline run is planned, because it would almost certainly sit at ~0% ASR.

## 8. Service

- **Stack:** Python 3.12, FastAPI, Pydantic v2, Postgres 16 (decisions and traces), OpenTelemetry → Jaeger (local compose only), Docker Compose.
- **Endpoints:**
  - `POST /v1/check/tool_output` `{session_id, tool_name, text}` → `{is_injection, score, action: allow|redact, latency_ms}`
  - `POST /v1/check/tool_call` `{session_id, tool_name, args}` → `{decision: allow|block, reason, tainted_args[]}`
  - `POST /v1/sessions` / `GET /v1/sessions/{id}/trace` for the provenance timeline and every decision
  - `GET /healthz`, `GET /metrics` (Prometheus format)
- **Caching:** LRU keyed by `sha256(text)` for detector calls.
- **Load test:** Locust, about 200 concurrent sessions on a laptop. Report RPS and p95/p99 for both endpoints, and state the hardware.
- **Demo deployment:** Hugging Face Spaces (Docker, free CPU tier). The page lets you paste an email or document and see the verdict, and replay a recorded AgentDojo trace showing the policy block. Record a GIF for the README in case the Space sleeps.

## 9. Repo skeleton

```
taintwall/
├── README.md                  # results table first, then architecture, then how to run
├── SPEC.md                    # this file
├── DECISIONS.md               # dated log: decision, options considered, why (interview prep)
├── LICENSE                    # Apache-2.0
├── pyproject.toml             # uv-managed; ruff, mypy, pytest config
├── uv.lock
├── Makefile                   # make dev | test | lint | eval-dev | eval-test | serve | loadtest
├── docker-compose.yml         # api + postgres (+ jaeger profile)
├── Dockerfile
├── .github/workflows/
│   ├── ci.yml                 # lint + mypy + unit + groundtruth policy tests + contamination audit
│   └── eval.yml               # workflow_dispatch only: small paid eval using a repo secret
├── src/taintwall/
│   ├── api/                   # FastAPI app, routes, schemas
│   ├── detector/              # model loading, inference, ONNX export, thresholds
│   ├── policy/                # registry loader, provenance store, normaliser, rules
│   ├── storage/               # Postgres repo layer, migrations (alembic)
│   ├── telemetry.py
│   └── adapters/agentdojo.py  # pipeline builders (section 5)
├── policies/                  # banking.yaml, slack.yaml, travel.yaml, workspace.yaml
├── training/
│   ├── build_dataset.py       # carriers × payloads × positions + hard negatives
│   ├── contamination_audit.py
│   ├── train.ipynb            # Colab; pinned versions
│   └── MODEL_CARD.md
├── eval/
│   ├── splits.json            # frozen dev/test user-task ids
│   ├── run_agentdojo.py       # CLI: --model --defense --split --attack
│   ├── stats.py               # bootstrap CIs, paired tests
│   └── make_report.py         # results/*.json → README table + plots
├── loadtest/locustfile.py
├── results/                   # committed JSON summaries only (raw logs gitignored)
└── tests/
    ├── unit/                  # normaliser, rules, schemas, cache
    ├── groundtruth/           # zero-cost AgentDojo checks, see below
    └── api/                   # FastAPI TestClient
```

**The zero-cost CI trick (no API spend):** AgentDojo ships ground-truth tool-call sequences for every user task and injection task.
- `tests/groundtruth/` replays them through the policy guard. Every benign user task's ground truth must be **allowed**, except a committed, explained list of known-blocked tasks (the measured utility cost).
- Every injection task's ground truth, with its sensitive arguments sourced from injected content, must be **blocked**.
- This makes policy regressions fail the PR without a single LLM call.

**Engineering standards:** ruff and ruff-format, mypy `--strict` on `src/`, pytest with ≥80% coverage on `policy/` and `api/`, pre-commit, conventional commits, and no data or model weights in git (weights go to the HF Hub).

## 10. Week-by-week plan

| Week | Deliverable | Definition of done |
|---|---|---|
| 1 | Repo + baselines | Skeleton, CI green, `splits.json` frozen. AgentDojo running with model (a) on the dev subset: no-defense BU/UA/ASR logged. Prompt Guard access requested. |
| 2 | Dataset | `build_dataset.py` produces the train/dev/test sets; contamination audit passes in CI. |
| 3 | Detector v1 | ModernBERT fine-tuned; AUROC and TPR@1%FPR vs both baselines on rings 1 and 2. Model on HF with a model card. |
| 4 | Service + L1 end-to-end | FastAPI `/check/tool_output` live in Compose; detector plugged into AgentDojo over HTTP; dev numbers for L1. **README with first results, then start applying.** |
| 5 | Policy L2 | Registries for all 4 suites, provenance store, guarded executor; groundtruth tests in CI. |
| 6 | Ablations | Dev runs of L1, L2 and L1+L2 for both models; pick final thresholds; **freeze config**. |
| 7 | Test runs | Full test-split runs (section 7 table) with paired stats. Costs logged. |
| 8 | Ops + robustness | Postgres traces, OpenTelemetry, Locust numbers. Stretch: one *adaptive* attack (paraphrase or encoding) registered via `register_attack` to show detector limits. |
| 9 | Polish | README (results table, plots, architecture diagram, limitations, "what I'd do next"), HF Space demo, GIF. |
| 10 | Write-up | Blog post (Medium, dev.to or your own site) plus a LinkedIn post. Send it to engineers at the target companies with a one-line ask. |

If you fall behind, cut in this order: adaptive attack → Jaeger → HF Space (keep the GIF) → second model on full test. **Never cut** the dev/test split, the CIs or the limitations section.

## 11. README results table (template)

| Model | Defense | BU ↑ | UA ↑ | ASR ↓ | p95 overhead |
|---|---|---|---|---|---|
| model-a | none | xx.x ± x.x | | | — |
| model-a | spotlighting | | | | |
| model-a | protectai detector | | | | |
| model-a | **taintwall L1+L2** | | | | |

Below the table:
- Error taxonomy: which injection tasks still succeed, and why.
- Detector false positives by carrier type.
- The list of benign tasks blocked by policy.

**Resume bullet:** fill it in only with real numbers.
> Built **taintwall**, a runtime firewall for tool-using LLM agents (Python, FastAPI, Postgres, Docker): cut AgentDojo attack success from **X% → Y%** while retaining **Z%** of benign utility (held-out test split, 95% CIs), at **N ms** p95 overhead; fine-tuned a ModernBERT detector for indirect injections reaching **T% TPR at 1% FPR** vs **B%** for the strongest public baseline.

## 12. Interview prep (fill in DECISIONS.md as you go)

Be ready to answer, without notes:
- **Why two layers?** The classifier is probabilistic and can be evaded by an adaptive attacker. The policy is deterministic but only covers flows you encoded, and it costs utility.
- **Why tune at FPR 1% instead of maximising F1?** Base rates: most tool outputs are benign, and every false positive breaks a user task.
- **How do you know there's no train/test leakage?** Point to the contamination audit, the frozen split and the dev-only tuning.
- **What happens with an IBAN that legitimately comes from a file?** Walk through the known-blocked list and the confirmation-flow or CaMeL alternatives.
- **What does the service do under load, and what would you change for 100× traffic?** Batching detector inference, async workers, moving the provenance store to Redis.
- **How was AI used in building this?** Say it straight: AI-assisted, but you designed every component and can rebuild the policy engine on a whiteboard.

## 13. Risks and rules

- **Clean room from SafeWorker.** SafeWorker started from course-provided code. Copy no files and no test suites from it. Reuse only ideas, and re-derive them here.
- **Write the core yourself:** `policy/` (normaliser, provenance, rules) and `eval/stats.py`. AI help is fine for boilerplate such as the FastAPI scaffolding, Docker and plots. You must be able to rebuild the core on a whiteboard.
- **Gated Prompt Guard:** if access isn't granted, drop that row and say so.
- **AgentDojo model enums are dated:** construct LLM elements directly (section 5).
- **Policy overfitting:** registries are written from schemas, tuning happens on dev only, and the config is frozen before test runs. Record the freeze commit hash in the README.
- **Secrets:** API keys only in `.env` (gitignored) and GitHub Actions secrets, with a secret scanner (gitleaks) in pre-commit.

## 14. Day-1 commands

```bash
brew install uv ollama
mkdir -p ~/projects/taintwall && cd ~/projects/taintwall && git init
uv init --package --name taintwall --python 3.12
uv add agentdojo fastapi "uvicorn[standard]" pydantic httpx openai anthropic
uv add --dev pytest pytest-cov ruff mypy pre-commit locust
ollama pull qwen3:8b   # or whichever tool-calling ~8B model you choose
```

References: AgentDojo, Debenedetti et al., NeurIPS 2024 D&B (arXiv 2406.13352) and github.com/ethz-spylab/agentdojo · CaMeL, "Defeating Prompt Injections by Design" (github.com/google-research/camel-prompt-injection) · BIPIA (github.com/microsoft/BIPIA) · InjecAgent (github.com/uiuc-kang-lab/InjecAgent) · Spotlighting (arXiv 2403.14720).
