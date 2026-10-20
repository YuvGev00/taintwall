# Decisions log

Each entry records what was decided, the alternatives, and why. Keep adding entries. This file is your interview prep.

---

## 2026-10-19: Split both axes (user tasks and injection tasks), 30/70, frozen

- **Decision:** dev pairs = dev users × dev injections; test pairs = test users × test injections. The ids are ranked by `sha256(salt:suite:axis:id)`, giving 29 dev / 68 test users and 11 dev / 24 test injections.
- **Alternative:** split only user tasks, with every injection task in both splits.
- **Why:**
  - The policy and detector are tuned on dev. If injection *goals* such as attacker IBANs and email addresses appear in dev, tuning can quietly overfit to them.
  - Splitting both axes means test results measure injections the defense has never seen.
- **Cost:** cross pairs (dev user × test injection and the reverse) are unused, about 42% of the 949 pairs. Test still has 461 pairs, and dev has 87, which keeps dev runs cheap.
- **Guard:** `tests/unit/test_splits.py` regenerates the split and fails if it differs from `eval/splits.json`.
- **Known quirk:** by chance, all four workspace dev injection tasks (10–13) come from the v1.2 additions, which are MEDIUM/HARD multi-step goals. Expect a low workspace ASR on dev. Don't "fix" this by re-salting the split, because that would be split-shopping.

## 2026-10-19: Our own LLM element instead of AgentDojo's `--model` enum

- **Decision:** `DeterministicOpenAILLM(openai.OpenAI(base_url=...), model)` for any OpenAI-compatible server.
- **Why:** `ModelsEnum` in agentdojo 0.1.35 stops at 2025-era models.
- **Bug found:** upstream `chat_completion_request` sends `temperature=temperature or NOT_GIVEN`. A temperature of `0.0` is falsy, so it is never sent and the server default applies (Qwen3's default sampling is not greedy). Our subclass sends it explicitly, and `tests/unit/test_adapter.py` pins this.
- **Correction (2026-10-20):** upstream already fixed this on `main` in [#141](https://github.com/ethz-spylab/agentdojo/pull/141), merged 2026-02-03. No PyPI release contains the fix, because the latest is 0.1.35 (2025-10-27). The workaround stays while we pin 0.1.35, and the finding is "the released package drops temperature=0", not a new bug.

## 2026-10-19: Register new models in `agentdojo.models.MODEL_NAMES`

- **Problem:** `important_instructions` addresses the model by name ("…to you, Qwen"). It finds the name by substring-matching `pipeline.name` against `MODEL_NAMES` and raises an error for unknown models.
- **Decision:** register `model_id → prose name` at pipeline build time.
- **Why:** this keeps the attack text identical to the paper's.
- **Rejected alternative:** switching to `important_instructions_no_model_name`, which is a different attack.

## 2026-10-19: Dev model = `qwen3:8b` via Ollama, thinking ON, 16K context

- **Why local:** the work machine is an M2 Pro with 16 GB RAM, and no API keys are set up yet. Local runs are free and fine for the 116-episode dev subset.
- **Thinking mode:**
  - With thinking off (`reasoning_effort="none"`), each call is about 8x faster, but the model narrates a plan and stops without emitting a tool call: 0/2 on the banking smoke test.
  - With thinking on, it scored 2/3 on the smoke test at about 70 s per episode.
  - The flag is kept in the run name (`-nothink`) so the two configs never share a trace cache.
- **Context length:** Ollama is started with `OLLAMA_CONTEXT_LENGTH=16384`. AgentDojo system prompts, tool schemas and tool outputs can exceed the 4096-token default, and Ollama truncates silently.
- **Full test runs:** use a hosted endpoint (`--provider openai-compatible`). Budget per SPEC §7.

## 2026-10-19: Empty ground truths in 9 injection tasks (workspace 6–13, travel 6)

- **Finding:** agentdojo 0.1.35 ships `ground_truth() -> []` for workspace 6–13 and travel 6 (independently reported in [#208](https://github.com/ethz-spylab/agentdojo/issues/208)), so `suite.check()` reports them as failing. Their `security()` functions are real: injection task 10, for example, checks for one trashed email to the attacker containing all 26 files. Live ASR on these tasks is therefore valid.
- **Decision:** pin the exact failing set in `tests/groundtruth/test_harness.py`, so an upstream change shows up as a test failure.
- **Week 5 consequence:** the policy ground-truth tests can't use these 8 tasks. Write hand-made "attacker call sequences" for them instead.

## 2026-10-19: CI runs no LLM

- **Decision:** lint, `mypy --strict`, unit tests and ground-truth replays. These are deterministic, free, and need no secrets.
- **Paid evals:** a future `workflow_dispatch` job will use a repo secret and run on demand only, never on PRs from forks.

## 2026-10-20: Three evaluation regimes, because frontier models leave no headroom

- **Evidence:** [#201](https://github.com/ethz-spylab/agentdojo/issues/201) reports 0/560 attack success on claude-sonnet-4-6 with no defense. [#208](https://github.com/ethz-spylab/agentdojo/issues/208) reports 0.0% on Haiku 4.5 and Sonnet 4.5 (banking). On such models the attack never lands, so a defense's ASR says nothing about the defense.
- **Decision** (SPEC §7):
  - **R1, model-free hijacked-agent replay:** the primary security metric for the policy. It is deterministic and free.
  - **R2, live runs on models that do fall for the attack:** a model is kept only if its no-defense ASR is at least 20% on dev.
  - **R3, utility cost on claude-haiku-5-5:** its ASR is reported as "≈0 without defense too".
- **Accounting rule from #208:** score only pairs where the injection was actually delivered, so a defense that blocks delivery isn't counted as a successful attack.
- **Rejected:** a Sonnet-class headline run. It would cost about $85 and would almost certainly measure the model rather than the defense.
- **Credit:** #208's author independently built the same ground-truth replay we planned for CI. Cite it in the README.

## 2026-10-20: Our own Claude element; upstream AnthropicLLM can't call current models

- **Finding:** agentdojo's `AnthropicLLM` (0.1.35 and `main` @089ed468c) always sends `temperature=0.0`, and a `budget_tokens` thinking config when thinking is on.
  - Opus 5.5 and Fable 5.1 reject any `temperature` (400).
  - Haiku 5.5 and Sonnet 5.5 reject non-default sampling values (400).
  - `budget_tokens` is rejected on all of them.
  - So the benchmark can't run any current Claude model without changes.
- **Decision:** `ClaudeLLM` subclasses AgentDojo's element and overrides only the request: no sampling parameters, adaptive thinking (or none), and an explicit `output_config.effort`. Thinking blocks are passed back unchanged, which AgentDojo's converters already do with signatures.
- **Upstream contribution:** a PR making `AnthropicLLM` omit sampling parameters when `temperature=None` and support `{"type": "adaptive"}` + effort. Hold it until it has been verified against the live API.

## 2026-10-20: $0 by default

- **Decision:**
  - All regimes run on free tiers: Gemini API free tier for R3, OpenRouter `:free` tool-calling models for R2, Colab for detector training.
  - Claude (existing credit) is an optional comparison row only.
- **Why:**
  - Hiring signal comes from measurement quality, not spend.
  - Both free providers are OpenAI-compatible, so they need no new code.
- **Trade-offs:**
  - Rate limits make runs slower, so they run overnight and resume.
  - `:free` model availability changes, so exact model ids and dates are logged with every result.
  - The Gemini free tier uses content to improve Google's products. Fine for AgentDojo's synthetic environments; never for private data.

## 2026-10-20: R1 replay design details

- **Delivery check: whitespace-insensitive search of the raw tool-result strings.**
  - Environments are YAML templates, so an injected string's whitespace can change on load.
  - Exact matching against the formatted output found the injection in **0 of 97** user tasks.
  - Whitespace-normalized matching against the formatted output found 74 of 97.
  - Matching the raw result strings with whitespace removed found **97 of 97**.
- **Plugs into AgentDojo's own scoring.** `HijackedReplay` is a pipeline element run through `TaskSuite.run_task_with_pipeline`, so the trace-based checkers apply unchanged: 7 workspace and 5 slack user tasks, plus slack injection_task_5.
- **Blocked calls are kept out of the trace.** Otherwise a trace-based checker would score an attempted-but-blocked call as a successful attack (upstream #168). A test pins this with a block-everything defense.
- **The attacker phase runs only when the injection was delivered and not redacted.** A defense that redacts the carrying output therefore stops the attack. Pairs where nothing was delivered are excluded from the ASR denominator (#208).
- **Utility under hijack is not reported.** The attacker's extra actions break strict utility checks: travel 0/56, workspace 0/168. R1 reports benign utility (the defense's false-positive cost) and ASR.
- **No-defense ceiling: 325/335 = 97.0% (test).** Ten delivered pairs fail even for a fully obedient agent (banking ×2 on injection_task_8, travel ×2 on injection_task_2, workspace ×6 on injection_task_0). Their user tasks change state that the attack goal depends on. Left as is and documented.
- **Workspace dev has 0 R1 pairs.** All four of its dev injection tasks have empty ground truths. Not re-salted (split-shopping). Workspace is covered by R1 test and by R2/R3.
