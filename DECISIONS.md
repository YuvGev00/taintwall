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
- **Follow-up:** this is worth an upstream issue or PR to ethz-spylab/agentdojo, a small open-source contribution.

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

## 2026-10-19: Empty ground truths in workspace injection tasks 6–13

- **Finding:** agentdojo 0.1.35 ships `ground_truth() -> []` for these v1.2 tasks, so `suite.check()` reports them as failing. Their `security()` functions are real: injection task 10, for example, checks for one trashed email to the attacker containing all 26 files. Live ASR on these tasks is therefore valid.
- **Decision:** pin the exact failing set in `tests/groundtruth/test_harness.py`, so an upstream change shows up as a test failure.
- **Week 5 consequence:** the policy ground-truth tests can't use these 8 tasks. Write hand-made "attacker call sequences" for them instead.

## 2026-10-19: CI runs no LLM

- **Decision:** lint, `mypy --strict`, unit tests and ground-truth replays. These are deterministic, free, and need no secrets.
- **Paid evals:** a future `workflow_dispatch` job will use a repo secret and run on demand only, never on PRs from forks.
