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

## 2026-10-20: L2 taint policy v1

- **Registry (`policies/*.yaml`) is written from tool schemas and descriptions only.** For each tool:
  - `source` (trusted or untrusted) says where its output comes from. Trusted means data the user owns or a system of record: contacts, account info, scheduled transactions, structured catalogs, channel and member lists. Untrusted means third-party content: emails, files, calendar events, reviews, messages, webpages, transaction subjects.
  - `effect` (write or external) and `sensitive` args mark where a hijacked agent could do harm: destinations, IBANs, URLs, passwords, reservation targets.
- **Rule:** block a call when a sensitive value appears only in untrusted data.
  - A value found nowhere is allowed, because it was produced by the agent, and an attacker's value must arrive through a tool output to exist.
  - A tool missing from the registry is blocked.
- **Dev error analysis led to field-level trust.** v0 trusted any substring of a trusted output, which let the slack attack through: the injection lives inside a *channel name*, and the channel list was trusted. Now a trusted output vouches only for whole field values, matched exactly after normalization. Text inside any field is untrusted. Dev slack attack success went from 6/10 to 0/12.
- **Dev led to protecting reservations.** Thanks to field-level trust, reservation targets can be sensitive without blocking benign bookings of catalog items. Dev travel went from 12/12 to 6/12. The rest is "book the most expensive hotel": the attacker computes a legitimate catalog item, which taint can't catch.
- **Accounting fix (eval code, not policy):** the ASR denominator is now *injectable* pairs, identical for every defense. It used to be pairs delivered in the defended run, which wrongly dropped pairs where the defense blocked the fetch of the injection.
- **Freeze:** the policy config was committed as `d8e79b6` before the first test run. Test results: attack success 325/335 → 44/335, benign utility 68/68 → 53/68.
- **Known limitations, documented and not tuned on test:**
  - delegation tasks are blocked; this would need a confirmation flow;
  - ID-based destructive calls are unprotected;
  - content payloads sent to trusted recipients need L1;
  - computed targets need intent checks (CaMeL).

## 2026-10-20: R2/R3 dev baselines on Gemini and OpenRouter

- **Free tiers are too small for a dev config.** Gemini: about 20 requests per day per model. OpenRouter free keys: 50 `:free` requests per day. One dev config needs 500-800 calls. Gemini billing was enabled and a $10 OpenRouter credit added (this unlocks 1000 free-model requests per day; `:free` models are not charged). Documented in `results/COSTS.md`.
- **R2 selection rule applied as written:** `gemini-3.1-flash-lite` 36/87 (41%) passes; `nvidia/nemotron-3.5-super-vl:free` 4/87 (4.6%) fails and gets no spotlighting run. R3 is `gemini-3.5-flash` (0/87, as expected).
- **R2 deviates from "free models only":** the one model that passed the headroom rule is a paid Gemini model. Dev only, so preliminary.

## 2026-10-20: L2 in live runs; ProtectAI in R1

- **`taintwall-l2` live defense** is a `ToolsExecutor` subclass (`PolicyToolsExecutor`). It calls `TaintPolicy.check(call, user_prompt, messages)` per call, in order, so a later call in a parallel batch sees the earlier results. A blocked call is not run; the model gets a tool result with `error="Blocked by policy: <reason>"`. Tools unknown to the runtime fall through to `ToolsExecutor`'s own invalid-tool error. The suite name is threaded through `run_suite` to load the registry. The policy itself is unchanged (`policies/` frozen at `d8e79b6`).
- **Live L2 dev results (preliminary):** R2 6/87 attack success (from 36/87), benign 24/29; R3 0/87, benign 25/29. All R2 successes are the travel "most expensive hotel" task, matching the documented limitation. Dev only; the test split has not been touched for live runs.
- **ProtectAI in R1** uses the same model and threshold as AgentDojo's baseline (`mode="message"`), plus 512-token truncation. CPU cost is contained by caching verdicts by text hash (`runs/protectai_cache.json`) and by a pass-through replay that collects every output first, so they are classified in batches before the real run.
- **ProtectAI + L2 raises benign utility over L2 alone (57 vs 53 of 68).** A redacted output cannot taint later arguments, so some L2 false positives disappear. Reported as is, with that explanation.
- **Cost note:** the live Gemini runs again used the billing-enabled key (see `results/COSTS.md`); about 5.5M tokens on flash-lite and 2.0M on flash for the L2 configs. No dollar figure is claimed.

## 2026-10-20: L1 dataset — carriers × permissive payloads, split on the span

- **Decision:** build the indirect-injection dataset by inserting one span into a
  benign carrier (email, invite, chat, note, invoice, review, web page). Positives
  are injection payloads; negatives are benign/hard inserts and untouched carriers.
  Both labels share the same carriers, positions and formatting wrappers, so the
  only class signal is the inserted text (`training/build_dataset.py`).
- **Why split on the span, not the row:** the train/dev/test bucket is a hash of the
  payload text (HF seeds) or the template id (synthetic inserts), and carriers are
  split independently on the same key space. So no payload or benign template ever
  appears in two splits. Tuning the detector threshold on dev therefore can't
  memorize a payload it will later be tested on.
- **Payload sources:** only `deepset/prompt-injections` (Apache-2.0),
  `Lakera/gandalf_ignore_instructions` (MIT), `reshabhs/SPML_Chatbot_Prompt_Injection`
  (MIT), `jackhhao/jailbreak-classification` (Apache-2.0). `xTRam1/safe-guard-prompt-injection`
  is excluded (no licence). Rows with conflicting labels across sources are dropped,
  not guessed.
- **Hard negatives are the point.** Benign text full of imperatives, payment details
  and URLs, plus benign uses of attack vocabulary ("ignore my previous email", "do
  not reply to this automated message"). Off-the-shelf detectors flag these; the
  dataset is designed so ours learns not to.
- **$0 and small-laptop constraints:** seeds and real carriers are *streamed* from
  the HF Hub at pinned revisions and capped (FineWeb-Edu `sample-10BT`, Amazon
  reviews), never fully downloaded. Full build is ~23.4k rows in under a minute.
  `data/` is gitignored; only a licence-clean 240-row sample is committed.
- **Known skew (documented, not hidden):** SPML (~16K rows) dominates both classes,
  so payload wording diversity is limited and the seeds are chatbot-style rather
  than agentic. Diversity comes from carriers/positions/formatting; the real test is
  the OOD rings and AgentDojo. Recorded in `training/MODEL_CARD.md`.
- **Result:** train 18,739 / dev 2,355 / test 2,333, ~51% positive each.

## 2026-10-20: Contamination audit as a CI gate — 8-gram + entity overlap vs AgentDojo

- **Decision:** `training/contamination_audit.py` builds a reference corpus from
  AgentDojo v1.2.2 (35 injection goals, 560 rendered attack strings across all
  registered attacks × injection tasks, 61 de-placeheldered templates) and fails if
  more than 0.1% of dataset rows share an 8-gram with it, or if **any** row contains
  an attacker email/URL/IBAN or the benchmark user's name.
- **Why this is the project's edge:** it turns "we didn't contaminate" from a claim
  into a test. Without it, a detector that had seen AgentDojo's attack text would be
  graded on its own homework, and the headline ASR number would be meaningless.
- **Design choices:**
  - *Word 8-grams after stripping punctuation/markup/whitespace*, so an attacker
    can't smuggle an overlap past the audit by HTML-commenting or re-quoting it, and
    generic 7-word English phrases don't trip it.
  - *Attacks are rendered, not just templated.* The gated set contains the exact
    strings AgentDojo plants (`attack.attack(user_task, injection_task)`), not only
    the `{goal}` templates, so paraphrase-free reuse is caught.
  - *Entities are substring-checked*, because a single token (an IBAN, an email)
    never forms an 8-gram but is still a leak.
  - *Informational corpora* (user prompts, the benign default environments) are
    reported but not gated: sharing a benign phrase like "let me know if you have
    any questions" with AgentDojo's emails is expected, not contamination.
- **CI:** runs on the committed sample (no network, no LLM) and pins the reference
  corpus **fingerprint** (`tests/groundtruth/test_contamination.py`), so an upstream
  AgentDojo change that alters attack text fails the PR instead of silently
  weakening the audit. The full build re-runs it before training (`make dataset`).
- **Result:** 0 / 23,427 rows flagged, 0 entity rows. Recorded in
  `training/audit_report.json` and surfaced in the README.

## 2026-10-20: Threshold chosen on dev for FPR ≤ 1%, notebook left un-run

- **Decision:** `training/train.ipynb` fine-tunes ModernBERT-base on a free Colab T4,
  picks the decision threshold as the (1 − 0.01) quantile of dev **negative** scores
  (lowest threshold with dev FPR ≤ 1%), freezes it, and only then measures the test
  split and the `protectai/deberta-v3-base-prompt-injection-v2` baseline.
- **Why FPR 1% instead of max F1:** base rates — most tool outputs are benign, so a
  2% FPR would break 1 in 50 benign tool calls, which destroys agent utility. TPR is
  reported *at* that FPR.
- **Why ModernBERT-base:** Apache-2.0, 149M params, 512-token window fits tool
  outputs, trains in minutes on a free T4. Ablation baseline `deberta-v3-small` (MIT).
- **Why the notebook is not run here:** $0 budget and no GPU on the work laptop; the
  task is to leave it ready, pinned and gated (Cell 3 refuses to train on
  contaminated data). The user runs it on Colab and fills the `TBD` metrics in the
  model card and README.

## 2026-10-21: L1 results. Wins in-distribution, loses on real agent injections

Trained on a Colab T4 with the frozen recipe (ModernBERT-base, 2 epochs, effective batch 32). The threshold was chosen on dev for FPR ≤ 1% and then frozen.

| | Synthetic test: TPR / FPR / AUROC | InjecAgent (OOD) AUROC |
|---|---|---|
| **taintwall L1** | **95.6% / 1.5% / 0.996** | 0.671 |
| ProtectAI (same dev-threshold rule) | 84.7% / 3.2% / 0.962 | **0.781** |

R1 worst case, test split (335 injectable pairs):

| Defense | Attack success | Benign utility |
|---|---|---|
| L1 | 154/335 | 68/68 |
| ProtectAI | 88/335 | — |
| L2 | 44/335 | 53/68 |
| **L1 + L2** | **26/335** | 53/68 |
| ProtectAI + L2 | 13/335 | 57/68 |

**What this means:**
- L1 beats ProtectAI on data shaped like its training set, but generalizes worse to real injections, both InjecAgent and AgentDojo's own.
- The training loss reached ~1e-4 early. The model learned artifacts of the synthetic carrier × payload construction rather than the concept.
- The detector to ship is ProtectAI + L2. L1 stays as a documented negative result about synthetic-data detectors.

**Not done, deliberately:**
- No re-tuning after seeing test or AgentDojo.
- Next steps if pursued: more diverse real carriers, adversarial paraphrases, and early stopping on an out-of-distribution validation set.

**Weights:** ~600 MB, left on Colab. Downloading them through the browser hangs. They are not needed for these results, because the replays ran on Colab next to the weights (`training/colab_l1_eval.sh`).
