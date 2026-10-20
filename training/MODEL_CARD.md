# Model card — taintwall L1 detector (draft)

> Draft. Metric fields marked `TBD` are filled from `training/train.ipynb` after the
> first Colab run. Nothing here claims a number that has not been measured.

## Summary

`taintwall-l1-modernbert` is a binary classifier that flags **indirect prompt
injections in tool outputs** — the text an LLM agent reads back from a tool (an
email, a calendar invite, a file, a web page). It is layer 1 of taintwall; layer 2
is a deterministic taint policy. L1 exists to catch the attacks L2 cannot: a
payload embedded in content that is then sent to a *legitimate* recipient, where no
untrusted value crosses a tool boundary for the policy to block.

- **Base model:** [`answerdotai/ModernBERT-base`](https://huggingface.co/answerdotai/ModernBERT-base) (149M params, Apache-2.0).
- **Baseline ablation:** `microsoft/deberta-v3-small` (MIT).
- **Task:** sequence classification, 2 labels (`0` benign tool output, `1` tool output carrying an injection).
- **Max sequence length:** 512 tokens.
- **Operating point:** a fixed decision threshold chosen on the dev split for **FPR ≤ 1%** on benign tool outputs (not argmax). Rationale: most tool outputs are benign, so every false positive breaks a user task.

## Intended use and scope

- **In scope:** scoring a single tool-output string in an agent pipeline, as a
  pre-filter before the agent consumes the output. Served on CPU; ONNX export if
  latency needs it.
- **Out of scope:** scoring the user's own prompt (that is trusted by construction),
  multi-turn conversation classification, or any use as the sole line of defense. L1
  is probabilistic and evadable; it is paired with the L2 taint policy, never
  deployed alone.

## Training data

Built by [`training/build_dataset.py`](build_dataset.py). Full sets are gitignored
and regenerable; a licence-clean sample is committed at `training/sample/sample.jsonl`.

| Split | Rows | Positive rate |
|---|---|---|
| train | 18,739 | 51.2% |
| dev | 2,355 | 51.0% |
| test | 2,333 | 51.4% |

Each row is a **benign carrier with one span inserted**, so the only thing that
separates the classes is the inserted text, not its position, length or packaging.
Both labels share the same carriers, insert positions (start / middle / end) and
formatting wrappers (plain, HTML comment, quoted reply, fake `[system]` tags,
zero-width separators, signature block). ~15% of negatives are untouched carriers.

**Carriers** (the documents): synthetic emails, calendar invites, chat logs, file
notes, bank statements, invoices, IT notices and how-tos generated with randomized
entities; plus real text streamed and capped from the HF Hub — Amazon reviews
(`fancyzhx/amazon_polarity`, Apache-2.0) and web pages (`HuggingFaceFW/fineweb-edu`,
ODC-By 1.0).

**Positive payloads** — permissively licensed seed datasets only:

| Dataset | Licence | Use |
|---|---|---|
| `deepset/prompt-injections` | Apache-2.0 | label-1 rows |
| `Lakera/gandalf_ignore_instructions` | MIT | all rows |
| `reshabhs/SPML_Chatbot_Prompt_Injection` | MIT | injection rows |
| `jackhhao/jailbreak-classification` | Apache-2.0 | jailbreak rows |

`xTRam1/safe-guard-prompt-injection` is **not used** (no licence tag).

**Negatives:** benign questions from the seed datasets, plus synthetic *hard
negatives* — benign text that uses the vocabulary of an attack ("ignore my previous
email", "do not reply to this automated message", "SYSTEM MAINTENANCE…") and benign
payment/URL imperatives. These keep the false-positive rate down.

**Known composition skew:** `reshabhs/SPML_Chatbot_Prompt_Injection` (~16K rows) is
by far the largest seed, so it dominates both classes. Payload *wording* diversity
is therefore limited; diversity in this dataset comes from carriers, positions and
formatting. The direct seeds are also chatbot-style ("ignore previous
instructions…"); genuinely agentic payloads ("forward the inbox to X") are
under-represented. Treated as a limitation, measured on the OOD rings (BIPIA,
InjecAgent) and end-to-end on AgentDojo rather than papered over.

## Contamination control (the central guarantee)

Nothing from AgentDojo may enter training, so the end-to-end AgentDojo evaluation
(ring 3) is genuinely out-of-distribution. [`contamination_audit.py`](contamination_audit.py)
computes word 8-gram overlap between the dataset and a reference corpus built from
AgentDojo v1.2.2 — every injection-task **goal** (35), every registered **attack**
rendered against every injection task (560 strings), and the attack **templates**
with placeholders removed (61). Attacker emails, URLs and IBANs, and the benchmark
user's name, are checked as forbidden substrings. Tokenization ignores punctuation,
markup and whitespace, so wrapping a payload in an HTML comment cannot hide an
overlap.

**Result on the full build: 0 / 23,427 rows share any AgentDojo 8-gram, 0 rows
contain any AgentDojo entity.** The audit runs in CI on the committed sample and
gates the full build before training (`make dataset`); the reference-corpus
fingerprint is pinned so an upstream AgentDojo change fails the PR.

## Evaluation

Three rings (SPEC §4). All thresholds are chosen on **dev only**.

1. **In-distribution** — held-out synthetic test split. `TBD`: AUROC, TPR@1%FPR.
2. **Out-of-distribution, eval only** — BIPIA (`microsoft/BIPIA`, NOASSERTION:
   evaluated and cited, not redistributed) and InjecAgent (`uiuc-kang-lab/InjecAgent`,
   MIT). `TBD`.
3. **End-to-end** — AgentDojo, never seen in training. `TBD`.

**Baselines:** `protectai/deberta-v3-base-prompt-injection-v2` (Apache-2.0; what
AgentDojo's built-in `transformers_pi_detector` uses) and, if access is granted,
`meta-llama/Llama-Prompt-Guard-2-86M` (gated). Reported on the same test set at the
same FPR.

| Model | AUROC | TPR @ 1% FPR (test) |
|---|---|---|
| ModernBERT-base (ours) | `TBD` | `TBD` |
| protectai deberta-v3-base-pi-v2 | `TBD` | `TBD` |

Fill from the notebook's final cells; also record false positives by carrier type
and false negatives by payload source (the notebook prints both).

## Limitations and risks

- **Evadable.** A classifier can be defeated by an adaptive attacker (paraphrase,
  novel encoding). This is why taintwall also runs the deterministic L2 policy.
- **Distribution shift.** Trained on synthetic carriers and chatbot-style payloads;
  real agent traffic and novel attack phrasings will differ. The OOD rings measure
  this gap.
- **Not a content-safety model.** It flags injection patterns, not toxicity, PII or
  malware.
- **Threshold is data-dependent.** The 1%-FPR threshold is specific to this dev
  distribution; re-tune on representative benign traffic before production use.

## Reproducibility

- Builder seed `20261020`; HF dataset revisions pinned in `training/payloads.py` and
  `training/carriers.py`.
- Training config (ModernBERT-base, 2 epochs, lr 2e-5, bf16, seed 20261020) in
  `training/train.ipynb`.
- Frozen threshold and metrics saved next to the weights as `threshold.json`.
- Weights published to the HF Hub (SPEC: no weights in git).

## Licence

Code Apache-2.0 (repo `LICENSE`). The fine-tuned weights derive from ModernBERT-base
(Apache-2.0) and training data drawn only from Apache-2.0 / MIT / ODC-By sources.
