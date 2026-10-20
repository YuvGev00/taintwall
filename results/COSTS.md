# Live-run costs and provenance

Dev split only (87 attacked pairs, 29 benign tasks per config), attack `important_instructions`,
AgentDojo v1.2.2, temperature 0. All runs on 2026-10-20 (UTC), via `taintwall.eval.run_agentdojo --provider openai-compatible`.
Token counts are summed over every call logged in `runs/usage/` (resumed sessions included; the
3-episode smoke tests of each model are included too).

| Regime | Model id | Endpoint | Defense | Calls | Prompt tokens | Completion tokens | Wall time |
|---|---|---|---|---|---|---|---|
| R3 | `gemini-3.5-flash` | Gemini OpenAI-compatible | none | 485 | 1,906,494 | 31,360 | 30 min |
| R3 | `gemini-3.5-flash` | Gemini OpenAI-compatible | spotlighting | 478 | 1,931,362 | 29,335 | 30 min |
| R2 | `gemini-3.1-flash-lite` | Gemini OpenAI-compatible | none | 779 | 5,470,555 | 36,472 | 12 min |
| R2 | `gemini-3.1-flash-lite` | Gemini OpenAI-compatible | spotlighting | 720 | 4,224,618 | 30,316 | 11 min |
| R2 (excluded, ASR 4.6% < 20%) | `nvidia/nemotron-3.5-super-vl:free` | OpenRouter | none | 615 | 2,442,837 | 150,639 | 62 min |

## Money

- **Gemini:** billed on a paid (Tier 1) account. The free tier allows about 20 requests per day per model, which is far below the ~500-800 calls one dev config needs. The exact charge is in the Google AI Studio billing console; it is not read by this repo, so no dollar figure is claimed here.
- **OpenRouter:** `:free` models are not charged ($0 usage on the key). A $10 credit balance was added only because free-tier keys are capped at 50 free-model requests per day; with credits the cap is 1000 per day.
- **Anthropic:** not used.

## Notes

- Gemini 3 models require each tool call's `thought_signature` to be echoed back; the adapter does that.
- OpenRouter sometimes answers a rate-limited request with a 200 and no `choices`; the adapter retries those. The first Nemotron run crashed on this and was resumed (AgentDojo skips finished episodes).
- `gemini-2.5-flash` is closed to new users; `gemini-3.5-flash` was used as "Gemini Flash".
