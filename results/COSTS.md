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
| R3 | `gemini-3.5-flash` | Gemini OpenAI-compatible | taintwall-l2 | 510 | 2,045,361 | 31,641 | 33 min |
| R2 | `gemini-3.1-flash-lite` | Gemini OpenAI-compatible | taintwall-l2 | 864 | 5,450,762 | 41,050 | 13 min |
| R2 (excluded, ASR 4.6% < 20%) | `nvidia/nemotron-3.5-super-vl:free` | OpenRouter | none | 615 | 2,442,837 | 150,639 | 62 min |

## Money

- **Gemini:** billed on a paid (Tier 1) account. The free tier allows about 20 requests per day per model, which is far below the ~500-800 calls one dev config needs. The exact charge is in the Google AI Studio billing console; it is not read by this repo, so no dollar figure is claimed here.
- **OpenRouter:** `:free` models are not charged ($0 usage on the key). A $10 credit balance was added only because free-tier keys are capped at 50 free-model requests per day; with credits the cap is 1000 per day.
- **Anthropic:** not used.

## Notes

- Gemini 3 models require each tool call's `thought_signature` to be echoed back; the adapter does that.
- OpenRouter sometimes answers a rate-limited request with a 200 and no `choices`; the adapter retries those. The first Nemotron run crashed on this and was resumed (AgentDojo skips finished episodes).
- `gemini-2.5-flash` is closed to new users; `gemini-3.5-flash` was used as "Gemini Flash".

## Test-split cost estimate (2026-10-21, before any test run)

Measured on 20 test episodes (banking, 4 user tasks x 5 injection tasks, no defense, temperature 0):
`gemini-3.1-flash-lite` 368,036 prompt / 5,787 completion tokens (144 calls); `gemini-3.5-flash` 160,680 / 3,443 (74 calls).
Banking is the lightest suite, so the projection below instead scales the per-config dev totals above by test/dev episode count (403 / 116 = 3.47).
List prices (third-party aggregators, not read from Google's console): flash-lite $0.25 in / $1.50 out per M tokens; 3.5-flash $1.50 / $9.00.

| Config | Projected prompt tokens | Projected $ |
|---|---|---|
| R2 flash-lite none | 19.0 M | 4.8 |
| R2 flash-lite spotlighting | 14.7 M | 3.7 |
| R2 flash-lite protectai (assumed = none) | 19.0 M | 4.8 |
| R2 flash-lite taintwall-l2 | 18.9 M | 4.8 |
| R3 3.5-flash none | 6.6 M | 11.4 |
| R3 3.5-flash taintwall-l2 | 7.1 M | 11.9 |
| **Total** | **85 M** | **about 41** |

This exceeds the ~$15 budget, so the full test runs wait for approval.
