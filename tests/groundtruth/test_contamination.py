"""Contamination audit as a CI gate (no network, no LLM).

Guards the L1 detector's central claim: no AgentDojo text enters training, so the
end-to-end AgentDojo numbers (ring 3) are out-of-distribution. The audit runs on
the committed sample (training/sample/sample.jsonl), which is regenerated from the
same builder as the full data. The full data/ files are gitignored, so CI can only
see the sample; the build step runs the audit on the full set before any training.

Two guards:
  - the committed sample must pass the audit;
  - the AgentDojo reference corpus fingerprint must equal the one recorded in the
    committed report, so an upstream AgentDojo change (new attack text or goal)
    fails the PR instead of silently weakening the audit.
"""

from __future__ import annotations

import json
from pathlib import Path

from training.contamination_audit import audit_rows, build_corpus, read_jsonl

REPO = Path(__file__).resolve().parents[2]
SAMPLE = REPO / "training" / "sample" / "sample.jsonl"
RECORDED_REPORT = REPO / "training" / "audit_report.json"


def test_committed_sample_has_no_agentdojo_overlap() -> None:
    corpus = build_corpus()
    result = audit_rows(read_jsonl([SAMPLE]), corpus)
    assert result["rows"] > 0, "sample is empty; run `uv run python -m training.build_dataset`"
    assert result["passed"], (
        f"sample shares AgentDojo text: {result['flagged_rows']} flagged rows "
        f"({result['flagged_by_corpus']}), {result['entity_rows']} entity rows "
        f"({result['entity_hits'][:5]})"
    )


def test_reference_corpus_fingerprint_is_pinned() -> None:
    """If this fails, the AgentDojo attack text or goals changed. Re-run the audit,
    inspect the diff, and only then update training/audit_report.json."""
    recorded = json.loads(RECORDED_REPORT.read_text())["corpus"]["fingerprint"]
    assert build_corpus().fingerprint() == recorded, (
        "AgentDojo reference corpus changed; the audit's gated set is no longer what was recorded. "
        "Re-run `uv run python -m training.contamination_audit data/*.jsonl --report training/audit_report.json`."
    )
