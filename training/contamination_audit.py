"""Contamination audit: no AgentDojo text may enter the L1 detector's data.

AgentDojo is ring 3 of the detector evaluation (SPEC §4), so a detector that has
seen AgentDojo's injection text in training would be graded on its own homework.
This script builds a reference corpus from the pinned benchmark version and
measures word 8-gram overlap with a JSONL dataset (one {"text": ...} per line).

Gated corpora (any overlap here counts against the threshold):
  - goals:     every injection task's GOAL, in every suite.
  - attacks:   every registered attack rendered against every injection task, i.e.
               the exact strings AgentDojo plants in tool outputs.
  - templates: the attack templates with their {placeholders} cut out, so the
               fixed wording is checked independently of any goal.
  - entities:  attacker emails, URLs and IBANs from the above. A single token would
               never form an 8-gram, so these are checked as substrings.

Informational corpora (reported, not gated): user-task prompts and the default
environments (the benign emails, files and reviews AgentDojo's tool outputs are
made of). Generic phrases such as "let me know if you have any questions" are
expected to be shared with any English text; the report lists them for a human.

Run:  uv run python -m training.contamination_audit data/train.jsonl data/dev.jsonl data/test.jsonl
Exit status 1 when the dataset fails, so it can gate CI and the build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.attacks.attack_registry import ATTACKS
from agentdojo.attacks.base_attacks import BaseAttack, FixedJailbreakAttack
from agentdojo.task_suite.load_suites import get_suites

BENCHMARK_VERSION = "v1.2.2"  # must match taintwall.eval.splits.BENCHMARK_VERSION
NGRAM = 8
# "Tiny threshold": at most 1 row in 1,000 may share any gated 8-gram, and no row may
# contain a gated entity. The committed report shows the real numbers (0 at build time).
MAX_FLAGGED_ROW_RATE = 0.001
MAX_ENTITY_ROWS = 0

REPO = Path(__file__).resolve().parents[1]
REPORT_PATH = REPO / "training" / "audit_report.json"

# `manual` reads its injections from stdin, so there is nothing to render.
SKIPPED_ATTACKS = {"manual"}
# Attacks address the model by name; any name in agentdojo.models.MODEL_NAMES works.
STUB_PIPELINE_NAME = "gpt-4o-2024-05-13"

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL = re.compile(r"(?:https?://|www\.)[^\s'\"<>]+")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_PLACEHOLDER = re.compile(r"\{\w+\}")


def tokens(text: str) -> list[str]:
    """Lowercased alphanumeric words. Punctuation, markup and whitespace are ignored,
    so wrapping a payload in an HTML comment or a quote block can't hide an overlap."""
    return re.findall(r"[a-z0-9]+", unicodedata.normalize("NFKC", text).lower())


def ngrams(text: str, n: int = NGRAM) -> set[str]:
    toks = tokens(text)
    return {" ".join(toks[i : i + n]) for i in range(len(toks) - n + 1)}


# --------------------------------------------------------------------------- corpus


class _StubPipeline(BasePipelineElement):
    """Attacks only read the pipeline's name (to address the model); they never run it."""

    name = STUB_PIPELINE_NAME

    def query(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


def _render_attack(attack: BaseAttack, suite: Any) -> Iterator[str]:
    """Yield the strings `attack` plants for every injection task of `suite`.

    The injected text depends only on the injection task, not on the user task, so
    one injectable user task per suite is enough."""
    for user_task in suite.user_tasks.values():
        try:
            attack.get_injection_candidates(user_task)
        except ValueError:  # not injectable
            continue
        for injection_task in suite.injection_tasks.values():
            yield from attack.attack(user_task, injection_task).values()
        return


def _strings_in(obj: Any) -> Iterator[str]:
    """Every string inside a (pydantic) environment, recursively."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings_in(v)
    elif isinstance(obj, list | tuple | set):
        for v in obj:
            yield from _strings_in(v)


@dataclass
class Corpus:
    gated: dict[str, list[str]] = field(default_factory=dict)
    info: dict[str, list[str]] = field(default_factory=dict)
    entities: set[str] = field(default_factory=set)

    def ngram_index(self, which: str) -> dict[str, str]:
        """8-gram -> name of the first corpus it came from."""
        corpora = self.gated if which == "gated" else self.info
        index: dict[str, str] = {}
        for name, texts in corpora.items():
            for text in texts:
                for g in ngrams(text):
                    index.setdefault(g, name)
        return index

    def fingerprint(self) -> str:
        """Hash of everything gated, so CI notices when the benchmark text changes."""
        payload = json.dumps(
            {"ngrams": sorted(self.ngram_index("gated")), "entities": sorted(self.entities)},
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()


def extract_entities(texts: Iterable[str]) -> set[str]:
    found: set[str] = set()
    for text in texts:
        for pattern in (_EMAIL, _URL, _IBAN):
            found.update(m.group(0).rstrip(".,;:)'\"").lower() for m in pattern.finditer(text))
    return found


@lru_cache(maxsize=2)
def build_corpus(benchmark_version: str = BENCHMARK_VERSION) -> Corpus:
    suites = get_suites(benchmark_version)
    corpus = Corpus()
    corpus.gated["goals"] = [t.GOAL for s in suites.values() for t in s.injection_tasks.values()]

    rendered: list[str] = []
    templates: list[str] = []
    for attack_name, attack_cls in sorted(ATTACKS.items()):
        if attack_name in SKIPPED_ATTACKS:
            continue
        for suite in suites.values():
            attack = attack_cls(suite, _StubPipeline())
            rendered.extend(_render_attack(attack, suite))
        template = attack.jailbreak if isinstance(attack, FixedJailbreakAttack) else getattr(attack, "_DOS_STRING", "")
        templates.extend(_PLACEHOLDER.split(template))
    corpus.gated["attacks"] = rendered
    corpus.gated["templates"] = [t for t in templates if t.strip()]

    corpus.entities = extract_entities(corpus.gated["goals"] + rendered)
    # The attacks sign as the benchmark's user; a carrier mentioning her would be a leak too.
    corpus.entities.add("emma johnson")

    corpus.info["user_prompts"] = [t.PROMPT for s in suites.values() for t in s.user_tasks.values()]
    environments: list[str] = []
    for suite in suites.values():
        env = suite.load_and_inject_default_environment({})
        environments.extend(_strings_in(env.model_dump()))
    corpus.info["environment"] = environments
    return corpus


# --------------------------------------------------------------------------- audit


def read_jsonl(paths: Iterable[Path]) -> Iterator[dict[str, Any]]:
    for path in paths:
        with path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit_rows(rows: Iterable[dict[str, Any]], corpus: Corpus, top_k: int = 20) -> dict[str, Any]:
    """Overlap statistics for `rows`; result["passed"] says whether they may be used."""
    gated, info = corpus.ngram_index("gated"), corpus.ngram_index("info")
    n_rows = flagged = entity_rows = info_rows = 0
    flagged_by_corpus: Counter[str] = Counter()
    shared_gated: Counter[str] = Counter()
    shared_info: Counter[str] = Counter()
    entity_hits: Counter[str] = Counter()
    flagged_ids: list[str] = []

    for row in rows:
        n_rows += 1
        text = row["text"]
        grams = ngrams(text)
        hits = grams & gated.keys()
        if hits:
            flagged += 1
            flagged_by_corpus.update({gated[g] for g in hits})
            shared_gated.update(hits)
            flagged_ids.append(str(row.get("id", n_rows)))
        lowered = unicodedata.normalize("NFKC", text).lower()
        ents = {e for e in corpus.entities if e in lowered}
        if ents:
            entity_rows += 1
            entity_hits.update(ents)
        info_hits = grams & info.keys()
        if info_hits:
            info_rows += 1
            shared_info.update(info_hits)

    rate = flagged / n_rows if n_rows else 0.0
    return {
        "rows": n_rows,
        "ngram": NGRAM,
        "flagged_rows": flagged,
        "flagged_row_rate": rate,
        "flagged_by_corpus": dict(flagged_by_corpus),
        "flagged_ids": flagged_ids[:top_k],
        "top_shared_gated_ngrams": shared_gated.most_common(top_k),
        "entity_rows": entity_rows,
        "entity_hits": entity_hits.most_common(top_k),
        "info_rows_sharing_any_ngram": info_rows,
        "top_shared_info_ngrams": shared_info.most_common(top_k),
        "thresholds": {"max_flagged_row_rate": MAX_FLAGGED_ROW_RATE, "max_entity_rows": MAX_ENTITY_ROWS},
        "passed": rate <= MAX_FLAGGED_ROW_RATE and entity_rows <= MAX_ENTITY_ROWS,
    }


def corpus_summary(corpus: Corpus) -> dict[str, Any]:
    return {
        "benchmark_version": BENCHMARK_VERSION,
        "fingerprint": corpus.fingerprint(),
        "gated_texts": {k: len(v) for k, v in corpus.gated.items()},
        "gated_ngrams": len(corpus.ngram_index("gated")),
        "entities": len(corpus.entities),
        "info_texts": {k: len(v) for k, v in corpus.info.items()},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("files", nargs="+", type=Path, help="JSONL files with a 'text' field")
    parser.add_argument("--report", type=Path, help=f"write a JSON report (the build writes {REPORT_PATH.name})")
    args = parser.parse_args(argv)

    corpus = build_corpus()
    result = audit_rows(read_jsonl(args.files), corpus)
    report = {
        "corpus": corpus_summary(corpus),
        "files": {_display(p): sha256_file(p) for p in args.files},
        "result": result,
    }
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    verdict = "PASS" if result["passed"] else "FAIL"
    print(
        f"{verdict}: {result['flagged_rows']}/{result['rows']} rows share an AgentDojo {NGRAM}-gram "
        f"(rate {result['flagged_row_rate']:.4%}, max {MAX_FLAGGED_ROW_RATE:.2%}); "
        f"{result['entity_rows']} rows contain an AgentDojo entity (max {MAX_ENTITY_ROWS})."
    )
    if not result["passed"]:
        print("top shared n-grams:", result["top_shared_gated_ngrams"][:10])
        print("entity hits:", result["entity_hits"][:10])
    return 0 if result["passed"] else 1


def _display(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO))
    except ValueError:
        return str(path)


if __name__ == "__main__":
    sys.exit(main())
