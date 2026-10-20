"""Build the L1 detector's indirect-injection dataset (SPEC §4).

Each row is a benign *carrier* (an email, invite, chat log, note, invoice, review
or web page) with one span inserted into it:

    label 1  an injection payload (direct-injection seed from the HF Hub), so the
             row is a realistic tool output carrying an attack;
    label 0  a benign or hard-negative insert, so the row is a realistic tool
             output that merely looks instruction-heavy.

Both labels are produced the same way — pick a carrier, pick an insert position,
pick a formatting wrapper — so the only thing that separates the classes is the
inserted text itself, not its position, length or packaging. Negatives also
include untouched carriers, so "clean document" is in-distribution too.

The train/dev/test split is keyed on the *span* (payload text or benign template),
not on the row, so no payload or template ever appears in more than one split.
Carriers are split independently on the same key space. Output is 50/50 balanced
within each split and written to data/ (gitignored); a small, licence-clean
sample is written to training/sample/ and committed.

Run:  uv run python -m training.build_dataset            # ~24k rows, streams from HF
      uv run python -m training.build_dataset --target 2000 --no-hf-carriers --sample-only
"""

from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

from training.carriers import Carrier, SyntheticCarriers, stream_amazon_reviews, stream_web_pages
from training.payloads import Span, dedupe, stable_hash, stream_hf_spans, synthetic_template_groups

REPO = Path(__file__).resolve().parents[1]
DATA_DIR = REPO / "data"
SAMPLE_DIR = REPO / "training" / "sample"
SPLITS = ("train", "dev", "test")
SPLIT_WEIGHTS = {"train": 0.8, "dev": 0.1, "test": 0.1}
SALT = "taintwall-l1-v1"
SEED = 20261020


@dataclass(frozen=True)
class Row:
    text: str
    label: int
    split: str
    carrier_kind: str
    carrier_source: str
    span_source: str
    position: str  # start | middle | end | none
    formatting: str  # the wrapper used (plain, html_comment, quoted, ...)


# --------------------------------------------------------------------------- split assignment


def assign_split(key: str) -> str:
    """Deterministic split from a hash of the span/carrier key. Keeps train/dev/test at
    roughly SPLIT_WEIGHTS and is stable across runs and machines."""
    bucket = (stable_hash(SALT, key) % 10_000) / 10_000
    cumulative = 0.0
    for split in SPLITS:
        cumulative += SPLIT_WEIGHTS[split]
        if bucket < cumulative:
            return split
    return SPLITS[-1]


# --------------------------------------------------------------------------- formatting wrappers


def wrap(span_text: str, style: str, rng: random.Random) -> str:
    """Dress a span the way injected content actually appears in documents."""
    if style == "plain":
        return span_text
    if style == "html_comment":
        return f"<!-- {span_text} -->"
    if style == "quoted":
        return "\n".join(f"> {line}" for line in span_text.splitlines() or [span_text])
    if style == "markdown_blockquote":
        return f"**Note:** {span_text}"
    if style == "fake_tag":
        tag = rng.choice(["system", "instructions", "admin", "important", "meta"])
        return f"[{tag}] {span_text} [/{tag}]"
    if style == "zero_width":  # invisible separators between words (an evasion trick)
        return span_text.replace(" ", "​ ")
    if style == "spaced":  # leading/trailing blank lines, as from a template boundary
        return f"\n\n{span_text}\n\n"
    if style == "signature":
        return f"--\n{span_text}"
    return span_text


FORMATTINGS = ["plain", "plain", "html_comment", "quoted", "markdown_blockquote", "fake_tag", "spaced", "signature"]


def insert(carrier: Carrier, piece: str, rng: random.Random) -> tuple[str, str]:
    """Insert `piece` between blocks of `carrier`. Returns (text, position label)."""
    blocks = list(carrier.blocks)
    slot = rng.randint(0, len(blocks))
    blocks.insert(slot, piece)
    position = "start" if slot == 0 else "end" if slot == len(blocks) - 1 else "middle"
    return "\n\n".join(blocks), position


# --------------------------------------------------------------------------- carrier supply


def synthetic_carrier_stream(rng: random.Random, synth: SyntheticCarriers) -> Iterator[Carrier]:
    while True:
        yield synth.make(rng.choice(synth.kinds))


def real_carriers(n_each: int, seed: int) -> list[Carrier]:
    """Streamed, capped real text. Returns [] if datasets/network is unavailable."""
    out: list[Carrier] = []
    try:
        out.extend(stream_amazon_reviews(n_each, seed=seed))
        out.extend(stream_web_pages(n_each // 2, seed=seed))
    except Exception as exc:  # offline, or datasets not installed: synthetic carriers still work
        print(f"  (real carriers skipped: {type(exc).__name__}: {str(exc)[:80]})")
    return out


# --------------------------------------------------------------------------- build


def synthetic_spans(rng: random.Random) -> list[Span]:
    """Benign and hard-negative inserts, each a filled template. Split is keyed on the
    template id (in `group`), so whole templates are held out, not just filled strings."""
    from training.fake import Fake

    fake = Fake(rng)
    spans: list[Span] = []
    for source, templates in synthetic_template_groups().items():
        for template_id, template in templates:
            for _ in range(rng.randint(8, 14)):  # several fillings of each template
                spans.append(Span(text=fake.fill(template), label=0, source=source, group=template_id))
    return spans


def make_rows(target: int, use_hf_carriers: bool, seed: int = SEED) -> list[Row]:
    rng = random.Random(seed)
    synth = SyntheticCarriers(random.Random(seed + 1))

    print("Loading injection seeds from the HF Hub (streaming)...")
    seed_spans = dedupe(stream_hf_spans())
    positives = [s for s in seed_spans if s.label == 1]
    seed_negatives = [s for s in seed_spans if s.label == 0]
    print(f"  {len(positives)} injection payloads, {len(seed_negatives)} benign seed questions (deduped)")

    negatives = seed_negatives + synthetic_spans(random.Random(seed + 2))
    rng.shuffle(positives)
    rng.shuffle(negatives)

    # A fixed pool of carriers, each tagged with a split, reused across many rows.
    carriers: list[Carrier] = [synth.make(k) for k in synth.kinds for _ in range(60)]
    if use_hf_carriers:
        print("Loading real carriers (Amazon reviews, FineWeb-Edu pages)...")
        carriers.extend(real_carriers(n_each=400, seed=seed))
    carriers_by_split: dict[str, list[Carrier]] = {s: [] for s in SPLITS}
    for c in carriers:
        carriers_by_split[assign_split(f"carrier:{c.uid}")].append(c)
    # Guarantee every split has carriers even if the hashing is lopsided for a tiny pool.
    for s in SPLITS:
        if not carriers_by_split[s]:
            carriers_by_split[s] = [synth.make(k) for k in synth.kinds]
    print({s: len(v) for s, v in carriers_by_split.items()})

    per_split_target = {s: round(target * w) for s, w in SPLIT_WEIGHTS.items()}
    rows: list[Row] = []
    seen: set[str] = set()
    for split in SPLITS:
        half = per_split_target[split] // 2
        pos = [s for s in positives if assign_split(f"span:{s.group}") == split]
        neg = [s for s in negatives if assign_split(f"span:{s.group}") == split]
        split_carriers = carriers_by_split[split]
        rows.extend(_rows_for_label(1, pos, half, split, split_carriers, seen, rng))
        # Reserve ~15% of negatives as untouched clean carriers.
        n_clean = half // 7
        rows.extend(_clean_rows(n_clean, split, split_carriers, seen, rng))
        rows.extend(_rows_for_label(0, neg, half - n_clean, split, split_carriers, seen, rng))

    rng.shuffle(rows)
    return rows


def _rows_for_label(
    label: int, spans: list[Span], n: int, split: str, carriers: list[Carrier], seen: set[str], rng: random.Random
) -> list[Row]:
    if not spans:
        return []
    out: list[Row] = []
    attempts = 0
    while len(out) < n and attempts < n * 6:
        attempts += 1
        span = spans[rng.randrange(len(spans))]
        carrier = carriers[rng.randrange(len(carriers))]
        style = rng.choice(FORMATTINGS)
        text, position = insert(carrier, wrap(span.text, style, rng), rng)
        if text in seen:
            continue
        seen.add(text)
        out.append(Row(text, label, split, carrier.kind, carrier.source, span.source, position, style))
    return out


def _clean_rows(n: int, split: str, carriers: list[Carrier], seen: set[str], rng: random.Random) -> list[Row]:
    out: list[Row] = []
    attempts = 0
    while len(out) < n and attempts < n * 8:
        attempts += 1
        carrier = carriers[rng.randrange(len(carriers))]
        text = carrier.text()
        if text in seen:
            continue
        seen.add(text)
        out.append(Row(text, 0, split, carrier.kind, carrier.source, "none", "none", "none"))
    return out


# --------------------------------------------------------------------------- IO + reporting


def write_jsonl(rows: Iterable[Row], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as f:
        for i, row in enumerate(rows):
            record = {"id": f"{row.split}-{i}", **asdict(row)}
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1
    return count


def summarize(rows: list[Row]) -> dict[str, object]:
    by_split = Counter(r.split for r in rows)
    out: dict[str, object] = {"total": len(rows), "by_split": dict(by_split)}
    for split in SPLITS:
        sub = [r for r in rows if r.split == split]
        if not sub:
            continue
        out[split] = {
            "rows": len(sub),
            "positives": sum(r.label for r in sub),
            "carrier_kinds": dict(Counter(r.carrier_kind for r in sub)),
            "span_sources": dict(Counter(r.span_source for r in sub)),
            "positions": dict(Counter(r.position for r in sub)),
            "formattings": dict(Counter(r.formatting for r in sub)),
        }
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--target", type=int, default=24000, help="approximate total row count")
    parser.add_argument("--no-hf-carriers", action="store_true", help="synthetic carriers only (offline)")
    parser.add_argument("--sample-only", action="store_true", help="write only the committed sample, not data/")
    parser.add_argument("--sample-size", type=int, default=120, help="rows per class in the committed sample")
    args = parser.parse_args(argv)

    rows = make_rows(args.target, use_hf_carriers=not args.no_hf_carriers)
    report = summarize(rows)
    print(json.dumps(report, indent=2, ensure_ascii=False))

    if not args.sample_only:
        for split in SPLITS:
            sub = [r for r in rows if r.split == split]
            n = write_jsonl(sub, DATA_DIR / f"{split}.jsonl")
            print(f"wrote {n:>6} rows -> {DATA_DIR.name}/{split}.jsonl")
        (DATA_DIR / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # Committed sample: only synthetic carriers + the permissively licensed HF payloads,
    # so nothing non-redistributable (FineWeb-Edu, Amazon text) enters git.
    sample_rows = [r for r in rows if r.carrier_source == "synthetic"]
    sample: list[Row] = []
    for label in (0, 1):
        pool = [r for r in sample_rows if r.label == label][: args.sample_size]
        sample.extend(pool)
    random.Random(SEED).shuffle(sample)
    n = write_jsonl(sample, SAMPLE_DIR / "sample.jsonl")
    print(f"wrote {n:>6} rows -> {SAMPLE_DIR.relative_to(REPO)}/sample.jsonl (committed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
