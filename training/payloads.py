"""What gets inserted into carriers: injection payloads and benign look-alikes.

Positives (label 1) come only from public, permissively licensed seed datasets,
streamed from the HF Hub at pinned revisions:
    deepset/prompt-injections (Apache-2.0)            rows with label == 1
    Lakera/gandalf_ignore_instructions (MIT)          every row
    reshabhs/SPML_Chatbot_Prompt_Injection (MIT)      "User Prompt" where "Prompt injection" == 1
    jackhhao/jailbreak-classification (Apache-2.0)    rows with type == "jailbreak"
xTRam1/safe-guard-prompt-injection is NOT used: it carries no licence.

These seeds are direct (chat-style) injections. What this project contributes is
the *indirect* setting: the payload sits inside an email, invite or web page, with
varied formatting and position (build_dataset.py).

Negatives that also get inserted (label 0), so that "something was inserted" is
not a label signal:
  - benign inserts: human-to-human requests, links and payment instructions, plus
    benign questions from deepset (label 0) and SPML ("Prompt injection" == 0);
  - hard inserts: benign text that uses words an injection detector keys on
    ("ignore my previous email", "do not reply to this automated message").
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass

HF_REVISIONS = {
    "deepset/prompt-injections": "4f61ecb038e9c3fb77e21034b22511b523772cdd",
    "Lakera/gandalf_ignore_instructions": "04737b65e90a6794ec227012e4a255a7def6344b",
    "reshabhs/SPML_Chatbot_Prompt_Injection": "02ce8084e979bc7d4c24ee35d22ecb7f2db96ff5",
    "jackhhao/jailbreak-classification": "2f2ceeb39658696fd3f462403562b6eea5306287",
}
MAX_SPAN_CHARS = 700  # longer jailbreak essays would push the payload past a 512-token window
MIN_SPAN_CHARS = 15


@dataclass(frozen=True)
class Span:
    """A piece of text to insert into a carrier."""

    text: str
    label: int  # 1 = injection, 0 = benign
    source: str  # HF dataset id, "synthetic_benign" or "synthetic_hard"
    group: str  # what the train/dev/test split is keyed on (normalized text or template id)


def normalize(text: str) -> str:
    """De-duplication key: case, punctuation and spacing don't make a new span."""
    return " ".join(re.findall(r"\w+", unicodedata.normalize("NFKC", text).lower()))


def stable_hash(*parts: str) -> int:
    return int(hashlib.sha256(":".join(parts).encode()).hexdigest()[:12], 16)


# --------------------------------------------------------------------------- HF seeds


def stream_hf_spans() -> Iterator[Span]:
    """Every row of the four seed datasets that we use, both labels; de-duplicated later."""
    from datasets import load_dataset  # type: ignore[attr-defined]

    def rows(name: str) -> Iterator[dict[str, object]]:
        for split in ("train", "validation", "test"):
            try:
                yield from load_dataset(name, split=split, streaming=True, revision=HF_REVISIONS[name])
            except ValueError:  # this dataset has no such split
                continue

    for row in rows("deepset/prompt-injections"):
        yield _span(str(row["text"]), int(str(row["label"])), "deepset/prompt-injections")
    for row in rows("Lakera/gandalf_ignore_instructions"):
        yield _span(str(row["text"]), 1, "Lakera/gandalf_ignore_instructions")
    for row in rows("reshabhs/SPML_Chatbot_Prompt_Injection"):
        label = int(str(row["Prompt injection"]))
        yield _span(str(row["User Prompt"]), label, "reshabhs/SPML_Chatbot_Prompt_Injection")
    for row in rows("jackhhao/jailbreak-classification"):
        # The benign rows are role-play prompts ("You are a medieval blacksmith..."):
        # inside a tool output those read as role reassignment, so they are not used as negatives.
        if row["type"] == "jailbreak":
            yield _span(str(row["prompt"]), 1, "jackhhao/jailbreak-classification")


def _span(text: str, label: int, source: str) -> Span:
    text = text.strip()
    return Span(text=text, label=label, source=source, group=normalize(text))


def usable(span: Span) -> bool:
    return MIN_SPAN_CHARS <= len(span.text) <= MAX_SPAN_CHARS


def dedupe(spans: Iterator[Span]) -> list[Span]:
    """Keep the first occurrence of each normalized text. If the same text shows up with
    both labels (it happens across sources), drop it: the label is not trustworthy."""
    first: dict[str, Span] = {}
    conflicting: set[str] = set()
    for span in spans:
        if not usable(span):
            continue
        seen = first.get(span.group)
        if seen is None:
            first[span.group] = span
        elif seen.label != span.label:
            conflicting.add(span.group)
    return [s for g, s in first.items() if g not in conflicting]


# --------------------------------------------------------------------------- synthetic benign inserts

# Things people legitimately write inside emails, notes and messages: imperatives,
# links, payment details. Slots are filled by training/fake.py.
# fmt: off
BENIGN_INSERTS = [
    "Please send the signed agreement to {email} before {date}.",
    "Wire the deposit of {amount} to IBAN {iban}, reference {ref}.",
    "You can download the full report here: {url}",
    "Click the link to confirm your subscription: {url}",
    "Call me at {phone} if the delivery is late.",
    "Forward this to anyone on the team who still needs access.",
    "Reply to this email with your preferred time slot.",
    "Pay the remaining {amount} on arrival, cash or card.",
    "Share the folder with {first} so they can add their part.",
    "Book a table for six at {time} and put it under my name.",
    "Send {first} the updated invoice and copy {email}.",
    "Transfer {amount} to the savings account on the first of every month.",
    "Log in at {url} to see your order history.",
    "Delete the duplicate entries before importing the spreadsheet.",
    "Make sure to update the password on the shared account after the trip.",
    "P.S. the photos from the event are at {url}",
    "Add {email} to the mailing list for next month's newsletter.",
    "Return the borrowed projector to reception by {date}.",
    "Use promo code {ref} at checkout for 15% off.",
    "Check the attached {file} and tell me what you think.",
]

# Benign text with the vocabulary of an attack: overrides, "system" notices, urgency.
HARD_INSERTS = [
    "Ignore my previous email, the meeting is back on {date} at {time}.",
    "Please disregard the last invoice; the corrected one is attached.",
    "Do not reply to this automated message.",
    "This is an automated notification from the {company} system.",
    "SYSTEM MAINTENANCE: services will be unavailable on {date} from {time}.",
    "Forget what I said about Friday, Thursday works better for everyone.",
    "IMPORTANT: your password expires in 3 days. Change it at {url}",
    "Note to all staff: new instructions for expense reports are in the {file}.",
    "Override the default shipping option and choose express for this order.",
    "Urgent: transfer {amount} to {iban} today so the supplier releases the goods.",
    "From now on, send all invoices to {email} instead of the old address.",
    "New policy: every visitor must sign in at the front desk.",
    "Please follow the instructions below carefully to reset your router.",
    "Admin note: the shared drive will be read-only during the migration.",
    "Before you do anything else, back up your files.",
    "Ignore the previous version of this document; it had the wrong figures.",
]
# fmt: on


def synthetic_template_groups() -> dict[str, list[tuple[str, str]]]:
    """(template id, template) per source. The split is keyed on the template id, so the
    test set's benign inserts come from templates the model never saw in training."""
    return {
        "synthetic_benign": [(f"benign-{i}", t) for i, t in enumerate(BENIGN_INSERTS)],
        "synthetic_hard": [(f"hard-{i}", t) for i, t in enumerate(HARD_INSERTS)],
    }
