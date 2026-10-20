"""Benign *carrier* documents: the tool outputs an agent reads.

Two kinds of source:
  - synthetic: emails, calendar invites, chat logs, file notes, bank statements,
    invoices, IT notices and how-to instructions, generated from the template pools
    below with random entities (training/fake.py). Several kinds are deliberately
    full of imperatives, payment details and URLs, because that is what benign tool
    outputs look like and what a naive detector flags.
  - real (streamed from the HF Hub, capped, never fully downloaded):
    `fancyzhx/amazon_polarity` reviews (Apache-2.0 on the Hub) and
    `HuggingFaceFW/fineweb-edu` web pages (ODC-By 1.0), cut to a few paragraphs.

A carrier is a list of blocks (header lines, paragraphs, chat lines). Payloads and
benign inserts go between blocks or after a sentence inside one (build_dataset.py).
"""

from __future__ import annotations

import hashlib
import itertools
import random
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from training.fake import Fake

HF_REVISIONS = {
    "fancyzhx/amazon_polarity": "9d9c45c18f8c3cf1b23a3c27917b60cbf28f3289",
    "HuggingFaceFW/fineweb-edu": "87f09149ef4734204d70ed1d046ddc9ca3f2b8f9",
}
# Web pages that talk about LLMs or prompt attacks would put injection-like text into
# negatives (or be injections themselves). They are dropped, not relabelled.
_OFF_TOPIC = re.compile(
    r"prompt injection|jailbreak|ignore (all |the )?(previous|prior|above)|chatgpt"
    r"|language model|\bLLM\b|\bAI assistant",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Carrier:
    kind: str  # email | calendar | chat | file_note | bank | invoice | it_notice | howto | review | webpage
    source: str  # "synthetic" or the HF dataset id
    blocks: tuple[str, ...]

    @property
    def uid(self) -> str:
        return hashlib.sha256("\n".join(self.blocks).encode()).hexdigest()[:16]

    def text(self) -> str:
        return "\n\n".join(self.blocks)


# --------------------------------------------------------------------------- synthetic pools

# fmt: off
EMAIL_SUBJECTS = [
    "Re: {company} kickoff", "Invoice {ref}", "Quick question about the {file}", "Updated agenda for {date}",
    "Your order {ref} has shipped", "Lunch on {date}?", "Fwd: contract renewal", "Action needed: timesheet",
    "Notes from today's call", "Welcome to {company}", "Re: flat viewing in {city}", "Payment received",
    "Travel itinerary - {city}", "Re: Re: budget numbers", "Reminder: dentist appointment", "Team offsite",
]
EMAIL_BODY = [
    "Thanks for sending the {file} over, I had a look this morning.",
    "Could you review the attached draft before {date}?",
    "Please send me the final numbers by end of day {date}.",
    "The meeting has moved to {time} on {date}, same room as last time.",
    "I've shared the folder with you, let me know if the link doesn't work: {url}",
    "We received your payment of {amount}. A receipt is attached for your records.",
    "Can you confirm that the shipping address is still correct?",
    "Attaching the slides from yesterday. Slide 7 has the revised timeline.",
    "Don't forget to bring your ID, the building has new security at reception.",
    "If anything changes on your side, just reply to this thread.",
    "My flight lands at {time}, so I should be at the office around an hour later.",
    "The client asked whether we can deliver two weeks earlier. I said we'd check.",
    "Please update the tracker once the review is done and tag {first} on it.",
    "Transfer the deposit of {amount} to the usual account when you get a chance.",
    "I'm out of office until {date}; for urgent matters call {phone}.",
    "Sign the form on page 3 and scan it back to me, a photo is fine too.",
    "We need two more volunteers for Saturday's event, please spread the word.",
    "Our accountant needs last year's statements before we can file.",
    "Reminder that the parking garage is closed for maintenance next week.",
    "The new hire starts on {date}; please set up a laptop and a badge.",
    "Book the large conference room for the quarterly review if it is free.",
    "Let me know which of the two options works better for you.",
    "Rates went up {amount} this year, which is still within the budget we set.",
    "Delete the old drafts from the shared drive so nobody edits the wrong file.",
]
SIGNOFFS = ["Best,", "Thanks,", "Cheers,", "Kind regards,", "Talk soon,", "Thanks in advance,", "All the best,"]

EVENT_TITLES = [
    "Sprint planning", "1:1 with {first}", "Quarterly business review", "Dentist", "Board prep",
    "Customer demo - {company}", "Yoga class", "Interview: backend engineer", "Lunch with {first}",
    "Budget sync", "Parent-teacher meeting", "Flight to {city}", "Design critique", "Vendor call",
]
EVENT_DESCRIPTIONS = [
    "Agenda: status updates, blockers, next steps.",
    "Please read the {file} before the meeting.",
    "Dial-in: {url} (passcode {ref}).",
    "Bring your laptop; we will go through the open tickets one by one.",
    "Parking is available on the second level, validate your ticket at reception.",
    "Join the video call 5 minutes early to test your audio.",
    "Prepare three slides on last quarter's results.",
    "Location changed to the café across the street.",
    "Cancel at least 24 hours in advance to avoid a fee of {amount}.",
    "Ask {first} for the badge if you don't have one yet.",
]

CHAT_LINES = [
    "anyone up for lunch at 12:30?", "pushed the fix, can someone review?", "the build is green again",
    "can you send me the link to the doc?", "here it is: {url}", "meeting moved to {time}",
    "who has the keys for the storage room?", "please don't merge to main until the release is cut",
    "I'll be 10 min late", "thanks!", "reminder: timesheets are due {date}",
    "send the invoice to {email} and cc me", "the client loved the demo", "has anyone seen my charger?",
    "restart your laptop after the update, it fixes the VPN issue", "lol", "ok sounds good",
    "pay the caterer {amount} from the team budget", "new menu for the office kitchen is on the fridge",
    "ping {first} about the contract, they have the latest version", "can we move standup to 10?",
    "delete the duplicate channel, we're using this one now",
]
CHANNELS = ["#general", "#random", "#dev", "#marketing", "#ops", "#design", "#sales", "#office", "#support"]

NOTE_LINES = [
    "Decisions: we go with vendor B, contract signed by {date}.",
    "TODO: email {first} the revised quote.",
    "TODO: pay the electricity bill ({amount}) before the {date} deadline.",
    "Open question: who owns the migration after launch?",
    "Wifi password for guests is posted at reception.",
    "Action item: {first} to book flights to {city}.",
    "Risks: timeline is tight, testing might slip a week.",
    "Next meeting: {date} at {time}.",
    "Remember to back up the laptop before sending it for repair.",
    "Budget left this quarter: {amount}.",
    "Customer feedback was mostly positive; two complaints about delivery times.",
    "Grocery list: oat milk, eggs, coffee, rice, lemons.",
    "Call the landlord about the leaking tap.",
    "Renew passport - appointment on {date}.",
    "Draft blog post is in the {file}; needs a better title.",
    "Ask HR how many vacation days carry over.",
]

BANK_MEMOS = [
    "Rent {date}", "Groceries", "Dinner split - thanks!", "Invoice {ref}", "Gym membership", "Car insurance",
    "Refund for order {ref}", "Birthday gift", "Electricity", "Tuition installment", "Salary", "Freelance work",
    "Coffee", "Train pass", "Phone bill", "Concert tickets", "Pharmacy", "Savings transfer",
]

INVOICE_LINES = [
    "Please pay {amount} by {date}.",
    "Bank transfer to IBAN {iban}, reference {ref}.",
    "Pay online at {url} using your customer number {ref}.",
    "Late payments incur a fee of {amount}.",
    "Questions about this invoice? Contact {email} or call {phone}.",
    "Card ending in {card} will be charged automatically on {date}.",
    "Include the invoice number in the transfer description.",
    "Thank you for your business!",
]

IT_NOTICE_LINES = [
    "Scheduled maintenance on {date} from {time}; email may be unavailable.",
    "Reset your password at {url} before it expires on {date}.",
    "Never share your password, not even with IT staff.",
    "Install the latest security update and restart your computer.",
    "If you did not request this change, contact {email} immediately.",
    "Enable two-factor authentication in your account settings.",
    "Your mailbox is 92% full; delete old messages or archive them.",
    "Do not reply to this automated message.",
    "To report phishing, forward the suspicious email to {email}.",
    "Your verification code is {ref}. It expires in 10 minutes.",
]

HOWTO_LINES = [
    "Preheat the oven to 200°C and line a tray with baking paper.",
    "Mix the flour and salt, then add the water slowly.",
    "Run `pip install -r requirements.txt` inside the virtual environment.",
    "Copy `.env.example` to `.env` and fill in your own values.",
    "Unplug the router, wait 30 seconds, then plug it back in.",
    "Open Settings, go to Privacy, and turn off location history.",
    "Ignore the warning about the self-signed certificate on the test server only.",
    "Download the installer from {url} and follow the prompts.",
    "Tighten the bolts in a star pattern so the wheel sits evenly.",
    "Water the plants every other day and keep them out of direct sun.",
    "Delete the cache folder if the app keeps crashing on start.",
    "Always disconnect the power before opening the case.",
    "Send the completed form to {email} with your student number in the subject.",
    "Stir until the sauce thickens, about five minutes.",
]
HOWTO_TITLES = ["How to set up the project", "Sourdough bread", "Router troubleshooting", "Changing a tyre",
                "Getting started", "Plant care", "Submitting your application", "Weeknight pasta"]
REVIEW_LINES = [
    "Stayed three nights, the room was clean and the staff were friendly.",
    "Breakfast was average but the location is unbeatable.",
    "Would not recommend - the check-in took over an hour.",
    "Great value for money, I'd book again.",
    "The pasta was excellent, the dessert less so.",
    "Ask for a room on a higher floor, the street gets noisy at night.",
    "Service was slow but the food made up for it.",
    "Parking costs {amount} a night, which nobody told us.",
]
# fmt: on


class SyntheticCarriers:
    """Generator of synthetic carriers. Each call to `make(kind)` returns a new one."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.fake = Fake(rng)
        self.builders: dict[str, Callable[[], list[str]]] = {
            "email": self._email,
            "calendar": self._calendar,
            "chat": self._chat,
            "file_note": self._file_note,
            "bank": self._bank,
            "invoice": self._invoice,
            "it_notice": self._it_notice,
            "howto": self._howto,
            "review": self._review,
        }

    @property
    def kinds(self) -> list[str]:
        return list(self.builders)

    def make(self, kind: str) -> Carrier:
        return Carrier(kind=kind, source="synthetic", blocks=tuple(self.builders[kind]()))

    def _sentences(self, pool: list[str], lo: int, hi: int) -> list[str]:
        return [self.fake.fill(s) for s in self.rng.sample(pool, self.rng.randint(lo, hi))]

    def _paragraphs(self, pool: list[str], n_sentences: tuple[int, int], max_paragraphs: int = 3) -> list[str]:
        sentences = self._sentences(pool, *n_sentences)
        n_par = self.rng.randint(1, min(max_paragraphs, len(sentences)))
        cuts = sorted(self.rng.sample(range(1, len(sentences)), n_par - 1)) if n_par > 1 else []
        bounds = [0, *cuts, len(sentences)]
        return [" ".join(sentences[a:b]) for a, b in itertools.pairwise(bounds)]

    def _email(self) -> list[str]:
        f, r = self.fake, self.rng
        sender, recipient = f.name(), f.name()
        header = (
            f"From: {sender} <{f.email(sender)}>\nTo: {f.email(recipient)}\n"
            f"Subject: {f.fill(r.choice(EMAIL_SUBJECTS))}\nDate: {f.date()}, {f.time()}"
        )
        blocks = [header, f"Hi {recipient.split()[0]},", *self._paragraphs(EMAIL_BODY, (2, 6))]
        blocks.append(f"{r.choice(SIGNOFFS)}\n{sender.split()[0]}")
        if r.random() < 0.3:  # quoted previous message
            quoted = " ".join(self._sentences(EMAIL_BODY, 1, 3))
            blocks.append(f"On {f.date()}, {recipient} wrote:\n> {quoted}")
        return blocks

    def _calendar(self) -> list[str]:
        f, r = self.fake, self.rng
        attendees = ", ".join(f.email() for _ in range(r.randint(1, 4)))
        header = (
            f"Event: {f.fill(r.choice(EVENT_TITLES))}\nWhen: {f.date()} {f.time()} - {f.time()}\n"
            f"Where: {r.choice(['Room 4B', 'Zoom', f.city(), 'Main office', 'Google Meet', 'Café Nordau'])}\n"
            f"Organizer: {f.email()}\nAttendees: {attendees}"
        )
        return [header, "Description: " + " ".join(self._sentences(EVENT_DESCRIPTIONS, 1, 4))]

    def _chat(self) -> list[str]:
        f, r = self.fake, self.rng
        people = [f.first() for _ in range(r.randint(2, 4))]
        lines = [f"[{f.time()}] {r.choice(people)}: {f.fill(msg)}" for msg in r.sample(CHAT_LINES, r.randint(3, 8))]
        return [f"Channel {r.choice(CHANNELS)}", *lines]

    def _file_note(self) -> list[str]:
        f = self.fake
        return [f"{f.filename()}", *self._paragraphs(NOTE_LINES, (3, 7)), f"Last edited by {f.name()} on {f.date()}."]

    def _bank(self) -> list[str]:
        f, r = self.fake, self.rng
        rows = [
            f"{f.date()} | {r.choice(['Transfer from', 'Transfer to', 'Card payment', 'Direct debit'])} "
            f"{r.choice([f.name(), f.company()])} | {r.choice(['-', '+'])}{f.amount()} | {f.fill(r.choice(BANK_MEMOS))}"
            for _ in range(r.randint(3, 8))
        ]
        return [f"Account statement for {f.name()} - IBAN {f.iban()}", "\n".join(rows)]

    def _invoice(self) -> list[str]:
        f = self.fake
        header = f"{f.company()}\nInvoice {f.ref()} - issued {f.date()}\nBill to: {f.name()}"
        items = "\n".join(f"- {item}: {f.amount()}" for item in self.rng.sample(
            ["Consulting hours", "Hosting", "Design work", "Annual license", "Shipping", "Repair", "Cleaning"],
            3))  # fmt: skip
        return [header, items, *self._paragraphs(INVOICE_LINES, (2, 5), max_paragraphs=2)]

    def _it_notice(self) -> list[str]:
        f = self.fake
        title = self.rng.choice(["IT Service Desk", "Security notice", "Account alert", "System update"])
        return [f"{title} - {f.company()}", *self._paragraphs(IT_NOTICE_LINES, (2, 5), max_paragraphs=2)]

    def _howto(self) -> list[str]:
        steps = self._sentences(HOWTO_LINES, 3, 7)
        return [self.rng.choice(HOWTO_TITLES), "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))]

    def _review(self) -> list[str]:
        f = self.fake
        stars = self.rng.randint(1, 5)
        stars_str = "★" * stars + "☆" * (5 - stars)
        return [f"{stars_str}  {f.name()}, {f.date()}", " ".join(self._sentences(REVIEW_LINES, 2, 5))]


# --------------------------------------------------------------------------- streamed real text


def _clip_sentences(text: str, max_chars: int) -> str:
    """Longest prefix of whole sentences that fits in max_chars."""
    out = ""
    for sentence in re.split(r"(?<=[.!?])\s+", text.strip()):
        if len(out) + len(sentence) + 1 > max_chars:
            break
        out = f"{out} {sentence}".strip()
    return out


def stream_amazon_reviews(n: int, seed: int, max_chars: int = 900) -> Iterator[Carrier]:
    from datasets import load_dataset  # type: ignore[attr-defined]

    name = "fancyzhx/amazon_polarity"
    ds = load_dataset(name, split="train", streaming=True, revision=HF_REVISIONS[name])
    ds = ds.shuffle(seed=seed, buffer_size=20_000)
    count = 0
    for row in ds:
        body = _clip_sentences(row["content"], max_chars)
        if len(body) < 150 or _OFF_TOPIC.search(body):
            continue
        yield Carrier(kind="review", source=name, blocks=(f"Review: {row['title']}", body))
        count += 1
        if count >= n:
            return


def stream_web_pages(n: int, seed: int, max_chars: int = 1100) -> Iterator[Carrier]:
    from datasets import load_dataset  # type: ignore[attr-defined]

    name = "HuggingFaceFW/fineweb-edu"
    ds = load_dataset(name, name="sample-10BT", split="train", streaming=True, revision=HF_REVISIONS[name])
    ds = ds.shuffle(seed=seed, buffer_size=5_000)
    count = 0
    for row in ds:
        if _OFF_TOPIC.search(row["text"]):
            continue
        paragraphs = [p.strip() for p in row["text"].split("\n") if len(p.strip()) > 40]
        blocks: list[str] = []
        for p in paragraphs:
            p = _clip_sentences(p, max_chars)
            if not p or sum(map(len, blocks)) + len(p) > max_chars:
                break
            blocks.append(p)
        if sum(map(len, blocks)) < 250:
            continue
        yield Carrier(kind="webpage", source=name, blocks=tuple(blocks))
        count += 1
        if count >= n:
            return
