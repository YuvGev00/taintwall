"""Random entities (people, emails, URLs, IBANs, amounts, dates) for synthetic text.

Benign carriers, benign inserts and malicious payloads all draw from this one
generator. If attacker URLs looked different from benign ones (say, every bad link
were `evil.com`), the classifier could learn the URL instead of the instruction.

Nothing here is copied from AgentDojo: the audit treats AgentDojo's attacker
emails, URLs and IBANs as forbidden entities and its user, "Emma Johnson", as a
forbidden name, so neither appears in these lists.
"""

from __future__ import annotations

import random
import string

FIRST_NAMES = [
    "Noa",
    "Yael",
    "Omer",
    "Itai",
    "Maya",
    "Daniel",
    "Sarah",
    "David",
    "Lior",
    "Tamar",
    "Amit",
    "Rotem",
    "Priya",
    "Arjun",
    "Wei",
    "Mei",
    "Hiroshi",
    "Yuki",
    "Fatima",
    "Omar",
    "Layla",
    "Karim",
    "Sofia",
    "Mateo",
    "Lucas",
    "Chloe",
    "Liam",
    "Olivia",
    "Ethan",
    "Ava",
    "Noah",
    "Isabella",
    "James",
    "Grace",
    "Michael",
    "Hannah",
    "Kofi",
    "Amara",
    "Ivan",
    "Elena",
    "Pierre",
    "Camille",
    "Jonas",
    "Freya",
    "Diego",
    "Valentina",
    "Tom",
    "Rachel",
    "Ben",
    "Nadia",
    "Sam",
    "Alex",
    "Jordan",
    "Taylor",
    "Chris",
    "Pat",
    "Robin",
    "Kim",
]
LAST_NAMES = [
    "Cohen",
    "Levi",
    "Mizrahi",
    "Peretz",
    "Biton",
    "Friedman",
    "Shapiro",
    "Katz",
    "Patel",
    "Sharma",
    "Chen",
    "Wang",
    "Tanaka",
    "Sato",
    "Haddad",
    "Nasser",
    "Garcia",
    "Rossi",
    "Muller",
    "Schmidt",
    "Dubois",
    "Martin",
    "Nguyen",
    "Kowalski",
    "Novak",
    "Okafor",
    "Mensah",
    "Andersson",
    "Larsen",
    "Silva",
    "Costa",
    "Brown",
    "Miller",
    "Davis",
    "Wilson",
    "Moore",
    "Clark",
    "Lewis",
    "Walker",
    "Young",
    "Hughes",
    "Price",
    "Reed",
]
COMPANIES = [
    "Northwind Analytics",
    "Cedar & Pine Legal",
    "Orbitline Logistics",
    "Brightpath Health",
    "Quillworks",
    "Halcyon Labs",
    "Meridian Freight",
    "Tidewater Insurance",
    "Sunfield Energy",
    "Kestrel Robotics",
    "Lumen Dental",
    "Harbor Street Bakery",
    "Granite Peak Realty",
    "Vantage Payroll",
    "Copperleaf Studio",
    "Atlas Fitness",
    "Bluefin Accounting",
    "Riverstone Clinic",
    "Mosaic Tutoring",
    "Alder Systems",
]
CITIES = [
    "Tel Aviv",
    "Haifa",
    "Jerusalem",
    "Berlin",
    "Lisbon",
    "Austin",
    "Toronto",
    "Osaka",
    "Nairobi",
    "Madrid",
    "Prague",
    "Melbourne",
    "Dublin",
    "Seoul",
    "Lyon",
    "Denver",
    "Krakow",
    "Oslo",
    "Porto",
    "Bangalore",
]
WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September",
          "October", "November", "December"]  # fmt: skip
TLDS = ["com", "net", "org", "io", "co", "info", "app", "site", "online", "co.il", "de", "biz"]
WORDS = [
    "secure",
    "account",
    "portal",
    "cloud",
    "pay",
    "verify",
    "update",
    "docs",
    "files",
    "share",
    "mail",
    "login",
    "billing",
    "support",
    "help",
    "team",
    "data",
    "sync",
    "drive",
    "notes",
    "travel",
    "booking",
    "deals",
    "news",
    "shop",
    "health",
    "bank",
    "invoice",
    "status",
    "review",
    "promo",
    "track",
    "safe",
]
CURRENCIES = ["$", "€", "£", "₪"]


class Fake:
    """Seeded entity factory. One instance per build, so output is reproducible."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng

    def first(self) -> str:
        return self.rng.choice(FIRST_NAMES)

    def name(self) -> str:
        return f"{self.first()} {self.rng.choice(LAST_NAMES)}"

    def company(self) -> str:
        return self.rng.choice(COMPANIES)

    def city(self) -> str:
        return self.rng.choice(CITIES)

    def domain(self) -> str:
        r = self.rng
        style = r.random()
        if style < 0.4:
            base = f"{r.choice(WORDS)}-{r.choice(WORDS)}"
        elif style < 0.7:
            base = f"{r.choice(WORDS)}{r.randint(2, 999)}"
        else:
            base = self.company().split()[0].lower().replace("&", "")
        return f"{base}.{r.choice(TLDS)}"

    def email(self, name: str | None = None) -> str:
        r = self.rng
        person = (name or self.name()).lower().split()
        local = r.choice([f"{person[0]}.{person[-1]}", f"{person[0]}{r.randint(1, 99)}", person[0][0] + person[-1]])
        host = r.choice(["gmail.com", "outlook.com", "proton.me", "yahoo.com", self.domain()])
        return f"{local}@{host}"

    def url(self) -> str:
        r = self.rng
        path = r.choice(["", "/login", "/verify", "/invoice/" + self.ref(), "/s/" + self.token(8), "/docs/guide",
                         "/account/settings", "/track?id=" + self.ref(), "/promo", "/reset-password"])  # fmt: skip
        scheme = r.choice(["https://", "https://www.", "http://", "www."])
        return f"{scheme}{self.domain()}{path}"

    def iban(self) -> str:
        r = self.rng
        country = r.choice(["IL", "DE", "GB", "FR", "ES", "NL", "IT", "CH", "PT", "BE"])
        return country + "".join(r.choice(string.digits) for _ in range(r.randint(16, 22)))

    def card_tail(self) -> str:
        return f"{self.rng.randint(0, 9999):04d}"

    def amount(self) -> str:
        r = self.rng
        value = r.choice([r.randint(5, 99), r.randint(100, 999), r.randint(1000, 25000)])
        cents = r.choice(["", f".{r.randint(0, 99):02d}"])
        return f"{r.choice(CURRENCIES)}{value:,}{cents}"

    def date(self) -> str:
        r = self.rng
        day, month = r.randint(1, 28), r.randint(1, 12)
        return r.choice([f"{day} {MONTHS[month - 1]}", f"{MONTHS[month - 1]} {day}", f"2026-{month:02d}-{day:02d}",
                         f"{day:02d}/{month:02d}/2026", r.choice(WEEKDAYS)])  # fmt: skip

    def time(self) -> str:
        r = self.rng
        hour, minute = r.randint(7, 19), r.choice([0, 15, 30, 45])
        suffix = "am" if hour < 12 else "pm"
        return r.choice([f"{hour:02d}:{minute:02d}", f"{(hour - 1) % 12 + 1}:{minute:02d} {suffix}"])

    def phone(self) -> str:
        r = self.rng
        return r.choice([f"+972-5{r.randint(0, 9)}-{r.randint(100, 999)}-{r.randint(1000, 9999)}",
                         f"+1 ({r.randint(200, 989)}) {r.randint(200, 999)}-{r.randint(1000, 9999)}",
                         f"+44 7{r.randint(100, 999)} {r.randint(100000, 999999)}"])  # fmt: skip

    def ref(self) -> str:
        return f"{self.rng.choice(string.ascii_uppercase)}{self.rng.randint(10000, 99999)}"

    def token(self, n: int) -> str:
        return "".join(self.rng.choice(string.ascii_letters + string.digits) for _ in range(n))

    def password(self) -> str:
        return self.token(self.rng.randint(8, 14))

    def filename(self) -> str:
        r = self.rng
        stem = r.choice(["q3-report", "budget_2026", "meeting-notes", "onboarding", "contract_draft", "roadmap",
                         "invoice", "travel-plan", "handbook", "release-notes", "minutes", "client-list"])  # fmt: skip
        return f"{stem}.{r.choice(['docx', 'pdf', 'txt', 'md', 'xlsx', 'csv'])}"

    def fill(self, template: str) -> str:
        """Replace {slots} in a template with fresh random entities."""
        slots = {
            "name": self.name, "first": self.first, "email": self.email, "url": self.url, "iban": self.iban,
            "amount": self.amount, "date": self.date, "time": self.time, "phone": self.phone, "ref": self.ref,
            "company": self.company, "city": self.city, "file": self.filename, "password": self.password,
            "card": self.card_tail, "domain": self.domain,
        }  # fmt: skip
        out = template
        for key, make in slots.items():
            while "{" + key + "}" in out:
                out = out.replace("{" + key + "}", make(), 1)
        return out
