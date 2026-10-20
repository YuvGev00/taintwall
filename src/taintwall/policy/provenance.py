"""Provenance: where did a value the agent wants to use come from?

- The user's request is trusted text: a value found anywhere in it is trusted.
- Output of tools the registry marks `trusted` vouches only for its *whole
  values* (exact match on a scalar field), never for text embedded inside a
  field. A channel list is trusted to name channels, but a channel whose name
  contains "visit www.evil.com" does not make that URL trusted. (Dev error
  analysis found exactly this injection in slack; DECISIONS.md, 2026-10-20.)
- Any text inside any tool output, trusted or not, is untrusted text.

Origin of a value: trusted if in the request or equal to a trusted field;
otherwise untrusted if it appears inside any tool output; otherwise unknown.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Literal

import yaml
from agentdojo.types import ChatMessage, get_text_content_as_str

from taintwall.policy.registry import Registry

Origin = Literal["trusted", "untrusted", "unknown"]

MIN_TRACKED_LENGTH = 3
"""Shorter normalized values match by accident too often to taint anything."""

_SCHEME = re.compile(r"^(https?://)?(www\.)?")
_DROP = re.compile(r"[\s'\"`<>()\[\]{},;]+")


def normalize(value: str) -> str:
    """Canonical form for matching: case-, whitespace- and URL-scheme-insensitive.

    Removing whitespace also makes IBANs match whether or not they are grouped
    ("DE89 3704 ..." vs "DE893704...").
    """
    v = value.strip().lower()
    v = _SCHEME.sub("", v)
    v = _DROP.sub("", v)
    return v.rstrip("/.")


def flatten(value: object) -> Iterable[str]:
    """The string leaves of an argument value (recipients may be a list)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list | tuple | set):
        for item in value:
            yield from flatten(item)


def _scalar_leaves(obj: object) -> Iterator[str]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield str(key)
            yield from _scalar_leaves(value)
    elif isinstance(obj, list | tuple):
        for item in obj:
            yield from _scalar_leaves(item)
    elif obj is not None:
        yield str(obj)


def field_values(tool_output: str) -> set[str]:
    """Normalized scalar fields of a tool output (AgentDojo formats results as YAML)."""
    try:
        parsed = yaml.safe_load(tool_output)
    except yaml.YAMLError:
        parsed = tool_output
    return {n for leaf in _scalar_leaves(parsed) if (n := normalize(leaf))}


@dataclass
class Provenance:
    request: str
    trusted_fields: set[str] = field(default_factory=set)
    tool_text: str = ""

    @classmethod
    def from_history(cls, user_prompt: str, messages: Sequence[ChatMessage], registry: Registry) -> Provenance:
        trusted_fields: set[str] = set()
        texts = []
        for message in messages:
            if message["role"] != "tool":
                continue
            raw = get_text_content_as_str(message["content"]) or ""
            texts.append(normalize(raw))
            spec = registry.get(message["tool_call"].function)
            if spec is not None and spec.source == "trusted":
                trusted_fields |= field_values(raw)
        return cls(request=normalize(user_prompt), trusted_fields=trusted_fields, tool_text="\n".join(texts))

    def origin(self, value: str) -> Origin:
        v = normalize(value)
        if len(v) < MIN_TRACKED_LENGTH:
            return "unknown"
        if v in self.request or v in self.trusted_fields:
            return "trusted"
        if v in self.tool_text:
            return "untrusted"
        return "unknown"
