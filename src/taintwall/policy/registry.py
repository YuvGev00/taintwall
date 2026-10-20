"""Tool registry: what each tool reads and does, loaded from policies/<suite>.yaml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml

POLICIES_DIR = Path(__file__).resolve().parents[3] / "policies"

Source = Literal["trusted", "untrusted"]
Effect = Literal["write", "external"]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    source: Source | None = None
    """Provenance of the tool's output. None = the tool returns no data worth tracking."""
    effect: Effect | None = None
    """None = read-only."""
    sensitive: tuple[str, ...] = field(default_factory=tuple)
    """Arguments whose values must not come only from untrusted data."""


Registry = dict[str, ToolSpec]


def load_registry(suite: str, policies_dir: Path = POLICIES_DIR) -> Registry:
    raw = yaml.safe_load((policies_dir / f"{suite}.yaml").read_text())
    registry: Registry = {}
    for name, spec in raw.items():
        unknown = set(spec) - {"source", "effect", "sensitive"}
        if unknown:
            raise ValueError(f"{suite}.yaml: {name} has unknown keys {sorted(unknown)}")
        if spec.get("source") not in (None, "trusted", "untrusted"):
            raise ValueError(f"{suite}.yaml: {name}.source must be trusted or untrusted")
        if spec.get("effect") not in (None, "write", "external"):
            raise ValueError(f"{suite}.yaml: {name}.effect must be write or external")
        registry[name] = ToolSpec(
            name=name,
            source=spec.get("source"),
            effect=spec.get("effect"),
            sensitive=tuple(spec.get("sensitive", ())),
        )
    return registry
