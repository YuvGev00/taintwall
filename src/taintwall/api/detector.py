"""Pluggable tool-output detector (L1) with an LRU verdict cache keyed by sha256(text).

The interface is one method: `score(text) -> float` in [0, 1], higher = more likely an injection.
"""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from typing import Any, Protocol

PROTECTAI_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"


class Detector(Protocol):
    name: str

    def score(self, text: str) -> float: ...


class NoopDetector:
    """Default: flags nothing, so the service runs without the optional `detector` group."""

    name = "noop"

    def score(self, text: str) -> float:
        return 0.0


class ProtectAIDetector:
    """ProtectAI deberta classifier; needs `uv sync --group detector`. Loaded on first use."""

    name = "protectai"

    def __init__(self) -> None:
        self._pipe: Any = None
        self._lock = threading.Lock()

    def score(self, text: str) -> float:
        with self._lock:
            if self._pipe is None:
                from transformers import pipeline

                self._pipe = pipeline("text-classification", model=PROTECTAI_MODEL, truncation=True, max_length=512)
            out = self._pipe(text)[0]
        return float(out["score"]) if out["label"] != "SAFE" else 1.0 - float(out["score"])


def build_detector(name: str) -> Detector:
    if name == "noop":
        return NoopDetector()
    if name == "protectai":
        return ProtectAIDetector()
    raise ValueError(f"unknown detector {name!r} (expected noop or protectai)")


class CachedDetector:
    """LRU cache in front of a detector. Thread-safe; the model call runs outside the lock."""

    def __init__(self, inner: Detector, capacity: int = 4096) -> None:
        self.inner = inner
        self.capacity = capacity
        self._cache: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return self.inner.name

    def __len__(self) -> int:
        return len(self._cache)

    def score(self, text: str) -> tuple[float, bool]:
        """Return (score, cache_hit)."""
        key = hashlib.sha256(text.encode()).hexdigest()
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key], True
        value = self.inner.score(text)
        with self._lock:
            self._cache[key] = value
            self._cache.move_to_end(key)
            while len(self._cache) > self.capacity:
                self._cache.popitem(last=False)
        return value, False
