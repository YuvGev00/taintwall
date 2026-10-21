"""L1: the fine-tuned prompt-injection detector for tool outputs (SPEC.md section 5).

One class serves both the R1 replay and the live AgentDojo pipeline. It loads the
weights trained by `training/train_l1.py` (local dir, gitignored) and the dev-chosen
threshold saved next to them, scores texts in length-sorted batches, and caches each
score by text hash next to the weights. The cache records which weights produced it,
so retraining invalidates it instead of serving stale scores.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
L1_MODEL_DIR = Path(os.environ.get("TAINTWALL_L1_MODEL", ROOT / "runs" / "l1-model"))
MAX_LEN = 512


def text_sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class L1Detector:
    batch_size = 32

    def __init__(self, model_dir: Path = L1_MODEL_DIR, threshold: float | None = None) -> None:
        self.model_dir = model_dir
        meta = json.loads((model_dir / "threshold.json").read_text())
        self.threshold: float = meta["threshold"] if threshold is None else threshold
        self.cache_path = model_dir / "score_cache.json"
        self.fingerprint = self._fingerprint()
        cached = json.loads(self.cache_path.read_text()) if self.cache_path.exists() else {}
        self.cache: dict[str, float] = cached.get("scores", {}) if cached.get("weights") == self.fingerprint else {}
        self._model: Any = None
        self._tok: Any = None

    def _fingerprint(self) -> str:
        weights = self.model_dir / "model.safetensors"
        if not weights.exists():
            return "no-weights"
        st = weights.stat()
        return f"{st.st_size}-{st.st_mtime_ns}"

    def _load(self) -> tuple[Any, Any, str]:
        import torch  # optional `detector` dependency group
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        device = "cuda" if torch.cuda.is_available() else "mps" if torch.backends.mps.is_available() else "cpu"
        if self._model is None:
            self._tok = AutoTokenizer.from_pretrained(self.model_dir)
            self._model = AutoModelForSequenceClassification.from_pretrained(self.model_dir).to(device).eval()
        return self._model, self._tok, device

    def _score_batch(self, texts: list[str]) -> list[float]:
        import torch

        model, tok, device = self._load()
        with torch.no_grad():
            enc = tok(texts, truncation=True, max_length=MAX_LEN, padding=True, return_tensors="pt").to(device)
            probs = torch.softmax(model(**enc).logits.float(), dim=-1)[:, 1]
        return [float(p) for p in probs.tolist()]

    def warm(self, texts: Sequence[str]) -> None:
        """Score every uncached text, in batches of similar length, and persist the cache."""
        todo = sorted({t for t in texts if text_sha(t) not in self.cache}, key=len)
        if not todo:
            return
        for start in range(0, len(todo), self.batch_size):
            batch = todo[start : start + self.batch_size]
            for text, score in zip(batch, self._score_batch(batch), strict=True):
                self.cache[text_sha(text)] = score
        self.cache_path.write_text(json.dumps({"weights": self.fingerprint, "scores": self.cache}))

    def score(self, text: str) -> float:
        if text_sha(text) not in self.cache:
            self.warm([text])
        return self.cache[text_sha(text)]

    def flagged(self, text: str) -> bool:
        return self.score(text) >= self.threshold
