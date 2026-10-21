"""Fine-tune and evaluate the L1 detector. One recipe for every launcher (local GPU/MPS or Modal).

    uv run --group detector --group training python -m training.train_l1

Same recipe as `train.ipynb` (ModernBERT-base, 2 epochs, lr 2e-5, warmup 10%,
weight decay 0.01, batch 32, seed 20261020), written as a plain PyTorch loop so it
needs no `accelerate`. bf16 autocast on GPUs that support it, fp32 otherwise.

Order of operations is the guarantee:
1. the contamination audit must pass on train/dev/test,
2. train on train only,
3. choose each model's threshold on dev for FPR <= 1% and freeze it,
4. only then score test and InjecAgent (MIT, out-of-distribution, evaluation only).
Weights go to `runs/l1-model/` (gitignored); metrics to `results/l1/metrics.json`.
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from training.metrics import rates, threshold_at_fpr

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
MODEL_DIR = ROOT / "runs" / "l1-model"
RESULTS_DIR = ROOT / "results" / "l1"
SCORES_PATH = ROOT / "runs" / "l1_scores.json"

BASE_MODEL = "answerdotai/ModernBERT-base"
PROTECTAI_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
MAX_LEN = 512
MICRO_BATCH = 8
"""Rows per forward pass; gradients accumulate up to BATCH (fits a 16 GB T4)."""
TARGET_FPR = 0.01
SEED = 20261020
EPOCHS = 2
BATCH = 32
LR = 2e-5
WARMUP = 0.1
WEIGHT_DECAY = 0.01

# InjecAgent (MIT) at a pinned commit; evaluation only, never trained on.
INJECAGENT_SHA = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
INJECAGENT_FILES = ("test_cases_dh_base", "test_cases_ds_base", "test_cases_dh_enhanced", "test_cases_ds_enhanced")
PLACEHOLDER = "<Attacker Instruction>"

Row = dict[str, Any]


def load_rows(path: Path) -> list[Row]:
    with path.open() as f:
        return [json.loads(line) for line in f]


def injecagent_rows() -> list[Row]:
    """Positives: every attacked tool response. Negatives: each distinct template with the slot emptied.

    InjecAgent has no benign tool outputs of its own, so the negatives are few (one per
    template); its main number is the detection rate at the dev-frozen threshold.
    """
    rows: list[Row] = []
    templates: set[str] = set()
    for name in INJECAGENT_FILES:
        url = f"https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/{INJECAGENT_SHA}/data/{name}.json"
        with urllib.request.urlopen(url) as r:
            cases = json.load(r)
        for case in cases:
            rows.append({"text": case["Tool Response"].strip('"'), "label": 1, "source": name})
            templates.add(case["Tool Response Template"])
    rows += [{"text": t.replace(PLACEHOLDER, ""), "label": 0, "source": "template"} for t in sorted(templates)]
    return rows


def pick_device() -> str:
    import torch

    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def batched_probs(model: Any, tok: Any, texts: list[str], device: str, positive: int, bs: int = 16) -> list[float]:
    """P(positive class) per text, in input order; length-sorted batches keep padding low."""
    import torch

    order = sorted(range(len(texts)), key=lambda i: len(texts[i]))
    out = [0.0] * len(texts)
    model.eval()
    with torch.no_grad():
        for start in range(0, len(order), bs):
            idx = order[start : start + bs]
            enc = tok([texts[i] for i in idx], truncation=True, max_length=MAX_LEN, padding=True, return_tensors="pt")
            logits = model(**enc.to(device)).logits.float()
            for i, p in zip(idx, torch.softmax(logits, -1)[:, positive].tolist(), strict=True):
                out[i] = float(p)
    return out


def train(train_rows: list[Row], device: str, log: Callable[[str], None] = print) -> tuple[Any, Any]:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    random.seed(SEED)
    torch.manual_seed(SEED)
    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(BASE_MODEL, num_labels=2).to(device)
    decay = [p for n, p in model.named_parameters() if not any(k in n for k in ("bias", "norm"))]
    no_decay = [p for n, p in model.named_parameters() if any(k in n for k in ("bias", "norm"))]
    groups: list[dict[str, Any]] = [{"params": decay, "weight_decay": WEIGHT_DECAY}, {"params": no_decay}]
    opt = torch.optim.AdamW(groups, lr=LR)
    total = (len(train_rows) + BATCH - 1) // BATCH * EPOCHS
    warmup = int(WARMUP * total)
    # Linear warmup then linear decay to 0, as transformers' get_linear_schedule_with_warmup.
    sched = torch.optim.lr_scheduler.LambdaLR(
        opt, lambda step: step / max(1, warmup) if step < warmup else max(0.0, (total - step) / max(1, total - warmup))
    )
    # Mixed precision on CUDA: bf16 where supported (L4, A100), fp16 + loss scaling on a
    # T4. A batch of 32 x 512 tokens in fp32 does not fit a 16 GB T4 (OOM on Colab,
    # 2026-10-21), so each batch of BATCH rows runs as micro-batches of MICRO_BATCH with
    # gradient accumulation (same effective batch, same recipe), plus gradient checkpointing.
    cuda = device == "cuda"
    bf16 = cuda and torch.cuda.is_bf16_supported()
    amp_dtype = torch.bfloat16 if bf16 else torch.float16
    scaler = torch.amp.GradScaler("cuda", enabled=cuda and not bf16)
    if cuda:
        model.gradient_checkpointing_enable()

    step, t0 = 0, time.time()
    for epoch in range(EPOCHS):
        model.train()
        rows = train_rows[:]
        random.shuffle(rows)
        for start in range(0, len(rows), BATCH):
            chunk = rows[start : start + BATCH]
            for m in range(0, len(chunk), MICRO_BATCH):
                micro = chunk[m : m + MICRO_BATCH]
                enc = tok(
                    [r["text"] for r in micro], truncation=True, max_length=MAX_LEN, padding=True, return_tensors="pt"
                )
                labels = torch.tensor([int(r["label"]) for r in micro])
                with torch.autocast("cuda", dtype=amp_dtype, enabled=cuda):
                    loss = model(**enc.to(device), labels=labels.to(device)).loss
                scaler.scale(loss * len(micro) / len(chunk)).backward()
            scaler.unscale_(opt)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(opt)
            scaler.update()
            sched.step()
            opt.zero_grad(set_to_none=True)
            step += 1
            if step % 50 == 0 or step == total:
                log(f"epoch {epoch + 1} step {step}/{total} loss {loss.item():.4f} ({time.time() - t0:.0f}s)")
    return model, tok


def train_and_evaluate(data_dir: Path, model_dir: Path, device: str | None = None) -> dict[str, Any]:
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    device = device or pick_device()
    train_rows, dev_rows, test_rows = (load_rows(data_dir / f"{s}.jsonl") for s in ("train", "dev", "test"))
    sets = {"dev": dev_rows, "test": test_rows, "injecagent": injecagent_rows()}

    model, tok = train(train_rows, device)
    scores: dict[str, dict[str, list[float]]] = {
        name: {"ours": batched_probs(model, tok, [r["text"] for r in rows], device, positive=1)}
        for name, rows in sets.items()
    }
    model_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(model_dir)
    tok.save_pretrained(model_dir)
    del model

    base_tok = AutoTokenizer.from_pretrained(PROTECTAI_MODEL)
    base = AutoModelForSequenceClassification.from_pretrained(PROTECTAI_MODEL).to(device)
    inj = next(int(i) for i, label in base.config.id2label.items() if "INJ" in label.upper())
    for name, rows in sets.items():
        scores[name]["protectai"] = batched_probs(base, base_tok, [r["text"] for r in rows], device, positive=inj)

    labels = {name: [int(r["label"]) for r in rows] for name, rows in sets.items()}
    metrics: dict[str, Any] = {
        "base_model": BASE_MODEL,
        "baseline": PROTECTAI_MODEL,
        "target_fpr": TARGET_FPR,
        "seed": SEED,
        "device": device,
        "injecagent_sha": INJECAGENT_SHA,
    }
    for model_name in ("ours", "protectai"):
        thr = threshold_at_fpr(scores["dev"][model_name], labels["dev"], TARGET_FPR)  # dev only, then frozen
        metrics[model_name] = {name: rates(scores[name][model_name], labels[name], thr) for name in sets}
    # ProtectAI at the 0.5 threshold AgentDojo's baseline (and our R1 "protectai" row) uses.
    metrics["protectai@0.5"] = {name: rates(scores[name]["protectai"], labels[name], 0.5) for name in sets}

    (model_dir / "threshold.json").write_text(
        json.dumps(
            {"threshold": metrics["ours"]["dev"]["threshold"], "target_fpr": TARGET_FPR, "max_len": MAX_LEN}, indent=2
        )
        + "\n"
    )
    meta = {name: [{k: v for k, v in r.items() if k != "text"} for r in rows] for name, rows in sets.items()}
    return {"metrics": metrics, "scores": scores, "rows": meta}


def audit(data_dir: Path) -> None:
    """Refuse to train on data that overlaps AgentDojo (same gate as train.ipynb Cell 3)."""
    splits = [str(data_dir / f"{s}.jsonl") for s in ("train", "dev", "test")]
    subprocess.run([sys.executable, "-m", "training.contamination_audit", *splits], check=True, cwd=ROOT)


def save_outputs(result: dict[str, Any]) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "metrics.json").write_text(json.dumps(result["metrics"], indent=2) + "\n")
    SCORES_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCORES_PATH.write_text(json.dumps({"scores": result["scores"], "rows": result["rows"]}))


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune and evaluate the taintwall L1 detector.")
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--model-dir", type=Path, default=MODEL_DIR)
    parser.add_argument("--device", choices=["cuda", "mps", "cpu"])
    args = parser.parse_args()
    audit(args.data_dir)
    result = train_and_evaluate(args.data_dir, args.model_dir, args.device)
    save_outputs(result)
    print(json.dumps(result["metrics"], indent=2))


if __name__ == "__main__":
    main()
