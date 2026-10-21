"""Run `training/train_l1.py` on Modal (one L4 GPU, free-tier credit).

    uv run --group training --with modal modal run -m training.modal_train
    uv run --with modal modal volume get taintwall-l1 l1-model runs/l1-model   # weights never go in git

Same recipe and outputs as a local run; only the hardware differs. The contamination
audit runs locally before anything is sent. The reported model was trained locally
(MPS) because Modal was not available; see DECISIONS.md.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import modal

from training.train_l1 import DATA_DIR, audit, save_outputs

app = modal.App("taintwall-l1")
volume = modal.Volume.from_name("taintwall-l1", create_if_missing=True)
image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("torch==2.9.1", "transformers==5.20.2")
    .add_local_python_source("training")
    .add_local_dir(DATA_DIR, "/data")
)


@app.function(image=image, gpu="L4", timeout=3600, volumes={"/vol": volume})
def remote_train() -> dict[str, Any]:
    from training.train_l1 import train_and_evaluate

    result = train_and_evaluate(Path("/data"), Path("/vol/l1-model"), "cuda")
    volume.commit()
    return result


@app.local_entrypoint()
def main() -> None:
    audit(DATA_DIR)
    save_outputs(remote_train.remote())
