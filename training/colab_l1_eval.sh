#!/usr/bin/env bash
# Run the L1 R1 replays on Colab next to the trained weights, then package only the
# small result files (the ~600 MB weights stay on Colab; downloading them hangs).
set -euo pipefail
cd /content/taintwall
git fetch -q origin feat/l1-detector && git reset -q --hard origin/feat/l1-detector
for split in dev test; do
  for defense in taintwall-l1 taintwall-l1+l2; do
    python -m taintwall.eval.replay --split "$split" --defense "$defense"
  done
done
rm -f l1_small.zip
zip -qr l1_small.zip results/l1 runs/l1_scores.json results/r1/taintwall-l1 "results/r1/taintwall-l1+l2" runs/l1-model/threshold.json
ls -la l1_small.zip
