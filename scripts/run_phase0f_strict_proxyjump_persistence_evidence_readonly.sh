#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 -m src.platformcompute.phase0f_strict_proxyjump_persistence_evidence \
  --contract contracts/phase0f_strict_proxyjump_persistence_evidence_v1.json \
  --output-root evidence
