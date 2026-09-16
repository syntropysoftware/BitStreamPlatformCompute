#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 -m src.platformcompute.phase0h_deterministic_route_evidence_admission \
  --contract contracts/phase0h_deterministic_route_evidence_admission_v1.json \
  --output-root evidence
