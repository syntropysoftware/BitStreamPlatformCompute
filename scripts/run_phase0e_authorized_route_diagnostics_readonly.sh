#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 -m src.platformcompute.phase0e_authorized_route_diagnostics \
  --contract contracts/phase0e_authorized_route_diagnostics_v1.json \
  --output-root evidence
