#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 -m src.platformcompute.phase0g_existing_alias_route_reconciliation \
  --contract contracts/phase0g_existing_alias_route_reconciliation_v1.json \
  --output-root evidence
