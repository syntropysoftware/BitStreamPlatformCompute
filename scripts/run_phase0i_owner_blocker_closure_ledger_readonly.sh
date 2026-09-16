#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 PHASE0H_IMMUTABLE_ZIP [PREVIOUS_PHASE0I_LEDGER_JSON_OR_ZIP]" >&2
  exit 64
fi
args=(
  --contract contracts/phase0i_owner_blocker_closure_ledger_v1.json
  --phase0h-zip "$1"
  --output-root evidence
)
if [[ $# -eq 2 ]]; then
  args+=(--previous-ledger "$2")
fi
python3 -m src.platformcompute.phase0i_owner_blocker_closure_ledger "${args[@]}"
