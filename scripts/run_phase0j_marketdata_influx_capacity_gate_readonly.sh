#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
if [[ $# -lt 1 ]]; then
  printf 'Usage:\n  %s collect --scope SCOPE.json --output SNAPSHOT.json\n  %s evaluate --snapshot SNAPSHOT.json --assessment ASSESSMENT.json [--output-root DIR]\n' "$0" "$0" >&2
  exit 64
fi
python3 -m src.platformcompute.phase0j_marketdata_influx_capacity_gate "$@"
