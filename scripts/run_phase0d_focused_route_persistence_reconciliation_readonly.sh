#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$REPO_ROOT/config/phase0d_targets.json"
OUT="$REPO_ROOT/output/phase0d"
echo "============================================================"
echo " PLATFORM & COMPUTE — PHASE-0D ROUTE / PERSISTENCE RECONCILIATION"
echo "============================================================"
echo "AUTHORITY=PLATFORM_INFRASTRUCTURE_FACTS_ONLY"
echo "SAFETY=READ_ONLY / STRICT_HOST_KEYS / NO_TOFU / NO_TRUST_ENROLLMENT / NO_MUTATION"
echo "NEXUSDB=SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED"
echo
echo "=== Accepted-source gate ==="
bash "$REPO_ROOT/scripts/validate_repository_acceptance_state.sh"
echo
echo "=== Repository regression validation ==="
bash "$REPO_ROOT/scripts/validate.sh"
mkdir -p "$OUT"
echo
echo "=== Phase-0D focused read-only collection ==="
python3 "$REPO_ROOT/src/platformcompute/phase0d_focused_route_persistence_reconciliation.py" --config "$CONFIG" --output-root "$OUT" --repo-root "$REPO_ROOT"
echo "PASS: Platform & Compute Phase-0D helper completed."
