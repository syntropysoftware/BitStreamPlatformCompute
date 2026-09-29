# Platform & Compute — Phase-0J Four-Defect Closure Evidence Capture

**Authority:** `PLATFORM_INFRASTRUCTURE_FACTS_ONLY`

This helper collects only the four Security closure proofs. It does **not** run the Phase-0J collector.

## Run

From the accepted BitStreamPlatformCompute checkout:

```bash
python3 scripts/phase0j_four_defect_closure_evidence.py
```

The evidence ZIP and `.sha256` sidecar are written to `~/Downloads`.

## Fixed safety boundary

The only remote target is the already-known owner SSH alias `hv2`. The helper uses fixed read-only commands against the exact known target `CBAdvMarketDataDBDEV`: `hostname`, `virsh domuuid`, `virsh dominfo`, `virsh domiflist`, `virsh net-dhcp-leases`, `virsh domblklist`, `stat`, and `findmnt -T`.

It performs no Git fetch/reset/checkout/pull, no new account/key/reader, no `sudo`, no trust enrollment, no alternate-host probing, no guest login, no service/configuration change, no firewall/routing change, no storage mutation, no backup/restore, no data movement, and no Segment C work.

The helper also hashes/copies the exact current Phase-0J source/contract/runner/templates/test/usage files, runs the existing Phase-0J unit test, creates a deterministic static operation inventory, and searches an existing local `BitStreamDisasterRecovery` checkout for the current `bitstream-dr-inventory` forced-command source.

It deliberately does **not** self-authorize Phase-0J. `EXISTING_AUTHORIZATION_FOR_EXACT_OPERATION_SET` remains `NOT_PROVEN` until the captured exact DR scope is compared with the captured exact Phase-0J operation set by the responsible owners/Security.

## Routing

Return the resulting evidence ZIP to the **MarketData centralized integration/closure point**. Do not start another planning chain. Phase-0J remains blocked until Security explicitly records:

```text
SECURITY_PHASE0J_ACCESS=EXISTING_PATH_ACCEPTED_FOR_BOUNDED_COLLECTION
```
