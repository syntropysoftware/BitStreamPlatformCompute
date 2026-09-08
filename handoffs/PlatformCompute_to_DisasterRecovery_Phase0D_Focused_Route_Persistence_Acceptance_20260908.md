# BitStream Platform & Compute → Disaster Recovery / Data Protection
## Phase-0D Focused Route / Persistence Reconciliation Acceptance

**Date:** 2026-09-08
**Authority:** `PLATFORM_INFRASTRUCTURE_FACTS_ONLY`
**Production mutation:** `NONE`

Platform & Compute accepts the next focused completion priority following the admitted Phase-0C run `platformcompute-phase0c-readonly-20260908T160719Z`.

Phase-0D does not repeat broad Phase-0/Phase-0B/Phase-0C discovery. It focuses on the existing H1 access path for MariaDB18, RedisServer6, and ClientAppDB19, using the H1 hypervisor as a read-only observation point to distinguish VM state, guest-port reachability, route behavior, and collector trust preconditions before any guest persistence probe is attempted.

Guest SSH is attempted only when the H1-side TCP probe shows an SSH candidate port reachable and the exact guest host key is already pre-approved on the collector. The collector never performs TOFU, host-key enrollment, `known_hosts` mutation, route mutation, VM lifecycle action, offline disk mounting, privilege escalation, backup/restore execution, retention/RPO assignment, or NexusDB reader implementation.

ETHService and NodeServer are limited to Platform-visible VM state/interface/block-device metadata. Application ownership and guest durable-state meaning remain owner evidence questions unless independently proven.

MarketData Influx retention remains bounded by the prior already-authorized-admin-read condition. NexusDB remains `SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED`.

The completed Phase-0D run will generate an immutable evidence ZIP, SHA-256, manifest, no-mutation receipt, human-readable report, and result-derived `HANDOFF_TO_DISASTER_RECOVERY.md`.
