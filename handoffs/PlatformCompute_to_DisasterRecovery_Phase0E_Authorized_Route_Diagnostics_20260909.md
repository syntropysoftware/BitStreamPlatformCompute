# Platform & Compute → Disaster Recovery — Phase-0E Authorized Route Diagnostics

Contract: `bitstream-platformcompute-phase0e-authorized-route-diagnostics-v1`
Authority: `PLATFORM_INFRASTRUCTURE_FACTS_ONLY`
Production mutation: `NONE`

This source update is a bounded successor to the Phase-0D focused reconciliation. It is intended to turn generic route timeouts into explicit evidence-layer classifications without broad inventory, new credentials, host-key enrollment, root fallback, sudo, service restart, guest lifecycle mutation, storage/network mutation, or backup/restore execution.

The runner checks the already-configured `hv` management route, probes exact guest SSH ports from that observation point, captures read-only libvirt metadata when available, and attempts guest SSH only under strict existing host-key trust. Direct workstation TCP failures are retained only as non-authoritative context because the accepted topology may depend on ProxyJump/H1 routing.

The targeted lanes remain MariaDB18 (`192.168.200.18`), RedisServer6 (`192.168.200.6`), and ClientAppDB19 (`192.168.200.19`). ETHService and NodeServer remain owner-evidence questions. MarketData Influx retention remains `BLOCKED_NO_AUTHORIZED_ADMIN_READ` absent explicit authorization. NexusDB remains `SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED`; this update does not implement its reader or establish a new trust path.

Expected evidence product: `platformcompute-phase0e-readonly-<timestamp>.zip` plus external SHA-256, containing per-lane JSON, `summary.csv`, `summary.env`, `receipt.json`, `REPORT.md`, `MANIFEST.sha256`, and `HANDOFF_TO_DISASTER_RECOVERY.md`.

DR/Data Protection retains all protection, retention, restore, and recovery acceptance authority.
