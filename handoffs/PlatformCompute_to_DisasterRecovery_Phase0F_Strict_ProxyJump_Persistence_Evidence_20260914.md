# Platform & Compute → Disaster Recovery — Phase-0F Strict ProxyJump + Persistence Evidence

Contract: `bitstream-platformcompute-phase0f-strict-proxyjump-persistence-evidence-v1`
Authority: `PLATFORM_INFRASTRUCTURE_FACTS_ONLY`
Production mutation: `NONE`

Phase-0F is the bounded successor to Phase-0E. It corrects the diagnostic topology so the guest SSH check itself traverses the strict existing `hv` ProxyJump path rather than using a direct workstation-to-guest SSH attempt after an independent gateway TCP probe.

The collector now fails closed unless the repository source exactly matches the accepted `origin/main` commit and the worktree is clean. It then exercises strict non-interactive SSH through `hv`, preserving host-key verification on both hops. No host key is enrolled; no password prompt, credential discovery, root fallback, sudo, route change, service restart, guest lifecycle action, storage mutation, or backup/restore execution is permitted.

When the strict ProxyJump guest route succeeds, Phase-0F performs only lane-specific allow-listed observations:

- **MariaDB18 (`192.168.200.18`)**: service state, installed client/server version, listener metadata, and metadata/size for conventional MariaDB filesystem paths. It does not log into MariaDB or read database/configuration contents.
- **RedisServer6 (`192.168.200.6`)**: service/version/listener/path metadata plus unauthenticated-only safe persistence/replication/keyspace-count metadata. It never supplies/discovers credentials, enumerates keys, or retrieves values; protected instances fail closed.
- **ClientAppDB19 (`192.168.200.19`)**: strict route classification only; no broadened persistence collector is introduced.

The route classifier distinguishes strict-host-key blocks, guest authorization blocks, gateway forwarding refusal, target timeout/refusal, hypervisor-present-but-unresolved state, and confirmed strict ProxyJump SSH. Failures are observations of the route/trust/auth layer only and are never treated as proof that the guest or datastore is down.

Standing boundaries remain unchanged:

- ETHService and NodeServer remain `UNRESOLVED_REQUIRES_OWNER_EVIDENCE` for application durability/rebuildability semantics.
- MarketData Influx retention remains `BLOCKED_NO_AUTHORIZED_ADMIN_READ` absent explicit administrative-read authorization.
- NexusDB remains `SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED`; this update does not implement its reader or establish a new trust path.

A successful runtime produces an immutable evidence ZIP, external SHA-256, internal manifest, source gate, per-lane JSON, summary CSV/environment fields, receipt, report, and result-derived DR handoff. DR/Data Protection retains protection, retention, restore, and recovery acceptance authority.
