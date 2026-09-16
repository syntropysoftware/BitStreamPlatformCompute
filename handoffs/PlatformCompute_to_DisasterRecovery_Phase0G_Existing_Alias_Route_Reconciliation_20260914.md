# Platform & Compute → Disaster Recovery — Phase-0G Existing SSH Alias Route Reconciliation

Contract: `bitstream-platformcompute-phase0g-existing-alias-route-reconciliation-v1`
Authority: `PLATFORM_INFRASTRUCTURE_FACTS_ONLY`
Production mutation: `NONE`

Phase-0G is the bounded successor to Phase-0F. Phase-0F corrected the guest probe so it traversed a strict manually constructed `hv` ProxyJump path. Phase-0G removes the remaining ambiguity between a constructed route and the workstation's actual pre-existing SSH topology.

The collector reads only `Host` and `Include` directives from the user's SSH configuration to discover literal aliases. It does not emit raw SSH configuration contents, private-key paths, credential material, or arbitrary option values. Each literal alias is resolved with `ssh -G`; only bounded effective routing fields are retained. A target may be exercised only when an existing literal alias resolves to the scoped IP **and** its effective configuration contains the required existing `hv` ProxyJump.

The route is then executed by alias under command-line `StrictHostKeyChecking=yes`, `BatchMode=yes`, password authentication disabled, and keyboard-interactive authentication disabled. These command-line controls preserve the existing alias's user/port/ProxyJump while overriding weaker trust/auth settings. There is no direct-IP fallback, manual `-J` fallback, TOFU, `ssh-keyscan`, host-key enrollment, password prompt, credential discovery, root fallback, or sudo escalation.

After strict configured-alias SSH succeeds:

- **MariaDB18 (`192.168.200.18`)** uses the already-bounded Phase-0F service/version/listener/path collector. It does not log into MariaDB or read database/configuration contents.
- **RedisServer6 (`192.168.200.6`)** uses the already-bounded Phase-0F unauthenticated-only persistence/replication/count collector. It never discovers/supplies credentials, enumerates keys, or retrieves values.
- **ClientAppDB19 (`192.168.200.19`)** remains route-only.

If no matching alias exists, or the matching alias does not use the required `hv` ProxyJump, the lane fails closed rather than constructing a new route. Transport/trust/auth failures remain observations of those layers and are never proof that the guest or datastore is down.

Standing boundaries remain unchanged: ETHService and NodeServer require owner evidence for durable-state/rebuildability semantics; MarketData retention remains `BLOCKED_NO_AUTHORIZED_ADMIN_READ`; NexusDB remains `SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED`; DR/Data Protection retains all protection, retention, restore, and recovery acceptance authority.

A runtime produces an immutable ZIP, SHA-256, internal manifest, accepted-source gate, alias-discovery metadata, bounded effective route evidence, per-lane JSON, summary fields, receipt, report, and result-derived DR handoff.
