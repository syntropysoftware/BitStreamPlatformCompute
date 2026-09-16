# Platform & Compute → Disaster Recovery — Phase-0H Deterministic Route Evidence Admission

Contract: `bitstream-platformcompute-phase0h-deterministic-route-evidence-admission-v1`
Authority: `PLATFORM_INFRASTRUCTURE_FACTS_ONLY`
Production mutation: `NONE`

Phase-0H is the bounded successor to Phase-0G. It does not broaden infrastructure access. Its purpose is to make the existing H1 route/persistence evidence deterministic, privacy-bounded, internally self-verifying, and easier for Disaster Recovery to review without confusing Platform packet integrity with DR acceptance.

The principal Phase-0G hardening closes a deterministic-selection edge case: matching aliases are no longer capped before route preference is evaluated. Phase-0H evaluates the complete already-bounded literal-alias set, selects an alias whose effective route contains the required existing `hv` ProxyJump when one exists, and only then caps the alias evidence emitted to the packet. A large number of direct aliases therefore cannot hide a later valid H1-routed alias.

Command evidence is also tightened. Long remote command bodies are represented by byte length and SHA-256 in the evidence command vector while their bounded stdout/stderr observations remain available. This preserves reproducibility without repeatedly embedding collector programs in every lane artifact.

The same authority boundaries remain in force. No TOFU, `ssh-keyscan`, host-key enrollment, direct-IP fallback, manual `-J` fallback, credential discovery, root fallback, sudo escalation, service restart, network/storage mutation, or backup/restore execution is permitted. MariaDB18 and RedisServer6 remain bounded persistence-observation lanes after strict existing-alias route success; ClientAppDB19 remains route-only.

ETHService and NodeServer remain application-owner evidence questions. MarketData retention remains `BLOCKED_NO_AUTHORIZED_ADMIN_READ`. NexusDB remains `SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED` unless a separate explicit Platform implementation authorization is issued.

Phase-0H adds result-derived routing proposals and a Platform self-admission classification. `PLATFORM_OBSERVATION_PACKET_READY_FOR_DR_REVIEW` means accepted-source provenance and packet integrity passed and the immutable packet may be reviewed by DR. It does **not** mean backup coverage, retention acceptance, restore proof, recovery readiness, or DR closure.

A runtime produces the immutable evidence ZIP, external SHA-256, manifest, verification JSON, per-lane observations, summary fields, routing proposals, receipt, report, and result-derived DR handoff.
