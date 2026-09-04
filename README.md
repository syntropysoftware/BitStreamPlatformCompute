# BitStream Platform & Compute

`BitStreamPlatformCompute` is the repository for BitStream's **Platform & Compute Department**, part of the **Engineering Division → Infrastructure Group**.

The department owns the implementation and operational facts of the shared compute and platform layer that BitStream systems run on. Its purpose is to make infrastructure placement, runtime state, host-level service ownership, durable local state, and approved platform configuration explicit, inspectable, reproducible, and safely operable without redefining the authority of the application or governance domains that consume that infrastructure.

## What “Platform & Compute” means

**Compute** is the execution substrate: virtual machines, guest operating systems, runtime hosts, CPU and memory resources, host placement, and the operating environment in which BitStream services execute.

**Platform** is the shared systems layer built on that substrate: operating-system runtime configuration, shared service placement, host-level datastore infrastructure, filesystem/runtime evidence, and other infrastructure capabilities required by BitStream applications and infrastructure-control departments.

This repository therefore sits between physical-machine ownership and application ownership. It describes and implements the platform on which services run; it does not redefine what those services mean or what business/trading decisions they are allowed to make.

## Department responsibilities

Platform & Compute is responsible, where infrastructure-owned, for:

- VM and guest operating-system platform state;
- runtime-host and shared-service infrastructure;
- compute/runtime placement and host identity;
- MariaDB, Redis/Valkey, and Influx host-level service placement and filesystem/runtime evidence;
- server-local durable-state inventory and reconstruction-relevant host state;
- shared datastore physical-host ownership and placement facts;
- implementation of approved least-privilege operating-system reader capabilities;
- platform configuration required to implement separately approved Security controls;
- infrastructure evidence required by Data Protection and Disaster Recovery;
- repeatable, read-only inspection and validation tooling for infrastructure-owned facts;
- immutable evidence and receipts for platform-level observations and approved changes.

## Authority boundaries

Platform & Compute has a deliberately narrow authority boundary.

It **does not own or redefine**:

- company security policy or access-control policy — owned by the Security Department;
- backup, retention, recovery, RPO, or restore-acceptance policy — owned by Data Protection and Disaster Recovery;
- monitoring-health meaning, alert semantics, or incident-health contracts — owned by Systems Monitoring & Observability;
- application/domain semantics — owned by the applicable application or data-producing department;
- network architecture and network-policy ownership — owned by Network Engineering where applicable;
- physical machine/datacenter ownership — owned by Data Center & Machine Engineering where applicable;
- trading authority or trading decisions — retained by Nexus and the applicable trading-authority contracts.

Platform & Compute may implement an approved control or capability, but approval remains with the department that owns the governing policy.

## Operating principles

### Evidence before inference

Infrastructure ownership, datastore role, durability, and application ownership must be supported by evidence. Hostnames, VM names, paths, process names, or historical assumptions are not sufficient by themselves to assign application or policy ownership.

Unknown or unproven facts should remain explicitly `UNKNOWN`, `UNRESOLVED`, or `REVIEW_REQUIRED` until authoritative evidence exists.

### Least privilege

Inspection and automation should use the least privilege necessary for the task. Tooling must not silently weaken SSH trust, enroll host keys, create accounts, escalate with `sudo`, change credentials, or broaden access merely to obtain evidence.

### Read-only by default

Discovery, inventory, and evidence collection should be non-mutating unless a separately approved change explicitly requires mutation. Repository tooling should make the difference between observation and modification obvious.

### Domain ownership is preserved

Platform-level evidence can establish where a service runs, which filesystem it uses, what process is active, and what platform configuration is observable. It must not infer application meaning, business ownership, backup acceptance, security approval, monitoring health, or trading authority from those observations.

### Reproducible receipts

Platform evidence and approved implementation work should produce sufficient identity, timestamps, hashes, and execution receipts to make the observation or change independently reviewable.

## Relationship to neighboring departments

| Department | Relationship |
| --- | --- |
| **Network Engineering** | Owns network engineering and network-specific architecture/policy; Platform consumes approved connectivity and reports host/runtime requirements. |
| **Data Center & Machine Engineering** | Owns physical machine/datacenter concerns; Platform owns the operating compute/platform layer above that physical substrate where assigned. |
| **Security** | Defines and approves security, access-control, and trust requirements; Platform implements approved platform-side controls. |
| **Data Protection** | Owns protection/retention policy; Platform provides authoritative host, filesystem, datastore-placement, and durable-state facts. |
| **Disaster Recovery** | Owns recovery/reconstruction policy and acceptance; Platform provides infrastructure evidence and approved platform implementation support. |
| **Systems Monitoring & Observability** | Owns operational-health semantics; Platform provides infrastructure/runtime observations and implementation support without redefining health. |
| **Application departments** | Own application and data semantics; Platform owns infrastructure placement and host-level implementation facts. |
| **Nexus** | Retains trading authority; Platform has no trading-decision authority. |

## Repository scope

This repository is the durable home for Platform & Compute-owned source, including:

- platform inventory and inspection tooling;
- compute/runtime host evidence collectors;
- shared datastore host-level inspection tooling;
- server-local durable-state inspection tooling;
- approved platform configuration and implementation assets;
- validators, schemas, and evidence contracts owned by Platform & Compute;
- tests for Platform & Compute-owned tooling;
- repository-level documentation needed to understand and safely operate the above.

Transient run output and generated evidence are not source code and should not be committed unless a specific evidence-retention contract requires it.

## Repository layout

The repository is intentionally organized so source and generated evidence remain distinct:

```text
BitStreamPlatformCompute/
├── README.md
├── config/        # checked-in, non-secret inventory/configuration contracts
├── scripts/       # operator entry points
├── src/           # Platform & Compute-owned implementation
├── tests/         # validation and regression tests
└── output/        # generated runtime evidence; ignored by Git
```

Additional directories should be introduced only when a durable responsibility requires them.

## Safety expectations

Platform & Compute tooling must fail closed when required identity, authorization, or trust prerequisites are absent. In particular, read-only evidence tooling must not compensate for missing access by creating users, modifying SSH trust, disabling host-key verification, automatically enrolling host keys, restarting services, changing storage/networking, or executing backup/restore operations.

Secrets, credentials, private keys, access tokens, and unredacted secret-bearing configuration must never be committed to this repository or intentionally copied into evidence artifacts.

## Repository identity

- **Department:** Platform & Compute Department
- **Division / Group:** Engineering Division → Infrastructure Group
- **Repository:** `BitStreamPlatformCompute`
- **Standard local path:** `/home/alien/Documents/Business/Entities/BitStream/BitStreamPlatformCompute`
- **Automation/drop-in routing identity:** `platformcompute`

The routing identity is only the canonical key used by BitStream's repository-integration/master drop-in workflow to resolve this repository. It is not a service name and does not create a separate runtime component.
