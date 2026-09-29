# Platform & Compute — Phase-0J Four-Defect Closure Evidence Capture R2

**Authority:** `PLATFORM_INFRASTRUCTURE_FACTS_ONLY`

R2 corrects evidence classification from the first September 29 capture. It does **not** run the Phase-0J collector.

## R2 corrections

- Corrects `virsh domiflist` ServicesDEV MAC-column parsing.
- Captures the read-only `ServicesDEV` libvirt network XML so the current target MAC can be bound to the `.27` reservation even when no DHCP lease is active.
- Attests each required Phase-0J file byte-for-byte against `refs/remotes/origin/main` without changing the current checkout.
- Treats the source's dynamic `subprocess.run(["git", *args])` only as the exact read-only Git wrapper it is, rather than an unknown dynamic external command.
- Derives and records the exact host-side Phase-0J `collect` operation allow-list from accepted source.
- Explicitly records whether accepted `collect` requires guest-local `data_path` / `wal_path` access.
- Captures local configuration/trust evidence for an exact `CBAdvMarketDataDBDEV` SSH alias if one already exists, but never connects to that guest and never infers authorization from configuration alone.
- Keeps `EXISTING_AUTHORIZATION_FOR_EXACT_OPERATION_SET` fail-closed until the captured existing path actually proves the reviewed guest-local operation set.

## Safety boundary

The only remote connection performed by this helper is the already-used `hv2` owner path. Remote commands are fixed and read-only:

- `date`, `hostname`
- `virsh domuuid`, `dominfo`, `domiflist`, `domblklist`
- `virsh net-dhcp-leases`, `virsh net-dumpxml`
- `stat` and `findmnt -T` for the returned host-side disk source

It performs no `sudo`, no guest login, no service/configuration change, no Git mutation, no trust enrollment, no storage mutation, no backup/restore, no Influx API call and no Phase-0J collection.

## Run

From the accepted PlatformCompute checkout:

```bash
python3 scripts/phase0j_four_defect_closure_evidence.py
```

Outputs are written under `~/Downloads` as:

```text
PlatformCompute-Phase0J-FourDefect-Closure-<UTC>.zip
PlatformCompute-Phase0J-FourDefect-Closure-<UTC>.zip.sha256
```

## Interpretation

R2 may prove the accepted **Phase-0J source and exact operation set** even when the operator's clean `david` checkout HEAD differs from `origin/main`, provided every required Phase-0J file is byte-identical to `origin/main` and validation passes. This does **not** mean the current checkout is ready to run the collector: the collector's own source gate still requires `HEAD == origin/main` at execution time.

If accepted source proves that guest-local Influx paths are required, the helper will not pretend the existing hypervisor inventory identity authorizes those operations. An already-configured/pinned exact guest path is captured only as a candidate; owner authorization and allowed operations must still be evidenced before Security can accept it.

Return the resulting R2 evidence ZIP to the **MarketData centralized integration/closure point**. Do not start another planning chain.
