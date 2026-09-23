# Platform & Compute → MarketData — DEV InfluxDB Capacity and Isolation Gate

**Date:** September 23, 2026
**In response to:** `MarketData-to-PlatformCompute-InfluxCapacityGate-20260923(1).md`
**Platform authority:** `PLATFORM_INFRASTRUCTURE_FACTS_ONLY`
**Request authority:** `NONE_COLLECTION_AND_ANALYSIS_ONLY`
**Disposition:** Interim scope/evidence review; **not** a capacity or backfill authorization.

## Requested gate — current disposition

```text
ACTUAL_INFLUX_HOST_AND_VOLUME = UNVERIFIED; DEV console endpoint 192.168.200.27:8086 is a reference, not physical host or volume proof
DEV_LIVE_ISOLATION = UNVERIFIED
RETENTION_SAFE_FOR_506_DAY_RESEARCH = UNVERIFIED
SEGMENT_C_CAPACITY = UNVERIFIED
MAX_PILOT_DAYS = unset
MAX_STAGED_BATCH_DAYS = unset
MIN_FREE_SPACE_AND_STOP_THRESHOLD = unset
REVIEWER / EVIDENCE_UTC = Platform & Compute (scope review only) / NOT_COLLECTED
DEPENDENCIES = owner-verified actual guest/hypervisor/storage mapping; authorized read-only volume/IO evidence; independent DEV/LIVE sharing assessment; authorized owner-provided bucket-retention and lifecycle proof; at least two attributable measured storage-growth windows; measured peak workload, WAL/index/compaction reserve, concurrency budget and stop policy; separate Disaster Recovery backup/restore IO and off-host-copy assessment
```

**Why:** The MarketData request supplies the console endpoint, bucket names and two trade-count/quality reference days but does not supply physical host/mount evidence, timestamped filesystem measurements, attributable stored-byte deltas, retention proof, workload contention measurements or DR restore evidence. Trade counts are not bytes/trade. The September 21, 2026 REVIEW day is outside Segment C and is not an eligible certified export reference.

## Scope and sequence

Segment C is BTC-USD `[2026-07-07 00:00 UTC, 2026-09-18 00:00 UTC)` (73 days). Segment A (303 days) and B (130 days) require separate forecasts, not approvals. The 506-day research horizon must be addressed in retention and protection planning. The canonical candle bucket `CBAdvMarketData-BTC-USD` remains read-only; raw historical trades belong to `CBAdvMarketTrades-BTC-USD` / `market_trades_raw`. No backfill has been launched or authorized.

The following owner-owned evidence is needed before a gate can be signed:

1. **Platform / inventory:** Establish the actual Influx guest, hypervisor and host backing `192.168.200.27:8086`; identify data, WAL, index and backup volumes and mount identity. Map DEV and LIVE clients, volumes, buckets and backup paths to show whether any bottleneck is shared. A workstation timeout or an endpoint IP is not host identity proof.
2. **Platform / permitted operator:** On the *owner-verified actual host*, obtain timestamped local read-only free/used/inode and mount observations, with CPU/RAM/IO and service write/compaction observations during the existing BTC collector and ETH candle backfill. Do not capture credentials, process environments, token-bearing configs or query raw trades. Measure disk latency and workload contention over representative intervals; a single `/proc/diskstats` counter is **not** a latency measurement.
3. **MarketData / authorized Influx administrator:** Provide redacted bucket IDs and effective retention, lifecycle/pruning/quota evidence for the trade bucket, canonical BTC candle bucket and all applicable multi-pair candle buckets. Phase-0I's earlier `BLOCKED_NO_AUTHORIZED_ADMIN_READ` remains in force for Platform unless explicit authorization is separately supplied. Do not change retention in this inventory.
4. **MarketData + Platform:** Record at least two separately attributable *persisted engine/index* byte-growth windows alongside known raw trade-count deltas and representative compaction state. Establish a measured peak-day workload, temporary WAL/TSM/index/compaction headroom, free-space stop policy, batch-size/concurrency limits and a way to measure incremental growth after each **separately authorized** pilot batch. The two reported trade-count days alone cannot establish bytes/trade or peak storage.
5. **Disaster Recovery / Data Protection:** Independently assess backup/snapshot IO, restore-time free-space requirements, off-host-copy bandwidth and shared-LIVE contention. A Platform capacity finding never implies backup/restore acceptance.

## Phase-0J read-only evidence kit

The companion repository drop-in adds a local-only host snapshot and offline capacity-gate evaluator. Its local collector does **not** SSH, probe networks, call Influx APIs, change service/retention/storage settings, create credentials or initiate backfills. It fails closed unless its supplied hostname and inventory mapping match the actual local machine and its source matches accepted `origin/main`. It collects only explicitly scoped existing volume paths; a remote backup mount is left unresolved for separately authorized owner evidence.

The offline evaluator reports `UNVERIFIED` when measurements or owner approvals are missing, derives C/A/B forecasts *only* from separately attributed stored-byte measurements, and requires explicit owner signoff and source references for any future Segment C capacity approval. It emits an immutable, manifest-verified evidence ZIP and separate MarketData/DR handoffs. The accompanying initial handoff is **not** a substitute for the completed post-collection packet.

**Safety / status:** No infrastructure, LIVE workload, Influx retention, backup/restore, trading authority, credentials or dataset was modified. No Segment C, A or B backfill is authorized by this response.
