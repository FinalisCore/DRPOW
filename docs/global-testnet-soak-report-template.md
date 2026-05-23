# Global Testnet Soak Report (Template)

Report date: `TBD`
Wave: `A|B|C`
Coordinator: `TBD`

## 1. Topology

1. Node count:
2. Regions:
3. Seed nodes:
4. Duration:

## 2. Build/Protocol Identity

1. Release tag/commit:
2. `params_version`:
3. `params_hash`:
4. Genesis hash:

## 3. Safety Summary

1. Invalid commit acceptance incidents: `0|N`
2. Finalized-boundary violation incidents: `0|N`
3. Commit QC invalid drops observed: `N`

## 4. Liveness Summary

1. Total commits:
2. Dead-round incidents:
3. Timeout/TIMEOUT_QC frequency:

## 5. Sync Summary

1. `sync_needed` count:
2. `sync_received` count:
3. Catchup success count:
4. Long-tail lag incidents:

## 6. Preemption Summary

1. `pow_preempted` count:
2. `assert_preempt_ok` count:
3. `assert_preempt_slow` count:
4. `preempt_fast_rate` (OBS latest):
5. `preempt_fast_rate` (derived):

## 7. Abuse/Drop Signals

1. `params_hash_mismatch` events:
2. unauthenticated message drops:
3. notable drop reasons:

## 8. Pass/Fail Against Gates

1. Safety gate: `PASS|FAIL`
2. Liveness gate: `PASS|FAIL`
3. Sync convergence gate: `PASS|FAIL`
4. Preemption utility gate: `PASS|FAIL`

## 9. Incidents and Root Cause

1. Incident ID:
2. Timeline:
3. Root cause:
4. Mitigation:
5. Follow-up patch/doc:

## 10. Artifact Index

1. Seed logs:
2. Parser outputs (`analyze_testnet_log.sh`):
3. Config snapshots (redacted):
4. Dashboard screenshots / exported metrics:
