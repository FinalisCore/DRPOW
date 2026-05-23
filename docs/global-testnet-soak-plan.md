# Global Testnet Soak Plan (Pilot-Open)

This is the execution plan for proving global-testnet readiness.

## 1. Test Waves

1. Wave A
- 10 nodes, single region, 24h.
- Goal: baseline stability and invariant safety.

2. Wave B
- 20 nodes, 3 regions, 48h.
- Goal: RTT diversity and sync convergence.

3. Wave C
- 30+ nodes, mixed hardware, 72h.
- Goal: churn resilience and operator heterogeneity.

## 2. Metrics to Capture

1. Consensus safety
- invalid commit count (must stay zero).

2. Liveness
- commit cadence and dead-round count.

3. Sync stability
- lag distribution,
- catchup success/failure counts,
- sync convergence time percentiles.

4. Preemption effectiveness
- `pow_preempt_rounds`,
- `pow_preempt_remote_commit_fast`,
- `pow_preempt_remote_commit_slow`,
- `preempt_fast_rate`.

5. Network hygiene
- drop summaries,
- params mismatch counts,
- unauthenticated drop spikes.

## 3. Fault-Injection Scenarios

1. Seed outage
- remove one seed, then restore.

2. Partition and heal
- isolate subset for fixed duration, then reconnect.

3. Message pressure
- malformed/replay-like load against parser/rate-limit paths.

4. Slow miner cohorts
- introduce lower hash-rate nodes and verify no control-loop collapse.

## 4. Pass/Fail Gates

1. Fail immediately if:
- any invalid commit accepted,
- finalized-boundary safety violation.

2. Wave pass targets:
- no persistent dead-round behavior,
- stable catchup convergence,
- `preempt_fast_rate >= 0.70` in mixed-leader periods.

## 5. Operator Command Skeleton

Each operator should run:

```bash
cd /home/greendragon/Desktop/coin/src
AUTOPROPOSE=1 \
POW_TARGET_PREFIX_BYTES=2 \
BIND_PORT=<port> \
PUBLIC_ENDPOINT=<public_ip>:<port> \
SEED_PEER=<seed_ip>:19440 \
./scripts/start_testnet.sh
```

Collect logs continuously and archive with UTC timestamps.
