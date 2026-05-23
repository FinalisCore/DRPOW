# Global Testnet Readiness (DRPOW)

This document defines the minimum bar before announcing a globally open DRPOW testnet.

It is constrained by:
- [`DRPOW.md`](../DRPOW.md)
- [`roadmap.md`](../roadmap.md)

If any item here conflicts with those documents, DRPOW.md wins.

## 1. Current Phase

Current status is **private/open pilot**, not yet global public GA.

Why:
- consensus path is improving but still actively tuned (pacemaker/sync control behavior),
- multi-region adversarial soak evidence is not yet complete,
- release/operations discipline for public operators is not fully frozen.

## 2. Decision Policy

Use these stage labels only:

1. `pilot-private`
- invitation-based nodes,
- protocol changes allowed between short epochs,
- metrics and rejection telemetry are primary objective.

2. `pilot-open`
- anyone can join with published params/genesis/seed list,
- protocol constants still considered "test mutable" between announced epochs,
- no economic-finality claims beyond testnet scope.

3. `public-testnet-ga`
- explicit release tags and deterministic launch manifest,
- frozen epoch constants for stated window,
- documented incident response and rollback policy.

## 3. Global-Ready Minimum Gates (Must Pass)

### A. Consensus safety/liveness gates

1. No invalid commit acceptance
- no commit accepted without valid typed QC in any path (live/sync/catchup/replay).

2. Reorg policy correctness
- reorg above finalized round behaves as designed,
- reorg below finalized round is denied by rule.

3. Pacemaker/sync stability
- no sustained sync storm behavior under normal churn,
- lag recovery converges within bounded rounds,
- timeout behavior does not dominate when peer commits are available.

4. Mining preemption effectiveness
- preemption events produce remote commit convergence in bounded time for most events,
- track via `pow_preempt_*` metrics and `preempt_fast_rate`.

### B. Abuse-resistance gates

1. Message abuse
- authenticated-gating, rate-limits, and cooldowns proven under spam/malformed traffic.

2. Peer churn resilience
- high join/leave and reconnect churn does not collapse liveness.

3. Resource bounds
- bounded CPU/memory behavior under adversarial payload mix.

### C. Multi-region network gates

1. Geographically distributed seed set
- minimum 3 independent seed operators across different regions/ASNs.

2. Reachability
- published port/NAT/firewall guide,
- validated inbound reachability from at least 3 external vantage points.

3. Latency diversity test
- sustained run with mixed RTT classes (e.g. <50ms, 50-150ms, >150ms).

### D. Release discipline gates

1. Deterministic launch manifest
- canonical: `params_version`, `params_hash`, genesis hash, seed list, port, release tag.

2. Binary/revision discipline
- release tag + build instructions,
- explicit compatibility matrix,
- documented policy for build-id mismatch (warn vs enforce).

3. Operator observability
- mandatory logs/metrics documented with expected ranges and alerts.

## 4. Test Program Before Public Announcement

## 4.1 Soak test matrix

1. `N=10` nodes / one region / 24h
- objective: baseline stability and invariant safety.

2. `N=20` nodes / 3 regions / 48h
- objective: RTT diversity and sync convergence.

3. `N=30+` nodes / mixed hardware / 72h
- objective: operator heterogeneity and churn resilience.

## 4.2 Fault-injection matrix

1. Seed outage and recovery
- remove one seed, then two, verify peer graph recovery.

2. Partition and heal
- isolate subset for fixed window, heal link, validate safe convergence.

3. Adversarial message pressure
- malformed/oversized/replay-like traffic against rate-limit and parser paths.

4. Slow miner cohorts
- ensure pacemaker does not destabilize when hash-rate is uneven.

## 4.3 Pass criteria (suggested)

1. Safety
- zero invalid commits.

2. Liveness
- no persistent dead rounds over soak window.

3. Sync
- 99th percentile catchup convergence within configured replay window budget.

4. Preemption utility
- `preempt_fast_rate >= 0.70` during mixed-leader periods (tunable target).

5. Ops signal quality
- metrics/logs sufficient to root-cause any liveness degradation within 15 minutes.

## 5. Launch Manifest Template (Publish Before Open Pilot)

Create `global_testnet_manifest_v1.md` with:

1. Protocol identity
- network name,
- `params_version`,
- `params_hash`,
- genesis hash.

2. Bootstrap set
- seed endpoints,
- expected listening port,
- minimal peer recommendations.

3. Runtime policy
- finality depth,
- replay window,
- autopropose defaults,
- sync policy.

4. Compatibility policy
- required release tag(s),
- compatibility window,
- deprecation timeline.

5. Operator SLOs
- expected commit cadence,
- acceptable lag envelope,
- expected RTT adaptation range.

## 6. Immediate Next Actions (Now)

1. Keep phase as `pilot-open` candidate, not GA.
2. Run multi-region soak and fault-injection matrix above.
3. Freeze and publish launch manifest draft.
4. Publish operator runbook/checklist (see companion doc).
5. Only after gates pass, announce globally.
