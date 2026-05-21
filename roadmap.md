# Roadmap

This roadmap is constrained by [`DRPOW.md`](./DRPOW.md). If any roadmap item conflicts with DRPOW normative requirements, DRPOW wins.

## Protocol Lock (Non-Negotiable)

1. Consensus security domain
- DRPOW is permissionless and deterministic, but finality is not plain longest-chain PoW finality.
- Finality is derived from **typed quorum certificates (QC)** with deterministic eligibility and weighted threshold rules defined in DRPOW.
- Any implementation path that allows commit without valid typed QC is invalid.

2. Settlement and finality semantics
- A round commit is valid only if QC verification passes all required checks:
  - round/hash consistency,
  - unique voters,
  - signature validity,
  - eligibility-type correctness,
  - weighted supermajority threshold.
- Reorg across finalized rounds is forbidden by consensus rule.

3. Determinism and auditability
- Canonical state transition is deterministic over committed history.
- Nodes may run state-first storage, but must preserve independent verifiability via deterministic commitments and replay/proof paths.

4. Open participation with anti-Sybil economics
- Admission/voting eligibility must be derived from committed on-chain data only.
- Admission policy must include deterministic anti-Sybil controls (work threshold, newcomer limits, epoch/churn bounds).

## Main Priorities

1. Deterministic, secure DRPOW finality
- Eliminate all legacy vote-count shortcuts and local-policy bypasses.
- Freeze typed QC formula, constants, and eligibility semantics as consensus-locked configuration.

2. Monetary and state safety
- Enforce no-inflation and single-use invariants in every commit path.
- Ensure all commit/reorg/replay paths preserve identical accounting and state roots.

3. Bounded validation cost
- Enforce strict caps on spends/mints/proofs/payload size.
- Keep worst-case verification cost deterministic and operator-auditable.

4. State-first verifiable storage
- Keep active DB oriented to current authenticated state.
- Preserve replay/audit guarantees with deterministic roots and transition witnesses.

5. Quantum-resistant + confidentiality roadmap
- Keep PQ and confidentiality as phased upgrades that do not weaken deterministic consensus safety.

## Derived Technical Requirements

- Deterministic consensus and replay.
- Typed QC-only finality path (no untyped or fallback acceptance path).
- Deterministic admission from on-chain data.
- Explicit, consensus-locked anti-Sybil economics.
- Bounded validation cost by protocol constants.
- Clean separation of consensus/state/network/wallet layers.

## Architecture Direction

### A. Finality engine
- Maintain a single canonical typed QC verifier used by:
  - live commit path,
  - sync catchup path,
  - replay/reorg path.
- Prohibit commit if QC fails in any path.

### B. Admission and eligibility
- Implement deterministic epoch admission from committed work history.
- Bind `eligibility_type` into signed vote bytes and enforce type correctness at verification.

### C. State and reorg policy
- Keep branch/replay window above finalized round only.
- Forbid branch switch below finalized checkpoint.
- Make branch swap atomic with full invariant checks.

### D. Storage and proofs
- State-first persistence with authenticated commitments.
- Deterministic recovery/rehydrate primitives for safe replay and branch execution.

### E. PQ and privacy
- Version cryptographic formats explicitly.
- Keep validation bounded when enabling confidentiality and PQ signatures.

## Phased Plan

### PR-1: Safety lock + deploy consistency (must stay green)
- Enforce “no commit after insufficient QC”.
- Keep build/config compatibility lock to prevent split-brain deployments.
- Ensure sync/catchup uses identical QC safety gate.

### PR-2: PoW-weighted QC and deterministic fork-choice
- Replace vote-count quorum semantics with weighted threshold semantics everywhere.
- Normalize wire/proof structures for cumulative weight verification.
- Implement deterministic same-round conflict resolution by valid-weighted rule.

### PR-3: Bounded reorg above finalized round only
- Add explicit branch index and replay window policy.
- Deny reorg below finalized round by rule.
- Execute safe branch replay + atomic state swap with invariant recheck.

### PR-4: Deterministic open admission economics
- Finalize epoch/admission constants on-chain.
- Implement anti-Sybil newcomer limits and deterministic churn bounds.
- Ensure joiner behavior follows deterministic sync-first eligibility policy.

### PR-5: DRPOW compliance closure
- Close full DRPOW test matrix and property tests.
- Publish fork-choice/finality assumptions and constants.
- Mark protocol “DRPOW compliant” only after all mandatory checks pass.

## Mandatory Security Test Gates

1. No-inflation property tests over long randomized histories.
2. Replay determinism across independent nodes.
3. Typed QC adversarial tests:
- wrong eligibility type,
- duplicate voter,
- forged signature,
- threshold mismatch,
- stale/future vote handling.
4. Admission transition tests:
- mine -> eligible -> vote under deterministic epoch rules.
5. Partition/rejoin and byzantine network tests:
- safety preserved,
- bounded catchup cost,
- no invalid commit via sync path.
6. Reorg policy tests:
- reorg above finalized round allowed when valid,
- reorg below finalized round denied.

## Open Questions (Constrained)

1. Exact DRPOW constants to freeze now:
- typed weight constants,
- quorum threshold integer form,
- epoch/admission bounds,
- finality depth/replay window.
2. PQ signature suite selection under bounded verification cost.
3. Confidential transaction design that preserves deterministic validation bounds.

## Success Criteria

- No commit is accepted without valid typed QC in any code path.
- No inflation and single-use invariants hold under replay, sync, and reorg.
- Admission is permissionless but deterministically anti-Sybil.
- Reorg below finalized round is impossible by consensus rule.
- State-first operation remains cryptographically auditable.
- DRPOW mandatory checklist in `DRPOW.md` is fully closed.
