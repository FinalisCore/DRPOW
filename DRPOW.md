# DRPOW: Decentralized Reusable Proof of Work

## 0. Purpose
This document upgrades the original RPOW idea (reusable work-backed value) from a trusted-server model to a deterministic, permissionless, multi-node consensus protocol.

Goal: preserve **reusability of work-backed value** while eliminating single-operator trust.

This is a normative protocol policy document. Any implementation claiming DRPOW compliance MUST satisfy all MUST-level requirements below.

---

## 1. Threat Model and Security Targets

### 1.1 Adversary Model
Adversary may:
- control arbitrary network links (delay/reorder/drop),
- run many Sybil nodes,
- contribute bounded but non-majority economic/work resources,
- attempt replay, equivocation, vote forgery, duplicate-leg churn, and admission gaming.

Adversary may NOT:
- break underlying cryptographic assumptions (hash preimage/collision resistance, signature unforgeability),
- exceed protocol-stated majority thresholds in the defined security domain.

### 1.2 Required Properties
Protocol MUST provide:
1. **No Inflation**: total minted value cannot exceed protocol-defined issuance + explicitly authorized transfer tax flows.
2. **Single-Use Consumption**: any spendable unit consumed in one accepted state transition cannot be consumed again.
3. **Deterministic Finality**: once a commit reaches valid QC threshold, conflicting commit at same round is invalid.
4. **Bounded Validation Cost**: per-round validation cost is capped by explicit policy constants.
5. **Deterministic Admission**: validator/voter eligibility is computed from on-chain data only.

---

## 2. Core Shift from RPOW to DRPOW

Original RPOW no-inflation was enforced by one trusted server database.

DRPOW replaces server trust with:
- replicated state machine (round commits),
- deterministic eligibility derivation,
- explicit typed votes + quorum-certificate (QC) verification,
- globally auditable replay of state transitions.

No server, operator, or single endpoint is trusted.

---

## 3. State, Value, and Conservation Rules (Normative)

### 3.1 Ledger State Variables
The canonical state MUST include at least:
- UTXO set,
- total_supply,
- total_minted,
- total_fees_burned (or explicit fee destinations),
- mint_budget / reserve accounting used by issuance policy,
- committed round number and state root.

### 3.2 No-Inflation Invariant
For every accepted commit at round `r`:

`delta_supply(r) = minted(r) - burned(r)`

`total_supply(r) = total_supply(r-1) + delta_supply(r)`

And MUST satisfy:

`minted(r) <= MintSubsidyForRound(r)`

plus any stricter reserve/budget caps.

Any batch violating this MUST be rejected deterministically by all nodes.

### 3.3 Single-Use Invariant
For each consumed input coin-id in accepted round `r`:
- coin-id MUST exist unspent in pre-state,
- coin-id MUST be removed exactly once,
- duplicate consumption in same or later accepted history MUST be rejected.

### 3.4 Replay Determinism
Given genesis + identical ordered accepted commits, all compliant nodes MUST derive identical final state root and accounting counters.

---

## 4. PoW Authorization and Reusability Semantics

### 4.1 PoW Role
PoW in DRPOW authorizes creation/advancement of batches under target constraints and contributes to admission evidence.

### 4.2 Reusability Semantics
“Reusable PoW” is realized as transfer/re-spendable ledger value whose issuance chain is rooted in valid PoW-authorized commits; not as re-presentation of identical external tokens.

### 4.3 Target Validation
For each minted batch:
- canonical batch hash MUST be computed deterministically,
- hash MUST satisfy declared/expected target relation,
- expected target MUST be derivable from prior committed history and policy constants only.

---

## 5. Typed Vote Eligibility and Finality (Normative)

### 5.1 Vote Eligibility Types
Each vote MUST include `eligibility_type`:
- `validator_set`
- `pow_recent`

Eligibility type MUST be signed as part of vote-sign bytes.

### 5.2 Eligibility Resolution
For vote `(round, validator_id, eligibility_type)`:
- if `validator_id` is in epoch validator set for `round`, only `validator_set` is valid,
- else `pow_recent` is valid only if `validator_id` is in deterministic recent-PoW eligible set for `round`.

Any mismatch MUST be rejected.

### 5.3 QC Verification
QC validity MUST require:
1. round/hash consistency,
2. unique voter IDs,
3. valid signatures (including eligibility type binding),
4. eligibility type correctness per 5.2,
5. typed weighted supermajority threshold.

### 5.4 Typed Weight Function
Define deterministic weight function `w(vote)`:
- validator-set voter weight = epoch voting power,
- pow_recent voter weight = fixed protocol constant `W_pow_recent`.

Total quorum denominator MUST be deterministic and auditable:

`W_total = sum(epoch validator powers) + W_pow_recent * |pow_recent_set(round)|`

QC passes iff:

`sum(w(votes_in_qc)) >= floor(2/3 * W_total) + 1` (or exact integer-safe equivalent).

All constants and formulas MUST be protocol constants, not local operator policy.

---

## 6. Admission and Open Competition

### 6.1 Objective
Any participant who satisfies protocol PoW and consensus rules SHOULD be able to transition to active voting eligibility without trusted approval.

### 6.2 Deterministic Admission Inputs
Admission MUST depend only on committed data, e.g.:
- recent committed PoW wins/work score in fixed windows,
- deterministic tie-breaks (hash/pubkey lexical order),
- explicit epoch size and newcomer caps.

### 6.3 Anti-Sybil Requirements
Admission policy MUST include explicit anti-Sybil economics:
- minimum recent work threshold,
- bounded newcomer growth per epoch,
- deterministic carry/retention criteria,
- optional slashing/quarantine for equivocation.

### 6.4 Joiner Mode
Nodes configured as joiners MUST NOT autopropose while unsynced.
Autopropose for joiners MAY be enabled only when deterministic eligibility checks pass.

---

## 7. Networking and Peer Identity Hygiene

### 7.1 Single-Connection-Per-Peer-ID
Implementations MUST enforce one canonical active leg per peer-id using deterministic tie-break.

### 7.2 Duplicate Suppression
Implementations SHOULD apply cooldown on duplicate node-id/endpoint handshakes to prevent redial storms.

### 7.3 Authenticated Message Gating
Consensus-critical messages from unauthenticated legs MUST be dropped.
Rate limiting MUST protect resources without creating arbitrary partition-via-quarantine behavior.

### 7.4 Mandatory Operator Metrics
Implementations MUST expose at least:
- duplicate keep/drop counts,
- cooldown hit counts,
- unauthenticated/rate-limited drop summaries,
- sync lag and catchup progress.

---

## 8. Bounded Validation Cost

Protocol MUST cap:
- spends per round,
- mints per round,
- proof verification budget per round,
- payload sizes for wire messages.

Exceeding caps MUST deterministically reject the batch/message.

---

## 9. Required Test Matrix Before Claiming DRPOW Compliance

A release MUST pass:
1. **No-inflation property tests** across long random histories.
2. **Replay determinism tests** across independent nodes/implementations.
3. **QC typed-eligibility tests**: mismatch, forgery, duplicate voter, wrong type.
4. **Admission transition tests**: mine -> eligible -> vote path in bounded rounds.
5. **Partition/rejoin tests**: safety under delayed links and reconnect churn.
6. **Cost-bound tests** under adversarial oversized payload/proof spam.

---

## 10. Current Implementation Gap Checklist (Actionable)

To claim “Decentralized Reusable Proof of Work”, the implementation MUST complete:

- [ ] Freeze and publish exact typed QC weight formula and constants.
- [ ] Ensure all QC paths use typed verification only (no legacy untyped acceptance path).
- [ ] Make epoch/admission constants chain-configurable and consensus-locked.
- [ ] Add formal no-inflation invariant checks to CI/property tests.
- [ ] Add byzantine network simulation tests for safety/liveness claims.
- [ ] Document fork-choice and finality theorem assumptions explicitly.

Until all boxes are checked, the system is an advanced DRPOW prototype, not a finalized DRPOW protocol.

---

## 11. Design Philosophy

RPOW proved that work-backed value can be reused.
DRPOW proves that this can be done **without trusting any single operator**:
- conservation from consensus state transitions,
- authenticity from cryptography,
- finality from typed quorum certificates,
- participation from open deterministic admission.

That is the standard for “Decentralized Reusable Proof of Work.”
