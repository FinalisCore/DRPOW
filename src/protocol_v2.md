# Protocol v2 (RPOW) Draft

This file locks the v1 direction for the new engine in `src`.

## 1. Target

- Decentralized RPOW network.
- Confidential UTXO model.
- No blockchain, no DAG.
- One replicated logical hex registry (current UTXO state only).
- Private-key ownership controls spend authority.
- Consensus atomically rewrites registry on spend/mint.
- Mining creates new coins (PoW).
- Post-quantum cryptography (PQC): quantum-resistant public-key cryptography designed to withstand attacks from quantum computers.

## 2. Normative Language

The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, and `MAY` in this document are to be interpreted as described in RFC 2119.

## 3. Core Rule Set

### 3.1 State

1. The canonical consensus state `S` SHALL be the live UTXO registry only.
2. Nodes MUST NOT require full transaction history as consensus state.
3. Each live UTXO entry MUST have a canonical byte serialization:
- `value` (`u64`, little-endian)
- `coin_id` (32 bytes)
- `commitment` (32 bytes)
- `owner_pubkey` (32 bytes)
- `range_proof` (64 bytes in current prototype; algorithm-specific in production)
- `mint_nonce` (32 bytes)
- `mint_signature` (32 bytes)
- `reserved` (32 bytes)
4. Registry iteration order MUST be deterministic and byte-lexicographic by `coin_id`.
5. State root computation MUST be deterministic:
- Leaf hash: `H("RPOV2:leaf:v1" || entry_bytes)`
- Parent hash: `H("RPOV2:node:v1" || left || right)`
- Odd leaf rule: duplicate the last leaf
- Empty state root: `H("RPOV2:empty:v1")`
6. All nodes processing the same accepted commit MUST derive identical post-state root bytes.

### 3.2 Ownership

1. A spend input MUST include owner authorization over canonical spend message bytes.
2. Only the holder of the corresponding spend private key SHALL be able to authorize that state mutation.
3. Nodes MUST reject any input where authorization proof does not match the referenced UTXO owner key.

### 3.3 Transition

1. Spend transition MUST:
- remove all referenced input UTXOs exactly once,
- add all output UTXOs,
- satisfy value conservation:
`sum(input_values) = sum(output_values) + fee`.
2. Mint transition MUST add new UTXO(s) only if PoW mint validity rules pass.
3. Overflow/underflow on all monetary arithmetic MUST be rejected.
4. Duplicate `coin_id` in resulting state MUST be rejected.
5. Any conflict (same input spent twice in one batch) MUST be rejected deterministically.

### 3.3.1 Fee Policy (Consensus-Critical)

1. Every spend transaction MUST include a fee field.
2. Fee validation MUST be deterministic and enforced in `propose`, `validate/vote`, and `commit`.
3. Nodes MUST reject a spend if `fee < MIN_FEE_PER_SPEND`.
4. Nodes MUST reject a spend if `fee > MAX_FEE_PER_SPEND` (when max is configured non-zero).
5. Current default consensus bounds are:
- `MIN_FEE_PER_SPEND = 1`
- `MAX_FEE_PER_SPEND = 100`
6. Rejection reason MUST be explicit and deterministic (`REJECT_FEE_POLICY_INVALID` in current implementation).
7. If fee policy changes in future releases, new bounds MUST be versioned and activated by deterministic network-wide rule.

### 3.4 Consensus (BFT Finality, PoW Authority, Zero PoS)

1. Consensus commit flow SHALL be round-based BFT: `propose -> vote -> commit`.
2. Voting rights MUST be granted only to PoW-qualified participants for the active epoch/round.
3. Validator authority MUST NOT depend on stake lock, stake weight, or deposit size.
4. Commit MUST apply a deterministic atomic state update.
5. All nodes MUST derive identical post-state bytes/root for an accepted commit.
6. If any latency target conflicts with deterministic verification/finality safety, safety rules MUST take precedence.
7. Liveness parameters MUST be explicit in implementation/config:
- proposal timeout,
- vote timeout,
- view-change timeout,
- maximum tolerated Byzantine faults.

### 3.4.1 `epoch_transition` (Operator Rules)

1. Nodes MUST compute epoch deterministically from round:
- `epoch = floor((round - 1) / EPOCH_LENGTH)`
- `round_start = epoch * EPOCH_LENGTH + 1`
2. If epoch data for a round is missing, node MUST install it only via deterministic derivation from canonical inputs:
- `seed = (state_root, epoch_number)`
- deterministic validator ordering/selection function
3. Node MUST compute expected PoW target for each round using canonical commit history window and deterministic difficulty function:
- `NextPowTargetDeterministic(...)`
4. Node MUST reject propose/vote/commit processing for round `R` if mint target in batch does not exactly match the derived expected target for `R`.
5. Transition application points MUST be identical across nodes:
- before processing incoming `PROPOSE`, `VOTE`, `COMMIT`,
- before catch-up replay apply,
- before local autopropose for next round.
6. Node SHOULD emit auditable transition log line:
- `epoch_transition epoch=<n> round_start=<r> validators=<k> target=<hex> seed_root=<hex>`

### 3.5 Confidentiality

1. Amount confidentiality MUST use a specified commitment/proof system (algorithm version MUST be explicit in wire/state format).
2. For each confidential spend, nodes MUST verify:
- ownership authorization,
- range validity,
- sum/consistency proof.
3. Verification costs MUST be bounded by consensus rules:
- max proof bytes per tx,
- max verification CPU budget per tx,
- max batch proof verification budget.
4. Any proof exceeding configured consensus bounds MUST be rejected.

### 3.6 Decentralization and Fault Penalties (Non-Stake)

1. Participant selection MUST be deterministic and Sybil-resistant via PoW qualification rules.
2. Equivocation detection MUST be objectively provable from signed messages.
3. Because this protocol is zero-PoS, penalties MUST NOT require stake slashing.
4. Non-stake penalties SHOULD include one or more of:
- temporary voting exclusion,
- PoW-eligibility cooldown,
- reputation downgrade used only for peer policy (not consensus truth),
- persistent publication of fault evidence.

### 3.7 PQC Requirement

1. Authorization and consensus signatures MUST be upgradable to post-quantum schemes.
2. Cryptographic formats MUST be versioned.
3. Mixed-algorithm transitions, if enabled, MUST be deterministic and consensus-safe.
4. Production profiles SHOULD disable non-PQC signature paths.

## 4. Required Safety Correction: Persistent Commit Log

Even without blockchain/DAG, nodes MUST persist a signed commit log of state roots.

Each commit record MUST include at least:
- `round`
- `batch_hash`
- `consensus_proof` (QC or PoW-authority proof, depending on configured consensus mode)
- `new_state_root`
- `record_hash`
- `record_signature`

Recovery rules:
1. A recovering node MUST replay commit records in canonical order.
2. For each record, node MUST verify signature/proof validity and recomputed state root.
3. Any invalid record MUST halt recovery.
4. Competing records at same height/round MUST be resolved by deterministic consensus fork-choice/finality rules configured for the mode.

Without this log, new/recovering nodes cannot independently verify canonical state.

## 5. Example State Mutation

Before:
- `0xafa: 0x2 coin`

After spend:
- `0xafa: 0x1 coin`
- `0xa32: 0x1 coin`

The transition is accepted only if authorization + confidentiality + consensus checks all pass.
