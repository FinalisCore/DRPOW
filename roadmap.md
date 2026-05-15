# Roadmap

## Main Priorities

1. Quantum resistance
- The protocol must be resistant to quantum computing attacks.
- It must also resist remote algorithmic attacks against cryptography, consensus, and validation logic.

2. Maximum confidentiality
- Transactions must not reveal user identity.
- The system should be designed for the highest practical confidentiality at protocol level, not only wallet/UI level.

3. State-first ledger (result, not full history storage)
- The chain should represent deterministic database state changes.
- The core persisted value should be the latest ownership state (final balances/rights), not mandatory full historical transaction storage in node DB.
- Example target behavior:
  - Alice public key balance: 150
  - Alice transfers 10 to Bob
  - New state: Alice 140, Bob 10
- Public key acts as ownership reference and authorization target; private key control authorizes state changes.
- Design requirement: keep verifiability/auditability while prioritizing final-state storage.

4. Instant confirmation with no reorg risk
- Transactions must be confirmed instantly.
- Confirmed transactions must not be reverted by forks/reorganizations.
- This target must hold under both low and high throughput (from 1 TPS up to 10,000+ TPS target range).

5. Prefer PoW if feasible
- If these properties can be achieved with PoW, that is preferred.
- If PoW alone cannot satisfy instant non-revertible finality safely, document the minimum additional mechanism required.

## Derived Technical Requirements

- Deterministic consensus: same input state + same block/input must produce identical state transition on all honest nodes.
- Bounded validation cost: validation must remain bounded and predictable per state transition.
- Clean separation of layers:
  - Consensus rules
  - State storage/DB
  - Networking/relay
  - Wallet/key management
- Consensus must not depend on UI behavior.

## Architecture Direction

### A. Consensus and finality
- Move away from probabilistic finality based only on longest-chain behavior.
- Introduce deterministic finalization rules so confirmed state cannot be rolled back.

### B. State model
- Evolve from transaction-history-centric storage toward authenticated current state storage.
- Keep cryptographic commitments/proofs so nodes can verify correctness without retaining unbounded full history in active DB.

### C. Privacy
- Add protocol-level privacy for sender/receiver/amount linkage resistance.
- Add network-layer anti-metadata-leak measures for relay.

### D. Post-quantum cryptography
- Introduce post-quantum signature/key scheme(s) for authorization.
- Version cryptographic formats so upgrades are explicit and auditable.

## Phased Plan

### Phase 0: Formal spec and threat model
- Write exact state transition specification.
- Define finality model and safety/liveness assumptions.
- Define threat model: reorg, eclipse, metadata deanonymization, key compromise, quantum adversary.

### Phase 1: Current codebase hardening
- Isolate consensus-critical code from non-consensus code.
- Remove remaining consensus coupling to wallet/network policy side effects.
- Add deterministic test vectors for block/tx/state validity.

### Phase 2: State-first storage engine
- Introduce authenticated state representation and root commitments.
- Add snapshot/pruning model oriented to current-state persistence.
- Ensure replay/proof verification still enables independent validation.

### Phase 3: Deterministic instant finality
- Implement finalization mechanism that prevents reorg of finalized state.
- Validate behavior under adversarial network conditions and high throughput targets.

### Phase 4: Privacy + PQ integration
- Integrate PQ authorization into consensus validation.
- Integrate confidentiality-preserving transaction/state transition format.
- Benchmark latency, proof/signature sizes, and validator cost.

### Phase 5: Performance and operations
- Optimize for 1 to 10,000+ TPS operating envelope.
- Enforce strict resource limits and anti-DoS protections.
- Add observability and deterministic replay/audit tooling.

## Open Questions

1. Can PoW alone provide instant deterministic non-revertible finality?
2. Which PQ scheme best fits verification cost, key size, and signature size constraints?
3. What privacy design gives strongest confidentiality while keeping validation bounded?
4. How do we preserve independent verifiability with state-first storage and reduced active history?
5. What activation/migration strategy avoids consensus splits during transition?

## Success Criteria

- Confirmed transactions are non-revertible by consensus rule.
- Node consensus depends on deterministic state transition logic only.
- Active node DB is state-first while still cryptographically verifiable.
- Protocol-level confidentiality and PQ authorization are both native.
- System remains auditable, testable, and bounded in validation cost.
