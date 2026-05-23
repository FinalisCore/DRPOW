# Global Testnet Operator Checklist

Use this checklist before claiming a node is valid for global DRPOW testnet participation.

## 1. Binary and Repo

1. Build from intended release tag/commit.
2. Build `drpow_node` and `drpow_cli` successfully.
3. Confirm runtime prints expected:
- `params_version`,
- `params_hash`,
- `genesis_hash_ok`.

## 2. Network and Reachability

1. Ensure configured bind port is reachable from internet.
2. Publish stable `PUBLIC_ENDPOINT`.
3. Verify inbound connectivity from external peers.

## 3. Consensus Configuration

1. Match canonical global manifest values exactly:
- `params_version`,
- `params_hash`,
- genesis hash,
- seed list policy.
2. Do not run custom local parameter forks while advertising global participation.

## 4. Startup Verification

On startup, validate logs include:
1. `[BOOT] consensus_mode=pow_open`
2. `[BOOT] params_version=...`
3. `[BOOT] params_hash=...`
4. `[BOOT] finality_depth_rounds=...`
5. `[BOOT] reorg_replay_window_rounds=...`
6. handshake acceptance with peers sharing same params.

## 5. Safety/Liveness Runtime Checks

1. No repeated `params_hash_mismatch` drops.
2. No persistent catchup loops without progress.
3. Commit stream continues (`[COMMIT] ok round=...`).
4. If preemptions occur, expect bounded convergence:
- `[ASSERT][PREEMPT] ... status=ok` should dominate.

## 6. Incident Triggers (Report Immediately)

1. Any commit accepted with invalid QC evidence.
2. Persistent reorg behavior crossing finalized boundary.
3. Frequent `status=slow` preemption assertions.
4. Sync lag that does not converge despite healthy peers.

## 7. Required Data When Reporting an Incident

1. Node release tag/commit hash.
2. Full boot block logs (from startup through first commit).
3. 5-minute surrounding logs for incident window.
4. Local config (redact secrets) including endpoint/seed settings.
5. Approximate peer count and region.
