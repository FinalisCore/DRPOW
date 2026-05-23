# DRPOW Global Testnet Manifest v1

Status: `pilot-open` (not GA)

Publish date: `TBD`

## 1. Protocol Identity

1. Network
- Name: `drpow-global-testnet`
- Mode: `pow_open`
- Voting mode: `pow_only`

2. Canonical parameters
- `params_version`: `drpow_params_v3`
- `params_hash`: `edc901112d7d4e16eb0b7a4b3d3497c634f0f51d65c2e604a15035e829c43b81`
- `network_magic`: `0x52504f57`

3. Genesis
- Genesis file path in repo: `src/genesis/testnet/genesis_epoch0.bin`
- Genesis SHA-256: `a6acb0e0cd6f38c387fe2fe404aa036a285d0b400cf60ee91767f36110481b2e`

## 2. Node Runtime Baseline

1. Port and endpoint
- Default p2p port: `29101`
- Operators MUST set `PUBLIC_ENDPOINT=<public_ip>:29101`.

2. Launcher
- Script: `src/scripts/start_testnet.sh`
- The script enforces genesis hash at startup and writes config under `~/.drpow/config/testnet.conf`.

3. Baseline policy values observed in current pilot
- `finality_depth_rounds=6`
- `reorg_replay_window_rounds=128`
- `sync_policy=sync_first`

## 3. Bootstrap Seed Set (Pilot)

Current pilot seed placeholders (replace with real hosts before announcement):

1. `seed-1`: `85.217.171.168:29101`
2. `seed-2`: `TBD`
3. `seed-3`: `TBD`

Requirements before public announcement:
- at least 3 independent seed operators,
- geographic and ASN diversity,
- published uptime/maintenance contacts.

## 4. Compatibility and Release Policy

1. Acceptance gate
- Handshake compatibility is based on `params_version` + `params_hash`.
- `build_id` mismatch is warning-only in pilot.

2. Release discipline
- Public operators SHOULD run an announced release tag and publish the commit hash.
- Protocol-breaking changes require a new manifest version.

## 5. Operator SLO Targets (Pilot)

1. Liveness
- Continuous `[COMMIT] ok` progression under healthy peer connectivity.

2. Sync
- catchup convergence should complete within replay window budget.

3. Preemption effectiveness
- Track:
  - `pow_preempt_rounds`
  - `pow_preempt_remote_commit_fast`
  - `preempt_fast_rate`
- Pilot target: `preempt_fast_rate >= 0.70` (tunable).

## 6. Required Pre-Announcement Checklist

1. Complete soak and fault-injection gates in [global-testnet-readiness.md](./global-testnet-readiness.md).
2. Replace seed placeholders with production seed list.
3. Freeze and publish release tag + commit.
4. Publish incident response channel and runbook.

## 7. Join Instructions (Pilot)

```bash
cd /home/greendragon/Desktop/coin/src
AUTOPROPOSE=1 \
BIND_PORT=29101 \
PUBLIC_ENDPOINT=<public_ip>:29101 \
SEED_PEER=85.217.171.168:29101 \
./scripts/start_testnet.sh
```

Verify startup includes:
- `genesis_hash_ok`
- `params_version=drpow_params_v3`
- `params_hash=edc901112d7d4e16eb0b7a4b3d3497c634f0f51d65c2e604a15035e829c43b81`
- successful `[HANDSHAKE] ok` with peers.
