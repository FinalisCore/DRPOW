# First Global Testnet (Operator Checklist)

## 1. Build

Use the same build profile on all operators:

```bash
PKG_CONFIG_PATH=/home/greendragon/Desktop/coin/src/liboqs/install/lib/pkgconfig make USE_LIBOQS=1 drpow_node
```

## 2. Network Identity Lock

Set one shared `network_magic_hex` for this testnet (non-zero, 32-bit hex) in every node config.

Example:

```text
network_magic_hex=0x52515431
```

Nodes with different magic MUST not interoperate.

## 3. Open Admission

Nodes do not use a static validator set. Any node may join, sync, and participate under PoW admission rules.

## 4. Seed Topology

Minimum bootstrap:
- Run 1 public seed node (example: `212.58.103.170:29101`).
- Joiners start with that seed in `peers=...`.

Recommended after first bootstrap:
- Add more public seeds in different regions.

## 5. Config Template

Start from:

`src/global_testnet.conf`

## 6. Runtime Signals to Watch

Healthy:
- `node_started ...`
- `network_magic=...`
- `difficulty_transition ...`
- `commit ok round=...`
- `sync_tip updated round=...`
- `final_status round=... state_root=...`

Failure indicators:
- `drop ... parse_failed`
- `drop commit invalid code=...`
- `convergence_assert_failed` (in harnesses)
- no round progress over expected interval

## 7. First External Acceptance Criteria

1. At least 3 seeds run for 24h without divergence.
2. Two external joiner nodes catch up from round 0 and from delayed start.
3. All nodes agree on `(round, state_root)` at checkpoints.
4. Restart/rejoin of one seed still converges.

## 8. Minimal Launch Command

```bash
LD_LIBRARY_PATH=/home/greendragon/Desktop/coin/src/liboqs/install/lib ./drpow_node /path/to/node.conf
```
