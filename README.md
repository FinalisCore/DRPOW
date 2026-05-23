# DRPOW

## Testnet Rollout Docs

- Global readiness gates: [`docs/global-testnet-readiness.md`](./docs/global-testnet-readiness.md)
- Operator launch checklist: [`docs/global-testnet-operator-checklist.md`](./docs/global-testnet-operator-checklist.md)
- Launch manifest (pilot): [`docs/global_testnet_manifest_v1.md`](./docs/global_testnet_manifest_v1.md)
- Soak execution plan: [`docs/global-testnet-soak-plan.md`](./docs/global-testnet-soak-plan.md)
- Pilot-open announcement checklist: [`docs/pilot-open-announcement-checklist.md`](./docs/pilot-open-announcement-checklist.md)
- Soak report template: [`docs/global-testnet-soak-report-template.md`](./docs/global-testnet-soak-report-template.md)
- Log parser: `src/scripts/analyze_testnet_log.sh`

## Run Node

Only two launcher scripts exist:
- `src/scripts/start_testnet.sh`
- `src/scripts/start_mainnet.sh`

Both launchers:
- build `drpow_node` and `drpow_cli`,
- write runtime config under `~/.drpow/config/`,
- use one node key file (`~/.drpow/keys/node_signer_privkey.hex` by default),
- copy canonical genesis artifact from repo:
  - `src/genesis/testnet/genesis_epoch0.bin`
  - `src/genesis/mainnet/genesis_epoch0.bin`
- compute and lock `genesis_hash_hex` into node config.

Hard genesis enforcement:
- node startup verifies `sha256(data_dir/genesis_epoch0.bin) == genesis_hash_hex`,
- startup fails on mismatch or missing genesis file (`genesis_hash_mismatch`).

Start testnet:

```bash
cd /home/greendragon/Desktop/coin/src
AUTOPROPOSE=1 \
BIND_PORT=19440 \
PUBLIC_ENDPOINT=192.168.0.104:19440 \
SEED_PEER= \
./scripts/start_testnet.sh
```

Start testnet:

```bash
cd /home/greendragon/Desktop/coin/src
AUTOPROPOSE=1 \
BIND_PORT=29102 \
PUBLIC_ENDPOINT=192.168.0.106:29102 \
SEED_PEER=192.168.0.104:19440 \
./scripts/start_testnet.sh
```

Start mainnet seed:

```bash
cd /home/greendragon/Desktop/coin/src
BIND_PORT=19440 PUBLIC_ENDPOINT=<public_ip>:19440 ./scripts/start_mainnet.sh
```

Start mainnet follower:

```bash
cd /home/greendragon/Desktop/coin/src
BIND_PORT=29102 SEED_PEER=<seed_ip>:19440 ./scripts/start_mainnet.sh
```

Wallet commands:

```bash
cd /home/greendragon/Desktop/coin/src
source ~/.drpow/env_liboqs.sh
build/drpow_cli wallet init
build/drpow_cli wallet show
build/drpow_cli wallet info
build/drpow_cli wallet miner-info
build/drpow_cli getbalance
build/drpow_cli getutxo
```

Send transaction:

```bash
cd /home/greendragon/Desktop/coin/src
build/drpow_cli send --to <address> --amount 0.001 --node 127.0.0.1:19440
```

## systemd Service (`drpow`)

Service files:
- `src/systemd/drpow.service`
- `src/systemd/drpow.env.example`
- installer: `src/scripts/install_systemd_drpow.sh`

Install and enable:

```bash
cd /home/greendragon/Desktop/coin/src
sudo ./scripts/install_systemd_drpow.sh
```

Configure runtime:

```bash
sudo nano /etc/default/drpow
```

Start and inspect:

```bash
sudo systemctl restart drpow
sudo systemctl status drpow --no-pager
sudo journalctl -u drpow -f
```
