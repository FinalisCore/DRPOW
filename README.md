# DRPOW

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
BIND_PORT=29101 \
PUBLIC_ENDPOINT=192.168.0.104:29101 \
SEED_PEER= \
./scripts/start_testnet.sh
```

Start testnet:

```bash
cd /home/greendragon/Desktop/coin/src
AUTOPROPOSE=1 \
BIND_PORT=29102 \
PUBLIC_ENDPOINT=192.168.0.106:29102 \
SEED_PEER=192.168.0.104:29101 \
./scripts/start_testnet.sh
```

Start mainnet seed:

```bash
cd /home/greendragon/Desktop/coin/src
BIND_PORT=29101 PUBLIC_ENDPOINT=<public_ip>:29101 ./scripts/start_mainnet.sh
```

Start mainnet follower:

```bash
cd /home/greendragon/Desktop/coin/src
BIND_PORT=29102 SEED_PEER=<seed_ip>:29101 ./scripts/start_mainnet.sh
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
build/drpow_cli send --to <address> --amount 0.001 --node 127.0.0.1:29101
```
