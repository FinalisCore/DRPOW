# rpow

## Run Node

All runtime state is under `~/.rpov`:
- node config: `~/.rpov/config/global_testnet.conf`
- node data: `~/.rpov/nodes/...`
- wallet: `~/.rpov/wallet`
- seed key: `~/.rpov/keys/seed_signer_privkey.hex`

Build binaries:

```bash
cd /home/greendragon/Desktop/coin/src
make rpov2_node rpov2_cli
```

Run seed node:

```bash
cd /home/greendragon/Desktop/coin/src
PUBLIC_IP=192.168.0.104 BIND_PORT=29101 ./scripts/run_global_seed.sh
```

Run joiner node:

```bash
cd /home/greendragon/Desktop/coin/src
SEED_IP=192.168.0.104 SEED_PORT=29101 BIND_PORT=29102 ./scripts/run_global_joiner.sh
```

Wallet commands:

```bash
cd /home/greendragon/Desktop/coin/src
build/rpov2_cli wallet init
build/rpov2_cli wallet show
build/rpov2_cli wallet info
build/rpov2_cli getbalance
build/rpov2_cli getutxo
```

Send transaction:

```bash
cd /home/greendragon/Desktop/coin/src
build/rpov2_cli send --to <address> --amount 0.001 --node 127.0.0.1:29101
```
