#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

SEED_IP="${SEED_IP:-192.168.0.104}"
SEED_PORT="${SEED_PORT:-29101}"
SEED_PEER="${SEED_PEER:-${SEED_IP}:${SEED_PORT}}"

BIND_PORT="${BIND_PORT:-29102}"
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT:-}"
DATA_DIR="${DATA_DIR:-${ROOT_DIR}/data_joiner_${BIND_PORT}}"
NETWORK_MAGIC_HEX="${NETWORK_MAGIC_HEX:-0x52504f57}"
AUTOPROPOSE="${AUTOPROPOSE:-0}"
AUTOPROPOSE_INTERVAL_SEC="${AUTOPROPOSE_INTERVAL_SEC:-3}"
DURATION_SEC="${DURATION_SEC:-0}"

cd "${ROOT_DIR}"

BIND_PORT="${BIND_PORT}" \
SEED_PEER="${SEED_PEER}" \
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT}" \
DATA_DIR="${DATA_DIR}" \
NETWORK_MAGIC_HEX="${NETWORK_MAGIC_HEX}" \
AUTOPROPOSE="${AUTOPROPOSE}" \
AUTOPROPOSE_INTERVAL_SEC="${AUTOPROPOSE_INTERVAL_SEC}" \
DURATION_SEC="${DURATION_SEC}" \
./scripts/install_testnet_node.sh

source "${ROOT_DIR}/env_liboqs.sh"

echo "starting joiner node..."
echo "bind_port=${BIND_PORT}"
echo "seed_peer=${SEED_PEER}"
echo "data_dir=${DATA_DIR}"

exec "${ROOT_DIR}/build/rpov2_node" "${ROOT_DIR}/global_testnet.conf"
