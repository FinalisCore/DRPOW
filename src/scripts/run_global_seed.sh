#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

BIND_PORT="${BIND_PORT:-29101}"
PUBLIC_IP="${PUBLIC_IP:-212.58.103.170}"
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT:-${PUBLIC_IP}:${BIND_PORT}}"
SEED_PEER="${SEED_PEER:-}"
DATA_DIR="${DATA_DIR:-${ROOT_DIR}/data_seed}"
KEY_DIR="${KEY_DIR:-${ROOT_DIR}/keys}"
SEED_KEY_FILE="${SEED_KEY_FILE:-${KEY_DIR}/seed_signer_privkey.hex}"
NETWORK_MAGIC_HEX="${NETWORK_MAGIC_HEX:-0x52504f57}"
AUTOPROPOSE="${AUTOPROPOSE:-1}"
AUTOPROPOSE_INTERVAL_SEC="${AUTOPROPOSE_INTERVAL_SEC:-10}"
DURATION_SEC="${DURATION_SEC:-0}"

cd "${ROOT_DIR}"
mkdir -p "${KEY_DIR}"
if [ ! -f "${SEED_KEY_FILE}" ]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32 > "${SEED_KEY_FILE}"
  else
    head -c 32 /dev/urandom | xxd -p -c 64 > "${SEED_KEY_FILE}"
  fi
  chmod 600 "${SEED_KEY_FILE}" || true
fi
SIGNER_PRIVKEY_HEX="$(tr -d '\r\n[:space:]' < "${SEED_KEY_FILE}")"

BIND_PORT="${BIND_PORT}" \
SEED_PEER="${SEED_PEER}" \
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT}" \
DATA_DIR="${DATA_DIR}" \
NETWORK_MAGIC_HEX="${NETWORK_MAGIC_HEX}" \
AUTOPROPOSE="${AUTOPROPOSE}" \
AUTOPROPOSE_INTERVAL_SEC="${AUTOPROPOSE_INTERVAL_SEC}" \
DURATION_SEC="${DURATION_SEC}" \
SIGNER_PRIVKEY_HEX="${SIGNER_PRIVKEY_HEX}" \
./scripts/install_testnet_node.sh

source "${ROOT_DIR}/env_liboqs.sh"

echo "starting seed node..."
echo "bind_port=${BIND_PORT}"
echo "public_endpoint=${PUBLIC_ENDPOINT}"
if [ -n "${SEED_PEER}" ]; then
  echo "seed_peer=${SEED_PEER}"
else
  echo "seed_peer=<none>"
fi
echo "data_dir=${DATA_DIR}"

exec "${ROOT_DIR}/build/rpov2_node" "${ROOT_DIR}/global_testnet.conf"
