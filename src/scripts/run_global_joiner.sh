#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RPOV_HOME="${RPOV_HOME:-${HOME}/.rpov}"
RPOV_NODE_CONFIG="${RPOV_NODE_CONFIG:-${RPOV_HOME}/config/global_testnet.conf}"
RPOV_ENV_FILE="${RPOV_ENV_FILE:-${RPOV_HOME}/env_liboqs.sh}"

SEED_IP="${SEED_IP:-192.168.0.104}"
SEED_PORT="${SEED_PORT:-29101}"
SEED_PEER="${SEED_PEER:-${SEED_IP}:${SEED_PORT}}"

BIND_PORT="${BIND_PORT:-29102}"
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT:-}"
DATA_DIR="${DATA_DIR:-${RPOV_HOME}/nodes/joiner_${BIND_PORT}}"
KEY_DIR="${KEY_DIR:-${RPOV_HOME}/keys}"
JOINER_KEY_FILE="${JOINER_KEY_FILE:-${KEY_DIR}/joiner_${BIND_PORT}_signer_privkey.hex}"
NETWORK_MAGIC_HEX="${NETWORK_MAGIC_HEX:-0x52504f57}"
AUTOPROPOSE="${AUTOPROPOSE:-1}"
AUTOPROPOSE_INTERVAL_SEC="${AUTOPROPOSE_INTERVAL_SEC:-20}"
DURATION_SEC="${DURATION_SEC:-0}"

cd "${ROOT_DIR}"
mkdir -p "${KEY_DIR}"
if [ ! -f "${JOINER_KEY_FILE}" ]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32 > "${JOINER_KEY_FILE}"
  else
    head -c 32 /dev/urandom | xxd -p -c 64 > "${JOINER_KEY_FILE}"
  fi
  chmod 600 "${JOINER_KEY_FILE}" || true
fi
SIGNER_PRIVKEY_HEX="$(tr -d '\r\n[:space:]' < "${JOINER_KEY_FILE}")"

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

source "${RPOV_ENV_FILE}"

echo "starting joiner node..."
echo "bind_port=${BIND_PORT}"
echo "seed_peer=${SEED_PEER}"
echo "data_dir=${DATA_DIR}"

exec "${ROOT_DIR}/build/rpov2_node" "${RPOV_NODE_CONFIG}"
