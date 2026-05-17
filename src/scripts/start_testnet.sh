#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RPOV_HOME="${RPOV_HOME:-${HOME}/.rpov}"
NETWORK="testnet"
NETWORK_MAGIC_HEX="${NETWORK_MAGIC_HEX:-0x52504f57}"
BIND_PORT="${BIND_PORT:-29101}"
SEED_PEER="${SEED_PEER:-}"
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT:-}"
AUTOPROPOSE="${AUTOPROPOSE:-}"
AUTOPROPOSE_INTERVAL_SEC="${AUTOPROPOSE_INTERVAL_SEC:-20}"
DURATION_SEC="${DURATION_SEC:-0}"

CONFIG_DIR="${RPOV_HOME}/config"
DATA_DIR="${DATA_DIR:-${RPOV_HOME}/nodes/${NETWORK}_${BIND_PORT}}"
KEY_DIR="${RPOV_HOME}/keys"
KEY_FILE="${KEY_FILE:-${KEY_DIR}/node_signer_privkey.hex}"
CONF_FILE="${RPOV_NODE_CONFIG:-${CONFIG_DIR}/${NETWORK}.conf}"
ENV_FILE="${RPOV_ENV_FILE:-${RPOV_HOME}/env_liboqs.sh}"
GENESIS_SRC="${ROOT_DIR}/genesis/${NETWORK}/genesis_epoch0.bin"
GENESIS_DST="${DATA_DIR}/genesis_epoch0.bin"
GENESIS_HASH_HEX=""

LIBOQS_SRC_DIR="${ROOT_DIR}/liboqs"
LIBOQS_BUILD_DIR="${LIBOQS_SRC_DIR}/build"
LIBOQS_INSTALL_DIR="${LIBOQS_SRC_DIR}/install"
LIBOQS_PC_DIR="${LIBOQS_INSTALL_DIR}/lib/pkgconfig"
LIBOQS_LIB_DIR="${LIBOQS_INSTALL_DIR}/lib"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }

install_liboqs_if_needed() {
  if PKG_CONFIG_PATH="${LIBOQS_PC_DIR}" pkg-config --exists liboqs 2>/dev/null; then
    echo "liboqs already installed in ${LIBOQS_INSTALL_DIR}"
    return
  fi
  need_cmd git; need_cmd cmake; need_cmd ninja
  if [ ! -d "${LIBOQS_SRC_DIR}" ]; then
    git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git "${LIBOQS_SRC_DIR}"
  fi
  mkdir -p "${LIBOQS_BUILD_DIR}"
  cmake -S "${LIBOQS_SRC_DIR}" -B "${LIBOQS_BUILD_DIR}" -GNinja -DCMAKE_INSTALL_PREFIX="${LIBOQS_INSTALL_DIR}"
  cmake --build "${LIBOQS_BUILD_DIR}" -j
  cmake --install "${LIBOQS_BUILD_DIR}"
}

build_binaries() {
  need_cmd make
  PKG_CONFIG_PATH="${LIBOQS_PC_DIR}" make -C "${ROOT_DIR}" USE_LIBOQS=1 rpov2_node rpov2_cli
}

write_env() {
  mkdir -p "${RPOV_HOME}"
  cat > "${ENV_FILE}" <<ENV
export PKG_CONFIG_PATH="${LIBOQS_PC_DIR}"
export LD_LIBRARY_PATH="${LIBOQS_LIB_DIR}:\${LD_LIBRARY_PATH:-}"
ENV
}

prepare_key() {
  mkdir -p "${KEY_DIR}"
  if [ ! -f "${KEY_FILE}" ]; then
    if command -v openssl >/dev/null 2>&1; then
      openssl rand -hex 32 > "${KEY_FILE}"
    else
      head -c 32 /dev/urandom | xxd -p -c 64 > "${KEY_FILE}"
    fi
    chmod 600 "${KEY_FILE}" || true
  fi
  SIGNER_PRIVKEY_HEX="$(tr -d '\r\n[:space:]' < "${KEY_FILE}")"
}

prepare_genesis() {
  mkdir -p "${DATA_DIR}"
  cp -f "${GENESIS_SRC}" "${GENESIS_DST}"
  if command -v sha256sum >/dev/null 2>&1; then
    GENESIS_HASH_HEX="$(sha256sum "${GENESIS_SRC}" | awk '{print $1}')"
  elif command -v openssl >/dev/null 2>&1; then
    GENESIS_HASH_HEX="$(openssl dgst -sha256 "${GENESIS_SRC}" | awk '{print $NF}')"
  else
    echo "missing required command: sha256sum or openssl" >&2
    exit 1
  fi
  if [ "${#GENESIS_HASH_HEX}" -ne 64 ]; then
    echo "genesis_hash_compute_failed file=${GENESIS_SRC}" >&2
    exit 1
  fi
}

write_config() {
  mkdir -p "${CONFIG_DIR}"
  if [ -z "${AUTOPROPOSE}" ]; then
    if [ -n "${SEED_PEER}" ]; then AUTOPROPOSE=0; else AUTOPROPOSE=1; fi
  fi
  cat > "${CONF_FILE}" <<CFG
bind_port=${BIND_PORT}
data_dir=${DATA_DIR}
network_magic_hex=${NETWORK_MAGIC_HEX}
duration_sec=${DURATION_SEC}
autopropose=${AUTOPROPOSE}
autopropose_interval_sec=${AUTOPROPOSE_INTERVAL_SEC}
signer_privkey_hex=${SIGNER_PRIVKEY_HEX}
genesis_hash_hex=${GENESIS_HASH_HEX}
CFG
  [ -n "${SEED_PEER}" ] && echo "peers=${SEED_PEER}" >> "${CONF_FILE}"
  [ -n "${PUBLIC_ENDPOINT}" ] && echo "public_endpoint=${PUBLIC_ENDPOINT}" >> "${CONF_FILE}"
}

main() {
  install_liboqs_if_needed
  build_binaries
  write_env
  prepare_key
  prepare_genesis
  write_config
  source "${ENV_FILE}"
  echo "starting ${NETWORK} node..."
  echo "genesis_file=${GENESIS_DST}"
  echo "genesis_hash_hex=${GENESIS_HASH_HEX}"
  echo "bind_port=${BIND_PORT}"
  [ -n "${SEED_PEER}" ] && echo "seed_peer=${SEED_PEER}" || echo "seed_peer=<none>"
  echo "data_dir=${DATA_DIR}"
  exec "${ROOT_DIR}/build/rpov2_node" "${CONF_FILE}"
}

main "$@"
