#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RPOV_HOME="${RPOV_HOME:-${HOME}/.rpov}"
RPOV_CONFIG_DIR="${RPOV_CONFIG_DIR:-${RPOV_HOME}/config}"
RPOV_ENV_FILE="${RPOV_ENV_FILE:-${RPOV_HOME}/env_liboqs.sh}"
RPOV_NODE_CONFIG="${RPOV_NODE_CONFIG:-${RPOV_CONFIG_DIR}/global_testnet.conf}"
LIBOQS_SRC_DIR="${ROOT_DIR}/liboqs"
LIBOQS_BUILD_DIR="${LIBOQS_SRC_DIR}/build"
LIBOQS_INSTALL_DIR="${LIBOQS_SRC_DIR}/install"
LIBOQS_PC_DIR="${LIBOQS_INSTALL_DIR}/lib/pkgconfig"
LIBOQS_LIB_DIR="${LIBOQS_INSTALL_DIR}/lib"

NODE_BIN="${ROOT_DIR}/build/rpov2_node"
CLI_BIN="${ROOT_DIR}/build/rpov2_cli"

BIND_PORT="${BIND_PORT:-29101}"
SEED_PEER="${SEED_PEER:-}"
DATA_DIR="${DATA_DIR:-${RPOV_HOME}/nodes/node_${BIND_PORT}}"
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT:-}"
NETWORK_MAGIC_HEX="${NETWORK_MAGIC_HEX:-0x52504f57}"
DURATION_SEC="${DURATION_SEC:-0}"
AUTOPROPOSE="${AUTOPROPOSE:-0}"
AUTOPROPOSE_INTERVAL_SEC="${AUTOPROPOSE_INTERVAL_SEC:-3}"
SIGNER_PRIVKEY_HEX="${SIGNER_PRIVKEY_HEX:-}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

install_liboqs_if_needed() {
  if PKG_CONFIG_PATH="${LIBOQS_PC_DIR}" pkg-config --exists liboqs 2>/dev/null; then
    echo "liboqs already installed in ${LIBOQS_INSTALL_DIR}"
    return
  fi

  need_cmd git
  need_cmd cmake
  need_cmd ninja

  if [ ! -d "${LIBOQS_SRC_DIR}" ]; then
    echo "cloning liboqs..."
    git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git "${LIBOQS_SRC_DIR}"
  fi

  mkdir -p "${LIBOQS_BUILD_DIR}"
  echo "building liboqs..."
  cmake -S "${LIBOQS_SRC_DIR}" -B "${LIBOQS_BUILD_DIR}" -GNinja -DCMAKE_INSTALL_PREFIX="${LIBOQS_INSTALL_DIR}"
  cmake --build "${LIBOQS_BUILD_DIR}" -j
  cmake --install "${LIBOQS_BUILD_DIR}"
}

build_binaries() {
  need_cmd make
  echo "building rpov2 binaries (PQ-only)..."
  rm -f "${NODE_BIN}" "${CLI_BIN}"
  PKG_CONFIG_PATH="${LIBOQS_PC_DIR}" make -C "${ROOT_DIR}" USE_LIBOQS=1 rpov2_node rpov2_cli
}

write_env_file() {
  mkdir -p "${RPOV_HOME}"
  cat > "${RPOV_ENV_FILE}" <<ENV
export PKG_CONFIG_PATH="${LIBOQS_PC_DIR}"
export LD_LIBRARY_PATH="${LIBOQS_LIB_DIR}:\${LD_LIBRARY_PATH:-}"
ENV
  chmod +x "${RPOV_ENV_FILE}"
}

write_config() {
  mkdir -p "${RPOV_CONFIG_DIR}"
  mkdir -p "${DATA_DIR}"
  cat > "${RPOV_NODE_CONFIG}" <<CFG
bind_port=${BIND_PORT}
data_dir=${DATA_DIR}
network_magic_hex=${NETWORK_MAGIC_HEX}
duration_sec=${DURATION_SEC}
autopropose=${AUTOPROPOSE}
autopropose_interval_sec=${AUTOPROPOSE_INTERVAL_SEC}
CFG
  if [ -n "${SEED_PEER}" ]; then
    echo "peers=${SEED_PEER}" >> "${RPOV_NODE_CONFIG}"
  fi
  if [ -n "${SIGNER_PRIVKEY_HEX}" ]; then
    echo "signer_privkey_hex=${SIGNER_PRIVKEY_HEX}" >> "${RPOV_NODE_CONFIG}"
  fi
  if [ -n "${PUBLIC_ENDPOINT}" ]; then
    echo "public_endpoint=${PUBLIC_ENDPOINT}" >> "${RPOV_NODE_CONFIG}"
  fi
}

print_next_steps() {
  cat <<MSG

Install complete.

Generated:
- ${NODE_BIN}
- ${CLI_BIN}
- ${RPOV_NODE_CONFIG}
- ${RPOV_ENV_FILE}

Run:
  source "${RPOV_ENV_FILE}"
  "${NODE_BIN}" "${RPOV_NODE_CONFIG}"

Wallet quick check:
  source "${RPOV_ENV_FILE}"
  "${CLI_BIN}" wallet init "${RPOV_HOME}/wallet" "${NETWORK_MAGIC_HEX#0x}"
MSG
}

main() {
  install_liboqs_if_needed
  build_binaries
  write_env_file
  write_config
  print_next_steps
}

main "$@"
