#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LIBOQS_SRC_DIR="${ROOT_DIR}/liboqs"
LIBOQS_BUILD_DIR="${LIBOQS_SRC_DIR}/build"
LIBOQS_INSTALL_DIR="${LIBOQS_SRC_DIR}/install"
LIBOQS_PC_DIR="${LIBOQS_INSTALL_DIR}/lib/pkgconfig"
LIBOQS_LIB_DIR="${LIBOQS_INSTALL_DIR}/lib"

NODE_BIN="${ROOT_DIR}/build/rpov2_node"
CLI_BIN="${ROOT_DIR}/build/rpov2_cli"

BIND_PORT="${BIND_PORT:-29101}"
SEED_PEER="${SEED_PEER:-}"
DATA_DIR="${DATA_DIR:-${ROOT_DIR}/data}"
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT:-}"
NETWORK_MAGIC_HEX="${NETWORK_MAGIC_HEX:-0x52504f57}"
DURATION_SEC="${DURATION_SEC:-0}"
AUTOPROPOSE="${AUTOPROPOSE:-0}"
AUTOPROPOSE_INTERVAL_SEC="${AUTOPROPOSE_INTERVAL_SEC:-3}"

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
  cat > "${ROOT_DIR}/env_liboqs.sh" <<ENV
export PKG_CONFIG_PATH="${LIBOQS_PC_DIR}"
export LD_LIBRARY_PATH="${LIBOQS_LIB_DIR}:\${LD_LIBRARY_PATH:-}"
ENV
  chmod +x "${ROOT_DIR}/env_liboqs.sh"
}

write_config() {
  mkdir -p "${DATA_DIR}"
  cat > "${ROOT_DIR}/global_testnet.conf" <<CFG
bind_port=${BIND_PORT}
data_dir=${DATA_DIR}
network_magic_hex=${NETWORK_MAGIC_HEX}
duration_sec=${DURATION_SEC}
autopropose=${AUTOPROPOSE}
autopropose_interval_sec=${AUTOPROPOSE_INTERVAL_SEC}
CFG
  if [ -n "${SEED_PEER}" ]; then
    echo "peers=${SEED_PEER}" >> "${ROOT_DIR}/global_testnet.conf"
  fi
  if [ -n "${PUBLIC_ENDPOINT}" ]; then
    echo "public_endpoint=${PUBLIC_ENDPOINT}" >> "${ROOT_DIR}/global_testnet.conf"
  fi
}

print_next_steps() {
  cat <<MSG

Install complete.

Generated:
- ${NODE_BIN}
- ${CLI_BIN}
- ${ROOT_DIR}/global_testnet.conf
- ${ROOT_DIR}/env_liboqs.sh

Run:
  source "${ROOT_DIR}/env_liboqs.sh"
  "${NODE_BIN}" "${ROOT_DIR}/global_testnet.conf"

Wallet quick check:
  source "${ROOT_DIR}/env_liboqs.sh"
  "${CLI_BIN}" wallet init "${DATA_DIR}" "${NETWORK_MAGIC_HEX#0x}"
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
