#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DRPOW_HOME="${DRPOW_HOME:-${HOME}/.drpow}"
NETWORK="testnet"
NETWORK_MAGIC_HEX="${NETWORK_MAGIC_HEX:-0x52504f57}"
DEFAULT_SEED_IP="${DEFAULT_SEED_IP:-192.168.0.104}"
DEFAULT_SEED_PORT="${DEFAULT_SEED_PORT:-29101}"
DEFAULT_SEED_PEER="${DEFAULT_SEED_IP}:${DEFAULT_SEED_PORT}"
BIND_PORT="${BIND_PORT:-29101}"
SEED_PEER="${SEED_PEER:-}"
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT:-}"
AUTOPROPOSE="${AUTOPROPOSE:-}"
AUTOPROPOSE_INTERVAL_SEC="${AUTOPROPOSE_INTERVAL_SEC:-20}"
DURATION_SEC="${DURATION_SEC:-0}"
LOG_LEVEL="${LOG_LEVEL:-normal}"
PEERS_FILE="${PEERS_FILE:-${DRPOW_HOME}/peers.txt}"
NODE_ROLE="${NODE_ROLE:-auto}"
DEFAULT_BOOTSTRAP_PEER="${DEFAULT_BOOTSTRAP_PEER:-${DEFAULT_SEED_PEER}}"

CONFIG_DIR="${DRPOW_HOME}/config"
DATA_DIR="${DATA_DIR:-${DRPOW_HOME}/nodes/${NETWORK}_${BIND_PORT}}"
KEY_DIR="${DRPOW_HOME}/keys"
KEY_FILE="${KEY_FILE:-${KEY_DIR}/node_signer_privkey.hex}"
CONF_FILE="${RPOV_NODE_CONFIG:-${CONFIG_DIR}/${NETWORK}.conf}"
ENV_FILE="${DRPOW_ENV_FILE:-${RPOV_ENV_FILE:-${DRPOW_HOME}/env_liboqs.sh}}"
GENESIS_SRC="${ROOT_DIR}/genesis/${NETWORK}/genesis_epoch0.bin"
GENESIS_DST="${DATA_DIR}/genesis_epoch0.bin"
GENESIS_HASH_HEX=""
BOOTSTRAP_PEERS=""

LIBOQS_SRC_DIR="${ROOT_DIR}/liboqs"
LIBOQS_BUILD_DIR="${LIBOQS_SRC_DIR}/build"
LIBOQS_INSTALL_DIR="${LIBOQS_SRC_DIR}/install"
LIBOQS_PC_DIR="${LIBOQS_INSTALL_DIR}/lib/pkgconfig"
LIBOQS_LIB_DIR="${LIBOQS_INSTALL_DIR}/lib"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }

ensure_default_peers_file() {
  local default_peer="${DEFAULT_BOOTSTRAP_PEER}"
  [ -z "${default_peer}" ] && return
  mkdir -p "$(dirname "${PEERS_FILE}")"
  touch "${PEERS_FILE}"
  # A node must not list itself in peers.
  if [ -n "${PUBLIC_ENDPOINT}" ]; then
    sed -i "/^[[:space:]]*${PUBLIC_ENDPOINT//./\\.}[[:space:]]*$/d" "${PEERS_FILE}"
    if [ "${default_peer}" = "${PUBLIC_ENDPOINT}" ]; then
      return
    fi
  fi
  if ! grep -Eq "^[[:space:]]*${default_peer//./\\.}[[:space:]]*$" "${PEERS_FILE}"; then
    echo "${default_peer}" >> "${PEERS_FILE}"
  fi
}

load_bootstrap_peers() {
  local peers=()
  local line=""
  if [ -f "${PEERS_FILE}" ]; then
    while IFS= read -r line || [ -n "${line}" ]; do
      line="${line%%#*}"
      line="$(echo "${line}" | tr -d '[:space:]')"
      [ -z "${line}" ] && continue
      [[ "${line}" == *:* ]] || continue
      peers+=("${line}")
    done < "${PEERS_FILE}"
  fi
  if [ -n "${SEED_PEER}" ]; then
    peers+=("${SEED_PEER}")
  fi
  # Never bootstrap to self.
  if [ -n "${PUBLIC_ENDPOINT}" ]; then
    local filtered=()
    local p=""
    for p in "${peers[@]}"; do
      [ "${p}" = "${PUBLIC_ENDPOINT}" ] && continue
      filtered+=("${p}")
    done
    peers=("${filtered[@]}")
  fi
  if [ "${#peers[@]}" -eq 0 ]; then
    BOOTSTRAP_PEERS=""
    return
  fi
  BOOTSTRAP_PEERS="$(printf '%s\n' "${peers[@]}" | awk '!seen[$0]++' | paste -sd, -)"
}

endpoint_in_bootstrap_peers() {
  local endpoint="$1"
  [ -z "${endpoint}" ] && return 1
  [ -z "${BOOTSTRAP_PEERS}" ] && return 1
  local IFS=','
  local p
  for p in ${BOOTSTRAP_PEERS}; do
    [ "${p}" = "${endpoint}" ] && return 0
  done
  return 1
}

check_bind_port_available() {
  if command -v ss >/dev/null 2>&1; then
    if ss -ltn "( sport = :${BIND_PORT} )" 2>/dev/null | tail -n +2 | grep -q .; then
      echo "port_in_use_error: bind_port=${BIND_PORT}" >&2
      echo "port_in_use_hint: ss -ltnp | grep :${BIND_PORT}" >&2
      exit 1
    fi
  elif command -v lsof >/dev/null 2>&1; then
    if lsof -iTCP:"${BIND_PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
      echo "port_in_use_error: bind_port=${BIND_PORT}" >&2
      echo "port_in_use_hint: lsof -iTCP:${BIND_PORT} -sTCP:LISTEN" >&2
      exit 1
    fi
  fi
}

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
  PKG_CONFIG_PATH="${LIBOQS_PC_DIR}" make -C "${ROOT_DIR}" USE_LIBOQS=1 drpow_node drpow_cli
}

write_env() {
  mkdir -p "${DRPOW_HOME}"
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
  local JOINER_MODE=0
  local role_lc="$(echo "${NODE_ROLE}" | tr '[:upper:]' '[:lower:]')"
  if [ -n "${SEED_PEER}" ]; then
    JOINER_MODE=1
  elif [ "${role_lc}" = "joiner" ] || [ "${role_lc}" = "follower" ] || [ "${role_lc}" = "sync" ]; then
    JOINER_MODE=1
  elif [ -n "${BOOTSTRAP_PEERS}" ] && [ -n "${PUBLIC_ENDPOINT}" ] && ! endpoint_in_bootstrap_peers "${PUBLIC_ENDPOINT}"; then
    # Follower inference: bootstrap peers configured and this node advertises a
    # non-bootstrap endpoint.
    JOINER_MODE=1
  fi
  if [ "${JOINER_MODE}" = "1" ]; then
    if [ -n "${AUTOPROPOSE}" ] && [ "${AUTOPROPOSE}" != "0" ]; then
      echo "config_override: forcing AUTOPROPOSE=0 because joiner_mode=1 (seed/bootstrap/role follower mode)" >&2
    fi
    AUTOPROPOSE=0
  elif [ -z "${AUTOPROPOSE}" ]; then
    AUTOPROPOSE=1
  fi
  cat > "${CONF_FILE}" <<CFG
bind_port=${BIND_PORT}
data_dir=${DATA_DIR}
network_magic_hex=${NETWORK_MAGIC_HEX}
duration_sec=${DURATION_SEC}
autopropose=${AUTOPROPOSE}
autopropose_interval_sec=${AUTOPROPOSE_INTERVAL_SEC}
joiner_mode=${JOINER_MODE}
signer_privkey_hex=${SIGNER_PRIVKEY_HEX}
genesis_hash_hex=${GENESIS_HASH_HEX}
log_level=${LOG_LEVEL}
CFG
  if [ -n "${BOOTSTRAP_PEERS}" ]; then
    echo "peers=${BOOTSTRAP_PEERS}" >> "${CONF_FILE}"
  fi
  if [ -n "${PUBLIC_ENDPOINT}" ]; then
    echo "public_endpoint=${PUBLIC_ENDPOINT}" >> "${CONF_FILE}"
  fi
}

main() {
  if [ -z "${SEED_PEER}" ] && [ "${BIND_PORT}" != "${DEFAULT_SEED_PORT}" ]; then
    SEED_PEER="${DEFAULT_SEED_PEER}"
    echo "config_default: using SEED_PEER=${SEED_PEER} because BIND_PORT=${BIND_PORT} != ${DEFAULT_SEED_PORT}" >&2
  fi
  install_liboqs_if_needed
  build_binaries
  write_env
  ensure_default_peers_file
  prepare_key
  prepare_genesis
  load_bootstrap_peers
  if [ -z "${SEED_PEER}" ] && [ "${BIND_PORT}" != "${DEFAULT_SEED_PORT}" ]; then
    echo "config_error: SEED_PEER is required when BIND_PORT != ${DEFAULT_SEED_PORT}" >&2
    echo "config_hint: BIND_PORT=29102 SEED_PEER=${DEFAULT_SEED_PEER} ./scripts/start_testnet.sh" >&2
    exit 1
  fi
  write_config
  check_bind_port_available
  source "${ENV_FILE}"
  echo "starting ${NETWORK} node..."
  echo "genesis_file=${GENESIS_DST}"
  echo "genesis_hash_hex=${GENESIS_HASH_HEX}"
  echo "config_file=${CONF_FILE}"
  echo "key_file=${KEY_FILE}"
  echo "bind_port=${BIND_PORT}"
  [ -n "${SEED_PEER}" ] && echo "seed_peer=${SEED_PEER}" || echo "seed_peer=<none>"
  echo "peers_file=${PEERS_FILE}"
  [ -n "${BOOTSTRAP_PEERS}" ] && echo "bootstrap_peers=${BOOTSTRAP_PEERS}" || echo "bootstrap_peers=<none>"
  echo "node_role=${NODE_ROLE}"
  echo "data_dir=${DATA_DIR}"
  echo "cli_env_hint=run 'source ${ENV_FILE}' in any shell before using build/drpow_cli"
  exec "${ROOT_DIR}/build/drpow_node" "${CONF_FILE}"
}

main "$@"
