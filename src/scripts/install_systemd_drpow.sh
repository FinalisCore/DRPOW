#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_SRC="${ROOT_DIR}/systemd/drpow.service"
ENV_EXAMPLE_SRC="${ROOT_DIR}/systemd/drpow.env.example"
SERVICE_DST="/etc/systemd/system/drpow.service"
ENV_DST="/etc/default/drpow"
INSTALL_USER="${SUDO_USER:-root}"
INSTALL_SRC_DIR="${ROOT_DIR}"
GLOBAL_SEED_IP="85.217.171.168"
GLOBAL_SEED_PORT="19440"
GLOBAL_SEED_PEER="${GLOBAL_SEED_IP}:${GLOBAL_SEED_PORT}"

resolve_home_dir() {
  local user="$1"
  local home_dir=""
  home_dir="$(getent passwd "${user}" | cut -d: -f6 || true)"
  if [ -z "${home_dir}" ]; then
    if [ "${user}" = "root" ]; then
      home_dir="/root"
    else
      home_dir="/home/${user}"
    fi
  fi
  echo "${home_dir}"
}

upsert_env_kv() {
  local key="$1"
  local value="$2"
  local file="$3"
  if grep -q "^${key}=" "${file}"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "${file}"
  else
    echo "${key}=${value}" >> "${file}"
  fi
}

is_local_seed_host() {
  if command -v ip >/dev/null 2>&1; then
    ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "${GLOBAL_SEED_IP}" && return 0
  fi
  return 1
}

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo ./scripts/install_systemd_drpow.sh" >&2
  exit 1
fi

if [ ! -f "${SERVICE_SRC}" ]; then
  echo "missing service template: ${SERVICE_SRC}" >&2
  exit 1
fi

install -m 0644 "${SERVICE_SRC}" "${SERVICE_DST}"

if [ ! -f "${ENV_DST}" ]; then
  install -m 0644 "${ENV_EXAMPLE_SRC}" "${ENV_DST}"
  echo "created ${ENV_DST} from example"
else
  echo "kept existing ${ENV_DST}"
fi

INSTALL_HOME="$(resolve_home_dir "${INSTALL_USER}")"
INSTALL_DRPOW_HOME="${INSTALL_HOME}/.drpow"
upsert_env_kv "RUN_AS_USER" "${INSTALL_USER}" "${ENV_DST}"
upsert_env_kv "DRPOW_SRC_DIR" "${INSTALL_SRC_DIR}" "${ENV_DST}"
upsert_env_kv "DRPOW_HOME" "${INSTALL_DRPOW_HOME}" "${ENV_DST}"
upsert_env_kv "BIND_PORT" "${GLOBAL_SEED_PORT}" "${ENV_DST}"
if is_local_seed_host; then
  upsert_env_kv "PUBLIC_ENDPOINT" "${GLOBAL_SEED_PEER}" "${ENV_DST}"
  upsert_env_kv "SEED_PEER" "" "${ENV_DST}"
  echo "auto-configured mode=seed public_endpoint=${GLOBAL_SEED_PEER}"
else
  upsert_env_kv "PUBLIC_ENDPOINT" "" "${ENV_DST}"
  upsert_env_kv "SEED_PEER" "${GLOBAL_SEED_PEER}" "${ENV_DST}"
  echo "auto-configured mode=follower seed_peer=${GLOBAL_SEED_PEER}"
fi
echo "auto-configured RUN_AS_USER=${INSTALL_USER}"
echo "auto-configured DRPOW_SRC_DIR=${INSTALL_SRC_DIR}"
echo "auto-configured DRPOW_HOME=${INSTALL_DRPOW_HOME}"

systemctl daemon-reload
systemctl enable drpow

echo
echo "installed: ${SERVICE_DST}"
echo "env file : ${ENV_DST}"
echo
echo "next steps:"
echo "  1) edit ${ENV_DST}"
echo "  2) systemctl restart drpow"
echo "  3) systemctl status drpow --no-pager"
echo "  4) journalctl -u drpow -f"
