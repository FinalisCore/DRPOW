#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_SRC="${ROOT_DIR}/systemd/drpow.service"
ENV_EXAMPLE_SRC="${ROOT_DIR}/systemd/drpow.env.example"
SERVICE_DST="/etc/systemd/system/drpow.service"
ENV_DST="/etc/default/drpow"

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
