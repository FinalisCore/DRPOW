#!/usr/bin/env bash
set -euo pipefail

ROOT=/tmp/rpov2_testnet
RUN_TIMEOUT_SEC="${RUN_TIMEOUT_SEC:-45}"
LIBOQS_PKGCFG="/home/greendragon/Desktop/coin/src/liboqs/install/lib/pkgconfig"
LIBOQS_LIBDIR="/home/greendragon/Desktop/coin/src/liboqs/install/lib"
case ":${PKG_CONFIG_PATH:-}:" in
  *":$LIBOQS_PKGCFG:"*) ;;
  *) PKG_CONFIG_PATH="$LIBOQS_PKGCFG${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" ;;
esac
case ":${LD_LIBRARY_PATH:-}:" in
  *":$LIBOQS_LIBDIR:"*) ;;
  *) LD_LIBRARY_PATH="$LIBOQS_LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
esac
export PKG_CONFIG_PATH
export LD_LIBRARY_PATH

pkill -f "rpov2_node /tmp/rpov2_testnet/node" >/dev/null 2>&1 || true

rm -rf "$ROOT"
mkdir -p "$ROOT/node1" "$ROOT/node2" "$ROOT/node3"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"
make USE_LIBOQS=1 rpov2_node
NODE_BIN="$REPO_ROOT/build/rpov2_node"

pick_port() {
  local p=$1
  while true; do
    if ! ss -ltn "( sport = :$p )" | rg -q ":$p\\b"; then
      echo "$p"
      return 0
    fi
    p=$((p + 1))
  done
}

P1_PORT=$(pick_port 29101)
P2_PORT=$(pick_port $((P1_PORT + 1)))
P3_PORT=$(pick_port $((P2_PORT + 1)))

K1=1111111111111111111111111111111111111111111111111111111111111111
K2=2222222222222222222222222222222222222222222222222222222222222222
K3=3333333333333333333333333333333333333333333333333333333333333333

derive_signer_id() {
  local key=$1
  local tmp_conf=$2
  local tmp_log=$3
  local tmp_port=$4
  cat > "$tmp_conf" <<CONF
data_dir=$ROOT/derive
bind_port=$tmp_port
duration_sec=1
signer_privkey_hex=$key
CONF
  "$NODE_BIN" "$tmp_conf" > "$tmp_log" 2>&1 || true
  rg -o "signer_id=[0-9a-f]{64}" "$tmp_log" | sed 's/^signer_id=//' | tail -n 1
}

mkdir -p "$ROOT/derive"
V1=$(derive_signer_id "$K1" "$ROOT/derive1.conf" "$ROOT/derive1.log" "$(pick_port 30101)")
V2=$(derive_signer_id "$K2" "$ROOT/derive2.conf" "$ROOT/derive2.log" "$(pick_port 30102)")
V3=$(derive_signer_id "$K3" "$ROOT/derive3.conf" "$ROOT/derive3.log" "$(pick_port 30103)")

if [[ -z "$V1" || -z "$V2" || -z "$V3" ]]; then
  echo "failed to derive validator pubkeys" >&2
  exit 1
fi

VALS="$V1,$V2,$V3"

cat > "$ROOT/node1.conf" <<CONF
data_dir=$ROOT/node1
bind_port=$P1_PORT
duration_sec=20
autopropose=1
autopropose_interval_sec=3
signer_privkey_hex=$K1
validator_pubkeys_hex=$VALS
peers=127.0.0.1:$P2_PORT,127.0.0.1:$P3_PORT
CONF

cat > "$ROOT/node2.conf" <<CONF
data_dir=$ROOT/node2
bind_port=$P2_PORT
duration_sec=20
signer_privkey_hex=$K2
validator_pubkeys_hex=$VALS
peers=127.0.0.1:$P1_PORT,127.0.0.1:$P3_PORT
CONF

cat > "$ROOT/node3.conf" <<CONF
data_dir=$ROOT/node3
bind_port=$P3_PORT
duration_sec=20
signer_privkey_hex=$K3
validator_pubkeys_hex=$VALS
peers=127.0.0.1:$P1_PORT,127.0.0.1:$P2_PORT
CONF

echo "ports: $P1_PORT $P2_PORT $P3_PORT"
echo "validators: $VALS"

stdbuf -oL -eL "$NODE_BIN" "$ROOT/node1.conf" > "$ROOT/node1.log" 2>&1 &
PID1=$!
stdbuf -oL -eL "$NODE_BIN" "$ROOT/node2.conf" > "$ROOT/node2.log" 2>&1 &
PID2=$!
stdbuf -oL -eL "$NODE_BIN" "$ROOT/node3.conf" > "$ROOT/node3.log" 2>&1 &
PID3=$!

(
  sleep "$RUN_TIMEOUT_SEC"
  if kill -0 "$PID1" >/dev/null 2>&1 || kill -0 "$PID2" >/dev/null 2>&1 || kill -0 "$PID3" >/dev/null 2>&1; then
    echo "testnet timeout: killing nodes after ${RUN_TIMEOUT_SEC}s" >&2
    kill "$PID1" "$PID2" "$PID3" >/dev/null 2>&1 || true
  fi
) &
WD_PID=$!

status=0
wait $PID1 || status=$?
wait $PID2 || status=$?
wait $PID3 || status=$?
kill "$WD_PID" >/dev/null 2>&1 || true
if [[ $status -ne 0 ]]; then
  echo "testnet failed status=$status"
  exit "$status"
fi

R1="$(rg -o "final_status round=[0-9]+" "$ROOT/node1.log" | tail -n 1 | awk -F= '{print $2}')"
R2="$(rg -o "final_status round=[0-9]+" "$ROOT/node2.log" | tail -n 1 | awk -F= '{print $2}')"
R3="$(rg -o "final_status round=[0-9]+" "$ROOT/node3.log" | tail -n 1 | awk -F= '{print $2}')"
H1="$(rg -o "final_status round=[0-9]+ state_root=[0-9a-f]+" "$ROOT/node1.log" | tail -n 1 | sed -E 's/.*state_root=([0-9a-f]+)/\1/')"
H2="$(rg -o "final_status round=[0-9]+ state_root=[0-9a-f]+" "$ROOT/node2.log" | tail -n 1 | sed -E 's/.*state_root=([0-9a-f]+)/\1/')"
H3="$(rg -o "final_status round=[0-9]+ state_root=[0-9a-f]+" "$ROOT/node3.log" | tail -n 1 | sed -E 's/.*state_root=([0-9a-f]+)/\1/')"

if [[ -z "${R1:-}" || -z "${R2:-}" || -z "${R3:-}" || -z "${H1:-}" || -z "${H2:-}" || -z "${H3:-}" ]]; then
  echo "convergence_assert_failed: missing final_status in logs" >&2
  for f in "$ROOT"/node*.log; do
    echo "== debug $f =="
    rg "node_started|validator_set|autopropose|commit ok|drop|sync_" "$f" || true
  done
  exit 20
fi
if [[ "$R1" -le 0 || "$R2" -le 0 || "$R3" -le 0 ]]; then
  echo "convergence_assert_failed: no round progress r1=$R1 r2=$R2 r3=$R3" >&2
  for f in "$ROOT"/node*.log; do
    echo "== debug $f =="
    rg "node_started|validator_set|autopropose|commit ok|drop|sync_" "$f" || true
  done
  exit 21
fi
if [[ "$H1" != "$H2" || "$H1" != "$H3" ]]; then
  echo "convergence_assert_failed: state_root mismatch h1=$H1 h2=$H2 h3=$H3" >&2
  for f in "$ROOT"/node*.log; do
    echo "== debug $f =="
    rg "node_started|validator_set|autopropose|commit ok|drop|sync_" "$f" || true
  done
  exit 22
fi

echo "convergence_ok rounds=$R1,$R2,$R3 root=$H1"
echo "testnet finished; logs in $ROOT"
