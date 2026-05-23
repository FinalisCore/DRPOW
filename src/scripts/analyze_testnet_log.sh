#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <log_file>" >&2
  exit 1
fi

LOG_FILE="$1"
if [ ! -f "$LOG_FILE" ]; then
  echo "log file not found: $LOG_FILE" >&2
  exit 1
fi

count() {
  local pattern="$1"
  grep -c -- "$pattern" "$LOG_FILE" 2>/dev/null || true
}

count_obs=$(count "\\[OBS\\]")
count_commit_ok=$(count "\\[COMMIT\\] ok")
count_catchup_ok=$(count "catchup commit ok")
count_sync_needed=$(count "sync_needed")
count_sync_received=$(count "sync_received payloads=")
count_timeout=$(count "\\[TIMEOUT\\] emit")
count_timeout_qc=$(count "\\[TIMEOUT_QC\\]")
count_pow_preempted=$(count "status=preempted")
count_assert_preempt_ok=$(count "\\[ASSERT\\]\\[PREEMPT\\].*status=ok")
count_assert_preempt_slow=$(count "\\[ASSERT\\]\\[PREEMPT\\].*status=slow")
count_assert_preempt_local=$(count "\\[ASSERT\\]\\[PREEMPT\\].*committed_by=local")

count_drop_params_mismatch=$(count "params_hash_mismatch")
count_drop_commit_qc_invalid=$(count "drop commit qc_invalid")
count_drop_commit_finalized_immutable=$(count "drop commit finalized_immutable")
count_drop_vote_pow_not_found=$(count "drop vote_pow_not_found")
count_drop_unauth=$(count "unauthenticated_message")

# Latest observed preempt_fast_rate in [OBS], if present.
latest_preempt_fast_rate="n/a"
if grep -q "preempt_fast_rate=" "$LOG_FILE"; then
  latest_preempt_fast_rate=$(grep "preempt_fast_rate=" "$LOG_FILE" | tail -n 1 | sed -E 's/.*preempt_fast_rate=([0-9.]+).*/\1/')
fi

# Derived fallback rate from assert logs.
derived_preempt_fast_rate="n/a"
if [ "$count_pow_preempted" -gt 0 ]; then
  derived_preempt_fast_rate=$(awk -v ok="$count_assert_preempt_ok" -v total="$count_pow_preempted" 'BEGIN { printf "%.4f", (ok/total) }')
fi

echo "=== DRPOW Testnet Log Analysis ==="
echo "log_file=$LOG_FILE"
echo
echo "[liveness]"
echo "commit_ok=$count_commit_ok"
echo "catchup_commit_ok=$count_catchup_ok"
echo "timeout_emit=$count_timeout"
echo "timeout_qc=$count_timeout_qc"
echo
echo "[sync]"
echo "sync_needed=$count_sync_needed"
echo "sync_received=$count_sync_received"
echo
echo "[preemption]"
echo "pow_preempted=$count_pow_preempted"
echo "assert_preempt_ok=$count_assert_preempt_ok"
echo "assert_preempt_slow=$count_assert_preempt_slow"
echo "assert_preempt_local=$count_assert_preempt_local"
echo "preempt_fast_rate_obs=$latest_preempt_fast_rate"
echo "preempt_fast_rate_derived=$derived_preempt_fast_rate"
echo
echo "[safety_signals]"
echo "drop_params_mismatch=$count_drop_params_mismatch"
echo "drop_commit_qc_invalid=$count_drop_commit_qc_invalid"
echo "drop_commit_finalized_immutable=$count_drop_commit_finalized_immutable"
echo "drop_vote_pow_not_found=$count_drop_vote_pow_not_found"
echo "drop_unauthenticated_message=$count_drop_unauth"
echo
echo "[telemetry]"
echo "obs_lines=$count_obs"

# Lightweight pass/fail hints (non-normative)
echo
echo "[hints]"
if [ "$count_drop_commit_qc_invalid" -eq 0 ]; then
  echo "qc_invalid_commits=PASS"
else
  echo "qc_invalid_commits=CHECK"
fi

if [ "$count_pow_preempted" -gt 0 ] && [ "$count_assert_preempt_slow" -eq 0 ]; then
  echo "preempt_slow=PASS"
else
  echo "preempt_slow=CHECK"
fi

if [ "$count_commit_ok" -gt 0 ]; then
  echo "commit_progress=PASS"
else
  echo "commit_progress=CHECK"
fi
