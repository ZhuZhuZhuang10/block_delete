#!/usr/bin/env bash
# iptables-agent.sh — watches GitHub rules and applies them on changes
set -uo pipefail

RULES_URL="https://raw.githubusercontent.com/ZhuZhuZhuang10/block_delete/main/rls.txt"
LOCAL_RULES="/etc/iptables-rls.txt"
LOCAL_HASH_FILE="/etc/iptables-rls.hash"
APPLY_SCRIPT="/usr/local/bin/apply_rules_from_url.sh"
TMP_RULES="/tmp/iptables-new.txt"
SLEEP_INTERVAL=30
LOG_FILE="/var/log/iptables-agent.log"

mkdir -p "$(dirname "$LOG_FILE")"

log() {
  printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG_FILE"
}

run_cmd() {
  log "RUN: $*"
  "$@" >>"$LOG_FILE" 2>&1
  local rc=$?
  log "EXIT($rc): $*"
  return $rc
}

trap 'log "Agent interrupted or exited. Last command status: $?"' EXIT

log "=== iptables-agent started ==="
log "RULES_URL=$RULES_URL"
log "LOCAL_RULES=$LOCAL_RULES"
log "LOCAL_HASH_FILE=$LOCAL_HASH_FILE"
log "APPLY_SCRIPT=$APPLY_SCRIPT"
log "SLEEP_INTERVAL=$SLEEP_INTERVAL"

while true; do
  log "Checking for rules update..."

  if ! curl --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 30 -fsSL "$RULES_URL" -o "$TMP_RULES" >>"$LOG_FILE" 2>&1; then
    log "ERROR: Failed to download rules from $RULES_URL"
    sleep "$SLEEP_INTERVAL"
    continue
  fi

  if [ ! -s "$TMP_RULES" ]; then
    log "ERROR: Downloaded rules file is empty"
    sleep "$SLEEP_INTERVAL"
    continue
  fi

  NEW_HASH="$(sha256sum "$TMP_RULES" | awk '{print $1}')"
  OLD_HASH="$(cat "$LOCAL_HASH_FILE" 2>/dev/null || true)"

  log "Hash old: ${OLD_HASH:-<empty>}"
  log "Hash new: $NEW_HASH"

  if [ "$NEW_HASH" = "$OLD_HASH" ]; then
    log "No changes detected, skipping apply."
    sleep "$SLEEP_INTERVAL"
    continue
  fi

  log "New rules detected, copying to local file..."
  if ! cp "$TMP_RULES" "$LOCAL_RULES" >>"$LOG_FILE" 2>&1; then
    log "ERROR: Failed to copy rules to $LOCAL_RULES"
    sleep "$SLEEP_INTERVAL"
    continue
  fi

  log "Local rules saved: $LOCAL_RULES"
  log "Applying rules via $APPLY_SCRIPT"

  if bash "$APPLY_SCRIPT" "$LOCAL_RULES" --continue-on-error >>"$LOG_FILE" 2>&1; then
    echo "$NEW_HASH" > "$LOCAL_HASH_FILE"
    log "SUCCESS: Rules applied and hash updated."
  else
    rc=$?
    log "ERROR: Apply script failed with exit code $rc"
    log "Hash not updated. Previous rules remain in effect."
  fi

  log "Sleeping ${SLEEP_INTERVAL}s before next check..."
  sleep "$SLEEP_INTERVAL"
done
