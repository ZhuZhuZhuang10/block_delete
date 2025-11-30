#!/usr/bin/env bash
# installer.sh — устанавливает apply_rules_from_url и агент автообновления правил с GitHub
set -o errexit
set -o nounset
set -o pipefail

# -----------------------
# Настройки
# -----------------------
APPLY_PATH="/usr/local/bin/apply_rules_from_url.sh"
AGENT_PATH="/usr/local/bin/iptables-agent.sh"
SERVICE_PATH="/etc/systemd/system/iptables-agent.service"
RULES_URL="https://raw.githubusercontent.com/ZhuZhuZhuang10/block_delete/main/rls.txt"
SLEEP_INTERVAL=30

# -----------------------
# Привилегии
# -----------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "Этот скрипт должен быть запущен от root (sudo)."
  exit 1
fi

# -----------------------
# Утилиты (best-effort)
# -----------------------
install_pkg() {
  pkg="$1"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y "$pkg"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "$pkg"
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache "$pkg"
  else
    echo "Неизвестный пакетный менеджер — убедитесь что $pkg установлен вручную."
    return 1
  fi
}

for p in curl wget iptables iptables-save iptables-restore; do
  if ! command -v "$p" >/dev/null 2>&1; then
    echo "Устанавливаю пакет: $p (если доступно)"
    install_pkg "$p" || echo "Установка $p не удалась — проверьте вручную."
  fi
done

# -----------------------
# Записываем apply_rules_from_url.sh (без POST IP, с безопасным откатом)
# -----------------------
cat > "$APPLY_PATH" <<'EOF'
#!/usr/bin/env bash
# apply_rules_from_url - robust version with conntrack tuning + automatic rollback on network failure
set -o errexit
set -o nounset
set -o pipefail

DEFAULT_RULES_URL="https://raw.githubusercontent.com/ZhuZhuZhuang10/block_delete/refs/heads/main/rls.txt"
RULES_URL="${1:-$DEFAULT_RULES_URL}"
DRY_RUN=false
CONTINUE_ON_ERROR=false
for arg in "${@:2}"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --continue-on-error) CONTINUE_ON_ERROR=true ;;
    *) echo "Unknown option: $arg"; exit 2 ;;
  esac
done

LOG="/var/log/apply_rules_from_url_fixed.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== apply_rules_from_url (safe) started: $(date -u +"%Y-%m-%dT%H:%M:%SZ") ==="
echo "Rules URL/File: $RULES_URL"
echo "Dry run: $DRY_RUN"
echo "Continue on error: $CONTINUE_ON_ERROR"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root (sudo)."
  exit 3
fi

TMP_DIR="$(mktemp -d)"
RULES_RAW="$TMP_DIR/rls.raw"
RULES_FILE="$TMP_DIR/rls.normalized"
BACKUP_FILE="/root/iptables.backup.$(date +%s)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# detect primary outgoing interface (best-effort)
OUT_IF="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')"
OUT_IF="${OUT_IF:-eth0}"

# download rules (or accept local file)
echo "Obtaining rules..."
if [ -f "$RULES_URL" ]; then
  echo "Source is a local file: $RULES_URL"
  cp "$RULES_URL" "$RULES_RAW"
else
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 20 "$RULES_URL" -o "$RULES_RAW" || { echo "Failed to download rules via curl"; exit 4; }
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$RULES_RAW" "$RULES_URL" || { echo "Failed to download rules via wget"; exit 4; }
  else
    echo "Neither curl nor wget available; please install one and re-run."
    exit 4
  fi
fi

# Remove Windows CRs and ensure sensible format.
tr -d '\r' < "$RULES_RAW" > "$RULES_RAW.nocr"

# Normalize: put each 'iptables' at line start (if rules were concatenated)
# Also remove empty lines and trim spaces.
sed -E 's/[[:space:]]*iptables/\
iptables/g' "$RULES_RAW.nocr" \
  | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
  | awk 'NF{print}' \
  > "$RULES_FILE"

echo "Preview of normalized rules (first 40 lines):"
nl -ba -w3 -s'. ' "$RULES_FILE" | sed -n '1,40p' || true

# Backup current iptables (always)
if command -v iptables-save >/dev/null 2>&1; then
  echo "Backing up current iptables to $BACKUP_FILE"
  if ! iptables-save > "$BACKUP_FILE" 2>/dev/null; then
    echo "Warning: iptables-save failed (continuing)"
  fi
else
  echo "iptables-save not found; backup skipped"
fi

# Ensure basic allowed traffic exists before making changes (best-effort)
# So temporary work processes (curl/ping) continue during apply.
echo "Ensuring temporary safety rules (allow DNS, HTTP(S), established) while applying..."
# accept loopback
iptables -C OUTPUT -o lo -j ACCEPT >/dev/null 2>&1 || iptables -I OUTPUT 1 -o lo -j ACCEPT || true
# accept established/related
iptables -C OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || iptables -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
# allow DNS and HTTP/HTTPS out
iptables -C OUTPUT -p udp --dport 53 -j ACCEPT >/dev/null 2>&1 || iptables -I OUTPUT 1 -p udp --dport 53 -j ACCEPT || true
iptables -C OUTPUT -p tcp --dport 53 -j ACCEPT >/dev/null 2>&1 || iptables -I OUTPUT 1 -p tcp --dport 53 -j ACCEPT || true
iptables -C OUTPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || iptables -I OUTPUT 1 -p tcp --dport 80 -j ACCEPT || true
iptables -C OUTPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1 || iptables -I OUTPUT 1 -p tcp --dport 443 -j ACCEPT || true
# ensure MASQUERADE exists for outbound interface
if ! iptables -t nat -C POSTROUTING -o "$OUT_IF" -j MASQUERADE >/dev/null 2>&1; then
  iptables -t nat -A POSTROUTING -o "$OUT_IF" -j MASQUERADE 2>/dev/null || true
fi

# Execute rules line-by-line (the rules file may add/flush further rules)
LINE_NO=0
APPLY_FAIL=0
while IFS= read -r rawline || [ -n "$rawline" ]; do
  LINE_NO=$((LINE_NO+1))
  # strip comments after # and trim
  line="$(printf '%s\n' "$rawline" | sed -E 's/#.*$//' | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')"
  [ -z "$line" ] && continue
  echo "[$LINE_NO] $line"

  if $DRY_RUN; then
    echo " (dry-run) skipping execution"
    continue
  fi

  # Only allow commands that start with iptables or ip (safer)
  if [[ "$line" =~ ^(iptables|ip\ ) ]]; then
    if eval "$line"; then
      echo "[$LINE_NO] OK"
    else
      echo "[$LINE_NO] ERROR executing: $line"
      APPLY_FAIL=1
      if [ "$CONTINUE_ON_ERROR" = true ]; then
        echo "Continuing due to --continue-on-error"
        continue
      else
        echo "Aborting on rule error. Will attempt rollback."
        break
      fi
    fi
  else
    echo "Skipping unsafe/unsupported command on line $LINE_NO: $line"
    if [ "$CONTINUE_ON_ERROR" = false ]; then
      echo "Aborting due to unsupported command. Use --continue-on-error to ignore."
      APPLY_FAIL=1
      break
    fi
  fi
done < "$RULES_FILE"

# Ensure POSTROUTING MASQUERADE exists (try to re-add if necessary)
echo "Ensuring POSTROUTING MASQUERADE exists (interface: $OUT_IF)..."
if ! iptables -t nat -C POSTROUTING -o "$OUT_IF" -j MASQUERADE >/dev/null 2>&1; then
  if $DRY_RUN; then
    echo "(dry-run) Would add: iptables -t nat -A POSTROUTING -o $OUT_IF -j MASQUERADE"
  else
    iptables -t nat -A POSTROUTING -o "$OUT_IF" -j MASQUERADE || echo "Warning: failed to add MASQUERADE"
  fi
else
  echo "MASQUERADE present."
fi

# Ensure ip forwarding
SYSCTL_KEY="net.ipv4.ip_forward"
if $DRY_RUN; then
  echo "(dry-run) Would set $SYSCTL_KEY = 1"
else
  if [ "$(sysctl -n $SYSCTL_KEY 2>/dev/null || echo 0)" != "1" ]; then
    if grep -q "^${SYSCTL_KEY}" /etc/sysctl.conf 2>/dev/null; then
      sed -i "s|^${SYSCTL_KEY}.*|${SYSCTL_KEY} = 1|" /etc/sysctl.conf || echo "${SYSCTL_KEY} = 1" >> /etc/sysctl.conf
    else
      echo "${SYSCTL_KEY} = 1" >> /etc/sysctl.conf
    fi
  fi
  if command -v sysctl >/dev/null 2>&1; then
    if sysctl --system >/dev/null 2>&1; then
      echo "sysctl settings reloaded with sysctl --system"
    else
      sysctl -p || echo "Warning: sysctl -p failed"
    fi
  else
    echo "Warning: sysctl not found; ip_forward persistence applied but not reloaded"
  fi
fi

# conntrack persistence
CONNTRACK_KEY="net.netfilter.nf_conntrack_max"
CONNTRACK_VALUE="1048576"
if $DRY_RUN; then
  echo "(dry-run) Would set ${CONNTRACK_KEY}=${CONNTRACK_VALUE}"
else
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -w "${CONNTRACK_KEY}=${CONNTRACK_VALUE}" >/dev/null 2>&1 || true
    SYSCTL_D_DIR="/etc/sysctl.d"
    SYSCTL_D_FILE="${SYSCTL_D_DIR}/99-rls.conf"
    mkdir -p "$SYSCTL_D_DIR" 2>/dev/null || true
    if grep -q "^${CONNTRACK_KEY}" "$SYSCTL_D_FILE" 2>/dev/null; then
      sed -i "s|^${CONNTRACK_KEY}.*|${CONNTRACK_KEY} = ${CONNTRACK_VALUE}|" "$SYSCTL_D_FILE" || echo "${CONNTRACK_KEY} = ${CONNTRACK_VALUE}" >> "$SYSCTL_D_FILE"
    else
      echo "${CONNTRACK_KEY} = ${CONNTRACK_VALUE}" >> "$SYSCTL_D_FILE"
    fi
    sysctl --system >/dev/null 2>&1 || true
  fi
fi

# If any rule application failed, rollback immediately
if [ "$APPLY_FAIL" -eq 1 ]; then
  echo "Rule application failed — restoring backup from $BACKUP_FILE"
  if [ -f "$BACKUP_FILE" ]; then
    iptables-restore < "$BACKUP_FILE" || echo "Warning: iptables-restore failed"
  fi
  echo "Aborted due to apply failure."
  exit 5
fi

# Connectivity checks — ensure we still have network/DNS and can reach GitHub raw content
echo "Running connectivity checks..."
OK=1

# 1) Basic IP ping
if ! ping -c1 -W2 8.8.8.8 >/dev/null 2>&1; then
  echo "Ping to 8.8.8.8 failed"
  OK=0
else
  echo "Ping to 8.8.8.8 ok"
fi

# 2) curl raw.githubusercontent.com (needs DNS + HTTPS)
if ! curl -s --max-time 8 https://raw.githubusercontent.com/ >/dev/null 2>&1; then
  echo "HTTP(S) test to raw.githubusercontent.com failed"
  OK=0
else
  echo "HTTP(S) test to raw.githubusercontent.com ok"
fi

if [ "$OK" -ne 1 ]; then
  echo "Connectivity checks failed — restoring backup from $BACKUP_FILE"
  if [ -f "$BACKUP_FILE" ]; then
    iptables-restore < "$BACKUP_FILE" || echo "Warning: iptables-restore failed"
  else
    echo "No backup available to restore!"
  fi
  echo "Rollback completed. Leaving previous rules in place."
  exit 6
fi

echo "All connectivity checks passed. Rules applied successfully."
echo "=== Completed successfully. Backup saved at: $BACKUP_FILE ==="
EOF

chmod 755 "$APPLY_PATH"
echo "Wrote $APPLY_PATH"

# -----------------------
# Записываем agent (без jq, простая проверка sha256)
# -----------------------
cat > "$AGENT_PATH" <<EOF
#!/usr/bin/env bash
# iptables-agent — скачивает rls.txt и применяет при изменениях
set -o errexit
set -o nounset
set -o pipefail

RULES_URL="${RULES_URL}"
LOCAL_RULES="/etc/iptables-rls.txt"
LOCAL_HASH_FILE="/etc/iptables-rls.hash"
APPLY_SCRIPT="${APPLY_PATH}"
TMP_RULES="/tmp/iptables-new.txt"
SLEEP_INTERVAL=${SLEEP_INTERVAL}

while true; do
  # try multiple times to fetch (helps transient DNS hiccups)
  if ! curl --retry 3 --retry-delay 2 -fsSL "\$RULES_URL" -o "\$TMP_RULES"; then
    echo "[agent] Failed to download rules (\$(date -u))"
    sleep "\$SLEEP_INTERVAL"
    continue
  fi

  NEW_HASH=\$(sha256sum "\$TMP_RULES" | awk '{print \$1}')
  OLD_HASH=\$(cat "\$LOCAL_HASH_FILE" 2>/dev/null || echo "")

  if [ "\$NEW_HASH" != "\$OLD_HASH" ]; then
    echo "[agent] New rules detected (\$(date -u)), applying..."
    # copy to local rules file (for reference)
    cp "\$TMP_RULES" "\$LOCAL_RULES"
    # run apply script (supports local file path as arg)
    if bash "\$APPLY_SCRIPT" "\$LOCAL_RULES" --continue-on-error; then
      # save hash only if apply succeeded (apply script will rollback on failure and exit non-zero)
      echo "\$NEW_HASH" > "\$LOCAL_HASH_FILE"
      echo "[agent] Rules updated (\$(date -u))."
    else
      echo "[agent] Apply script failed and rolled back — not updating local hash (\$(date -u))."
    fi
  fi

  sleep "\$SLEEP_INTERVAL"
done
EOF

chmod 755 "$AGENT_PATH"
echo "Wrote $AGENT_PATH"

# -----------------------
# Systemd unit (fixed: StartLimit keys in [Unit])
# -----------------------
cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Auto-updater for iptables rules (github -> apply_rules_from_url)
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=${AGENT_PATH}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "Wrote $SERVICE_PATH"

# -----------------------
# Daemon reload and enable/start service
# -----------------------
systemctl daemon-reload
systemctl enable --now iptables-agent.service

echo ""
echo "Installation complete."
echo " - apply script: $APPLY_PATH"
echo " - agent: $AGENT_PATH"
echo " - systemd unit: $SERVICE_PATH (enabled & started)"
echo ""
echo "Agent polls: $RULES_URL every ${SLEEP_INTERVAL}s and runs apply script when changes detected."
echo ""
echo "If you want to test now, run (dry-run):"
echo "  bash $APPLY_PATH $RULES_URL --dry-run"
echo ""
echo "Logs:"
echo " - apply script: /var/log/apply_rules_from_url_fixed.log"
echo " - agent service journal: journalctl -u iptables-agent.service -f"
