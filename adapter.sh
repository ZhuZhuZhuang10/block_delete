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

for p in curl wget iptables iptables-save; do
  if ! command -v "$p" >/dev/null 2>&1; then
    echo "Устанавливаю пакет: $p (если доступно)"
    install_pkg "$p" || echo "Установка $p не удалась — проверьте вручную."
  fi
done

# -----------------------
# Записываем apply_rules_from_url.sh (модифицированная версия)
# -----------------------
cat > "$APPLY_PATH" <<'EOF'
#!/usr/bin/env bash
# apply_rules_from_url - fixed robust version with conntrack tuning
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

echo "=== apply_rules_from_url (fixed) started: $(date -u +"%Y-%m-%dT%H:%M:%SZ") ==="
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

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

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

# Backup current iptables
BACKUP_FILE="/root/iptables.backup.$(date +%s)"
if command -v iptables-save >/dev/null 2>&1; then
  echo "Backing up current iptables to $BACKUP_FILE"
  if ! iptables-save > "$BACKUP_FILE" 2>/dev/null; then
    echo "Warning: iptables-save failed (continuing)"
  fi
else
  echo "iptables-save not found; backup skipped"
fi

# Try to ensure iptables tool exists (best-effort)
install_pkg() {
  pkg="$1"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y "$pkg"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "$pkg"
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache "$pkg"
  else
    echo "No supported package manager found to install $pkg."
    return 1
  fi
}

if ! command -v iptables >/dev/null 2>&1; then
  echo "iptables not found — attempting to install..."
  install_pkg iptables || echo "Auto-install failed; continuing (system may use nftables)"
fi

# Flush PREROUTING (best-effort)
echo "Flushing NAT PREROUTING chain (best-effort)..."
if iptables -t nat -F PREROUTING 2>/dev/null; then
  echo "PREROUTING flushed."
else
  echo "Warning: could not flush PREROUTING (chain may not exist or iptables unavailable)."
fi

# Execute rules line-by-line
LINE_NO=0
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
      if [ "$CONTINUE_ON_ERROR" = true ]; then
        echo "Continuing due to --continue-on-error"
        continue
      else
        echo "Aborting. You can restore previous rules with: iptables-restore < $BACKUP_FILE"
        exit 5
      fi
    fi
  else
    echo "Skipping unsafe/unsupported command on line $LINE_NO: $line"
    if [ "$CONTINUE_ON_ERROR" = false ]; then
      echo "Aborting due to unsupported command. Use --continue-on-error to ignore."
      exit 6
    fi
  fi
done < "$RULES_FILE"

# Ensure MASQUERADE exists
echo "Ensuring POSTROUTING MASQUERADE exists..."
if ! iptables -t nat -C POSTROUTING -j MASQUERADE >/dev/null 2>&1; then
  if $DRY_RUN; then
    echo "(dry-run) Would add: iptables -t nat -A POSTROUTING -j MASQUERADE"
  else
    iptables -t nat -A POSTROUTING -j MASQUERADE || echo "Warning: failed to add MASQUERADE"
  fi
else
  echo "MASQUERADE rule already present."
fi

# Enable ip forwarding
SYSCTL_KEY="net.ipv4.ip_forward"
if $DRY_RUN; then
  echo "(dry-run) Would set $SYSCTL_KEY = 1 and run sysctl -p (or sysctl --system)"
else
  if [ "$(sysctl -n $SYSCTL_KEY 2>/dev/null || echo 0)" != "1" ]; then
    if grep -q "^${SYSCTL_KEY}" /etc/sysctl.conf 2>/dev/null; then
      sed -i "s|^${SYSCTL_KEY}.*|${SYSCTL_KEY} = 1|" /etc/sysctl.conf || echo "${SYSCTL_KEY} = 1" >> /etc/sysctl.conf
    else
      echo "${SYSCTL_KEY} = 1" >> /etc/sysctl.conf
    fi
  fi
  # Try to reload sysctl settings; prefer --system if available
  if command -v sysctl >/dev/null 2>&1; then
    if sysctl --system >/dev/null 2>&1; then
      echo "sysctl settings reloaded with sysctl --system"
    else
      sysctl -p || echo "Warning: sysctl -p failed"
    fi
  else
    echo "Warning: sysctl not found; ip_forward persistence applied to file but not reloaded"
  fi
fi

# --- New: ensure conntrack max is set and persisted ---
CONNTRACK_KEY="net.netfilter.nf_conntrack_max"
CONNTRACK_VALUE="1048576"

echo "Ensuring $CONNTRACK_KEY = $CONNTRACK_VALUE (runtime + persisted)"
if $DRY_RUN; then
  echo "(dry-run) Would run: sysctl -w ${CONNTRACK_KEY}=${CONNTRACK_VALUE}"
  echo "(dry-run) Would persist: write '${CONNTRACK_KEY} = ${CONNTRACK_VALUE}' to /etc/sysctl.d/99-rls.conf (or /etc/sysctl.conf fallback)"
else
  if command -v sysctl >/dev/null 2>&1; then
    # Apply at runtime
    current_val="$(sysctl -n "$CONNTRACK_KEY" 2>/dev/null || echo "")"
    if [ "$current_val" = "$CONNTRACK_VALUE" ]; then
      echo "$CONNTRACK_KEY already set to $CONNTRACK_VALUE (runtime)"
    else
      if sysctl -w "${CONNTRACK_KEY}=${CONNTRACK_VALUE}" >/dev/null 2>&1; then
        echo "Set $CONNTRACK_KEY = $CONNTRACK_VALUE (runtime)"
      else
        echo "Warning: failed to set $CONNTRACK_KEY at runtime"
      fi
    fi

    # Persist the setting in /etc/sysctl.d/99-rls.conf (preferred)
    SYSCTL_D_DIR="/etc/sysctl.d"
    SYSCTL_D_FILE="${SYSCTL_D_DIR}/99-rls.conf"
    if mkdir -p "$SYSCTL_D_DIR" 2>/dev/null; then
      if grep -q "^${CONNTRACK_KEY}" "$SYSCTL_D_FILE" 2>/dev/null; then
        sed -i "s|^${CONNTRACK_KEY}.*|${CONNTRACK_KEY} = ${CONNTRACK_VALUE}|" "$SYSCTL_D_FILE" || echo "${CONNTRACK_KEY} = ${CONNTRACK_VALUE}" >> "$SYSCTL_D_FILE"
      else
        echo "${CONNTRACK_KEY} = ${CONNTRACK_VALUE}" >> "$SYSCTL_D_FILE"
      fi
      # Try to reload sysctl settings
      if sysctl --system >/dev/null 2>&1; then
        echo "Persisted $CONNTRACK_KEY in $SYSCTL_D_FILE and reloaded sysctl --system"
      else
        echo "Warning: sysctl --system failed; the value is written to $SYSCTL_D_FILE but may not be active until next boot"
      fi
    else
      # Fallback to /etc/sysctl.conf if /etc/sysctl.d can't be used
      if grep -q "^${CONNTRACK_KEY}" /etc/sysctl.conf 2>/dev/null; then
        sed -i "s|^${CONNTRACK_KEY}.*|${CONNTRACK_KEY} = ${CONNTRACK_VALUE}|" /etc/sysctl.conf || echo "${CONNTRACK_KEY} = ${CONNTRACK_VALUE}" >> /etc/sysctl.conf
      else
        echo "${CONNTRACK_KEY} = ${CONNTRACK_VALUE}" >> /etc/sysctl.conf
      fi
      if sysctl -p >/dev/null 2>&1; then
        echo "Persisted $CONNTRACK_KEY in /etc/sysctl.conf and reloaded sysctl -p"
      else
        echo "Warning: sysctl -p failed; the value is written to /etc/sysctl.conf but may not be active until next boot"
      fi
    fi
  else
    echo "Warning: sysctl command not found; cannot set $CONNTRACK_KEY"
  fi
fi

# Stop/disable ufw quietly
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop ufw.service 2>/dev/null || true
  systemctl disable ufw.service 2>/dev/null || true
fi

echo "=== Completed successfully. Backup: $BACKUP_FILE ==="
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
  if ! curl -fsSL "\$RULES_URL" -o "\$TMP_RULES"; then
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
    bash "\$APPLY_SCRIPT" "\$LOCAL_RULES" --continue-on-error || echo "[agent] apply script returned non-zero"
    # save hash if apply didn't exit script (we use --continue-on-error)
    echo "\$NEW_HASH" > "\$LOCAL_HASH_FILE"
    echo "[agent] Rules updated (\$(date -u))."
  fi

  sleep "\$SLEEP_INTERVAL"
done
EOF

chmod 755 "$AGENT_PATH"
echo "Wrote $AGENT_PATH"

# -----------------------
# Systemd unit
# -----------------------
cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Auto-updater for iptables rules (github -> apply_rules_from_url)
After=network.target

[Service]
ExecStart=${AGENT_PATH}
Restart=always
RestartSec=10
StartLimitIntervalSec=60
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
EOF

echo "Wrote $SERVICE_PATH"

# -----------------------
# Daemon reload and enable/start service
# -----------------------
systemctl daemon-reload
systemctl enable --now iptables-agent.service

# -----------------------
# Set hostname to localhost (по просьбе)
# -----------------------
echo "WARNING: устанавливаю hostname в 'localhost'. Это может повлиять на сетевые настройки."
if command -v hostnamectl >/dev/null 2>&1; then
  hostnamectl set-hostname localhost || echo "hostnamectl failed"
else
  sethostname() { /bin/hostname "$1" 2>/dev/null || true; }
  sethostname "localhost"
fi

# Ensure /etc/hosts contains mapping for localhost
if ! grep -E "^127\\.0\\.0\\.1[[:space:]]+localhost" /etc/hosts >/dev/null 2>&1; then
  echo "127.0.0.1 localhost" >> /etc/hosts
fi

# Optional: replace any 127.0.1.1 <oldname> with localhost (best-effort)
if grep -E "^127\\.0\\.1\\.1" /etc/hosts >/dev/null 2>&1; then
  sed -i 's/^127\\.0\\.1\\.1.*/127.0.1.1 localhost/' /etc/hosts || true
fi

echo ""
echo "Installation complete."
echo " - apply script: $APPLY_PATH"
echo " - agent: $AGENT_PATH"
echo " - systemd unit: $SERVICE_PATH (enabled & started)"
echo ""
echo "Agent polls: $RULES_URL every ${SLEEP_INTERVAL}s and runs apply script when changes detected."
echo ""
echo "If you want to test now, run:"
echo "  bash $APPLY_PATH $RULES_URL --dry-run"
echo ""
echo "Logs: /var/log/apply_rules_from_url_fixed.log and journalctl -u iptables-agent.service -f"
