#!/usr/bin/env bash
# installer.sh — installs apply_rules_from_url and the GitHub rules agent
set -euo pipefail

# -----------------------
# Settings
# -----------------------
APPLY_PATH="/usr/local/bin/apply_rules_from_url.sh"
AGENT_PATH="/usr/local/bin/iptables-agent.sh"
SERVICE_PATH="/etc/systemd/system/iptables-agent.service"

RULES_URL="https://raw.githubusercontent.com/ZhuZhuZhuang10/block_delete/main/rls.txt"
SLEEP_INTERVAL=30

# -----------------------
# Root check
# -----------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root (sudo)."
  exit 1
fi

# -----------------------
# Package install helpers
# -----------------------
install_with_apt() {
  apt-get update -y
  apt-get install -y curl wget iptables iproute2 procps ca-certificates coreutils
}

install_with_yum() {
  yum install -y curl wget iptables iproute procps-ng ca-certificates coreutils
}

install_with_apk() {
  apk add --no-cache curl wget iptables iproute2 procps ca-certificates coreutils
}

ensure_required_tools() {
  local missing=0

  for cmd in curl wget iptables iptables-save iptables-restore ip sysctl sha256sum awk sed tr cp mktemp tee; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing=1
      break
    fi
  done

  if [ "$missing" -eq 0 ]; then
    return 0
  fi

  echo "Some required tools are missing, trying to install them..."

  if command -v apt-get >/dev/null 2>&1; then
    install_with_apt
  elif command -v yum >/dev/null 2>&1; then
    install_with_yum
  elif command -v apk >/dev/null 2>&1; then
    install_with_apk
  else
    echo "Unsupported package manager. Install these tools manually:"
    echo "curl wget iptables iproute2 procps ca-certificates coreutils"
    exit 1
  fi
}

ensure_required_tools

# -----------------------
# Write apply_rules_from_url.sh
# -----------------------
cat > "$APPLY_PATH" <<'EOF'
#!/usr/bin/env bash
# apply_rules_from_url.sh — downloads/apply rules safely with rollback
set -euo pipefail

DEFAULT_RULES_URL="https://raw.githubusercontent.com/ZhuZhuZhuang10/block_delete/refs/heads/main/rls.txt"
RULES_SOURCE="${1:-$DEFAULT_RULES_URL}"

DRY_RUN=false
CONTINUE_ON_ERROR=false

for arg in "${@:2}"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --continue-on-error) CONTINUE_ON_ERROR=true ;;
    *)
      echo "Unknown option: $arg"
      exit 2
      ;;
  esac
done

LOG="/var/log/apply_rules_from_url_fixed.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== apply_rules_from_url started: $(date -u +"%Y-%m-%dT%H:%M:%SZ") ==="
echo "Source: $RULES_SOURCE"
echo "Dry run: $DRY_RUN"
echo "Continue on error: $CONTINUE_ON_ERROR"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 3
fi

TMP_DIR="$(mktemp -d)"
RULES_RAW="$TMP_DIR/rules.raw"
RULES_FILE="$TMP_DIR/rules.normalized"
BACKUP_FILE="/root/iptables.backup.$(date +%s)"
SYSCTL_FILE="/etc/sysctl.d/99-iptables-agent.conf"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

OUT_IF="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')"
OUT_IF="${OUT_IF:-eth0}"

echo "Downloading rules..."
if [ -f "$RULES_SOURCE" ]; then
  cp "$RULES_SOURCE" "$RULES_RAW"
else
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 20 "$RULES_SOURCE" -o "$RULES_RAW"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$RULES_RAW" "$RULES_SOURCE"
  else
    echo "Neither curl nor wget is available."
    exit 4
  fi
fi

if [ ! -s "$RULES_RAW" ]; then
  echo "Rules file is empty."
  exit 4
fi

tr -d '\r' < "$RULES_RAW" \
  | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
  | awk 'NF{print}' \
  > "$RULES_FILE"

echo "Preview of normalized rules (first 40 lines):"
nl -ba -w3 -s'. ' "$RULES_FILE" | sed -n '1,40p' || true

if command -v iptables-save >/dev/null 2>&1; then
  echo "Backing up current iptables to $BACKUP_FILE"
  if ! iptables-save > "$BACKUP_FILE" 2>/dev/null; then
    echo "Warning: iptables-save failed, rollback may be unavailable."
  fi
else
  echo "iptables-save not found, backup skipped."
fi

echo "Adding temporary allow rules to reduce risk of lockout..."
iptables -C OUTPUT -o lo -j ACCEPT >/dev/null 2>&1 || iptables -I OUTPUT 1 -o lo -j ACCEPT || true
iptables -C OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || iptables -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
iptables -C OUTPUT -p udp --dport 53 -j ACCEPT >/dev/null 2>&1 || iptables -I OUTPUT 1 -p udp --dport 53 -j ACCEPT || true
iptables -C OUTPUT -p tcp --dport 53 -j ACCEPT >/dev/null 2>&1 || iptables -I OUTPUT 1 -p tcp --dport 53 -j ACCEPT || true
iptables -C OUTPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || iptables -I OUTPUT 1 -p tcp --dport 80 -j ACCEPT || true
iptables -C OUTPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1 || iptables -I OUTPUT 1 -p tcp --dport 443 -j ACCEPT || true
iptables -t nat -C POSTROUTING -o "$OUT_IF" -j MASQUERADE >/dev/null 2>&1 || iptables -t nat -A POSTROUTING -o "$OUT_IF" -j MASQUERADE >/dev/null 2>&1 || true

APPLY_FAIL=0
LINE_NO=0

while IFS= read -r rawline || [ -n "$rawline" ]; do
  LINE_NO=$((LINE_NO + 1))

  line="$(printf '%s\n' "$rawline" \
    | sed -E 's/#.*$//' \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"

  [ -z "$line" ] && continue

  echo "[$LINE_NO] $line"

  if $DRY_RUN; then
    echo "[$LINE_NO] dry-run: skipped"
    continue
  fi

  read -r -a argv <<< "$line"
  cmd="${argv[0]}"

  case "$cmd" in
    iptables|ip)
      if "$cmd" "${argv[@]:1}"; then
        echo "[$LINE_NO] OK"
      else
        echo "[$LINE_NO] ERROR: $line"
        APPLY_FAIL=1
        if [ "$CONTINUE_ON_ERROR" = true ]; then
          echo "Continuing because --continue-on-error is enabled."
          continue
        fi
        break
      fi
      ;;
    *)
      echo "Skipping unsupported command on line $LINE_NO: $cmd"
      if [ "$CONTINUE_ON_ERROR" = false ]; then
        APPLY_FAIL=1
        break
      fi
      ;;
  esac
done < "$RULES_FILE"

echo "Ensuring POSTROUTING MASQUERADE exists for interface: $OUT_IF"
if ! iptables -t nat -C POSTROUTING -o "$OUT_IF" -j MASQUERADE >/dev/null 2>&1; then
  if $DRY_RUN; then
    echo "(dry-run) Would add MASQUERADE on $OUT_IF"
  else
    iptables -t nat -A POSTROUTING -o "$OUT_IF" -j MASQUERADE || true
  fi
fi

if $DRY_RUN; then
  echo "(dry-run) Would ensure net.ipv4.ip_forward=1"
else
  mkdir -p /etc/sysctl.d
  cat > "$SYSCTL_FILE" <<SYSCTL_EOF
net.ipv4.ip_forward = 1
SYSCTL_EOF
  sysctl --system >/dev/null 2>&1 || sysctl -p >/dev/null 2>&1 || true
fi

if [ "$APPLY_FAIL" -eq 1 ]; then
  echo "Rule application failed."
  if [ -f "$BACKUP_FILE" ]; then
    echo "Restoring backup: $BACKUP_FILE"
    iptables-restore < "$BACKUP_FILE" || echo "Warning: iptables-restore failed."
  fi
  exit 5
fi

echo "Running connectivity checks..."
OK=1

if command -v curl >/dev/null 2>&1; then
  if ! curl -fsSL --max-time 8 https://raw.githubusercontent.com/ >/dev/null 2>&1; then
    echo "HTTPS check to raw.githubusercontent.com failed"
    OK=0
  else
    echo "HTTPS check to raw.githubusercontent.com OK"
  fi
else
  echo "curl not found, skipping HTTPS check"
fi

if [ "$OK" -ne 1 ]; then
  echo "Connectivity check failed."
  if [ -f "$BACKUP_FILE" ]; then
    echo "Restoring backup: $BACKUP_FILE"
    iptables-restore < "$BACKUP_FILE" || echo "Warning: iptables-restore failed."
  fi
  exit 6
fi

echo "All checks passed."
echo "Backup saved at: $BACKUP_FILE"
echo "=== apply_rules_from_url completed successfully ==="
EOF

chmod 755 "$APPLY_PATH"
echo "Wrote $APPLY_PATH"

# -----------------------
# Write iptables-agent.sh
# -----------------------
cat > "$AGENT_PATH" <<'EOF'
#!/usr/bin/env bash
# iptables-agent.sh — watches GitHub rules and applies them on changes
set -uo pipefail

RULES_URL="__RULES_URL__"
LOCAL_RULES="/etc/iptables-rls.txt"
LOCAL_HASH_FILE="/etc/iptables-rls.hash"
APPLY_SCRIPT="__APPLY_PATH__"
TMP_RULES="/tmp/iptables-new.txt"
SLEEP_INTERVAL=__SLEEP_INTERVAL__

while true; do
  if ! curl --retry 3 --retry-delay 2 -fsSL "$RULES_URL" -o "$TMP_RULES"; then
    echo "[agent] Failed to download rules at $(date -u)"
    sleep "$SLEEP_INTERVAL"
    continue
  fi

  NEW_HASH="$(sha256sum "$TMP_RULES" | awk '{print $1}')"
  OLD_HASH="$(cat "$LOCAL_HASH_FILE" 2>/dev/null || true)"

  if [ "$NEW_HASH" != "$OLD_HASH" ]; then
    echo "[agent] New rules detected at $(date -u), applying..."
    cp "$TMP_RULES" "$LOCAL_RULES"

    if bash "$APPLY_SCRIPT" "$LOCAL_RULES" --continue-on-error; then
      echo "$NEW_HASH" > "$LOCAL_HASH_FILE"
      echo "[agent] Rules updated at $(date -u)."
    else
      echo "[agent] Apply failed, hash not updated."
    fi
  fi

  sleep "$SLEEP_INTERVAL"
done
EOF

sed -i \
  -e "s|__RULES_URL__|$RULES_URL|g" \
  -e "s|__APPLY_PATH__|$APPLY_PATH|g" \
  -e "s|__SLEEP_INTERVAL__|$SLEEP_INTERVAL|g" \
  "$AGENT_PATH"

chmod 755 "$AGENT_PATH"
echo "Wrote $AGENT_PATH"

# -----------------------
# Write systemd unit
# -----------------------
cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Auto-updater for iptables rules (github -> apply_rules_from_url)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=$AGENT_PATH
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "Wrote $SERVICE_PATH"

# -----------------------
# Reload and start
# -----------------------
systemctl daemon-reload
systemctl enable --now iptables-agent.service

echo
echo "Installation complete."
echo "  apply script:  $APPLY_PATH"
echo "  agent script:   $AGENT_PATH"
echo "  systemd unit:   $SERVICE_PATH"
echo "  polling every:  ${SLEEP_INTERVAL}s"
echo
echo "Useful commands:"
echo "  systemctl status iptables-agent"
echo "  journalctl -u iptables-agent -f"
echo "  bash $APPLY_PATH $RULES_URL --dry-run"
