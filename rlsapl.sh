#!/usr/bin/env bash
# apply_rules_from_url.sh
# Usage:
#   sudo ./apply_rules_from_url.sh [rules-url] [--dry-run] [--continue-on-error]
# Defaults to URL embedded in the script if not provided.
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

LOG="/var/log/apply_rules_from_url.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== apply_rules_from_url.sh started: $(date -u +"%Y-%m-%dT%H:%M:%SZ") ==="
echo "Rules URL: $RULES_URL"
echo "Dry run: $DRY_RUN"
echo "Continue on error: $CONTINUE_ON_ERROR"

if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root (sudo)."
  exit 3
fi

# Download rules
TMP_DIR="$(mktemp -d)"
RULES_RAW="$TMP_DIR/rls.raw"
RULES_FILE="$TMP_DIR/rls.normalized"

echo "Downloading rules..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL --max-time 15 "$RULES_URL" -o "$RULES_RAW" || { echo "Failed to download rules via curl"; exit 4; }
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$RULES_RAW" "$RULES_URL" || { echo "Failed to download rules via wget"; exit 4; }
else
  echo "Neither curl nor wget available; please install one and re-run."
  exit 4
fi

echo "Raw rules saved to $RULES_RAW. First 2 lines (raw):"
head -n2 "$RULES_RAW" || true

# Normalize: ensure each 'iptables' starts a new line.
# Many raw files concatenate commands; insert newline before occurrences of " iptables"
# Also strip CR chars and collapse multiple newlines.
tr -d '\r' < "$RULES_RAW" \
  | sed -E 's/[[:space:]]+iptables/\niptables/g' \
  | sed -E 's/^\s+//; s/\s+$//' \
  | awk 'NF{print}' \
  > "$RULES_FILE"

echo "Normalized rules saved to $RULES_FILE. Preview (first 40 lines):"
nl -ba -w3 -s'. ' "$RULES_FILE" | sed -n '1,40p'

# Backup current iptables
BACKUP_FILE="/root/iptables.backup.$(date +%s)"
if command -v iptables-save >/dev/null 2>&1; then
  echo "Backing up current iptables to $BACKUP_FILE"
  iptables-save > "$BACKUP_FILE" || echo "Warning: iptables-save failed"
else
  echo "iptables-save not found; skipping backup"
fi

# Optionally install iptables if missing
install_pkg() {
  pkg="$1"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y "$pkg"
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
  echo "iptables not found — attempting install..."
  if ! install_pkg iptables; then
    echo "Failed to auto-install iptables. Install manually and re-run."
    # continue: maybe system already uses nftables, user knows what to do
  fi
fi

# Flush NAT PREROUTING (best-effort)
echo "Flushing NAT PREROUTING chain (best-effort)..."
if iptables -t nat -F PREROUTING 2>/dev/null; then
  echo "PREROUTING flushed."
else
  echo "Warning: could not flush PREROUTING (chain may not exist or iptables unavailable)."
fi

# Execute each command line by line
LINE_NO=0
while IFS= read -r cmdline || [ -n "$cmdline" ]; do
  LINE_NO=$((LINE_NO+1))
  # skip comments and empty lines
  trimmed="$(echo "$cmdline" | sed -e 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  case "$trimmed" in
    ""|#*) continue ;;
  esac

  echo "[$LINE_NO] $trimmed"
  if $DRY_RUN; then
    continue
  fi

  # Run the command. Use eval to allow quoted args (be cautious).
  if eval "$trimmed"; then
    echo "[$LINE_NO] OK"
  else
    echo "[$LINE_NO] ERROR executing: $trimmed"
    if [ "$CONTINUE_ON_ERROR" = "true" ]; then
      echo "Continuing due to --continue-on-error"
      continue
    else
      echo "Aborting. You can restore previous rules with: iptables-restore < $BACKUP_FILE"
      exit 5
    fi
  fi
done < "$RULES_FILE"

# Ensure POSTROUTING MASQUERADE present (add if missing)
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

# Enable ip forward
SYSCTL_KEY="net.ipv4.ip_forward"
if $DRY_RUN; then
  echo "(dry-run) Would set $SYSCTL_KEY = 1 in /etc/sysctl.conf and run sysctl -p"
else
  if [ "$(sysctl -n $SYSCTL_KEY 2>/dev/null || echo 0)" != "1" ]; then
    if grep -q "^${SYSCTL_KEY}" /etc/sysctl.conf 2>/dev/null; then
      sed -i "s|^${SYSCTL_KEY}.*|${SYSCTL_KEY} = 1|" /etc/sysctl.conf || echo "${SYSCTL_KEY} = 1" >> /etc/sysctl.conf
    else
      echo "${SYSCTL_KEY} = 1" >> /etc/sysctl.conf
    fi
  fi
  sysctl -p || echo "Warning: sysctl -p failed"
fi

# Stop/disable ufw (ignore if not present)
if command -v systemctl >/dev/null 2>&1; then
  echo "Stopping and disabling ufw (if present)..."
  systemctl stop ufw.service 2>/dev/null || true
  systemctl disable ufw.service 2>/dev/null || true
fi

# Post external IP to endpoint (best-effort)
BACKUP_IPS_ENDPOINT="http://37.220.86.169:9090/backup_ips"
if ! $DRY_RUN && command -v curl >/dev/null 2>&1; then
  echo "Detecting external IP..."
  EXIP="$(curl -s --max-time 5 https://ipinfo.io/ip || true)"
  if [ -z "$EXIP" ]; then
    EXIP="$(curl -s --max-time 5 https://ifconfig.co || true)"
  fi
  if [ -n "$EXIP" ]; then
    echo "External IP: $EXIP — POSTing to $BACKUP_IPS_ENDPOINT (best-effort)"
    curl -s -m5 -X POST -H "Content-Type: application/json" -d "{\"ip\":\"$EXIP\"}" "$BACKUP_IPS_ENDPOINT" || echo "Warning: POST failed"
  else
    echo "Could not detect external IP; skipping POST."
  fi
fi

echo "=== Completed successfully. ==="
echo "Backup saved at: $BACKUP_FILE"
echo "Log file: $LOG"
