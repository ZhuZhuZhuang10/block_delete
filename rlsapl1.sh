#!/usr/bin/env bash
# installer.sh — ставит:
# 1) apply_rules_from_url.sh
# 2) verify_iptables_rules.sh
# 3) iptables-agent.service
# 4) speedtest web app на http://IP:7777
#
# Повторный запуск безопасен:
# - файлы перезаписываются
# - speedtest обновляется
# - если iptables-agent уже активен, первичное применение правил пропускается

set -Eeuo pipefail

# -----------------------
# Конфигурация
# -----------------------
APPLY_PATH="/usr/local/bin/apply_rules_from_url.sh"
AGENT_PATH="/usr/local/bin/iptables-agent.sh"
VERIFY_PATH="/usr/local/bin/verify_iptables_rules.sh"
SPEEDTEST_APP_PATH="/usr/local/bin/iptables-speedtest.py"

AGENT_SERVICE_PATH="/etc/systemd/system/iptables-agent.service"
SPEEDTEST_SERVICE_PATH="/etc/systemd/system/iptables-speedtest.service"

RULES_URL="https://raw.githubusercontent.com/ZhuZhuZhuang10/block_delete/main/rls.txt"
SLEEP_INTERVAL=30
RECHECK_INTERVAL=300

BACKUP_DIR="/var/backups/iptables"
LOG_DIR="/var/log/iptables-agent"
LOCAL_RULES="/etc/iptables-rls.txt"
LOCAL_HASH_FILE="/etc/iptables-rls.hash"

# -----------------------
# Цвета
# -----------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "${BLUE}[STEP]${NC}  $*"; }

# -----------------------
# Проверка root
# -----------------------
if [ "$(id -u)" -ne 0 ]; then
  log_error "Запусти скрипт от root (sudo)."
  exit 1
fi

# -----------------------
# Директории
# -----------------------
mkdir -p "$BACKUP_DIR" "$LOG_DIR"
chmod 700 "$BACKUP_DIR" || true
chmod 755 "$LOG_DIR" || true

# -----------------------
# Установка пакетов
# -----------------------
install_pkg() {
  local pkg="$1"
  log_info "Устанавливаю пакет: $pkg"

  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q "$pkg"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q "$pkg"
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache "$pkg"
  else
    log_error "Не найден пакетный менеджер."
    return 1
  fi
}

log_step "Проверка зависимостей..."
for p in curl wget iptables python3; do
  if ! command -v "$p" >/dev/null 2>&1; then
    install_pkg "$p" || log_warn "Не удалось установить $p"
  else
    log_info "$p уже установлен: $(command -v "$p")"
  fi
done

if command -v modprobe >/dev/null 2>&1; then
  log_step "Проверка модулей ядра..."
  for mod in ip_tables iptable_filter iptable_nat nf_conntrack; do
    if lsmod 2>/dev/null | grep -q "^${mod}\b"; then
      log_info "Модуль активен: $mod"
    else
      modprobe "$mod" >/dev/null 2>&1 && log_info "Загружен: $mod" || log_warn "Не удалось загрузить: $mod"
    fi
  done
fi

# -----------------------
# verify_iptables_rules.sh
# -----------------------
log_step "Записываю verify_iptables_rules.sh..."
cat > "$VERIFY_PATH" <<'VERIFY_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

RULES_FILE="${1:-}"
VERBOSE=false
shift || true
for arg in "${@:-}"; do
  [ "$arg" = "--verbose" ] && VERBOSE=true
done

if [ -z "$RULES_FILE" ] || [ ! -f "$RULES_FILE" ]; then
  echo "Usage: $0 <rules_file> [--verbose]"
  exit 2
fi

PASS=0
MISS=0
SKIP=0
FAIL_LINES=()

trim() {
  local s="$1"
  s="${s#${s%%[![:space:]]*}}"
  s="${s%${s##*[![:space:]]}}"
  printf '%s' "$s"
}

while IFS= read -r rawline || [ -n "$rawline" ]; do
  line="$(printf '%s' "$rawline" | sed -E 's/#.*$//')"
  line="$(trim "$line")"
  [ -z "$line" ] && continue

  case "$line" in
    iptables*|ip6tables*)
      ;;
    *)
      SKIP=$((SKIP+1))
      $VERBOSE && echo "[SKIP] $line"
      continue
      ;;
  esac

  check_line="$line"
  check_line="$(printf '%s' "$check_line" | sed -E 's/^iptables( -t [[:alnum:]_]+)? -[AI] /iptables\1 -C /')"
  check_line="$(printf '%s' "$check_line" | sed -E 's/^ip6tables( -t [[:alnum:]_]+)? -[AI] /ip6tables\1 -C /')"

  if bash -lc "$check_line" >/dev/null 2>&1; then
    PASS=$((PASS+1))
    $VERBOSE && echo "[OK]   $line"
  else
    MISS=$((MISS+1))
    FAIL_LINES+=("$line")
    $VERBOSE && echo "[MISS] $line"
  fi
done < "$RULES_FILE"

echo "Верификация: OK=$PASS  MISS=$MISS  SKIP=$SKIP"

if [ "$MISS" -gt 0 ]; then
  echo "Не найдены правила:"
  for fl in "${FAIL_LINES[@]}"; do
    echo "  - $fl"
  done
  exit 1
fi

exit 0
VERIFY_EOF
chmod 755 "$VERIFY_PATH"
log_info "Записан: $VERIFY_PATH"

# -----------------------
# apply_rules_from_url.sh
# -----------------------
log_step "Записываю apply_rules_from_url.sh..."
cat > "$APPLY_PATH" <<APPLY_EOF
#!/usr/bin/env bash
set -Eeuo pipefail

DEFAULT_RULES_URL="${RULES_URL}"
RULES_SOURCE="\${1:-\$DEFAULT_RULES_URL}"

DRY_RUN=false
CONTINUE_ON_ERROR=false
SKIP_VERIFY=false

for arg in "\${@:2}"; do
  case "\$arg" in
    --dry-run) DRY_RUN=true ;;
    --continue-on-error) CONTINUE_ON_ERROR=true ;;
    --skip-verify) SKIP_VERIFY=true ;;
    *)
      echo "Unknown option: \$arg"
      exit 2
      ;;
  esac
done

LOG="${LOG_DIR}/apply_rules.log"
BACKUP_DIR="${BACKUP_DIR}"
VERIFY_SCRIPT="${VERIFY_PATH}"
LOCAL_RULES="${LOCAL_RULES}"

exec > >(tee -a "\$LOG") 2>&1

trim() {
  local s="\$1"
  s="\${s#\${s%%[![:space:]]*}}"
  s="\${s%\${s##*[![:space:]]}}"
  printf '%s' "\$s"
}

ensure_7777_open() {
  iptables -C INPUT -p tcp --dport 7777 -j ACCEPT >/dev/null 2>&1 || \
    iptables -I INPUT 1 -p tcp --dport 7777 -j ACCEPT >/dev/null 2>&1 || true
}

fetch_rules() {
  local src="\$1"
  local out="\$2"

  if [ -f "\$src" ]; then
    cp "\$src" "\$out"
    return 0
  fi

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 20 --retry 3 --retry-delay 2 "\$src" -o "\$out" && return 0
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO "\$out" "\$src" && return 0
  fi

  return 1
}

if [ "\$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root"
  exit 3
fi

TMP_DIR="\$(mktemp -d)"
trap 'rm -rf "\$TMP_DIR"' EXIT

RAW="\$TMP_DIR/rules.raw"
NORM="\$TMP_DIR/rules.norm"
BACKUP_FILE="${BACKUP_DIR}/iptables.backup.\$(date +%s)"

mkdir -p "$BACKUP_DIR" >/dev/null 2>&1 || true
mkdir -p /etc/iptables >/dev/null 2>&1 || true

echo "=========================================================="
echo "=== apply_rules_from_url started: \$(date -u +"%Y-%m-%dT%H:%M:%SZ") ==="
echo "=== source: \$RULES_SOURCE ==="
echo "=== dry-run=\$DRY_RUN continue-on-error=\$CONTINUE_ON_ERROR skip-verify=\$SKIP_VERIFY ==="
echo "=========================================================="

echo "[FETCH] \$RULES_SOURCE"
if ! fetch_rules "\$RULES_SOURCE" "\$RAW"; then
  echo "[FETCH] ERROR: cannot download rules"
  exit 4
fi

if [ ! -s "\$RAW" ]; then
  echo "[FETCH] ERROR: rules file is empty"
  exit 4
fi

tr -d '\r' < "\$RAW" | sed -E 's/#.*\$//' | while IFS= read -r line; do
  line="\$(trim "\$line")"
  [ -n "\$line" ] && printf '%s\n' "\$line"
done > "\$NORM"

LINE_COUNT="\$(wc -l < "\$NORM" | tr -d ' ')"
echo "[NORM] lines=\$LINE_COUNT"

echo "[BACKUP] saving current iptables..."
if command -v iptables-save >/dev/null 2>&1; then
  iptables-save > "\$BACKUP_FILE" || true
  chmod 600 "\$BACKUP_FILE" 2>/dev/null || true
  echo "[BACKUP] file=\$BACKUP_FILE"
fi

echo "[SAFETY] opening local management + speedtest port"
ensure_7777_open
iptables -C INPUT -p tcp --dport 22 -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT >/dev/null 2>&1 || true
iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || true

echo "[APPLY] applying rules..."
LINE_NO=0
APPLY_FAIL=0
APPLIED=0
SKIPPED=0

while IFS= read -r line || [ -n "\$line" ]; do
  LINE_NO=\$((LINE_NO+1))
  line="\$(trim "\$line")"
  [ -z "\$line" ] && continue

  case "\$line" in
    iptables*|ip6tables*)
      ;;
    *)
      SKIPPED=\$((SKIPPED+1))
      echo "[SKIP L\$LINE_NO] \$line"
      continue
      ;;
  esac

  if \$DRY_RUN; then
    echo "[DRY  L\$LINE_NO] \$line"
    APPLIED=\$((APPLIED+1))
    continue
  fi

  if bash -lc "\$line"; then
    echo "[OK   L\$LINE_NO] \$line"
    APPLIED=\$((APPLIED+1))
  else
    rc=\$?
    echo "[ERR  L\$LINE_NO] exit=\$rc cmd=\$line"
    APPLY_FAIL=1
    if \$CONTINUE_ON_ERROR; then
      echo "[ERR  L\$LINE_NO] continue-on-error enabled"
      continue
    else
      break
    fi
  fi
done < "\$NORM"

echo "[APPLY] applied=\$APPLIED skipped=\$SKIPPED fail=\$APPLY_FAIL"

echo "[SAFETY] ensuring speedtest port is open after apply"
if ! \$DRY_RUN; then
  ensure_7777_open
fi

if [ "\$APPLY_FAIL" -eq 1 ]; then
  echo "[ROLLBACK] restoring backup..."
  if [ -f "\$BACKUP_FILE" ] && command -v iptables-restore >/dev/null 2>&1; then
    iptables-restore < "\$BACKUP_FILE" && echo "[ROLLBACK] OK" || echo "[ROLLBACK] FAILED"
  else
    echo "[ROLLBACK] backup not available"
  fi
  exit 5
fi

if ! \$DRY_RUN; then
  echo "[POST] enabling ip_forward"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  cat > /etc/sysctl.d/99-iptables-agent.conf <<'SYSCTL_EOF'
net.ipv4.ip_forward = 1
net.netfilter.nf_conntrack_max = 1048576
SYSCTL_EOF
  sysctl --system >/dev/null 2>&1 || true
fi

if ! \$DRY_RUN && ! \$SKIP_VERIFY; then
  echo "[VERIFY] checking rules..."
  if [ -x "\$VERIFY_SCRIPT" ]; then
    if "\$VERIFY_SCRIPT" "\$NORM" --verbose; then
      echo "[VERIFY] OK"
    else
      echo "[VERIFY] WARN: some rules not matched"
      iptables -L -n -v --line-numbers 2>/dev/null | head -80 || true
      iptables -t nat -L -n -v --line-numbers 2>/dev/null | head -50 || true
    fi
  else
    echo "[VERIFY] WARN: verifier not found: \$VERIFY_SCRIPT"
  fi
fi

if ! \$DRY_RUN; then
  echo "[CHECK] network sanity"
  if ping -c1 -W3 8.8.8.8 >/dev/null 2>&1; then
    echo "[CHECK] ping 8.8.8.8 OK"
  else
    echo "[CHECK] ping 8.8.8.8 FAIL"
  fi
fi

if ! \$DRY_RUN; then
  echo "[PERSIST] saving firewall state"
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  fi
  if command -v iptables-save >/dev/null 2>&1; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
  fi
fi

echo "=========================================================="
echo "=== finished: \$(date -u +"%Y-%m-%dT%H:%M:%SZ") ==="
echo "=== backup: \$BACKUP_FILE ==="
echo "=== log: \$LOG ==="
echo "=========================================================="
APPLY_EOF

chmod 755 "$APPLY_PATH"
log_info "Записан: $APPLY_PATH"

# -----------------------
# iptables-agent.sh
# -----------------------
log_step "Записываю iptables-agent.sh..."
cat > "$AGENT_PATH" <<AGENT_EOF
#!/usr/bin/env bash
set -Eeuo pipefail

RULES_URL="${RULES_URL}"
LOCAL_RULES="${LOCAL_RULES}"
LOCAL_HASH_FILE="${LOCAL_HASH_FILE}"
APPLY_SCRIPT="${APPLY_PATH}"
VERIFY_SCRIPT="${VERIFY_PATH}"
SLEEP_INTERVAL=${SLEEP_INTERVAL}
RECHECK_INTERVAL=${RECHECK_INTERVAL}
LOG="${LOG_DIR}/agent.log"

exec > >(tee -a "\$LOG") 2>&1

echo "[agent] started: \$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

LAST_RECHECK=0

while true; do
  NOW=\$(date +%s)
  TMP_FILE="\$(mktemp /tmp/iptables-agent.XXXXXX)"

  FETCH_OK=0
  if command -v curl >/dev/null 2>&1 && curl -fsSL --max-time 20 --retry 3 --retry-delay 2 "\$RULES_URL" -o "\$TMP_FILE"; then
    FETCH_OK=1
  elif command -v wget >/dev/null 2>&1 && wget -qO "\$TMP_FILE" "\$RULES_URL"; then
    FETCH_OK=1
  fi

  if [ "\$FETCH_OK" -ne 1 ]; then
    echo "[agent] WARN: cannot download rules: \$(date -u)"
    rm -f "\$TMP_FILE"
    sleep "\$SLEEP_INTERVAL"
    continue
  fi

  if [ ! -s "\$TMP_FILE" ]; then
    echo "[agent] WARN: empty rules file: \$(date -u)"
    rm -f "\$TMP_FILE"
    sleep "\$SLEEP_INTERVAL"
    continue
  fi

  NEW_HASH=\$(sha256sum "\$TMP_FILE" | awk '{print \$1}')
  OLD_HASH=\$(cat "\$LOCAL_HASH_FILE" 2>/dev/null || true)

  NEED_APPLY=0

  if [ "\$NEW_HASH" != "\$OLD_HASH" ]; then
    echo "[agent] detected new rules: \$(date -u)"
    NEED_APPLY=1
  fi

  if [ \$((NOW - LAST_RECHECK)) -ge "\$RECHECK_INTERVAL" ] && [ -f "\$LOCAL_RULES" ]; then
    if [ -x "\$VERIFY_SCRIPT" ] && ! "\$VERIFY_SCRIPT" "\$LOCAL_RULES" >/dev/null 2>&1; then
      echo "[agent] WARN: rules disappeared from iptables, reapplying: \$(date -u)"
      NEED_APPLY=1
    fi
    LAST_RECHECK="\$NOW"
  fi

  if [ "\$NEED_APPLY" -eq 1 ]; then
    cp "\$TMP_FILE" "\$LOCAL_RULES"
    if bash "\$APPLY_SCRIPT" "\$LOCAL_RULES" --continue-on-error; then
      echo "\$NEW_HASH" > "\$LOCAL_HASH_FILE"
      echo "[agent] applied successfully: \$(date -u)"
    else
      echo "[agent] WARN: apply script failed: \$(date -u)"
    fi
  fi

  rm -f "\$TMP_FILE"
  sleep "\$SLEEP_INTERVAL"
done
AGENT_EOF

chmod 755 "$AGENT_PATH"
log_info "Записан: $AGENT_PATH"

# -----------------------
# Speedtest app
# -----------------------
log_step "Записываю speedtest web app..."
cat > "$SPEEDTEST_APP_PATH" <<'PY_EOF'
#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "0.0.0.0"
PORT = 7777
CHUNK_SIZE = 64 * 1024
DEFAULT_DOWNLOAD_MB = 50
DEFAULT_UPLOAD_MB = 25
MAX_TEST_MB = 200

HTML_PAGE = """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Speedtest</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0b1020;
      --card: #121a2f;
      --card2: #17213a;
      --text: #ecf2ff;
      --muted: #9fb0d0;
      --accent: #74c0fc;
      --ok: #6ee7b7;
      --warn: #fbbf24;
      --err: #fb7185;
      --border: rgba(255,255,255,.08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background: radial-gradient(circle at top, #15213f 0, var(--bg) 50%);
      color: var(--text);
    }
    .wrap { max-width: 960px; margin: 0 auto; padding: 24px; }
    .hero {
      background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));
      border: 1px solid var(--border);
      border-radius: 24px;
      padding: 24px;
      box-shadow: 0 18px 45px rgba(0,0,0,.28);
    }
    h1 { margin: 0 0 10px; font-size: 32px; }
    p { color: var(--muted); line-height: 1.6; }
    .grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 16px;
      margin-top: 18px;
    }
    .card {
      background: rgba(255,255,255,.04);
      border: 1px solid var(--border);
      border-radius: 22px;
      padding: 18px;
      min-height: 130px;
    }
    .label { color: var(--muted); font-size: 13px; letter-spacing: .04em; text-transform: uppercase; }
    .value { font-size: 30px; font-weight: 700; margin-top: 10px; }
    .sub { color: var(--muted); margin-top: 8px; font-size: 14px; }
    .controls {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 18px;
      align-items: center;
    }
    button {
      border: 0;
      border-radius: 16px;
      padding: 13px 18px;
      background: linear-gradient(180deg, #8bd5ff, #5ea9f0);
      color: #04111f;
      font-weight: 700;
      font-size: 15px;
      cursor: pointer;
      box-shadow: 0 10px 25px rgba(94,169,240,.25);
    }
    button:disabled { opacity: .55; cursor: not-allowed; }
    input {
      width: 110px;
      background: rgba(255,255,255,.05);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 12px 14px;
      color: var(--text);
      outline: none;
    }
    .status {
      margin-top: 18px;
      background: rgba(255,255,255,.04);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 14px 16px;
      color: var(--muted);
      white-space: pre-wrap;
      min-height: 88px;
    }
    .footer { margin-top: 16px; color: var(--muted); font-size: 13px; }
    .good { color: var(--ok); }
    .bad { color: var(--err); }
    @media (max-width: 860px) {
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <h1>Speedtest</h1>
      <p>Проверка связи клиента с сервером: ping, download и upload. Тест работает прямо из браузера на <b>http://IP:7777</b>.</p>

      <div class="controls">
        <button id="run">Запустить тест</button>
        <label>Download MB <input id="downSize" type="number" min="1" max="200" value="50"></label>
        <label>Upload MB <input id="upSize" type="number" min="1" max="200" value="25"></label>
      </div>

      <div class="grid">
        <div class="card">
          <div class="label">Ping</div>
          <div class="value" id="ping">—</div>
          <div class="sub">RTT через fetch</div>
        </div>
        <div class="card">
          <div class="label">Download</div>
          <div class="value" id="download">—</div>
          <div class="sub">Скорость загрузки данных с сервера</div>
        </div>
        <div class="card">
          <div class="label">Upload</div>
          <div class="value" id="upload">—</div>
          <div class="sub">Скорость отправки данных на сервер</div>
        </div>
      </div>

      <div class="status" id="status">Готов к тесту.</div>
      <div class="footer">API: /api/ping, /api/download?size=50, /api/upload</div>
    </div>
  </div>

<script>
const $ = (id) => document.getElementById(id);

function mbps(bytes, seconds) {
  return (bytes * 8 / seconds / 1e6);
}

function fmt(n) {
  if (!isFinite(n)) return "—";
  return n.toFixed(2) + " Mbps";
}

async function pingOnce() {
  const t0 = performance.now();
  const r = await fetch('/api/ping?ts=' + Date.now(), { cache: 'no-store' });
  await r.json();
  const t1 = performance.now();
  return t1 - t0;
}

async function downloadTest(sizeMB) {
  const t0 = performance.now();
  const r = await fetch('/api/download?size=' + encodeURIComponent(sizeMB) + '&ts=' + Date.now(), { cache: 'no-store' });
  const reader = r.body.getReader();
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
  }
  const t1 = performance.now();
  const sec = (t1 - t0) / 1000;
  return { mbps: mbps(received, sec), seconds: sec, bytes: received };
}

async function uploadTest(sizeMB) {
  const bytes = Math.max(1, sizeMB) * 1024 * 1024;
  const payload = new Uint8Array(bytes);
  for (let i = 0; i < payload.length; i += 4096) payload[i] = i & 255;

  const blob = new Blob([payload], { type: 'application/octet-stream' });
  const t0 = performance.now();
  const r = await fetch('/api/upload?ts=' + Date.now(), {
    method: 'POST',
    body: blob,
    cache: 'no-store',
  });
  await r.json();
  const t1 = performance.now();
  const sec = (t1 - t0) / 1000;
  return { mbps: mbps(bytes, sec), seconds: sec, bytes };
}

$('run').addEventListener('click', async () => {
  const btn = $('run');
  btn.disabled = true;
  $('status').textContent = 'Тест запускается...';
  $('ping').textContent = '—';
  $('download').textContent = '—';
  $('upload').textContent = '—';

  try {
    const dMB = Math.min(200, Math.max(1, parseInt($('downSize').value || '50', 10)));
    const uMB = Math.min(200, Math.max(1, parseInt($('upSize').value || '25', 10)));

    $('status').textContent = 'Пинг...';
    const ping = await pingOnce();
    $('ping').textContent = ping.toFixed(2) + ' ms';

    $('status').textContent = 'Download...';
    const down = await downloadTest(dMB);
    $('download').textContent = fmt(down.mbps);

    $('status').textContent = 'Upload...';
    const up = await uploadTest(uMB);
    $('upload').textContent = fmt(up.mbps);

    $('status').innerHTML =
      'Готово.\\n' +
      'Ping: ' + ping.toFixed(2) + ' ms\\n' +
      'Download: ' + down.mbps.toFixed(2) + ' Mbps\\n' +
      'Upload: ' + up.mbps.toFixed(2) + ' Mbps';
  } catch (e) {
    console.error(e);
    $('status').innerHTML = '<span class="bad">Ошибка:</span> ' + (e && e.message ? e.message : e);
  } finally {
    btn.disabled = false;
  }
});
</script>
</body>
</html>
"""

def clamp_mb(value: int, default: int) -> int:
    try:
      v = int(value)
    except Exception:
      v = default
    return max(1, min(MAX_TEST_MB, v))

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def _json(self, code: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _html(self):
        body = HTML_PAGE.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/":
            return self._html()

        if path == "/api/ping":
            return self._json(200, {
                "ok": True,
                "server_time": time.time(),
            })

        if path == "/api/download":
            mb = clamp_mb(qs.get("size", [DEFAULT_DOWNLOAD_MB])[0], DEFAULT_DOWNLOAD_MB)
            total = mb * 1024 * 1024
            chunk = b"0" * CHUNK_SIZE

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(total))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

            remaining = total
            while remaining > 0:
                n = min(remaining, CHUNK_SIZE)
                self.wfile.write(chunk[:n])
                remaining -= n
            return

        self.send_response(HTTPStatus.NOT_FOUND)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"Not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path != "/api/upload":
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not found")
            return

        length = self.headers.get("Content-Length")
        if length is None:
            # fallback: read until EOF, but browser upload with Blob usually sends Content-Length
            body = self.rfile.read()
            received = len(body)
        else:
            try:
                remaining = int(length)
            except Exception:
                remaining = 0
            received = 0
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, CHUNK_SIZE))
                if not chunk:
                    break
                received += len(chunk)
                remaining -= len(chunk)

        return self._json(200, {
            "ok": True,
            "received_bytes": received,
        })

def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"speedtest listening on http://{HOST}:{PORT}", flush=True)
    server.serve_forever()

if __name__ == "__main__":
    main()
PY_EOF
chmod 755 "$SPEEDTEST_APP_PATH"
log_info "Записан: $SPEEDTEST_APP_PATH"

# -----------------------
# systemd unit для speedtest
# -----------------------
log_step "Записываю systemd unit для speedtest..."
cat > "$SPEEDTEST_SERVICE_PATH" <<UNIT_EOF
[Unit]
Description=iptables speedtest web app
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/python3 ${SPEEDTEST_APP_PATH}
Restart=always
RestartSec=3
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
UNIT_EOF
log_info "Записан: $SPEEDTEST_SERVICE_PATH"

# -----------------------
# Идемпотентное открытие порта 7777
# -----------------------
log_step "Открываю порт 7777 в iptables, если он ещё не открыт..."
iptables -C INPUT -p tcp --dport 7777 -j ACCEPT >/dev/null 2>&1 || \
  iptables -I INPUT 1 -p tcp --dport 7777 -j ACCEPT >/dev/null 2>&1 || true

# -----------------------
# Сервис iptables-agent
# -----------------------
log_step "Настраиваю iptables-agent.service..."
cat > "$AGENT_SERVICE_PATH" <<UNIT_EOF
[Unit]
Description=Auto-updater for iptables rules
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${AGENT_PATH}
Restart=always
RestartSec=15
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
UNIT_EOF
log_info "Записан: $AGENT_SERVICE_PATH"

# -----------------------
# systemd reload
# -----------------------
log_step "Перечитываю systemd..."
systemctl daemon-reload

# -----------------------
# Enable/start services
# -----------------------
log_step "Включаю и запускаю speedtest..."
systemctl enable --now iptables-speedtest.service

log_step "Включаю и запускаю iptables-agent..."
systemctl enable --now iptables-agent.service

# -----------------------
# Первичное применение правил
# -----------------------
log_step "Проверяю, нужен ли первичный запуск apply_rules..."
if systemctl is-active --quiet iptables-agent.service; then
  log_info "iptables-agent уже активен — первичное применение пропущено"
else
  log_step "Первичное применение правил..."
  if bash "$APPLY_PATH" "$RULES_URL" --continue-on-error; then
    log_info "Первичное применение правил успешно"
  else
    log_warn "Первичное применение завершилось с ошибками"
  fi
fi

# -----------------------
# Проверка статуса
# -----------------------
sleep 2
if systemctl is-active --quiet iptables-speedtest.service; then
  log_info "speedtest.service активен"
else
  log_warn "speedtest.service не запустился, смотри: journalctl -u iptables-speedtest.service -n 50"
fi

if systemctl is-active --quiet iptables-agent.service; then
  log_info "iptables-agent.service активен"
else
  log_warn "iptables-agent.service не запустился, смотри: journalctl -u iptables-agent.service -n 50"
fi

# -----------------------
# Итог
# -----------------------
echo ""
echo "============================================================"
log_info "Установка завершена"
echo "============================================================"
echo ""
echo "Файлы:"
echo "  apply:    $APPLY_PATH"
echo "  verify:   $VERIFY_PATH"
echo "  agent:    $AGENT_PATH"
echo "  speedtest:$SPEEDTEST_APP_PATH"
echo ""
echo "Сервисы:"
echo "  iptables-agent.service"
echo "  iptables-speedtest.service"
echo ""
echo "Проверка speedtest:"
echo "  http://<IP_СЕРВЕРА>:7777"
echo ""
echo "Логи:"
echo "  $LOG_DIR/apply_rules.log"
echo "  $LOG_DIR/agent.log"
echo ""
echo "Команды:"
echo "  systemctl status iptables-agent.service"
echo "  systemctl status iptables-speedtest.service"
echo "  journalctl -u iptables-speedtest.service -f"
echo "============================================================"
