#!/usr/bin/env bash
# installer.sh v3 — агент синхронизации iptables-правил с GitHub
#
# Что изменилось по сравнению с v2 и почему:
#  * Правила живут в СВОИХ цепочках (RLS_PREROUTING, RLS_FORWARD, ...).
#    При каждом применении цепочка очищается и заполняется заново атомарно
#    (iptables-restore --noflush). Старая версия только дописывала -A в конец,
#    и старое правило для того же порта оставалось выше нового — срабатывало оно.
#  * После изменения DNAT-правил сбрасываются conntrack-записи для затронутых
#    портов: иначе уже установленные потоки (особенно UDP) продолжают идти
#    на старый адрес, даже когда правило уже новое.
#  * Обход кэша raw.githubusercontent.com (до ~5 минут задержки).
#  * Нет eval удалённого содержимого от root: строки разбираются и проверяются
#    по белому списку символов, допускаются только `iptables [-t nat|filter] -A ...`.
#  * Ошибка в файле = файл целиком отклоняется, текущие правила не трогаются.
#  * Убран verify-скрипт, который при проверке выполнял строки (-F и т.п.).
#  * systemd timer вместо бесконечного цикла, flock против параллельных запусков,
#    ротация логов.
set -o errexit -o nounset -o pipefail

# -----------------------
# Настройки
# -----------------------
RULES_URL="https://raw.githubusercontent.com/ZhuZhuZhuang10/block_delete/main/rls.txt"
CHECK_EVERY_SEC=60          # как часто проверять репозиторий
CHAIN_PREFIX="RLS_"
APPLY_PATH="/usr/local/bin/apply_rules_from_url.sh"
CONF_PATH="/etc/iptables-agent.conf"
SERVICE_PATH="/etc/systemd/system/iptables-agent.service"
TIMER_PATH="/etc/systemd/system/iptables-agent.timer"
BACKUP_DIR="/var/backups/iptables"
LOG_DIR="/var/log/iptables-agent"
STATE_DIR="/var/lib/iptables-agent"
# Удалить DNAT-правила, которые старая версия насыпала прямо в nat PREROUTING
# (с дублями и устаревшими адресами). Перед удалением делается бэкап.
MIGRATE_OLD_RULES=1

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "${BLUE}[STEP]${NC}  $*"; }

if [ "$(id -u)" -ne 0 ]; then
  log_error "Запустите от root (sudo)."
  exit 1
fi

mkdir -p "$BACKUP_DIR" "$LOG_DIR" "$STATE_DIR"
chmod 700 "$BACKUP_DIR" "$STATE_DIR"

# -----------------------
# Зависимости
# -----------------------
install_pkg() {
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q "$@"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q "$@"
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache -q "$@"
  else
    return 1
  fi
}

log_step "Проверка зависимостей..."
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -q >/dev/null 2>&1 || true
fi
command -v curl     >/dev/null 2>&1 || install_pkg curl     || log_warn "Не удалось установить curl"
command -v iptables >/dev/null 2>&1 || install_pkg iptables || log_warn "Не удалось установить iptables"
command -v flock    >/dev/null 2>&1 || install_pkg util-linux || true
if ! command -v conntrack >/dev/null 2>&1; then
  install_pkg conntrack 2>/dev/null || install_pkg conntrack-tools 2>/dev/null || \
    log_warn "conntrack не установлен — старые потоки после смены правил не будут сбрасываться"
fi
if command -v apt-get >/dev/null 2>&1 && ! command -v netfilter-persistent >/dev/null 2>&1; then
  echo "iptables-persistent iptables-persistent/autosave_v4 boolean false" | debconf-set-selections 2>/dev/null || true
  echo "iptables-persistent iptables-persistent/autosave_v6 boolean false" | debconf-set-selections 2>/dev/null || true
  install_pkg iptables-persistent 2>/dev/null || log_warn "iptables-persistent недоступен"
fi
for m in ip_tables iptable_filter iptable_nat nf_conntrack; do modprobe "$m" 2>/dev/null || true; done

# -----------------------
# Останавливаем старую версию
# -----------------------
log_step "Останавливаю старый агент (если есть)..."
systemctl disable --now iptables-agent.timer   >/dev/null 2>&1 || true
systemctl disable --now iptables-agent.service >/dev/null 2>&1 || true
pkill -f /usr/local/bin/iptables-agent.sh 2>/dev/null || true
rm -f /usr/local/bin/iptables-agent.sh /usr/local/bin/verify_iptables_rules.sh \
      /etc/iptables-rls.txt /etc/iptables-rls.hash /tmp/iptables-new.txt

# -----------------------
# Конфиг
# -----------------------
cat > "$CONF_PATH" <<CONF_EOF
# Конфиг iptables-agent (читается apply_rules_from_url.sh)
RULES_URL="${RULES_URL}"
CHAIN_PREFIX="${CHAIN_PREFIX}"
BACKUP_DIR="${BACKUP_DIR}"
LOG_DIR="${LOG_DIR}"
STATE_DIR="${STATE_DIR}"
KEEP_BACKUPS=20
CONF_EOF
chmod 644 "$CONF_PATH"
log_info "Записан: $CONF_PATH"

# -----------------------
# Основной скрипт
# -----------------------
log_step "Записываю $APPLY_PATH ..."
cat > "$APPLY_PATH" <<'APPLY_EOF'
#!/usr/bin/env bash
# apply_rules_from_url.sh v3
#
#   apply_rules_from_url.sh [URL|файл] [--dry-run]   применить правила
#   apply_rules_from_url.sh --auto                   (для таймера) применить, только если
#                                                    правила в репозитории изменились
#                                                    или в iptables что-то пропало
#   apply_rules_from_url.sh --check                  0 = в iptables стоит то, что применяли
#   apply_rules_from_url.sh --status                 показать текущее состояние
set -o nounset -o pipefail

CONF=/etc/iptables-agent.conf
# shellcheck disable=SC1090
[ -r "$CONF" ] && . "$CONF"
RULES_URL="${RULES_URL:?RULES_URL не задан в $CONF}"
CHAIN_PREFIX="${CHAIN_PREFIX:-RLS_}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/iptables}"
LOG_DIR="${LOG_DIR:-/var/log/iptables-agent}"
STATE_DIR="${STATE_DIR:-/var/lib/iptables-agent}"
KEEP_BACKUPS="${KEEP_BACKUPS:-20}"
LOG="$LOG_DIR/apply_rules.log"
LOCK=/run/iptables-agent.lock

# Какие таблицы/цепочки разрешено трогать из файла правил
declare -A MANAGED=( [nat]="PREROUTING POSTROUTING OUTPUT" [filter]="INPUT FORWARD OUTPUT" )
TABLES=(nat filter)

IPT=(iptables -w 10)
IPT_RESTORE=(iptables-restore)
iptables-restore --help 2>&1 | grep -q -- '--wait' && IPT_RESTORE=(iptables-restore -w 10)

SRC="$RULES_URL"; MODE=apply; DRY_RUN=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --auto)    MODE=auto ;;
    --check)   MODE=check ;;
    --status)  MODE=status ;;
    -*)        echo "Неизвестный параметр: $arg" >&2; exit 2 ;;
    *)         SRC="$arg" ;;
  esac
done

mkdir -p "$LOG_DIR" "$STATE_DIR" "$BACKUP_DIR"
log() { local m; m="$(date -u +%FT%TZ) $*"; echo "$m"; echo "$m" >> "$LOG"; }

if [ "$(id -u)" -ne 0 ]; then echo "Нужен root" >&2; exit 3; fi

# ---------- проверка: совпадает ли iptables с последним применённым набором ----------
check_state() {
  local state="$STATE_DIR/applied.rules" t c expected actual
  [ -f "$state" ] || return 1
  for t in "${TABLES[@]}"; do
    for c in ${MANAGED[$t]}; do
      "${IPT[@]}" -t "$t" -C "$c" -j "${CHAIN_PREFIX}$c" >/dev/null 2>&1 || return 1
      expected=$(awk -v t="$t" -v c="$c" '$1==t && $2==c' "$state" | wc -l)
      actual=$("${IPT[@]}" -t "$t" -S "${CHAIN_PREFIX}$c" 2>/dev/null | grep -c '^-A ') || true
      [ "$expected" -eq "$actual" ] || return 1
    done
  done
  return 0
}

if [ "$MODE" = check ]; then check_state; exit $?; fi
if [ "$MODE" = status ]; then
  echo "Применённый хэш: $(cat "$STATE_DIR/applied.hash" 2>/dev/null || echo нет)"
  echo "Применено:       $(stat -c %y "$STATE_DIR/applied.hash" 2>/dev/null || echo никогда)"
  if check_state; then echo "Состояние:       OK (iptables совпадает с применённым)"
  else echo "Состояние:       РАСХОЖДЕНИЕ"; fi
  for t in "${TABLES[@]}"; do for c in ${MANAGED[$t]}; do
    n=$("${IPT[@]}" -t "$t" -S "${CHAIN_PREFIX}$c" 2>/dev/null | grep -c '^-A ') || true
    [ "${n:-0}" -gt 0 ] && echo "  $t/${CHAIN_PREFIX}$c: $n правил"
  done; done
  exit 0
fi

# ---------- блокировка от параллельных запусков ----------
exec 9>"$LOCK"
if ! flock -w 120 9; then log "ERROR: не дождался блокировки $LOCK"; exit 7; fi

TMP_DIR="$(mktemp -d)"; trap 'rm -rf "$TMP_DIR"' EXIT
RAW="$TMP_DIR/raw"; PARSED="$TMP_DIR/parsed"; RESTORE="$TMP_DIR/restore"

# ---------- 1. загрузка ----------
fetch() {
  local src="$1" out="$2" sep='?'
  if [ -f "$src" ]; then cp "$src" "$out"; return; fi
  [[ "$src" == *\?* ]] && sep='&'
  # Параметр в URL обходит CDN-кэш raw.githubusercontent.com (иначе до ~5 мин старья)
  curl -fsSL --max-time 20 --retry 3 --retry-delay 2 \
       -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' \
       "${src}${sep}nocache=$(date +%s%N)" -o "$out"
}
if ! fetch "$SRC" "$RAW" || [ ! -s "$RAW" ]; then
  log "ERROR: не удалось загрузить правила из $SRC (или файл пуст) — ничего не меняю"
  exit 4
fi
NEW_HASH=$(sha256sum < "$RAW" | cut -d' ' -f1)
OLD_HASH=$(cat "$STATE_DIR/applied.hash" 2>/dev/null || true)
FAILED_HASH=$(cat "$STATE_DIR/failed.hash" 2>/dev/null || true)

# ---------- режим таймера: решаем, нужно ли что-то делать ----------
if [ "$MODE" = auto ]; then
  if [ "$NEW_HASH" != "$OLD_HASH" ] && [ "$NEW_HASH" != "$FAILED_HASH" ]; then
    log "В репозитории изменились правила (${OLD_HASH:0:12} -> ${NEW_HASH:0:12}), применяю"
  elif ! check_state; then
    if [ -f "$STATE_DIR/applied.raw" ]; then
      log "Правила в iptables не совпадают с применёнными (кто-то/что-то их сбросил) — восстанавливаю"
      cp "$STATE_DIR/applied.raw" "$RAW"; NEW_HASH="$OLD_HASH"
    elif [ "$NEW_HASH" = "$FAILED_HASH" ]; then
      exit 0   # применять нечего: рабочего набора ещё не было, новый уже признан ошибочным
    fi
  else
    exit 0     # всё актуально, молчим
  fi
fi

# ---------- 2. разбор и проверка ----------
tr -d '\r' < "$RAW" | sed -E 's/[[:space:]]+(iptables[[:space:]])/\n\1/g' > "$TMP_DIR/split"
: > "$PARSED"
BAD=0; N=0
RE_OK='^[A-Za-z0-9 ._:/,=!+-]+$'
RE_CMD='^iptables( -t ([a-z]+))? -A ([A-Z]+) (.+)$'
while IFS= read -r line || [ -n "$line" ]; do
  N=$((N+1))
  line="${line%%#*}"
  read -r -a parts <<< "$line" || true
  [ "${#parts[@]}" -eq 0 ] && continue
  line="${parts[*]}"
  if [[ ! "$line" =~ $RE_OK ]]; then
    log "  строка $N: недопустимые символы: $line"; BAD=$((BAD+1)); continue
  fi
  if [[ "$line" =~ $RE_CMD ]]; then
    t="${BASH_REMATCH[2]:-filter}"; c="${BASH_REMATCH[3]}"; rest="${BASH_REMATCH[4]}"
    if [ -z "${MANAGED[$t]:-}" ] || [[ " ${MANAGED[$t]} " != *" $c "* ]]; then
      log "  строка $N: таблица/цепочка $t/$c не поддерживается: $line"; BAD=$((BAD+1)); continue
    fi
    printf '%s %s %s\n' "$t" "$c" "$rest" >> "$PARSED"
  else
    log "  строка $N: поддерживается только 'iptables [-t nat|filter] -A ЦЕПОЧКА ...': $line"
    BAD=$((BAD+1))
  fi
done < "$TMP_DIR/split"

COUNT=$(wc -l < "$PARSED")
if [ "$BAD" -gt 0 ]; then
  log "ERROR: в файле $BAD ошибочных строк — файл отклонён, текущие правила НЕ тронуты"
  [ "$MODE" = auto ] && echo "$NEW_HASH" > "$STATE_DIR/failed.hash"
  exit 10
fi
if [ "$COUNT" -eq 0 ]; then
  log "ERROR: в файле нет ни одного правила — отказываюсь очищать всё (защита от пустого файла)"
  [ "$MODE" = auto ] && echo "$NEW_HASH" > "$STATE_DIR/failed.hash"
  exit 10
fi

# Предупреждение: один и тот же порт перенаправлен дважды — сработает только первое правило
awk '$1=="nat" && $2=="PREROUTING" {
       p=""; d="";
       for(i=3;i<=NF;i++){ if($i=="-p")p=$(i+1); if($i=="--dport")d=$(i+1) }
       if(p!="" && d!=""){ k=p"/"d; if(k in seen) print k; seen[k]=1 }
     }' "$PARSED" | sort -u | while read -r k; do
  log "  WARN: порт $k встречается в файле несколько раз — работать будет только первая строка"
done

# ---------- 3. собираем атомарный restore-файл ----------
{
  for t in "${TABLES[@]}"; do
    echo "*$t"
    for c in ${MANAGED[$t]}; do echo ":${CHAIN_PREFIX}$c - [0:0]"; done
    for c in ${MANAGED[$t]}; do echo "-F ${CHAIN_PREFIX}$c"; done
    awk -v t="$t" -v p="$CHAIN_PREFIX" '$1==t { c=$2; $1=""; $2=""; sub(/^ +/, ""); print "-A " p c " " $0 }' "$PARSED"
    echo "COMMIT"
  done
} > "$RESTORE"

if ! TEST_ERR=$("${IPT_RESTORE[@]}" --noflush --test < "$RESTORE" 2>&1); then
  log "ERROR: iptables-restore --test отверг правила — ничего не меняю:"
  log "$TEST_ERR"
  [ "$MODE" = auto ] && echo "$NEW_HASH" > "$STATE_DIR/failed.hash"
  exit 11
fi

if $DRY_RUN; then
  echo "=== dry-run: будет загружено ($COUNT правил) ==="
  cat "$RESTORE"
  exit 0
fi

# ---------- 4. бэкап ----------
BACKUP_FILE="$BACKUP_DIR/iptables.backup.$(date +%s)"
iptables-save > "$BACKUP_FILE" 2>/dev/null && chmod 600 "$BACKUP_FILE"
# shellcheck disable=SC2012
ls -1t "$BACKUP_DIR"/iptables.backup.* 2>/dev/null | tail -n +"$((KEEP_BACKUPS+1))" | xargs -r rm -f

# ---------- 5. применяем ----------
if ! ERR=$("${IPT_RESTORE[@]}" --noflush < "$RESTORE" 2>&1); then
  log "ERROR: iptables-restore не прошёл: $ERR — откатываю из $BACKUP_FILE"
  "${IPT_RESTORE[@]}" < "$BACKUP_FILE" || log "ERROR: откат тоже не прошёл!"
  exit 5
fi

# Переходы из системных цепочек в наши — первым правилом
for t in "${TABLES[@]}"; do
  for c in ${MANAGED[$t]}; do
    "${IPT[@]}" -t "$t" -C "$c" -j "${CHAIN_PREFIX}$c" >/dev/null 2>&1 || \
      "${IPT[@]}" -t "$t" -I "$c" 1 -j "${CHAIN_PREFIX}$c"
  done
done

# ---------- 6. MASQUERADE и ip_forward (нужны для DNAT на внешние адреса) ----------
OUT_IF="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
OUT_IF="${OUT_IF:-eth0}"
"${IPT[@]}" -t nat -C POSTROUTING -o "$OUT_IF" -j MASQUERADE >/dev/null 2>&1 || \
  "${IPT[@]}" -t nat -A POSTROUTING -o "$OUT_IF" -j MASQUERADE
if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" != "1" ]; then
  sysctl -qw net.ipv4.ip_forward=1
fi
SYSCTL_D=/etc/sysctl.d/99-iptables-agent.conf
if [ ! -f "$SYSCTL_D" ]; then
  printf 'net.ipv4.ip_forward = 1\nnet.netfilter.nf_conntrack_max = 1048576\n' > "$SYSCTL_D"
  sysctl -q -p "$SYSCTL_D" >/dev/null 2>&1 || true
fi

# ---------- 7. сбрасываем conntrack для изменившихся портов ----------
# Без этого уже идущие потоки продолжают ходить по СТАРОМУ правилу,
# потому что NAT для соединения выбирается один раз, на первом пакете.
if command -v conntrack >/dev/null 2>&1; then
  OLD_PARSED="$STATE_DIR/applied.rules"; [ -f "$OLD_PARSED" ] || OLD_PARSED=/dev/null
  comm -3 <(sort -u "$OLD_PARSED") <(sort -u "$PARSED") | sed 's/^\t//' \
    | awk '$1=="nat" && $2=="PREROUTING" {
             p=""; d="";
             for(i=3;i<=NF;i++){ if($i=="-p")p=$(i+1); if($i=="--dport")d=$(i+1) }
             if(p!="" && d ~ /^[0-9]+$/) print p, d
           }' | sort -u | while read -r p d; do
      if conntrack -D -p "$p" --orig-port-dst "$d" >/dev/null 2>&1; then
        log "  conntrack: сброшены соединения $p/$d"
      fi
    done
else
  log "WARN: conntrack не установлен — существующие соединения могут идти по старым правилам до переподключения"
fi

# ---------- 8. проверка связи (только если трогали filter — NAT не ломает связь хоста) ----------
if awk '$1=="filter"{f=1} END{exit !f}' "$PARSED"; then
  if ! curl -s --max-time 10 -o /dev/null https://raw.githubusercontent.com/; then
    log "ERROR: после применения пропала связь — откатываю из $BACKUP_FILE"
    "${IPT_RESTORE[@]}" < "$BACKUP_FILE" || log "ERROR: откат не прошёл!"
    [ "$MODE" = auto ] && echo "$NEW_HASH" > "$STATE_DIR/failed.hash"
    exit 6
  fi
fi

# ---------- 9. сохраняем состояние ----------
cp "$PARSED" "$STATE_DIR/applied.rules"
cp "$RAW"    "$STATE_DIR/applied.raw"
echo "$NEW_HASH" > "$STATE_DIR/applied.hash"
rm -f "$STATE_DIR/failed.hash"

# ---------- 10. переживаем перезагрузку ----------
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null 2>&1 || log "WARN: netfilter-persistent save не прошёл"
else
  mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4
fi

log "OK: применено $COUNT правил (хэш ${NEW_HASH:0:12}), бэкап: $BACKUP_FILE"
exit 0
APPLY_EOF
chmod 755 "$APPLY_PATH"
log_info "Записан: $APPLY_PATH"

# -----------------------
# Миграция со старой версии
# -----------------------
if [ "$MIGRATE_OLD_RULES" = 1 ]; then
  log_step "Удаляю DNAT-правила старой версии из nat/PREROUTING..."
  MIG_BACKUP="$BACKUP_DIR/before-v3-migration.$(date +%s)"
  iptables-save > "$MIG_BACKUP"; chmod 600 "$MIG_BACKUP"
  REMOVED=0; SKIPPED=0
  while IFS= read -r r; do
    case "$r" in *'"'*) SKIPPED=$((SKIPPED+1)); continue ;; esac   # правила с кавычками не трогаем
    read -r -a a <<< "${r/#-A /-D }"
    iptables -w 10 -t nat "${a[@]}" 2>/dev/null && REMOVED=$((REMOVED+1))
  done < <(iptables -w 10 -t nat -S PREROUTING | grep -E -- '^-A PREROUTING .*-j DNAT( |$)' || true)
  log_info "Удалено старых DNAT-правил: $REMOVED (пропущено: $SKIPPED). Бэкап до миграции: $MIG_BACKUP"
fi

# -----------------------
# systemd: oneshot + timer
# -----------------------
log_step "Записываю systemd unit и timer..."
cat > "$SERVICE_PATH" <<UNIT_EOF
[Unit]
Description=Sync iptables rules from GitHub (block_delete/rls.txt)
Documentation=https://github.com/ZhuZhuZhuang10/block_delete
Wants=network-online.target
After=network-online.target netfilter-persistent.service

[Service]
Type=oneshot
ExecStart=${APPLY_PATH} --auto
TimeoutStartSec=180
UNIT_EOF

cat > "$TIMER_PATH" <<TIMER_EOF
[Unit]
Description=Check GitHub for iptables rule changes every ${CHECK_EVERY_SEC}s

[Timer]
OnBootSec=20
OnUnitActiveSec=${CHECK_EVERY_SEC}
AccuracySec=5
Unit=iptables-agent.service

[Install]
WantedBy=timers.target
TIMER_EOF

cat > /etc/logrotate.d/iptables-agent <<LR_EOF
${LOG_DIR}/*.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
}
LR_EOF

systemctl daemon-reload

# -----------------------
# Первое применение и запуск таймера
# -----------------------
log_step "Первое применение правил..."
rm -f "$STATE_DIR/failed.hash"
if "$APPLY_PATH"; then
  log_info "Правила применены"
else
  log_warn "Первое применение не удалось — см. вывод выше и $LOG_DIR/apply_rules.log"
fi

systemctl enable --now iptables-agent.timer >/dev/null
if systemctl is-active --quiet iptables-agent.timer; then
  log_info "Таймер iptables-agent.timer активен (проверка каждые ${CHECK_EVERY_SEC}s)"
else
  log_warn "Таймер не запустился: systemctl status iptables-agent.timer"
fi

echo ""
echo "============================================================"
log_info "Установка завершена"
echo "============================================================"
echo "  Состояние:       $APPLY_PATH --status"
echo "  Сухой прогон:    $APPLY_PATH --dry-run"
echo "  Применить сразу: $APPLY_PATH"
echo "  Ваши правила:    iptables -t nat -S ${CHAIN_PREFIX}PREROUTING"
echo "  Лог:             $LOG_DIR/apply_rules.log  |  journalctl -u iptables-agent.service"
echo "  Таймер:          systemctl list-timers iptables-agent.timer"
echo "============================================================"
