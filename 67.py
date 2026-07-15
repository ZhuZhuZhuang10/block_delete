#!/usr/bin/env python3
"""
forwarder.py — TCP/UDP-форвардер (в т.ч. под Hysteria2/QUIC) с
автосинхронизацией правил из удалённого файла (формат iptables DNAT-строк),
почасовым отчётом в Telegram и firewall-allowlist на VPS:

  - OUTPUT (что форвардер может слать дальше) разрешён ТОЛЬКО на
    destination-IP из текущих правил + служебные infra-хосты (RULES_URL,
    Telegram API) + DNS. Всё остальное — DROP.
  - INPUT (кто может постучаться к форвардеру) разрешён на активные
    listen-порты (отдельно udp/tcp) С ЛЮБОГО IP — это же публичный
    сервис, клиенты подключаются с произвольных адресов. Никакой
    гео- или ASN-фильтрации по стране/провайдеру здесь нет и не будет.

ВАЖНО: ipset и iptables требуют root и утилиты `ipset`, `iptables`
(на Debian/Ubuntu: apt install ipset iptables).

Запуск:
    export TELEGRAM_BOT_TOKEN="123456:AA..."
    export TELEGRAM_CHAT_ID="123456789"
    export ADMIN_SSH_PORT="22"      # порт, который никогда не блокируется
    sudo python3 forwarder.py

Все настройки — через переменные окружения (см. блок CONFIG ниже).
"""

import asyncio
import html
import logging
import os
import re
import shutil
import signal
import socket
import sys
import time
import urllib.parse
import urllib.request
from typing import Dict, List, Set, Tuple

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

RULES_URL = os.environ.get(
    "RULES_URL",
    "https://raw.githubusercontent.com/ZhuZhuZhuang10/block_delete/refs/heads/main/rls.txt",
)
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL", "30"))  # сек, как часто перечитывать rls.txt
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
TELEGRAM_REPORT_INTERVAL = int(os.environ.get("TELEGRAM_REPORT_INTERVAL", "3600"))  # сек, раз в час
UDP_IDLE_TIMEOUT = int(os.environ.get("UDP_IDLE_TIMEOUT", "120"))  # сек простоя UDP-сессии до закрытия
BUFFER_SIZE = 65536

# Размер приёмного/передающего буфера UDP-сокетов (в байтах). Больше буфер —
# меньше шанс потерять пакеты при всплесках трафика на нестабильных/лоссовых
# сетях (актуально для Hysteria2/QUIC поверх BBR). 4 МБ — разумный дефолт.
UDP_SOCK_BUF_SIZE = int(os.environ.get("UDP_SOCK_BUF_SIZE", str(4 * 1024 * 1024)))

# Порт, который НИКОГДА не блокируется firewall'ом (чтобы не потерять доступ к серверу)
ADMIN_SSH_PORT = int(os.environ.get("ADMIN_SSH_PORT", "22"))

# Включить/выключить автоматическое управление firewall'ом
FIREWALL_ENABLED = os.environ.get("FIREWALL_ENABLED", "1") == "1"
IPSET_NAME = os.environ.get("IPSET_NAME", "fwd_allowed_dst")
INFRA_IPSET_NAME = os.environ.get("INFRA_IPSET_NAME", "fwd_infra_allow")


def _infra_hosts() -> List[str]:
    """Хосты, к которым скрипту всегда нужен доступ, иначе он не сможет
    скачать rls.txt / отправить отчёт в Telegram после включения
    default-DROP. Резолвятся в IP и добавляются в отдельный,
    "накопительный" ipset (только add, без remove — чтобы не потерять
    доступ из-за смены CDN-адреса между циклами синхронизации)."""
    hosts = set()
    try:
        hosts.add(urllib.parse.urlparse(RULES_URL).hostname)
    except Exception:
        pass
    hosts.add("api.telegram.org")
    extra = os.environ.get("EXTRA_INFRA_HOSTS", "")
    for h in extra.split(","):
        h = h.strip()
        if h:
            hosts.add(h)
    return [h for h in hosts if h]


INFRA_HOSTS = _infra_hosts()

# Часто злоупотребляемые / нежелательные порты — правила на них всегда игнорируются
BT_PORTS = {
    6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889,
    6969, 51413, 8999, 16881,
}
BLOCKED_PORTS = BT_PORTS | {
    25, 53, 110, 135, 137, 138, 139, 445, 143, 389, 465, 587, 993, 995,
    1433, 1723, 1900, 2049, 2375, 2376, 3306, 3389, 5432, 6379, 11211,
}

RULE_RE = re.compile(
    r"-p\s+(tcp|udp).*?--dport\s+(\d+).*?--to-destination\s+([\d.]+):(\d+)",
    re.IGNORECASE,
)

BT_HANDSHAKE = b"\x13BitTorrent protocol"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("forwarder")


# ---------------------------------------------------------------------------
# Root-права: firewall (ipset/iptables) требует root. Если скрипт запущен
# обычным пользователем, перезапускаем себя же через sudo, сохраняя все
# переданные переменные окружения (-E). Для non-interactive запуска
# (systemd/cron) нужен либо запуск сразу от root, либо NOPASSWD в sudoers —
# интерактивный sudo просто попросит пароль в терминале.
# ---------------------------------------------------------------------------

def _ensure_root():
    if not FIREWALL_ENABLED:
        return
    if os.name != "posix" or not hasattr(os, "geteuid"):
        return
    if os.geteuid() == 0:
        return

    sudo_path = shutil.which("sudo")
    if not sudo_path:
        log.error(
            "Нужны root-права для управления firewall (ipset/iptables), а "
            "sudo не найден в PATH. Запустите скрипт от root вручную: "
            "'sudo python3 forwarder.py', либо задайте FIREWALL_ENABLED=0."
        )
        sys.exit(1)

    log.info("Скрипт запущен не от root — перезапускаю себя через sudo...")
    os.execvp(sudo_path, [sudo_path, "-E", sys.executable] + sys.argv)


_ensure_root()


def _find_bin(name: str) -> str:
    """Абсолютный путь к бинарнику. Нужен, потому что sudo/systemd иногда
    подставляют урезанный PATH (secure_path), где ipset/iptables из
    обычного PATH пользователя не видны."""
    p = shutil.which(name)
    if p:
        return p
    for prefix in ("/usr/sbin", "/sbin", "/usr/bin", "/bin"):
        cand = os.path.join(prefix, name)
        if os.path.exists(cand):
            return cand
    log.warning(f"Не нашёл бинарник '{name}' в стандартных путях, использую как есть — может не сработать.")
    return name


IPTABLES_BIN = _find_bin("iptables")
IPSET_BIN = _find_bin("ipset")


# ---------------------------------------------------------------------------
# Парсинг правил (tcp + udp)
# ---------------------------------------------------------------------------

def parse_rules(text: str) -> Tuple[Dict[Tuple[str, int], Tuple[str, int]], List[dict]]:
    """Парсит файл со строками iptables DNAT и возвращает:
    - rules: {(proto, port): (dst_host, dst_port)}
    - blocked_entries: список правил с запрещёнными портами, которые были проигнорированы
    """
    rules: Dict[Tuple[str, int], Tuple[str, int]] = {}
    blocked_entries: List[dict] = []

    for line in text.splitlines():
        raw_line = line.strip()
        if not raw_line or raw_line.startswith("#"):
            continue

        m = RULE_RE.search(raw_line)
        if not m:
            continue

        proto, dport, dst_host, dst_port = m.groups()
        proto = proto.lower()
        dport = int(dport)
        dst_port = int(dst_port)

        if dport in BLOCKED_PORTS or dst_port in BLOCKED_PORTS:
            reason = "BitTorrent port" if (dport in BT_PORTS or dst_port in BT_PORTS) else "blocked port"
            blocked_entries.append({
                "raw": raw_line, "proto": proto, "dport": dport,
                "dst_host": dst_host, "dst_port": dst_port, "reason": reason,
            })
            log.info(f"[PORT-FILTER] Пропускаю правило {proto}:{dport} -> {dst_host}:{dst_port} ({reason})")
            continue

        rules[(proto, dport)] = (dst_host, dst_port)

    return rules, blocked_entries


def _fetch_rules_blocking() -> Tuple[Dict[Tuple[str, int], Tuple[str, int]], List[dict]]:
    req = urllib.request.Request(RULES_URL, headers={"User-Agent": "rules-sync/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        text = resp.read().decode("utf-8", errors="ignore")
    return parse_rules(text)


async def fetch_rules() -> Tuple[Dict[Tuple[str, int], Tuple[str, int]], List[dict]]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _fetch_rules_blocking)


def blocked_signature(blocked_entries: List[dict]) -> str:
    parts = [
        f'{x["proto"]}:{x["dport"]}->{x["dst_host"]}:{x["dst_port"]}|{x["reason"]}'
        for x in blocked_entries
    ]
    return "\n".join(sorted(parts))


# ---------------------------------------------------------------------------
# Firewall: OUTPUT — allowlist по destination-IP; INPUT — allowlist по
# номеру listen-порта (с любого IP отправителя). Никакой геолокации/ASN.
# ---------------------------------------------------------------------------

async def _run(cmd: List[str], check: bool = True) -> Tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    out, err = await proc.communicate()
    if check and proc.returncode != 0:
        log.error(f"Команда {' '.join(cmd)} завершилась с кодом {proc.returncode}: {err.decode().strip()}")
    return proc.returncode, out.decode(), err.decode()


class FirewallManager:
    """Поддерживает ipset с destination-IP из активных правил (для OUTPUT)
    и ipset-ы с активными listen-портами отдельно для udp/tcp (для INPUT,
    с любого source-IP — публичный сервис). Метод teardown() полностью
    откатывает всё это назад к стандартной ACCEPT-политике — вызывается
    гарантированно при остановке скрипта (Ctrl+C / SIGTERM)."""

    def __init__(self, ipset_name: str, infra_ipset_name: str, admin_port: int,
                 listen_ports_udp_ipset: str = "fwd_listen_ports_udp",
                 listen_ports_tcp_ipset: str = "fwd_listen_ports_tcp"):
        self.ipset_name = ipset_name
        self.infra_ipset_name = infra_ipset_name
        self.listen_ports_udp_ipset = listen_ports_udp_ipset
        self.listen_ports_tcp_ipset = listen_ports_tcp_ipset
        self.admin_port = admin_port
        self.current_ips: Set[str] = set()
        self.infra_ips: Set[str] = set()
        self.current_udp_ports: Set[int] = set()
        self.current_tcp_ports: Set[int] = set()
        self.initialized = False

    async def _resolve_infra_ips(self) -> Set[str]:
        loop = asyncio.get_running_loop()
        ips: Set[str] = set()
        for host in INFRA_HOSTS:
            try:
                infos = await loop.getaddrinfo(host, None)
                for info in infos:
                    ips.add(info[4][0])
            except Exception as e:
                log.warning(f"Не удалось зарезолвить infra-хост {host}: {e}")
        return ips

    def _rule_specs(self) -> List[Tuple[str, List[str]]]:
        """Список (chain, match-args) без -I/-D и без номера позиции —
        используется и для вставки (ensure_base_rules), и для удаления
        (teardown), чтобы правила были гарантированно симметричны.

        Важно: conntrack (ESTABLISHED,RELATED) держим как бонус, но НЕ как
        единственный путь для критичного трафика — на части VPS (особенно
        OpenVZ/урезанные контейнеры) модуль nf_conntrack может быть
        недоступен, и тогда весь обратный трафик (ответы SSH, ответы
        форвардера клиентам, ответы backend-сервера форвардеру) будет
        тихо дропаться. Поэтому ниже — статичные правила по порту/IP,
        не зависящие от state-трекинга ядра:
          - SSH: разрешаем tcp both dst (входящие подключения) и
            src (исходящие ответы) на ADMIN_SSH_PORT напрямую.
          - Ответы форвардера клиентам: разрешаем OUTPUT с src-портом из
            listen_ports_udp/tcp (тем же ipset, что и для входящих).
          - Ответы backend-сервера форвардеру: разрешаем INPUT с src-IP
            из ipset destination-адресов (тот же список, что для OUTPUT)."""
        return [
            ("OUTPUT", ["-o", "lo", "-j", "ACCEPT"]),
            ("OUTPUT", ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]),
            ("OUTPUT", ["-p", "udp", "--dport", "53", "-j", "ACCEPT"]),
            ("OUTPUT", ["-p", "tcp", "--dport", "53", "-j", "ACCEPT"]),
            ("OUTPUT", ["-p", "tcp", "--sport", str(self.admin_port), "-j", "ACCEPT"]),
            ("OUTPUT", ["-m", "set", "--match-set", self.infra_ipset_name, "dst", "-j", "ACCEPT"]),
            ("OUTPUT", ["-m", "set", "--match-set", self.ipset_name, "dst", "-j", "ACCEPT"]),
            ("OUTPUT", ["-p", "udp", "-m", "set", "--match-set", self.listen_ports_udp_ipset, "src", "-j", "ACCEPT"]),
            ("OUTPUT", ["-p", "tcp", "-m", "set", "--match-set", self.listen_ports_tcp_ipset, "src", "-j", "ACCEPT"]),
            ("INPUT", ["-i", "lo", "-j", "ACCEPT"]),
            ("INPUT", ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]),
            ("INPUT", ["-p", "udp", "--sport", "53", "-j", "ACCEPT"]),
            ("INPUT", ["-p", "tcp", "--dport", str(self.admin_port), "-j", "ACCEPT"]),
            ("INPUT", ["-m", "set", "--match-set", self.infra_ipset_name, "src", "-j", "ACCEPT"]),
            ("INPUT", ["-m", "set", "--match-set", self.ipset_name, "src", "-j", "ACCEPT"]),
            ("INPUT", ["-p", "udp", "-m", "set", "--match-set", self.listen_ports_udp_ipset, "dst", "-j", "ACCEPT"]),
            ("INPUT", ["-p", "tcp", "-m", "set", "--match-set", self.listen_ports_tcp_ipset, "dst", "-j", "ACCEPT"]),
        ]

    async def ensure_base_rules(self):
        if self.initialized:
            return

        await _run([IPSET_BIN, "create", self.ipset_name, "hash:ip", "-exist"])
        await _run([IPSET_BIN, "create", self.infra_ipset_name, "hash:ip", "-exist"])
        await _run([IPSET_BIN, "create", self.listen_ports_udp_ipset, "bitmap:port",
                    "range", "0-65535", "-exist"])
        await _run([IPSET_BIN, "create", self.listen_ports_tcp_ipset, "bitmap:port",
                    "range", "0-65535", "-exist"])

        infra_ips = await self._resolve_infra_ips()
        for ip in infra_ips:
            await _run([IPSET_BIN, "add", self.infra_ipset_name, ip, "-exist"])
        self.infra_ips |= infra_ips
        log.info(f"[FW] Infra-allowlist ({', '.join(INFRA_HOSTS)}): {len(self.infra_ips)} IP")

        for chain, args in self._rule_specs():
            await _run([IPTABLES_BIN, "-D", chain] + args, check=False)
        for chain, args in self._rule_specs():
            await _run([IPTABLES_BIN, "-I", chain, "1"] + args, check=False)

        await _run([IPTABLES_BIN, "-P", "OUTPUT", "DROP"], check=False)
        await _run([IPTABLES_BIN, "-P", "INPUT", "DROP"], check=False)

        self.initialized = True
        log.info(
            f"Firewall инициализирован: default-DROP на INPUT/OUTPUT. "
            f"OUTPUT разрешён на loopback/established/DNS/infra-хосты и на "
            f"destination-IP из ipset '{self.ipset_name}'. "
            f"INPUT разрешён на loopback/established/DNS/admin tcp/{self.admin_port} "
            f"и на listen-порты (udp: '{self.listen_ports_udp_ipset}', "
            f"tcp: '{self.listen_ports_tcp_ipset}') с ЛЮБОГО IP."
        )

    async def sync(self, rules: Dict[Tuple[str, int], Tuple[str, int]]):
        await self.ensure_base_rules()

        new_infra_ips = await self._resolve_infra_ips()
        added_infra = new_infra_ips - self.infra_ips
        for ip in added_infra:
            await _run([IPSET_BIN, "add", self.infra_ipset_name, ip, "-exist"])
            log.info(f"[FW] Добавлен infra IP: {ip}")
        self.infra_ips |= new_infra_ips

        wanted_ips = {dst_host for (_proto, _port), (dst_host, _dst_port) in rules.items()}
        to_add = wanted_ips - self.current_ips
        to_remove = self.current_ips - wanted_ips
        for ip in to_add:
            await _run([IPSET_BIN, "add", self.ipset_name, ip, "-exist"])
            log.info(f"[FW] Разрешён destination IP: {ip}")
        for ip in to_remove:
            await _run([IPSET_BIN, "del", self.ipset_name, ip], check=False)
            log.info(f"[FW] Убран из allowlist destination IP: {ip}")
        self.current_ips = wanted_ips

        wanted_udp_ports = {port for (proto, port) in rules.keys() if proto == "udp"}
        wanted_tcp_ports = {port for (proto, port) in rules.keys() if proto == "tcp"}

        for proto_name, ipset_name, wanted, current_attr in (
            ("udp", self.listen_ports_udp_ipset, wanted_udp_ports, "current_udp_ports"),
            ("tcp", self.listen_ports_tcp_ipset, wanted_tcp_ports, "current_tcp_ports"),
        ):
            current = getattr(self, current_attr)
            ports_to_add = wanted - current
            ports_to_remove = current - wanted
            for port in ports_to_add:
                await _run([IPSET_BIN, "add", ipset_name, str(port), "-exist"])
                log.info(f"[FW] Открыт входящий доступ на порт {proto_name}/{port} (любой IP)")
            for port in ports_to_remove:
                await _run([IPSET_BIN, "del", ipset_name, str(port)], check=False)
                log.info(f"[FW] Закрыт входящий доступ на порт {proto_name}/{port}")
            setattr(self, current_attr, wanted)

    async def teardown(self):
        """Гарантированно откатывает всё, что сделал ensure_base_rules():
        удаляет вставленные iptables-правила, возвращает политику ACCEPT
        на INPUT/OUTPUT и уничтожает все ipset."""
        if not self.initialized:
            return

        log.info("Останавливаюсь: откатываю firewall-правила к политике ACCEPT...")

        await _run([IPTABLES_BIN, "-P", "OUTPUT", "ACCEPT"], check=False)
        await _run([IPTABLES_BIN, "-P", "INPUT", "ACCEPT"], check=False)

        for chain, args in self._rule_specs():
            await _run([IPTABLES_BIN, "-D", chain] + args, check=False)

        await _run([IPSET_BIN, "destroy", self.ipset_name], check=False)
        await _run([IPSET_BIN, "destroy", self.infra_ipset_name], check=False)
        await _run([IPSET_BIN, "destroy", self.listen_ports_udp_ipset], check=False)
        await _run([IPSET_BIN, "destroy", self.listen_ports_tcp_ipset], check=False)

        self.initialized = False
        self.current_ips = set()
        self.infra_ips = set()
        self.current_udp_ports = set()
        self.current_tcp_ports = set()
        log.info("Firewall-правила удалены, политика INPUT/OUTPUT — ACCEPT.")


# ---------------------------------------------------------------------------
# Telegram-отчёты
# ---------------------------------------------------------------------------

def send_telegram_message(text: str, parse_mode: str = "HTML"):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log.warning("TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID не заданы — сообщение не отправлено")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "disable_web_page_preview": "true"}
    if parse_mode:
        payload["parse_mode"] = parse_mode

    data = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(url, data=data)
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log.error(f"Не удалось отправить сообщение в Telegram: {e}")


async def send_telegram_message_async(text: str, parse_mode: str = "HTML"):
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, send_telegram_message, text, parse_mode)


def build_report(manager: "ForwarderManager", fw: FirewallManager) -> str:
    lines = [
        "<b>Отчёт о переадресации (TCP + UDP / Hysteria)</b>",
        f"Время: {html.escape(time.strftime('%Y-%m-%d %H:%M:%S'))}",
        "",
    ]

    lines.append("<b>Активные правила:</b>")
    if manager.active:
        for (proto, port), info in sorted(manager.active.items()):
            dst = info["dst"]
            st = manager.stats.get((proto, port), {})
            lines.append(
                f"{html.escape(proto)}:{port} → {html.escape(dst[0])}:{dst[1]} | "
                f"conns: {st.get('conns', 0)}, "
                f"tx: {st.get('bytes_tx', 0) / 1024 / 1024:.2f} MB, "
                f"rx: {st.get('bytes_rx', 0) / 1024 / 1024:.2f} MB"
            )
    else:
        lines.append("нет активных правил")

    lines.append("")
    lines.append(f"Заблокировано BitTorrent-соединений (TCP, всего): {manager.bt_blocked}")

    lines.append("")
    lines.append(f"<b>Firewall allowlist ({len(fw.current_ips)} destination IP):</b>")
    if fw.current_ips:
        lines.extend(f"• {html.escape(ip)}" for ip in sorted(fw.current_ips))
    else:
        lines.append("пусто")

    lines.append("")
    lines.append(
        f"<b>Открытые входящие порты (любой IP):</b> "
        f"udp: {len(fw.current_udp_ports)}, tcp: {len(fw.current_tcp_ports)}"
    )
    if fw.current_udp_ports:
        lines.append("udp: " + ", ".join(f"{p}" for p in sorted(fw.current_udp_ports)))
    if fw.current_tcp_ports:
        lines.append("tcp: " + ", ".join(f"{p}" for p in sorted(fw.current_tcp_ports)))
    if not fw.current_udp_ports and not fw.current_tcp_ports:
        lines.append("пусто")

    lines.append("")
    lines.append(f"<b>Infra allowlist ({len(fw.infra_ips)} IP, {html.escape(', '.join(INFRA_HOSTS))}):</b>")
    if fw.infra_ips:
        lines.extend(f"• {html.escape(ip)}" for ip in sorted(fw.infra_ips))
    else:
        lines.append("пусто")

    if manager.changes_log:
        lines.append("")
        lines.append("<b>Изменения правил с прошлого отчёта:</b>")
        lines.extend(html.escape(item) for item in manager.changes_log)

    return "\n".join(lines)


def build_blocked_rules_alert(blocked_entries: List[dict]) -> str:
    lines = [
        "<b>Обнаружены запрещённые правила в rules</b>",
        f"Время: {html.escape(time.strftime('%Y-%m-%d %H:%M:%S'))}",
        "", f"Количество: {len(blocked_entries)}", "",
    ]
    for x in blocked_entries[:50]:
        lines.append(
            f"• {html.escape(x['proto'])}:{x['dport']} → "
            f"{html.escape(x['dst_host'])}:{x['dst_port']} ({html.escape(x['reason'])})"
        )
    if len(blocked_entries) > 50:
        lines.append("")
        lines.append(f"И ещё {len(blocked_entries) - 50} правил(а)...")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Тюнинг UDP-сокетов под нестабильные сети (Hysteria2/QUIC поверх BBR)
# ---------------------------------------------------------------------------

def _make_tuned_udp_socket() -> socket.socket:
    """Создаёт UDP-сокет с увеличенными приёмным/передающим буферами
    (меньше потерь пакетов при всплесках на лоссовых/нестабильных сетях)
    и отключённым Path MTU Discovery (DF-бит), чтобы избежать PMTUD
    black hole на мобильных и других сетях."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_SOCK_BUF_SIZE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_SOCK_BUF_SIZE)
    except OSError as e:
        log.warning(f"Не удалось увеличить буферы UDP-сокета: {e}")

    ip_mtu_discover = getattr(socket, "IP_MTU_DISCOVER", None)
    ip_pmtudisc_dont = getattr(socket, "IP_PMTUDISC_DONT", 0)
    if ip_mtu_discover is not None:
        try:
            sock.setsockopt(socket.IPPROTO_IP, ip_mtu_discover, ip_pmtudisc_dont)
        except OSError:
            pass

    sock.setblocking(False)
    return sock


# ---------------------------------------------------------------------------
# Менеджер форвардинга (TCP + UDP)
# ---------------------------------------------------------------------------

class ForwarderManager:
    def __init__(self):
        self.active = {}
        self.stats = {}
        self.changes_log = []
        self.bt_blocked = 0

    async def apply_rules(self, new_rules: dict):
        current_keys = set(self.active.keys())
        new_keys = set(new_rules.keys())

        for key in current_keys - new_keys:
            await self._stop_rule(key)

        for key in new_keys:
            dst = new_rules[key]
            existing = self.active.get(key)
            if existing is None or existing["dst"] != dst:
                if existing is not None:
                    await self._stop_rule(key)
                await self._start_rule(key, dst)

    async def _start_rule(self, key, dst):
        proto, port = key
        try:
            loop = asyncio.get_running_loop()
            if proto == "udp":
                sock = _make_tuned_udp_socket()
                sock.bind(("0.0.0.0", port))
                transport, protocol = await loop.create_datagram_endpoint(
                    lambda k=key, d=dst: UDPForwarder(k, d, self),
                    sock=sock,
                )
                self.active[key] = {"kind": "udp", "dst": dst, "transport": transport, "protocol": protocol}
            else:  # tcp
                server = await asyncio.start_server(
                    lambda r, w, k=key, d=dst: self._handle_tcp(r, w, k, d),
                    host="0.0.0.0",
                    port=port,
                )
                self.active[key] = {"kind": "tcp", "dst": dst, "server": server}
                asyncio.create_task(server.serve_forever())

            self.stats.setdefault(key, {"bytes_tx": 0, "bytes_rx": 0, "conns": 0})
            msg = f"+ {proto}:{port} → {dst[0]}:{dst[1]}"
            self.changes_log.append(msg)
            log.info(f"Добавлено правило {msg}")
        except OSError as e:
            log.error(f"Не удалось забиндить {proto}:{port} — {e}")

    async def _stop_rule(self, key):
        proto, port = key
        info = self.active.pop(key, None)
        if not info:
            return
        if info["kind"] == "udp":
            info["transport"].close()
        else:
            info["server"].close()
            try:
                await info["server"].wait_closed()
            except Exception:
                pass
        msg = f"- {proto}:{port}"
        self.changes_log.append(msg)
        log.info(f"Удалено правило {msg}")

    @staticmethod
    def _enable_nodelay(writer: asyncio.StreamWriter):
        """Отключает алгоритм Нейгла на сокете. Без этого каждый мелкий
        пакет (характерно для интерактивного/прокси-трафика, в т.ч. TCP)
        может задерживаться на клиенте/сервере до срабатывания
        delayed-ACK (обычно ~40-200 мс) — это ощущается как «тормозит»,
        особенно на большом числе мелких запросов/ответов."""
        try:
            sock = writer.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    async def _handle_tcp(self, reader, writer, key, dst):
        peer = writer.get_extra_info("peername")
        dst_writer = None
        try:
            # ВАЖНО: раньше здесь стоял `await reader.read(68)` с таймаутом
            # 2 секунды ДО открытия соединения к backend — то есть КАЖДОЕ
            # TCP-соединение (не только BitTorrent) стопорилось минимум до
            # первого байта от клиента, а если клиент ждёт первым слова от
            # сервера (как многие прокси-протоколы) — влетало в полные 2
            # секунды задержки на каждое новое соединение. Именно это и
            # давало ощущение "TCP работает очень медленно".
            #
            # Теперь соединение к backend открывается сразу, а проверка на
            # BitTorrent-хендшейк делается "по пути", не блокируя старт
            # форвардинга.
            dst_reader, dst_writer = await asyncio.open_connection(dst[0], dst[1])

            self._enable_nodelay(writer)
            self._enable_nodelay(dst_writer)

            self.stats[key]["conns"] += 1
            bt_checked = {"done": False}

            async def pipe(src, dst_w, direction, check_bt=False):
                try:
                    while True:
                        data = await src.read(BUFFER_SIZE)
                        if not data:
                            break
                        if check_bt and not bt_checked["done"]:
                            bt_checked["done"] = True
                            if data.startswith(BT_HANDSHAKE):
                                self.bt_blocked += 1
                                log.info(f"[BT-BLOCK] Заблокировано BT-соединение от {peer} на {key}")
                                break
                        dst_w.write(data)
                        await dst_w.drain()
                        self.stats[key][direction] += len(data)
                except (ConnectionResetError, BrokenPipeError, OSError):
                    pass
                finally:
                    dst_w.close()

            await asyncio.gather(
                pipe(reader, dst_writer, "bytes_tx", check_bt=True),
                pipe(dst_reader, writer, "bytes_rx"),
            )
        except Exception as e:
            log.debug(f"TCP {key} ошибка ({peer}): {e}")
        finally:
            writer.close()
            if dst_writer:
                dst_writer.close()

    async def cleanup_udp_clients(self):
        while True:
            await asyncio.sleep(30)
            now = time.time()
            for key, info in list(self.active.items()):
                if info["kind"] != "udp":
                    continue
                protocol = info["protocol"]
                stale = [addr for addr, c in protocol.clients.items()
                         if now - c["last_seen"] > UDP_IDLE_TIMEOUT]
                for addr in stale:
                    protocol.clients[addr]["transport"].close()
                    del protocol.clients[addr]
                    protocol.pending_queue.pop(addr, None)


class UDPForwarder(asyncio.DatagramProtocol):
    def __init__(self, key, dst, manager: ForwarderManager):
        self.key = key
        self.dst = dst
        self.manager = manager
        self.clients: Dict[tuple, dict] = {}
        self.pending: Set[tuple] = set()
        # Пакеты, пришедшие от клиента, пока для него ещё поднимается
        # сокет к backend (см. _open_client). Раньше такие пакеты просто
        # молча дропались — ни в "clients", ни в "pending"-обработке они
        # никуда не попадали. Для QUIC/Hysteria2 это критично: хендшейк
        # состоит из нескольких пакетов подряд, и потеря даже одного
        # означает retransmit по таймауту (сотни мс — секунды), что и
        # выглядит как "ужасно работает". Теперь такие пакеты
        # буферизуются и досылаются сразу после установления соединения.
        self.pending_queue: Dict[tuple, List[bytes]] = {}
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        entry = self.clients.get(addr)
        if entry:
            entry["transport"].sendto(data)
            entry["last_seen"] = time.time()
            self.manager.stats[self.key]["bytes_tx"] += len(data)
            return

        if addr in self.pending:
            # Соединение к backend ещё открывается — не теряем пакет.
            self.pending_queue.setdefault(addr, []).append(data)
            return

        self.pending.add(addr)
        asyncio.create_task(self._open_client(addr, data))

    async def _open_client(self, addr, first_data):
        loop = asyncio.get_running_loop()
        try:
            sock = _make_tuned_udp_socket()
            sock.connect(self.dst)
            transport, _ = await loop.create_datagram_endpoint(
                lambda: UDPClientSide(addr, self), sock=sock,
            )
        except OSError as e:
            log.error(f"UDP {self.key}: не удалось подключиться к {self.dst}: {e}")
            self.pending.discard(addr)
            self.pending_queue.pop(addr, None)
            return

        self.clients[addr] = {"transport": transport, "last_seen": time.time()}
        self.manager.stats[self.key]["conns"] += 1

        # Отправляем первый пакет и всё, что накопилось в очереди за
        # время установления соединения, строго в порядке получения.
        queued = self.pending_queue.pop(addr, [])
        transport.sendto(first_data)
        self.manager.stats[self.key]["bytes_tx"] += len(first_data)
        for chunk in queued:
            transport.sendto(chunk)
            self.manager.stats[self.key]["bytes_tx"] += len(chunk)

        self.pending.discard(addr)


class UDPClientSide(asyncio.DatagramProtocol):
    def __init__(self, client_addr, parent: UDPForwarder):
        self.client_addr = client_addr
        self.parent = parent

    def datagram_received(self, data, addr):
        if self.parent.transport:
            self.parent.transport.sendto(data, self.client_addr)
            self.parent.manager.stats[self.parent.key]["bytes_rx"] += len(data)


# ---------------------------------------------------------------------------
# Синхронизация правил и алерты
# ---------------------------------------------------------------------------

async def maybe_send_blocked_rules_alert(blocked_entries: List[dict], state: dict):
    if not blocked_entries:
        return
    sig = blocked_signature(blocked_entries)
    if sig == state.get("last_sig"):
        return
    state["last_sig"] = sig
    await send_telegram_message_async(build_blocked_rules_alert(blocked_entries), parse_mode="HTML")


async def sync_loop(manager: ForwarderManager, fw: FirewallManager):
    alert_state = {"last_sig": ""}
    while True:
        try:
            rules, blocked_entries = await fetch_rules()
            await manager.apply_rules(rules)
            if FIREWALL_ENABLED:
                await fw.sync(rules)
            await maybe_send_blocked_rules_alert(blocked_entries, alert_state)
        except Exception as e:
            log.error(f"Ошибка синхронизации правил: {e}")
        await asyncio.sleep(SYNC_INTERVAL)


async def telegram_loop(manager: ForwarderManager, fw: FirewallManager):
    while True:
        await asyncio.sleep(TELEGRAM_REPORT_INTERVAL)
        await send_telegram_message_async(build_report(manager, fw), parse_mode="HTML")
        manager.changes_log = []


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

async def main():
    manager = ForwarderManager()
    fw = FirewallManager(IPSET_NAME, INFRA_IPSET_NAME, ADMIN_SSH_PORT)
    stop_event = asyncio.Event()

    def _request_shutdown(sig_name: str):
        if not stop_event.is_set():
            log.info(f"Получен сигнал {sig_name} — останавливаюсь и откатываю firewall...")
            stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_shutdown, sig.name)
        except (NotImplementedError, RuntimeError):
            pass

    try:
        rules, blocked_entries = await fetch_rules()
        await manager.apply_rules(rules)
        if FIREWALL_ENABLED:
            await fw.sync(rules)
        await maybe_send_blocked_rules_alert(blocked_entries, {"last_sig": ""})
    except Exception as e:
        log.error(f"Не удалось получить правила при старте: {e}")

    log.info(f"Источник правил: {RULES_URL}")
    log.info(f"Интервал синхронизации: {SYNC_INTERVAL} сек")
    log.info(f"Интервал отчётов в Telegram: {TELEGRAM_REPORT_INTERVAL} сек")
    log.info(f"Firewall allowlist: {'включён' if FIREWALL_ENABLED else 'выключен'}, admin-порт: {ADMIN_SSH_PORT}")

    tasks = [
        asyncio.create_task(sync_loop(manager, fw)),
        asyncio.create_task(manager.cleanup_udp_clients()),
        asyncio.create_task(telegram_loop(manager, fw)),
    ]

    try:
        await stop_event.wait()
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

        if FIREWALL_ENABLED:
            try:
                await fw.teardown()
            except Exception as e:
                log.error(
                    f"Ошибка при откате firewall-правил: {e}. "
                    f"Проверьте вручную: '{IPTABLES_BIN} -L -n', "
                    f"'{IPTABLES_BIN} -P INPUT ACCEPT', '{IPTABLES_BIN} -P OUTPUT ACCEPT'."
                )

    log.info("Остановлено чисто.")


if __name__ == "__main__":
    try:
        import uvloop
        uvloop.install()
        log.info("Использую uvloop для event loop (быстрее, чем стандартный asyncio).")
    except ImportError:
        pass

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
