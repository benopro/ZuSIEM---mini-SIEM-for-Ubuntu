#!/usr/bin/env python3
"""
ZuSIEM - Mini SIEM Engine
Monitor: auth.log, UFW, auditd
Alert: Desktop notification + Telegram
"""

import re
import os
import json
import stat
import time
import sqlite3
import ipaddress
import threading
import subprocess
import configparser
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

# Giải mã secret (token/password) dạng enc:... từ siem.conf
from secrets_manager import decrypt

# ─── CONFIG ───────────────────────────────────────────────
CONFIG_FILE = Path(__file__).parent / "siem.conf"
DB_FILE     = Path(__file__).parent / "siem.db"

# Whitelist cấp độ hợp lệ — dùng để ngăn SQL injection
VALID_LEVELS = frozenset({"critical", "warning", "info"})

# ─── THREAD SAFETY ────────────────────────────────────────
# Một lock dùng chung cho tất cả shared state (mini SIEM, overhead thấp)
_state_lock = threading.Lock()

# ─── PRETTY LOGGING ───────────────────────────────────────
RESET = "\033[0m"
DIM   = "\033[2m"
BOLD  = "\033[1m"
COLORS = {
    "INFO":     "\033[36m",
    "WARNING":  "\033[33m",
    "ERROR":    "\033[31m",
    "CRITICAL": "\033[91m",
}

def log_line(level, scope, message):
    ts    = datetime.now().strftime("%H:%M:%S")
    lvl   = (level or "INFO").upper()
    color = COLORS.get(lvl, "\033[37m")
    scope_str = f"{scope:<10}"[:10]
    print(f"{DIM}{ts}{RESET} {color}{BOLD}{lvl:<8}{RESET} {DIM}{scope_str}{RESET} {message}", flush=True)

def load_config():
    cfg = configparser.ConfigParser()
    cfg.read(CONFIG_FILE)
    return cfg

def check_config_permissions():
    """Cảnh báo nếu siem.conf để world-readable (chứa token nhạy cảm)."""
    try:
        mode = os.stat(CONFIG_FILE).st_mode
        if mode & stat.S_IROTH:
            log_line("WARNING", "security",
                     f"siem.conf để world-readable! Chạy: chmod 600 {CONFIG_FILE}")
    except Exception:
        pass

# ─── DATABASE ─────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source    TEXT NOT NULL,
            level     TEXT NOT NULL,
            category  TEXT NOT NULL,
            message   TEXT NOT NULL,
            raw       TEXT,
            host      TEXT,
            user      TEXT,
            ip        TEXT,
            alerted   INTEGER DEFAULT 0,
            ack       INTEGER DEFAULT 0,
            score     INTEGER DEFAULT 0,
            mitre     TEXT    DEFAULT ''
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            date     TEXT PRIMARY KEY,
            total    INTEGER DEFAULT 0,
            critical INTEGER DEFAULT 0,
            warning  INTEGER DEFAULT 0,
            info     INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            ip       TEXT PRIMARY KEY,
            reason   TEXT,
            added_at TEXT
        )
    """)
    # Migration: thêm cột mới vào DB cũ nếu chưa có
    for col, typedef in [
        ("ack",   "INTEGER DEFAULT 0"),
        ("score", "INTEGER DEFAULT 0"),
        ("mitre", "TEXT DEFAULT ''"),
    ]:
        try:
            c.execute(f"ALTER TABLE events ADD COLUMN {col} {typedef}")
        except sqlite3.OperationalError:
            pass  # Cột đã tồn tại
    conn.commit()
    conn.close()

def insert_event(source, level, category, message, raw="", user="", ip="",
                 score=0, mitre=""):
    lvl      = (level or "INFO").upper()
    safe_lvl = lvl.lower() if lvl.lower() in VALID_LEVELS else "info"

    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    import socket
    host = socket.gethostname()
    c.execute("""
        INSERT INTO events
            (timestamp, source, level, category, message, raw, host, user, ip, score, mitre)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (ts, source, lvl, category, message, raw, host, user or "", ip or "", score, mitre or ""))
    event_id = c.lastrowid

    date = datetime.now().strftime("%Y-%m-%d")
    c.execute("INSERT OR IGNORE INTO stats (date) VALUES (?)", (date,))
    # safe_lvl đã được validate — không có SQL injection
    c.execute(
        f"UPDATE stats SET total=total+1, {safe_lvl}={safe_lvl}+1 WHERE date=?",
        (date,)
    )
    conn.commit()
    conn.close()

    if lvl in ("CRITICAL", "WARNING") or source in ("system", "scanner"):
        msg = f"{category} | {message}"
        if ip:    msg += f" ip={ip}"
        if user:  msg += f" user={user}"
        if mitre: msg += f" [{mitre}]"
        log_line(lvl, source, msg)
    return event_id

# ─── COLUMN POSITIONS ─────────────────────────────────────
# id=0, timestamp=1, source=2, level=3, category=4, message=5,
# raw=6, host=7, user=8, ip=9, alerted=10, ack=11, score=12, mitre=13
COL = {k: v for v, k in enumerate(
    ["id","timestamp","source","level","category","message",
     "raw","host","user","ip","alerted","ack","score","mitre"]
)}

def get_events(limit=100, level=None, source=None, hours=24, unacked_only=False):
    conn   = sqlite3.connect(DB_FILE)
    c      = conn.cursor()
    since  = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    query  = "SELECT * FROM events WHERE timestamp >= ?"
    params = [since]
    if level:
        query += " AND level = ?"
        params.append(level.upper())
    if source:
        query += " AND source = ?"
        params.append(source)
    if unacked_only:
        query += " AND ack = 0 AND level IN ('CRITICAL','WARNING')"
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    return rows

def ack_event(event_id):
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute("UPDATE events SET ack=1 WHERE id=?", (event_id,))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def ack_all_events():
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute("UPDATE events SET ack=1 WHERE ack=0 AND level IN ('CRITICAL','WARNING')")
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected

def get_stats(days=7):
    conn  = sqlite3.connect(DB_FILE)
    c     = conn.cursor()
    since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    c.execute("SELECT * FROM stats WHERE date >= ? ORDER BY date DESC", (since,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_summary():
    conn      = sqlite3.connect(DB_FILE)
    c         = conn.cursor()
    since_1h  = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    since_24h = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")

    c.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (since_1h,))
    last_1h = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (since_24h,))
    last_24h = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM events WHERE level='CRITICAL' AND timestamp >= ?", (since_24h,))
    critical_24h = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM events WHERE level='WARNING' AND timestamp >= ?", (since_24h,))
    warning_24h = c.fetchone()[0]

    c.execute("""SELECT COUNT(*) FROM events
                 WHERE ack=0 AND level IN ('CRITICAL','WARNING') AND timestamp >= ?""",
              (since_24h,))
    unacked = c.fetchone()[0]

    c.execute("""SELECT ip, COUNT(*) as cnt FROM events
                 WHERE ip != '' AND timestamp >= ?
                 GROUP BY ip ORDER BY cnt DESC LIMIT 5""", (since_24h,))
    top_ips = c.fetchall()

    c.execute("""SELECT user, COUNT(*) as cnt FROM events
                 WHERE user != '' AND timestamp >= ?
                 GROUP BY user ORDER BY cnt DESC LIMIT 5""", (since_24h,))
    top_users = c.fetchall()

    conn.close()
    return {
        "last_1h":      last_1h,
        "last_24h":     last_24h,
        "critical_24h": critical_24h,
        "warning_24h":  warning_24h,
        "unacked":      unacked,
        "top_ips":      top_ips,
        "top_users":    top_users,
    }

def get_trend(hours=24, by="hour"):
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    now  = datetime.now()
    data = []
    if by == "day":
        for i in range(hours):
            day = (now - timedelta(days=hours - i - 1)).strftime("%Y-%m-%d")
            c.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ? AND timestamp < ?",
                      (f"{day} 00:00:00", f"{day} 23:59:59"))
            data.append({"bucket": day, "count": c.fetchone()[0]})
    else:
        for i in range(hours):
            start_dt = now - timedelta(hours=hours - i)
            end_dt   = start_dt + timedelta(hours=1)
            c.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ? AND timestamp < ?",
                      (start_dt.strftime("%Y-%m-%d %H:00:00"),
                       end_dt.strftime("%Y-%m-%d %H:00:00")))
            data.append({"bucket": start_dt.strftime("%m-%d %H:00"), "count": c.fetchone()[0]})
    conn.close()
    return data

def cleanup_old_events():
    """Xóa events cũ hơn retention.days."""
    cfg    = load_config()
    days   = cfg.getint("retention", "days", fallback=30)
    conn   = sqlite3.connect(DB_FILE)
    c      = conn.cursor()
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    c.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    if deleted > 0:
        log_line("INFO", "db", f"Đã dọn {deleted} events cũ hơn {days} ngày")
    return deleted

def get_db_stats():
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute("SELECT COUNT(*) FROM events")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM events WHERE level='CRITICAL'")
    crits = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM events WHERE ack=0 AND level IN ('CRITICAL','WARNING')")
    unacked = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM whitelist")
    wl = c.fetchone()[0]
    conn.close()
    size_mb = DB_FILE.stat().st_size / 1024 / 1024 if DB_FILE.exists() else 0
    return {"total": total, "critical": crits, "unacked": unacked,
            "whitelist": wl, "size_mb": round(size_mb, 2)}

# ─── WHITELIST ────────────────────────────────────────────
_whitelist_cache      = set()
_whitelist_cache_time = 0.0
_WHITELIST_TTL        = 30  # seconds

def _load_whitelist_ips():
    cfg        = load_config()
    config_ips = {x.strip() for x in cfg.get("whitelist", "ips", fallback="127.0.0.1").split(",") if x.strip()}
    try:
        conn   = sqlite3.connect(DB_FILE)
        c      = conn.cursor()
        c.execute("SELECT ip FROM whitelist")
        db_ips = {row[0] for row in c.fetchall()}
        conn.close()
        return config_ips | db_ips
    except Exception:
        return config_ips

def is_whitelisted(ip):
    global _whitelist_cache, _whitelist_cache_time
    if not ip:
        return False
    now = time.time()
    if now - _whitelist_cache_time > _WHITELIST_TTL:
        with _state_lock:
            _whitelist_cache      = _load_whitelist_ips()
            _whitelist_cache_time = now
    return ip in _whitelist_cache

def add_to_whitelist(ip, reason="manual"):
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT OR REPLACE INTO whitelist (ip, reason, added_at) VALUES (?,?,?)",
              (ip, reason, ts))
    conn.commit()
    conn.close()
    # Invalidate cache
    global _whitelist_cache_time
    _whitelist_cache_time = 0.0
    log_line("INFO", "whitelist", f"Đã thêm {ip} vào whitelist ({reason})")

def remove_from_whitelist(ip):
    conn     = sqlite3.connect(DB_FILE)
    c        = conn.cursor()
    c.execute("DELETE FROM whitelist WHERE ip=?", (ip,))
    affected = c.rowcount
    conn.commit()
    conn.close()
    global _whitelist_cache_time
    _whitelist_cache_time = 0.0
    return affected > 0

def get_whitelist():
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute("SELECT ip, reason, added_at FROM whitelist ORDER BY added_at DESC")
    rows = c.fetchall()
    conn.close()
    return rows

# ─── MITRE ATT&CK TAGGING ─────────────────────────────────
MITRE_MAP = {
    "BRUTE_FORCE":        "T1110",       # Brute Force
    "DIST_BRUTE":         "T1110",       # Brute Force (distributed)
    "LOGIN_FAIL":         "T1110",
    "LOGIN_SUCCESS":      "T1078",       # Valid Accounts
    "SESSION":            "T1078",
    "SUDO":               "T1548.003",   # Abuse Elevation: Sudo
    "SU":                 "T1548.003",
    "USER_MGMT":          "T1136",       # Create Account
    "ACCOUNT_LOCKED":     "T1110",
    "SSH_KEY_CHANGE":     "T1098.004",   # Account Manipulation: SSH Auth Keys
    "FIREWALL_BLOCK":     "T1046",       # Network Service Scanning
    "PORT_SCAN":          "T1046",
    "WEB_SCAN":           "T1190",       # Exploit Public-Facing Application
    "WEB_AUTH_FAIL":      "T1110",
    "SUSPICIOUS_CMD":     "T1059",       # Command and Scripting Interpreter
    "SUSPICIOUS_PORT":    "T1571",       # Non-Standard Port
    "SUSPICIOUS_PROCESS": "T1059",
    "SUSPICIOUS_CONNECT": "T1071",       # Application Layer Protocol
    "FILE_ACCESS":        "T1083",       # File and Directory Discovery
    "PERM_CHANGE":        "T1222",       # File Permissions Modification
    "SUID_CHANGE":        "T1548.001",   # Setuid / Setgid
    "CRON_CHANGE":        "T1053.003",   # Scheduled Task: Cron
    "AUTO_BAN":           "T1562",       # Impair Defenses
    "AUTO_UNBAN":         "",
    "HONEYPOT":           "T1190",       # Exploit Public-Facing Application
    "LAN_FLOOD":          "T1498",       # Network Denial of Service
    "MALWARE_SCAN":       "T1204",       # User Execution: Malicious File
    "POSTURE":            "T1562",       # Impair Defenses
    "POSTURE_RESOLVED":   "",
}

# ─── RISK SCORING (1-10) ──────────────────────────────────
SCORE_MAP = {
    "DIST_BRUTE":         10,
    "BRUTE_FORCE":         9,
    "SUSPICIOUS_CMD":      9,
    "SUID_CHANGE":         9,
    "USER_MGMT":           8,
    "SSH_KEY_CHANGE":      8,
    "ACCOUNT_LOCKED":      7,
    "PORT_SCAN":           7,
    "SUSPICIOUS_CONNECT":  7,
    "CRON_CHANGE":         7,
    "FILE_ACCESS":         5,
    "SUSPICIOUS_PORT":     6,
    "SUSPICIOUS_PROCESS":  6,
    "WEB_SCAN":            5,
    "PERM_CHANGE":         5,
    "SUDO":                3,
    "SU":                  3,
    "WEB_AUTH_FAIL":       3,
    "LOGIN_FAIL":          3,
    "FIREWALL_BLOCK":      2,
    "WEB_ERROR":           2,
    "LOGIN_SUCCESS":       1,
    "SESSION":             1,
    "WEB_WRITE":           1,
    "AUTO_BAN":            0,
    "AUTO_UNBAN":          0,
    "HONEYPOT":           10,
    "LAN_FLOOD":           9,
    "MALWARE_SCAN":       10,
    "POSTURE":             6,
    "POSTURE_RESOLVED":    0,
}

def get_mitre(category): return MITRE_MAP.get(category, "")
def get_score(category): return SCORE_MAP.get(category, 1)

# ─── ALERTS ───────────────────────────────────────────────
def send_desktop_alert(title, message, urgency="normal"):
    try:
        subprocess.Popen([
            "notify-send", "-u", urgency, "-a", "ZuSIEM",
            f"🛡️ ZuSIEM: {title}", message
        ])
    except Exception as e:
        log_line("ERROR", "alert", f"Desktop notification failed: {e}")

def send_telegram_alert(title, message):
    cfg     = load_config()
    token   = decrypt(cfg.get("telegram", "token", fallback=""))
    chat_id = cfg.get("telegram", "chat_id", fallback="")
    if not token or not chat_id:
        return
    try:
        import urllib.request, urllib.parse
        text = (f"🛡️ *ZuSIEM Alert*\n\n*{title}*\n`{message}`\n\n"
                f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        data = urllib.parse.urlencode({
            "chat_id": chat_id, "text": text, "parse_mode": "Markdown"
        }).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage", data=data
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        log_line("ERROR", "alert", f"Telegram failed: {e}")

def send_telegram_message(text):
    cfg     = load_config()
    token   = decrypt(cfg.get("telegram", "token", fallback=""))
    chat_id = cfg.get("telegram", "chat_id", fallback="")
    if not token or not chat_id:
        return False
    try:
        import urllib.request, urllib.parse
        data = urllib.parse.urlencode({
            "chat_id": chat_id, "text": text, "parse_mode": "Markdown"
        }).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage", data=data
        )
        urllib.request.urlopen(req, timeout=8)
        return True
    except Exception as e:
        log_line("ERROR", "telegram", f"sendMessage failed: {e}")
        return False

def send_email_report(subject, body):
    cfg = load_config()
    if not cfg.getboolean("reports", "email_enabled", fallback=False):
        return
    host     = cfg.get("email", "smtp_host", fallback="")
    port     = cfg.getint("email", "smtp_port", fallback=587)
    username = cfg.get("email", "username", fallback="")
    password = decrypt(cfg.get("email", "password", fallback=""))
    to_addr  = cfg.get("email", "to", fallback="")
    use_tls  = cfg.getboolean("email", "use_tls", fallback=True)
    if not host or not to_addr:
        return
    try:
        msg             = MIMEText(body, "plain", "utf-8")
        msg["Subject"]  = subject
        msg["From"]     = username or "zusiem@localhost"
        msg["To"]       = to_addr
        with smtplib.SMTP(host, port, timeout=15) as s:
            if use_tls:
                s.starttls()
            if username and password:
                s.login(username, password)
            s.send_message(msg)
    except Exception as e:
        log_line("ERROR", "report", f"send mail failed: {e}")

def send_discord_alert(title, message, level="WARNING"):
    cfg = load_config()
    if not cfg.getboolean("discord", "enabled", fallback=False):
        return
    webhook_url = decrypt(cfg.get("discord", "webhook_url", fallback=""))
    if not webhook_url:
        return
    try:
        import urllib.request, socket
        color_map = {"CRITICAL": 0xFF3B5C, "WARNING": 0xFFCC00, "INFO": 0x4488FF}
        emoji_map = {"CRITICAL": "🚨", "WARNING": "⚠️", "INFO": "ℹ️"}
        payload = json.dumps({
            "username": "ZuSIEM",
            "embeds": [{
                "title":       f"{emoji_map.get(level,'🛡️')} {title}",
                "description": f"```{message[:1000]}```",
                "color":       color_map.get(level, 0x4488FF),
                "fields": [
                    {"name": "Mức độ", "value": level, "inline": True},
                    {"name": "Host",   "value": socket.gethostname(), "inline": True},
                ],
                "footer": {"text": f"ZuSIEM • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}
            }]
        }).encode("utf-8")
        req = urllib.request.Request(
            webhook_url, data=payload,
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        log_line("ERROR", "discord", f"webhook failed: {e}")

_alert_cooldown    = {}
_ALERT_COOLDOWN_SEC = 60

def alert(level, title, message):
    key = f"{level}:{title}"
    now = time.time()
    with _state_lock:
        if key in _alert_cooldown and now - _alert_cooldown[key] < _ALERT_COOLDOWN_SEC:
            return
        _alert_cooldown[key] = now

    cfg              = load_config()
    desktop_enabled  = cfg.getboolean("alerts", "desktop",  fallback=True)
    telegram_enabled = cfg.getboolean("alerts", "telegram", fallback=False)
    discord_enabled  = cfg.getboolean("discord", "enabled", fallback=False)
    urgency_map      = {"CRITICAL": "critical", "WARNING": "normal", "INFO": "low"}
    urgency          = urgency_map.get(level, "normal")

    if desktop_enabled  and level in ("CRITICAL", "WARNING"): send_desktop_alert(title, message, urgency)
    if telegram_enabled and level in ("CRITICAL", "WARNING"): send_telegram_alert(title, message)
    if discord_enabled  and level in ("CRITICAL", "WARNING"): send_discord_alert(title, message, level)

def format_summary_text(title="ZuSIEM Summary"):
    s = get_summary()
    lines = [
        f"*{title}*", "",
        f"- Last 1h:    `{s['last_1h']}` events",
        f"- Last 24h:   `{s['last_24h']}` events",
        f"- Critical:   `{s['critical_24h']}`",
        f"- Warning:    `{s['warning_24h']}`",
        f"- Unacked:    `{s['unacked']}` ⚠️",
        "", "*Top IPs:*",
    ]
    lines += [f"  - `{ip}`: {cnt}" for ip, cnt in s["top_ips"]] or ["  - none"]
    lines += ["", "*Top Users:*"]
    lines += [f"  - `{u}`: {cnt}" for u, cnt in s["top_users"]] or ["  - none"]
    return "\n".join(lines)

# ─── DETECTION STATE ──────────────────────────────────────
_failed_logins         = defaultdict(list)   # ip  -> [timestamps]
_failed_logins_by_user = defaultdict(set)    # user -> {ip, ...}  (distributed BF)
_auto_banned_ips       = set()
_port_scan_tracker     = defaultdict(set)    # ip  -> {port, ...}
_port_scan_time        = defaultdict(float)  # ip  -> first_seen epoch

# ─── AUTO-BAN ─────────────────────────────────────────────
_PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                 ("127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12")]

def _is_private_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETS)

def maybe_auto_ban_ip(ip, reason):
    cfg = load_config()
    if not cfg.getboolean("security", "auto_ban_enabled", fallback=False):
        return
    if not ip or _is_private_ip(ip):
        return
    with _state_lock:
        if ip in _auto_banned_ips:
            return
    try:
        cmd = ["ufw", "insert", "1", "deny", "from", ip, "comment", f"ZuSIEM {reason}"]
        r   = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            with _state_lock:
                _auto_banned_ips.add(ip)
            msg = f"Auto-ban IP qua UFW: {ip} ({reason})"
            insert_event("ufw", "CRITICAL", "AUTO_BAN", msg, ip=ip,
                         score=get_score("AUTO_BAN"), mitre=get_mitre("AUTO_BAN"))
            alert("CRITICAL", "UFW Auto-ban", msg)
        else:
            log_line("ERROR", "ban", f"ufw failed for {ip}: {r.stderr.strip()}")
    except Exception as e:
        log_line("ERROR", "ban", f"auto ban failed for {ip}: {e}")

# ─── BRUTE FORCE DETECTION ────────────────────────────────
def check_bruteforce(ip, user):
    if is_whitelisted(ip):
        return
    cfg       = load_config()
    threshold = cfg.getint("thresholds", "brute_force_count",  fallback=5)
    window    = cfg.getint("thresholds", "brute_force_window", fallback=300)
    dist_src  = cfg.getint("detection",  "distributed_bf_sources", fallback=3)
    now       = time.time()

    with _state_lock:
        _failed_logins[ip] = [t for t in _failed_logins[ip] if now - t < window]
        _failed_logins[ip].append(now)
        count = len(_failed_logins[ip])

        _failed_logins_by_user[user].add(ip)
        user_ip_count = len(_failed_logins_by_user[user])

    if count >= threshold:
        msg = f"Brute-force: IP={ip} User={user} ({count} lần/{window}s)"
        insert_event("auth.log", "CRITICAL", "BRUTE_FORCE", msg, ip=ip, user=user,
                     score=get_score("BRUTE_FORCE"), mitre=get_mitre("BRUTE_FORCE"))
        alert("CRITICAL", "Brute-Force Attack!", msg)
        maybe_auto_ban_ip(ip, "bruteforce")
        with _state_lock:
            _failed_logins[ip] = []

    if user_ip_count >= dist_src:
        msg = f"Distributed brute-force: user={user} từ {user_ip_count} IP khác nhau"
        insert_event("auth.log", "CRITICAL", "DIST_BRUTE", msg, user=user,
                     score=get_score("DIST_BRUTE"), mitre=get_mitre("DIST_BRUTE"))
        alert("CRITICAL", "Distributed Brute-Force!", msg)
        with _state_lock:
            _failed_logins_by_user[user] = set()

# ─── PORT SCAN DETECTION ──────────────────────────────────
def check_port_scan(ip, port):
    if is_whitelisted(ip):
        return
    cfg       = load_config()
    threshold = cfg.getint("detection", "port_scan_count",  fallback=10)
    window    = cfg.getint("detection", "port_scan_window", fallback=60)
    now       = time.time()

    with _state_lock:
        if now - _port_scan_time.get(ip, 0) > window:
            _port_scan_tracker[ip] = set()
        _port_scan_time[ip] = now
        _port_scan_tracker[ip].add(port)
        count = len(_port_scan_tracker[ip])

    if count >= threshold:
        msg = f"Port scan: IP={ip} quét {count} cổng trong {window}s"
        insert_event("ufw", "CRITICAL", "PORT_SCAN", msg, ip=ip,
                     score=get_score("PORT_SCAN"), mitre=get_mitre("PORT_SCAN"))
        alert("CRITICAL", "Port Scan Detected!", msg)
        maybe_auto_ban_ip(ip, "portscan")
        with _state_lock:
            _port_scan_tracker[ip] = set()

# ─── PARSERS ──────────────────────────────────────────────
def parse_auth_log(line):
    # Failed password (IPv4 + IPv6)
    m = re.search(r"Failed password for (?:invalid user )?(\S+) from ([\d.:a-fA-F]+)", line)
    if m:
        user, ip = m.group(1), m.group(2)
        if not is_whitelisted(ip):
            insert_event("auth.log", "WARNING", "LOGIN_FAIL",
                         f"Login thất bại: user={user} ip={ip}",
                         raw=line.strip(), user=user, ip=ip,
                         score=get_score("LOGIN_FAIL"), mitre=get_mitre("LOGIN_FAIL"))
            check_bruteforce(ip, user)
        return

    # Accepted login
    m = re.search(r"Accepted (\S+) for (\S+) from ([\d.:a-fA-F]+)", line)
    if m:
        method, user, ip = m.group(1), m.group(2), m.group(3)
        insert_event("auth.log", "INFO", "LOGIN_SUCCESS",
                     f"Login thành công: user={user} method={method} ip={ip}",
                     raw=line.strip(), user=user, ip=ip,
                     score=get_score("LOGIN_SUCCESS"), mitre=get_mitre("LOGIN_SUCCESS"))
        return

    # sudo — phân biệt lệnh nguy hiểm
    m = re.search(r"sudo:\s+(\S+) : .* COMMAND=(.*)", line)
    if m:
        user, cmd = m.group(1), m.group(2).strip()
        danger_cmds = [
            "passwd", "visudo", "chmod 777", "rm -rf", "chmod +s", "chown root",
            "/etc/shadow", "sudoers", "pkill", "kill -9", "iptables -F",
            "ufw disable", "systemctl disable", "service stop",
        ]
        level = "WARNING" if any(x in cmd for x in danger_cmds) else "INFO"
        insert_event("auth.log", level, "SUDO",
                     f"sudo: user={user} cmd={cmd[:100]}",
                     raw=line.strip(), user=user,
                     score=get_score("SUDO"), mitre=get_mitre("SUDO"))
        return

    # su
    m = re.search(r"su: .*(Successful|FAILED) su for (\S+) by (\S+)", line)
    if m:
        status, target, by = m.group(1), m.group(2), m.group(3)
        level = "WARNING" if status == "FAILED" else "INFO"
        insert_event("auth.log", level, "SU",
                     f"su {status}: {by} -> {target}",
                     raw=line.strip(), user=by,
                     score=get_score("SU"), mitre=get_mitre("SU"))
        return

    # Tài khoản mới được tạo
    if "new user:" in line or "useradd" in line:
        insert_event("auth.log", "WARNING", "USER_MGMT",
                     f"Tài khoản mới: {line.strip()[:100]}",
                     raw=line.strip(),
                     score=get_score("USER_MGMT"), mitre=get_mitre("USER_MGMT"))
        alert("WARNING", "Tài khoản mới!", line.strip()[:80])
        return

    # Tài khoản bị xóa
    if "userdel" in line or "deleted user" in line.lower():
        insert_event("auth.log", "WARNING", "USER_MGMT",
                     f"Tài khoản bị xóa: {line.strip()[:100]}",
                     raw=line.strip(),
                     score=get_score("USER_MGMT"), mitre=get_mitre("USER_MGMT"))
        alert("WARNING", "Tài khoản bị xóa!", line.strip()[:80])
        return

    # SSH authorized_keys thay đổi
    if "authorized_keys" in line:
        insert_event("auth.log", "WARNING", "SSH_KEY_CHANGE",
                     f"SSH authorized_keys thay đổi: {line.strip()[:100]}",
                     raw=line.strip(),
                     score=get_score("SSH_KEY_CHANGE"), mitre=get_mitre("SSH_KEY_CHANGE"))
        alert("WARNING", "SSH Key thay đổi!", line.strip()[:80])
        return

    # PAM authentication failure
    m = re.search(r"pam_unix\(.*\): authentication failure.*user=(\S+)", line)
    if m:
        user = m.group(1)
        insert_event("auth.log", "WARNING", "LOGIN_FAIL",
                     f"PAM auth failure: user={user}",
                     raw=line.strip(), user=user,
                     score=get_score("LOGIN_FAIL"), mitre=get_mitre("LOGIN_FAIL"))
        return

    # Tài khoản bị khóa
    if "account locked" in line.lower() or "maximum amount of failed" in line.lower():
        m    = re.search(r"user[= ](\S+)", line)
        user = m.group(1) if m else "unknown"
        insert_event("auth.log", "WARNING", "ACCOUNT_LOCKED",
                     f"Tài khoản bị khóa: user={user}",
                     raw=line.strip(), user=user,
                     score=get_score("ACCOUNT_LOCKED"), mitre=get_mitre("ACCOUNT_LOCKED"))
        alert("WARNING", "Tài khoản bị khóa!", f"user={user}")
        return

    # Session opened
    m = re.search(r"session opened for user (\S+)", line)
    if m:
        user = m.group(1)
        insert_event("auth.log", "INFO", "SESSION",
                     f"Session mở: user={user}",
                     raw=line.strip(), user=user,
                     score=get_score("SESSION"), mitre=get_mitre("SESSION"))


def parse_ufw_log(line):
    if "[UFW BLOCK]" not in line:
        return

    ip_m    = re.search(r"SRC=([\d.]+)", line)
    dst_m   = re.search(r"DST=([\d.]+)", line)
    dpt_m   = re.search(r"DPT=(\d+)", line)
    spt_m   = re.search(r"SPT=(\d+)", line)
    proto_m = re.search(r"PROTO=(\S+)", line)

    src   = ip_m.group(1)    if ip_m    else "?"
    dst   = dst_m.group(1)   if dst_m   else "?"
    dpt   = dpt_m.group(1)   if dpt_m   else "?"
    spt   = spt_m.group(1)   if spt_m   else "?"
    proto = proto_m.group(1) if proto_m else "?"

    if is_whitelisted(src):
        return

    sensitive_ports = {
        "21", "22", "23", "25", "445", "139", "3389",
        "3306", "5432", "6379", "27017", "2222", "8080", "9200", "5900",
    }
    level = "WARNING" if dpt in sensitive_ports else "INFO"
    msg   = f"UFW BLOCK: {src}:{spt} -> {dst}:{dpt} ({proto})"
    insert_event("ufw", level, "FIREWALL_BLOCK", msg, raw=line.strip(), ip=src,
                 score=get_score("FIREWALL_BLOCK"), mitre=get_mitre("FIREWALL_BLOCK"))

    if level == "WARNING":
        alert("WARNING", f"Cổng nhạy cảm bị quét! Port {dpt}", msg)

    if dpt.isdigit():
        check_port_scan(src, int(dpt))


def parse_nginx_log(line):
    m = re.search(
        r'([\d.:a-fA-F]+) - \S+ \[[^\]]+\] "(\S+) ([^"]*) HTTP/[\d.]+" (\d+)',
        line
    )
    if not m:
        return
    ip, method, path, status = m.group(1), m.group(2), m.group(3), m.group(4)
    if is_whitelisted(ip):
        return
    status_i = int(status)
    path     = path[:120]

    sensitive_paths = [
        "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/etc/passwd",
        "/shell", "/cmd", "/.git", "/config", "/backup", "/.aws",
        "/actuator", "/console", "/manager", "/api/v1/pods", "/.well-known",
    ]
    if any(p in path for p in sensitive_paths):
        msg = f"Web scan: {method} {path} → {status} ip={ip}"
        insert_event("nginx", "WARNING", "WEB_SCAN", msg, raw=line.strip(), ip=ip,
                     score=get_score("WEB_SCAN"), mitre=get_mitre("WEB_SCAN"))
        alert("WARNING", f"Web Scan từ {ip}", f"{method} {path[:60]} → {status}")
    elif status_i in (401, 403):
        insert_event("nginx", "WARNING", "WEB_AUTH_FAIL",
                     f"{method} {path} → {status}", raw=line.strip(), ip=ip,
                     score=get_score("WEB_AUTH_FAIL"), mitre=get_mitre("WEB_AUTH_FAIL"))
    elif status_i >= 500:
        insert_event("nginx", "WARNING", "WEB_ERROR",
                     f"{method} {path} → {status}", raw=line.strip(), ip=ip,
                     score=get_score("WEB_ERROR"), mitre="")
    elif status_i == 200 and method in ("POST", "PUT", "DELETE", "PATCH"):
        insert_event("nginx", "INFO", "WEB_WRITE",
                     f"{method} {path} → {status}", raw=line.strip(), ip=ip,
                     score=get_score("WEB_WRITE"), mitre="")


def parse_audit_log(line):
    # execve — lệnh nguy hiểm
    if "type=EXECVE" in line:
        m   = re.search(r'a0="([^"]+)"', line)
        cmd = m.group(1) if m else ""
        danger_patterns = [
            "nc ", "ncat", "nmap", "wget http", "curl http", "/tmp/", "base64 -d",
            "python -c", "python3 -c", "bash -i", "perl -e", "ruby -e",
            "php -r", "/dev/tcp", "/dev/udp", "mkfifo", "msfvenom", "msfconsole",
        ]
        if any(d in line for d in danger_patterns):
            insert_event("auditd", "CRITICAL", "SUSPICIOUS_CMD",
                         f"Lệnh đáng ngờ: {cmd}",
                         raw=line.strip(),
                         score=get_score("SUSPICIOUS_CMD"), mitre=get_mitre("SUSPICIOUS_CMD"))
            alert("CRITICAL", "Lệnh đáng ngờ!", f"cmd={cmd}")
        return

    # PATH — file nhạy cảm bị truy cập/sửa
    if "type=PATH" in line:
        path_map = {
            "/etc/passwd":   "FILE_ACCESS",
            "/etc/shadow":   "FILE_ACCESS",
            "/etc/sudoers":  "FILE_ACCESS",
            "/root/.ssh":    "SSH_KEY_CHANGE",
            "/etc/crontab":  "CRON_CHANGE",
            "/etc/cron.d":   "CRON_CHANGE",
            "/boot/":        "FILE_ACCESS",
            "/etc/ld.so":    "FILE_ACCESS",
        }
        for path, category in path_map.items():
            if path in line:
                insert_event("auditd", "WARNING", category,
                             f"Truy cập file nhạy cảm: {path}",
                             raw=line.strip(),
                             score=get_score(category), mitre=get_mitre(category))
                alert("WARNING", "File nhạy cảm!", f"File: {path}")
                return

    # chmod — phát hiện SUID/SGID
    if "type=SYSCALL" in line and ("chmod" in line or "fchmod" in line):
        # a1=4xxx=SUID, a1=2xxx=SGID
        if re.search(r"\ba1=0?[42]\d{3}\b", line):
            insert_event("auditd", "CRITICAL", "SUID_CHANGE",
                         "SUID/SGID bit được set trên file",
                         raw=line.strip(), score=9, mitre=get_mitre("SUID_CHANGE"))
            alert("CRITICAL", "SUID/SGID Change!", "Phát hiện thay đổi SUID/SGID bit")
        else:
            insert_event("auditd", "WARNING", "PERM_CHANGE",
                         "Thay đổi quyền file",
                         raw=line.strip(),
                         score=get_score("PERM_CHANGE"), mitre=get_mitre("PERM_CHANGE"))
        return

    # connect syscall từ process đáng ngờ
    if "type=SYSCALL" in line and "connect" in line:
        m    = re.search(r'comm="([^"]+)"', line)
        comm = m.group(1) if m else ""
        if comm in ("nc", "ncat", "bash", "sh", "python", "python3", "perl", "ruby"):
            insert_event("auditd", "WARNING", "SUSPICIOUS_CONNECT",
                         f"Process '{comm}' tạo kết nối mạng",
                         raw=line.strip(),
                         score=get_score("SUSPICIOUS_CONNECT"),
                         mitre=get_mitre("SUSPICIOUS_CONNECT"))

# ─── LOG WATCHERS ─────────────────────────────────────────
def tail_file(filepath, parser_func, name):
    log_line("INFO", "watch", f"Watching {name}: {filepath}")
    try:
        with open(filepath, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    try:
                        parser_func(line)
                    except Exception as e:
                        log_line("ERROR", name, f"parse error: {e}")
                else:
                    time.sleep(0.5)
    except PermissionError:
        log_line("ERROR", "watch", f"Permission denied: {filepath} (cần sudo hoặc group adm)")
    except FileNotFoundError:
        log_line("ERROR", "watch", f"File không tồn tại: {filepath}")

def tail_journald(unit, parser_func, name):
    log_line("INFO", "watch", f"Watching journald unit: {unit}")
    try:
        proc = subprocess.Popen(
            ["journalctl", "-u", unit, "-f", "-n", "0", "--no-pager"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        for line in proc.stdout:
            try:
                parser_func(line)
            except Exception as e:
                log_line("ERROR", name, f"journald parse error: {e}")
    except Exception as e:
        log_line("ERROR", "watch", f"journald watch failed for {unit}: {e}")

def _extract_ip_from_ss(line):
    ip_match = re.findall(r"(\d+\.\d+\.\d+\.\d+):\d+", line)
    return ip_match[0] if ip_match else ""

# ─── BACKGROUND LOOPS ─────────────────────────────────────
def scan_anomalies_loop():
    cfg = load_config()
    if not cfg.getboolean("scanner", "enabled", fallback=True):
        return
    interval     = cfg.getint("scanner", "interval_sec", fallback=300)
    bad_ports    = {int(p.strip()) for p in
                    cfg.get("scanner", "suspicious_ports",
                            fallback="4444,5555,1337,31337").split(",")
                    if p.strip().isdigit()}
    bad_proc_kw  = [x.strip() for x in
                    cfg.get("scanner", "suspicious_process_keywords",
                            fallback="ncat,nmap,masscan,socat,hydra,metasploit").split(",")
                    if x.strip()]

    seen_ports = set()
    seen_procs = set()

    while True:
        try:
            ss = subprocess.run(["ss", "-tunap"], capture_output=True, text=True, timeout=8)
            if ss.returncode == 0:
                for line in ss.stdout.splitlines():
                    dpt = re.search(r":(\d+)\s", line)
                    if not dpt:
                        continue
                    port = int(dpt.group(1))
                    if port in bad_ports:
                        key = f"{port}:{line[:80]}"
                        if key not in seen_ports:
                            seen_ports.add(key)
                            ip  = _extract_ip_from_ss(line)
                            msg = f"Cổng đáng ngờ đang lắng nghe: {port}"
                            insert_event("scanner", "WARNING", "SUSPICIOUS_PORT",
                                         msg, raw=line.strip(), ip=ip,
                                         score=get_score("SUSPICIOUS_PORT"),
                                         mitre=get_mitre("SUSPICIOUS_PORT"))

            ps = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=8)
            if ps.returncode == 0:
                for line in ps.stdout.splitlines():
                    low = line.lower()
                    for kw in bad_proc_kw:
                        if kw.lower() in low:
                            # Dùng PID làm key — không re-alert cùng 1 process
                            parts = line.split(None, 2)
                            pid = parts[1] if len(parts) > 1 else line[:20]
                            key = f"{kw}:{pid}"
                            if key not in seen_procs:
                                seen_procs.add(key)
                                insert_event("scanner", "WARNING", "SUSPICIOUS_PROCESS",
                                             f"Process đáng ngờ: '{kw}'",
                                             raw=line.strip()[:200],
                                             score=get_score("SUSPICIOUS_PROCESS"),
                                             mitre=get_mitre("SUSPICIOUS_PROCESS"))
                            break

            # Giới hạn bộ nhớ seen sets
            if len(seen_ports) > 500: seen_ports.clear()
            if len(seen_procs) > 500: seen_procs.clear()

            # Dọn DB theo retention policy
            cleanup_old_events()

        except Exception as e:
            log_line("ERROR", "scanner", f"anomaly scan failed: {e}")
        time.sleep(max(30, interval))

def daily_report_loop():
    cfg = load_config()
    if not cfg.getboolean("reports", "daily_enabled", fallback=False):
        return
    at        = cfg.get("reports", "daily_at", fallback="08:00")
    sent_date = ""
    while True:
        try:
            now = datetime.now()
            if now.strftime("%H:%M") == at and sent_date != now.strftime("%Y-%m-%d"):
                text = format_summary_text("ZuSIEM Daily Report")
                if cfg.getboolean("reports", "telegram_enabled", fallback=True):
                    send_telegram_message(text)
                send_email_report("ZuSIEM Daily Report", text)
                sent_date = now.strftime("%Y-%m-%d")
                insert_event("system", "INFO", "DAILY_REPORT_SENT",
                             "Đã gửi báo cáo hàng ngày")
        except Exception as e:
            log_line("ERROR", "report", f"daily report failed: {e}")
        time.sleep(30)

def telegram_command_loop():
    cfg          = load_config()
    if not cfg.getboolean("telegram", "commands_enabled", fallback=True):
        return
    token        = decrypt(cfg.get("telegram", "token", fallback=""))
    allowed_chat = cfg.get("telegram", "chat_id", fallback="")
    if not token:
        return
    import urllib.request
    offset    = 0
    backoff   = 5
    while True:
        try:
            url = (f"https://api.telegram.org/bot{token}"
                   f"/getUpdates?timeout=20&offset={offset}")
            with urllib.request.urlopen(url, timeout=25) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            backoff = 5  # reset khi thành công
            for item in payload.get("result", []):
                offset   = item["update_id"] + 1
                msg      = item.get("message", {})
                chat_id  = str(msg.get("chat", {}).get("id", ""))
                text     = (msg.get("text") or "").strip()
                if not text.startswith("/"):
                    continue
                parts = text.split()
                # Trong group chat lệnh có dạng /status@BotName → chỉ lấy phần trước @
                cmd   = parts[0].split("@")[0].lower()
                # /chatid luôn trả lời (giúp tìm ID group mới) — mọi lệnh khác cần khớp chat_id
                if cmd != "/chatid" and allowed_chat and chat_id != allowed_chat:
                    continue

                if cmd == "/status":
                    send_telegram_message(format_summary_text("ZuSIEM Status"))

                elif cmd == "/critical":
                    events = get_events(limit=10, level="CRITICAL", hours=24)
                    lines  = ["*Last 10 Critical (🔴=unacked ✅=acked)*"]
                    for e in events:
                        mark = "✅" if e[COL["ack"]] else "🔴"
                        lines.append(f"{mark} `{e[1]}` {e[4]} `{e[9] or '-'}`")
                    send_telegram_message("\n".join(lines))

                elif cmd == "/unacked":
                    events = get_events(limit=10, unacked_only=True, hours=24)
                    lines  = [f"*Unacked alerts ({len(events)})*"]
                    for e in events:
                        lines.append(f"🔴 #{e[0]} `{e[1]}` {e[4]} `{e[9] or '-'}`")
                    send_telegram_message("\n".join(lines) if events else "✅ Không có alert chưa xử lý")

                elif cmd == "/banlist":
                    with _state_lock:
                        bans = sorted(_auto_banned_ips)
                    msg_txt = ("*Auto-banned IPs:*\n" + "\n".join(f"- `{ip}`" for ip in bans)
                               if bans else "Chưa có IP nào bị ban tự động.")
                    send_telegram_message(msg_txt)

                elif cmd == "/ban" and len(parts) >= 2:
                    ip_to_ban = parts[1]
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip_to_ban):
                        maybe_auto_ban_ip(ip_to_ban, "manual-telegram")
                        send_telegram_message(f"✅ Đã ban IP: `{ip_to_ban}` qua UFW")
                    else:
                        send_telegram_message("❌ IP không hợp lệ")

                elif cmd == "/whitelist" and len(parts) >= 2:
                    ip_to_wl = parts[1]
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip_to_wl):
                        add_to_whitelist(ip_to_wl, "telegram")
                        send_telegram_message(f"✅ Đã thêm `{ip_to_wl}` vào whitelist")
                    else:
                        send_telegram_message("❌ IP không hợp lệ")

                elif cmd == "/top":
                    s     = get_summary()
                    lines = ["*Top IPs (24h):*"]
                    lines += [f"- `{ip}`: {cnt}" for ip, cnt in s["top_ips"]]
                    send_telegram_message("\n".join(lines) if s["top_ips"] else "Không có dữ liệu")

                elif cmd == "/ackall":
                    n = ack_all_events()
                    send_telegram_message(f"✅ Đã xác nhận {n} alerts")

                elif cmd == "/chatid":
                    # Lệnh helper để tìm chat_id của group — xóa khỏi config sau khi dùng
                    send_telegram_message(
                        f"🆔 Chat ID của chat này: `{chat_id}`\n"
                        f"Cập nhật vào siem.conf:\n`chat_id = {chat_id}`"
                    )

                elif cmd == "/help":
                    send_telegram_message(
                        "*ZuSIEM Commands:*\n"
                        "/status — Tổng quan\n"
                        "/critical — Critical events\n"
                        "/unacked — Alerts chưa xử lý\n"
                        "/top — Top IPs đáng ngờ\n"
                        "/ban `<ip>` — Ban IP qua UFW\n"
                        "/whitelist `<ip>` — Thêm vào whitelist\n"
                        "/banlist — Danh sách IP bị ban\n"
                        "/ackall — Xác nhận tất cả alerts\n"
                        "/help — Trợ giúp"
                    )
                else:
                    send_telegram_message("Gõ /help để xem danh sách lệnh")

        except Exception as e:
            log_line("ERROR", "telegram", f"command loop error: {e}")
            time.sleep(min(backoff, 120))
            backoff = min(backoff * 2, 120)  # exponential backoff tối đa 2 phút

# ─── EXPORT ───────────────────────────────────────────────
def export_events(hours=24, limit=1000, level=None, source=None):
    rows   = get_events(limit=limit, level=level, source=source, hours=hours)
    result = []
    for e in rows:
        result.append({
            "id":        e[COL["id"]],
            "timestamp": e[COL["timestamp"]],
            "source":    e[COL["source"]],
            "level":     e[COL["level"]],
            "category":  e[COL["category"]],
            "message":   e[COL["message"]],
            "host":      e[COL["host"]],
            "user":      e[COL["user"]]  or "",
            "ip":        e[COL["ip"]]    or "",
            "ack":       bool(e[COL["ack"]]),
            "score":     e[COL["score"]],
            "mitre":     e[COL["mitre"]] or "",
        })
    return result

# ─── MAIN ─────────────────────────────────────────────────
def start_watchers():
    check_config_permissions()
    cfg        = load_config()
    auth_path  = cfg.get("log_paths", "auth",  fallback="/var/log/auth.log")
    kern_path  = cfg.get("log_paths", "kern",  fallback="/var/log/kern.log")
    audit_path = cfg.get("log_paths", "audit", fallback="/var/log/audit/audit.log")
    nginx_path = cfg.get("log_paths", "nginx", fallback="")

    sources = [
        (auth_path,  parse_auth_log,  "auth"),
        (kern_path,  parse_ufw_log,   "ufw"),
        (audit_path, parse_audit_log, "audit"),
    ]
    if nginx_path:
        sources.append((nginx_path, parse_nginx_log, "nginx"))

    threads = []
    for filepath, parser, name in sources:
        t = threading.Thread(target=tail_file, args=(filepath, parser, name), daemon=True)
        t.start()
        threads.append(t)

    log_line("INFO", "system", "ZuSIEM Engine đang chạy... (Ctrl+C để dừng)")
    insert_event("system", "INFO", "SIEM_START", "ZuSIEM engine khởi động")

    bg_jobs = [
        threading.Thread(target=telegram_command_loop, daemon=True),
        threading.Thread(target=daily_report_loop,     daemon=True),
        threading.Thread(target=scan_anomalies_loop,   daemon=True),
    ]
    for t in bg_jobs:
        t.start()
        threads.append(t)
    return threads

if __name__ == "__main__":
    init_db()
    threads = start_watchers()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_line("INFO", "system", "ZuSIEM dừng.")

# ─── OLLAMA AI ANALYSIS ───────────────────────────────────
def get_recent_events_text(hours=1, limit=20):
    events = get_events(limit=limit, hours=hours)
    if not events:
        return "Không có sự kiện nào trong thời gian này."
    lines = []
    for e in events:
        line = (f"[{e[COL['timestamp']]}] {e[COL['level']]} | "
                f"{e[COL['source']]} | {e[COL['category']]} | {e[COL['message']]}")
        if e[COL["ip"]]:    line += f" | IP: {e[COL['ip']]}"
        if e[COL["user"]]:  line += f" | User: {e[COL['user']]}"
        if e[COL["mitre"]]: line += f" | MITRE: {e[COL['mitre']]}"
        lines.append(line)
    return "\n".join(lines)


def analyze_with_ollama(events_text: str, question: str = None) -> str:
    import urllib.request, json as _json
    cfg     = load_config()
    enabled = cfg.getboolean("ollama", "enabled", fallback=False)
    if not enabled:
        return "Ollama chưa được bật. Đặt enabled=true trong [ollama] siem.conf"

    host    = cfg.get("ollama",    "host",    fallback="http://localhost:11434")
    model   = cfg.get("ollama",    "model",   fallback="qwen2.5-coder:7b")
    timeout = cfg.getint("ollama", "timeout", fallback=60)

    if question:
        prompt = (f"Bạn là chuyên gia bảo mật Linux (Blue Team).\n\n"
                  f"Log SIEM:\n{events_text}\n\n"
                  f"Câu hỏi: {question}\n\nTrả lời ngắn gọn bằng tiếng Việt.")
    else:
        prompt = (f"Bạn là chuyên gia bảo mật Linux (Blue Team). Phân tích log SIEM sau:\n\n"
                  f"{events_text}\n\n"
                  f"1. Tóm tắt tình trạng bảo mật\n"
                  f"2. Mối đe dọa đáng chú ý (nếu có)\n"
                  f"3. Đề xuất hành động cụ thể\n\n"
                  f"Trả lời ngắn gọn bằng tiếng Việt.")
    try:
        payload = _json.dumps({
            "model":   model,
            "prompt":  prompt,
            "stream":  False,
            "options": {"temperature": 0.3, "num_predict": 512}
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{host}/api/generate", data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = _json.loads(resp.read().decode("utf-8"))
            return data.get("response", "Không có phản hồi từ Ollama")
    except urllib.error.URLError:
        return f"Không kết nối được Ollama tại {host}. Kiểm tra: ollama serve"
    except Exception as e:
        return f"Lỗi Ollama: {str(e)}"


def list_ollama_models() -> list:
    import urllib.request, json as _json
    cfg  = load_config()
    host = cfg.get("ollama", "host", fallback="http://localhost:11434")
    try:
        with urllib.request.urlopen(f"{host}/api/tags", timeout=5) as resp:
            data = _json.loads(resp.read())
            return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


def check_ollama_status() -> dict:
    import urllib.request
    cfg  = load_config()
    host = cfg.get("ollama", "host", fallback="http://localhost:11434")
    try:
        with urllib.request.urlopen(f"{host}/api/tags", timeout=3) as resp:
            if resp.status == 200:
                return {"running": True, "models": list_ollama_models(), "host": host}
    except Exception:
        pass
    return {"running": False, "models": [], "host": host}