import os
import sys
import time
import struct
import random
import socket
import threading
import subprocess
from functools import partial
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from siem_engine import insert_event, init_db, alert, load_config  # noqa: E402

# ─── CẤU HÌNH ──────────────────────────────────────────────────────────────
_cfg     = load_config()
AUTO_BAN = _cfg.getboolean("honeypot", "auto_ban", fallback=True)
READ_LIMIT      = 4096           # tăng để bắt HTTP POST body
SOCK_TIMEOUT    = 10
BANNER_DELAY    = (0.08, 0.30)
MAX_LOGIN_TRIES = 3
THROTTLE_WINDOW = 60

HP_MITRE = "T1190"
HP_SCORE = 9

# ─── BANNER MỒI ────────────────────────────────────────────────────────────
SSH_BANNER    = b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1\r\n"
FTP_BANNER    = b"220 (vsFTPd 2.3.4)\r\n"
TELNET_HOST   = b"server01"
MYSQL_VERSION = "5.5.62-0ubuntu0"
SMTP_HELO     = "mail.corp.local"

# Telnet IAC negotiation (nmap nhận đúng telnet)
IAC_NEG = bytes([255,253,24, 255,253,31, 255,251,1, 255,251,3])


# ─── MYSQL HANDSHAKE V10 ────────────────────────────────────────────────────
def _build_mysql_handshake(server_version=MYSQL_VERSION, conn_id=None):
    conn_id = conn_id or random.randint(10, 9999)
    payload = (
        b"\x0a" + server_version.encode() + b"\x00"
        + struct.pack("<I", conn_id) + os.urandom(8) + b"\x00"
        + struct.pack("<H", 0xffff) + b"\xff" + struct.pack("<H", 0x0002)
        + struct.pack("<H", 0xffff) + b"\x15" + b"\x00" * 10
        + os.urandom(12) + b"\x00" + b"mysql_native_password\x00"
    )
    return struct.pack("<I", len(payload))[:3] + b"\x00" + payload

def _mysql_err(seq=2, code=1045, sqlstate=b"28000", msg=b"Access denied for user"):
    body = b"\xff" + struct.pack("<H", code) + b"#" + sqlstate + msg
    return struct.pack("<I", len(body))[:3] + bytes([seq]) + body

def _parse_mysql_username(data: bytes) -> str:
    """Extract username từ MySQL client handshake response packet."""
    try:
        # 4-byte packet header + 4-byte caps + 4-byte maxpkt + 1-byte charset
        # + 23-byte filler = 36 bytes trước username
        pos = 36
        if len(data) <= pos:
            return ""
        end = data.index(b"\x00", pos)
        return data[pos:end].decode("utf-8", errors="replace")
    except Exception:
        return ""


# ─── TỰ BẢO VỆ ─────────────────────────────────────────────────────────────
def _protected_ips():
    ips = {"127.0.0.1", "::1"}
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
        ips.update(out.stdout.split())
    except Exception:
        pass
    try:
        out = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines():
            if line.startswith("default") and "via" in line:
                p = line.split(); ips.add(p[p.index("via") + 1])
    except Exception:
        pass
    return ips

PROTECTED = _protected_ips()
_banned   = set()
_agg      = {}          # ip -> {count, last_event, ports}
_lock     = threading.Lock()


def _sanitize(data: bytes) -> str:
    text = data.decode("latin-1", errors="replace")
    return "".join(ch for ch in text if 32 <= ord(ch) < 127)[:300]

def _recv(conn, limit=None):
    try:
        return conn.recv(limit or READ_LIMIT)
    except Exception:
        return b""


# ─── HANDLER GIAO THỨC ─────────────────────────────────────────────────────

def proto_ssh(conn):
    """SSH: gửi banner, đọc client banner + bắt đầu kex."""
    conn.sendall(SSH_BANNER)
    data = _recv(conn)
    # Phần lớn scanner gửi banner của chúng trước khi kex
    client_ver = ""
    if data.startswith(b"SSH-"):
        eol = data.find(b"\r\n")
        client_ver = data[:eol if eol > 0 else 40].decode("latin-1", errors="replace")
    return (f"client={client_ver!r} " if client_ver else "") + _sanitize(data)


def proto_ftp(conn):
    """FTP: vsFTPd 2.3.4 — detect backdoor trigger ':)' trong username."""
    cap = []
    conn.sendall(FTP_BANNER)
    for _ in range(MAX_LOGIN_TRIES):
        u = _recv(conn)
        if not u:
            break
        cap.append(u)
        u_str = u.decode("latin-1", errors="replace").strip()

        # vsFTPd 2.3.4 backdoor: username chứa ':)' -> giả vờ mở port 6200
        if ":)" in u_str:
            conn.sendall(b"331 Please specify the password.\r\n")
            p = _recv(conn)
            if p:
                cap.append(p)
            # Trả lỗi như khi backdoor shell crash (không mở shell thật)
            conn.sendall(b"500 OOPS: priv_sock_get_cmd\r\n")
            break

        conn.sendall(b"331 Please specify the password.\r\n")
        p = _recv(conn)
        if p:
            cap.append(p)
        conn.sendall(b"530 Login incorrect.\r\n")
    return _sanitize(b" ".join(cap))


def proto_telnet(conn):
    cap = []
    conn.sendall(IAC_NEG + b"\r\nUbuntu 22.04.3 LTS\r\n" + TELNET_HOST + b" login: ")
    for _ in range(MAX_LOGIN_TRIES):
        u = _recv(conn)
        if not u:
            break
        cap.append(u)
        conn.sendall(b"Password: ")
        p = _recv(conn)
        if p:
            cap.append(p)
        conn.sendall(b"\r\nLogin incorrect\r\n" + TELNET_HOST + b" login: ")
    return _sanitize(b" ".join(cap))


def proto_mysql(conn):
    """MySQL: gửi handshake thật, extract username từ login response."""
    conn.sendall(_build_mysql_handshake())
    d = _recv(conn)
    username = _parse_mysql_username(d)
    try:
        deny_msg = b"Access denied for user '" + (username.encode() if username else b"?") + b"'@'%' (using password: YES)"
        conn.sendall(_mysql_err(msg=deny_msg))
    except Exception:
        pass
    prefix = f"user={username!r} " if username else ""
    return prefix + _sanitize(d)


def proto_smtp(conn):
    """SMTP Postfix — capture AUTH LOGIN / PLAIN credentials."""
    cap = []
    conn.sendall(f"220 {SMTP_HELO} ESMTP Postfix (Ubuntu)\r\n".encode())
    for _ in range(12):
        line = _recv(conn)
        if not line:
            break
        cap.append(line)
        cmd = line[:4].upper().rstrip()
        if cmd in (b"EHLO", b"HELO"):
            domain = line[5:].strip().decode("latin-1", errors="replace")[:50]
            conn.sendall(
                f"250-{SMTP_HELO}\r\n"
                f"250-PIPELINING\r\n"
                f"250-SIZE 10240000\r\n"
                f"250-AUTH LOGIN PLAIN\r\n"
                f"250 STARTTLS\r\n".encode()
            )
        elif cmd == b"AUTH":
            # Base64("Username:") = VXNlcm5hbWU6
            conn.sendall(b"334 VXNlcm5hbWU6\r\n")
            u = _recv(conn)
            if u: cap.append(u)
            conn.sendall(b"334 UGFzc3dvcmQ6\r\n")   # Base64("Password:")
            p = _recv(conn)
            if p: cap.append(p)
            conn.sendall(b"535 5.7.8 Error: authentication failed\r\n")
        elif cmd == b"MAIL":
            conn.sendall(b"250 2.1.0 Ok\r\n")
        elif cmd == b"RCPT":
            conn.sendall(b"550 5.1.1 The email account does not exist\r\n")
        elif cmd == b"DATA":
            conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
        elif cmd == b"QUIT":
            conn.sendall(b"221 2.0.0 Bye\r\n")
            break
        elif cmd == b"STAR":   # STARTTLS
            conn.sendall(b"454 4.7.0 TLS not available\r\n")
        else:
            conn.sendall(b"502 5.5.2 Error: command not recognized\r\n")
    return _sanitize(b"\n".join(cap))


# ─── HTTP ──────────────────────────────────────────────────────────────────
_PMA_PAGE = b"""\
HTTP/1.1 200 OK\r\n\
Server: Apache/2.4.41 (Ubuntu)\r\n\
X-Powered-By: PHP/7.4.3\r\n\
Content-Type: text/html; charset=UTF-8\r\n\
Connection: close\r\n\
\r\n\
<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body>
<h2>phpMyAdmin 4.6.6</h2>
<form method="post" action="/phpmyadmin/index.php">
Username: <input name="pma_username"><br>
Password: <input name="pma_password" type="password"><br>
<input type="submit" value="Go">
</form></body></html>"""

_TOMCAT_401 = b"""\
HTTP/1.1 401 Unauthorized\r\n\
Server: Apache-Coyote/1.1\r\n\
WWW-Authenticate: Basic realm="Tomcat Manager Application"\r\n\
Content-Type: text/html;charset=utf-8\r\n\
Connection: close\r\n\
\r\n\
<html><body><h1>401 Unauthorized</h1></body></html>"""

_WP_LOGIN = b"""\
HTTP/1.1 200 OK\r\n\
Server: Apache/2.4.41 (Ubuntu)\r\n\
X-Powered-By: PHP/7.4.3\r\n\
Content-Type: text/html; charset=UTF-8\r\n\
Connection: close\r\n\
\r\n\
<!DOCTYPE html><html><head><title>Log In &#8212; WordPress</title></head><body>
<form name="loginform" method="post" action="/wp-login.php">
<input name="log" type="text"><input name="pwd" type="password">
<input type="submit" value="Log In">
</form></body></html>"""

_HTTP_404 = b"HTTP/1.1 404 Not Found\r\nServer: Apache/2.4.41 (Ubuntu)\r\nConnection: close\r\n\r\n"

def _parse_http(req_bytes):
    """Trả về (method, path, body_str)."""
    text = req_bytes.decode("latin-1", errors="replace")
    method, path, body = "GET", "/", ""
    try:
        first = text.split("\r\n")[0]
        parts = first.split(" ")
        method = parts[0]
        path   = parts[1] if len(parts) > 1 else "/"
    except Exception:
        pass
    if "\r\n\r\n" in text:
        body = text.split("\r\n\r\n", 1)[1][:500]
    return method, path, body

def proto_http(conn, lure="pma"):
    req = _recv(conn)
    method, path, body = _parse_http(req)

    if lure == "tomcat":
        resp = _TOMCAT_401
    elif any(x in path.lower() for x in ["/wp-login", "/wordpress", "/wp-admin"]):
        resp = _WP_LOGIN
    elif any(x in path.lower() for x in ["/phpmyadmin", "/pma", "/admin", "/"]):
        resp = _PMA_PAGE
    else:
        resp = _HTTP_404

    try:
        conn.sendall(resp)
    except Exception:
        pass

    result = f"method={method} path={path!r}"
    if body.strip():
        result += f" body={body.strip()!r}"
    return result[:300]


# ─── RDP ───────────────────────────────────────────────────────────────────
def proto_rdp(conn):
    """RDP: TPKT + X.224 Connection Confirm (nmap nhận đúng ms-wbt-server)."""
    req = _recv(conn)
    # TPKT header (4) + X.224 CC TPDU (7)
    cc = bytes([
        0x03, 0x00, 0x00, 0x0b,   # TPKT: version=3, length=11
        0x06,                      # X.224 data length
        0xd0,                      # CC TPDU (0xD0)
        0x00, 0x00,                # dst-ref
        0x00, 0x00,                # src-ref
        0x00,                      # class option
    ])
    try:
        conn.sendall(cc)
    except Exception:
        pass
    return _sanitize(req)


# ─── VNC ───────────────────────────────────────────────────────────────────
def proto_vnc(conn):
    """VNC: RFB 003.008, SecurityType=2 (VNC Auth), capture challenge response."""
    conn.sendall(b"RFB 003.008\n")
    client_ver = _recv(conn)                  # client echoes its version
    # Offer only VNC Authentication (type 2)
    try:
        conn.sendall(bytes([0x00, 0x00, 0x00, 0x01, 0x02]))
        challenge = os.urandom(16)
        conn.sendall(challenge)               # 16-byte DES challenge
        response  = _recv(conn)              # 16-byte client response
        # Reject auth
        conn.sendall(bytes([0x00, 0x00, 0x00, 0x01]))   # auth failed
        conn.sendall(b"\x00\x00\x00\x1cAuthentication failure\x00")
    except Exception:
        response = b""
    return _sanitize(client_ver + response)


# ─── BẢNG DỊCH VỤ ─────────────────────────────────────────────────────────
BAITS = {
    2222: ("SSH",    "svc-a", proto_ssh),
    23:   ("TELNET", "svc-b", proto_telnet),
    21:   ("FTP",    "svc-c", proto_ftp),
    25:   ("SMTP",   "svc-f", proto_smtp),
    3306: ("MYSQL",  "svc-d", proto_mysql),
    80:   ("HTTP",   "svc-e", partial(proto_http, lure="pma")),
    8080: ("HTTP",   "svc-e", partial(proto_http, lure="tomcat")),
    3389: ("RDP",    "svc-g", proto_rdp),
    5900: ("VNC",    "svc-h", proto_vnc),
}


# ─── BAN / THROTTLE ────────────────────────────────────────────────────────
def _ban_ip(ip, ufw_label):
    if not AUTO_BAN or ip in PROTECTED:
        return
    with _lock:
        if ip in _banned:
            return
        _banned.add(ip)
    try:
        subprocess.run(
            ["ufw", "insert", "1", "deny", "from", ip, "comment", f"blk-{ufw_label}"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        pass


def _should_emit(ip, port):
    """THROTTLE: event đầu tiên luôn emit; sau THROTTLE_WINDOW emit tổng kết."""
    now = time.time()
    with _lock:
        a = _agg.get(ip)
        if a is None:
            _agg[ip] = {"count": 1, "last_event": now, "ports": {port}}
            return True, 1
        a["count"] += 1
        a["ports"].add(port)
        if now - a["last_event"] >= THROTTLE_WINDOW:
            n = a["count"]
            a["count"] = 0
            a["last_event"] = now
            return True, n
        return False, 0


# ─── HANDLE / LISTEN ───────────────────────────────────────────────────────
def handle(conn, addr, port):
    ip = addr[0]
    label, ufw_label, proto = BAITS[port]
    payload = ""
    try:
        conn.settimeout(SOCK_TIMEOUT)
        time.sleep(random.uniform(*BANNER_DELAY))
        payload = proto(conn)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

    note = ""
    if AUTO_BAN and ip not in PROTECTED:
        _ban_ip(ip, ufw_label)
        note = "  -> BAN"
    elif ip in PROTECTED:
        note = "  (protected)"

    emit, count = _should_emit(ip, port)
    if emit:
        extra = f" (gộp {count} lần)" if count > 1 else ""
        msg = f"Honeypot {label} hit on port {port}{extra}"
        raw = f"port={port} service={label} hits={count} data={payload!r}"
        insert_event("honeypot", "CRITICAL", "HONEYPOT", msg,
                     raw=raw, ip=ip, score=HP_SCORE, mitre=HP_MITRE)
        alert("CRITICAL", f"Honeypot {label}:{port}", msg)

    cred = f"  data={payload[:80]!r}" if payload.strip() else ""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] HIT {label:6} :{port:<5} {ip}{note}{cred}", flush=True)


def listen(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        s.listen(32)
    except PermissionError:
        print(f"[!] Port {port} requires elevated privileges.", flush=True)
        return
    except OSError as e:
        print(f"[!] Cannot bind port {port}: {e}", flush=True)
        return
    print(f"[+] Listening :{port}", flush=True)
    while True:
        try:
            conn, addr = s.accept()
            threading.Thread(target=handle, args=(conn, addr, port), daemon=True).start()
        except Exception:
            continue


def main():
    init_db()
    svc_list = "  ".join(f"{v[0]}:{p}" for p, v in sorted(BAITS.items()))
    print("=" * 60)
    print("  netsvc honeypot")
    print(f"  services : {svc_list}")
    print(f"  auto-ban : {'on' if AUTO_BAN else 'off'} | throttle: {THROTTLE_WINDOW}s")
    print(f"  protected: {', '.join(sorted(PROTECTED))}")
    print("=" * 60)
    for port in BAITS:
        threading.Thread(target=listen, args=(port,), daemon=True).start()
    print("  Ctrl+C to stop.\n")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()