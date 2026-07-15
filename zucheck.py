#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZuCheck v3 - Security Posture & Drift Auditor (chạy nền, đẩy vào ZuSIEM)

Khác bản cũ:
  - CHẠY NỀN định kỳ (systemd) thay vì chỉ chạy tay.
  - DRIFT DETECTION: so với baseline, phát hiện cổng/user/SUID/cron/service MỚI
    (dấu hiệu xâm nhập/cài cắm) — đây là giá trị chính khi chạy định kỳ.
  - Chỉ đẩy vào ZuSIEM khi có vấn đề MỚI hoặc đã KHẮC PHỤC (tránh spam).
  - Chấm điểm CÓ TRỌNG SỐ theo mức nghiêm trọng (CRIT/HIGH/MED/LOW), ra điểm 0-100 + hạng.
  - Xuất HTML report đẹp (self-contained) thay vì JSON thô.

Chế độ:
  zucheck.py            -> chạy nền, quét mỗi SCAN_INTERVAL
  zucheck.py --once     -> quét 1 lần, in ra terminal + xuất report
  zucheck.py --reset    -> xoá baseline (thiết lập lại từ đầu)
"""
import os
import re
import sys
import json
import html
import time
import socket
import subprocess
from pathlib import Path
from datetime import datetime

# ─── Tích hợp ZuSIEM (tuỳ chọn, không có vẫn chạy) ─────────
sys.path.insert(0, str(Path(__file__).parent))
try:
    from siem_engine import insert_event, init_db
    _HAS_SIEM = True
except Exception:
    _HAS_SIEM = False
    def insert_event(*a, **k): pass
    def init_db(): pass

# ─── CẤU HÌNH ─────────────────────────────────────────────
DESKTOP_MODE  = True
SCAN_INTERVAL = 3600                                   # giây giữa mỗi lần quét (nền)
BASE_DIR      = Path(__file__).parent
STATE_FILE    = BASE_DIR / "zucheck_state.json"        # baseline + lần quét trước
REPORT_FILE   = BASE_DIR / "zucheck_report.html"
HISTORY_FILE  = BASE_DIR / "zucheck_history.jsonl"

# Trọng số phạt theo mức nghiêm trọng (điểm = 100 - tổng phạt)
PENALTY = {"CRIT": 25, "HIGH": 12, "MED": 5, "LOW": 2}
# Điểm rủi ro đẩy vào SIEM theo severity
SIEM_SCORE = {"CRIT": 9, "HIGH": 7, "MED": 4, "LOW": 2}

# Màu terminal
R, BD, DIM = "\033[0m", "\033[1m", "\033[2m"
RED, GRN, YLW, CYN, BLU = "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[94m"


# ─── HELPERS ──────────────────────────────────────────────
def run(cmd, timeout=15):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:
        return -1, "", str(e)

def is_root():
    return os.geteuid() == 0

class Finding:
    __slots__ = ("status", "sev", "cat", "key", "msg", "detail")
    def __init__(self, status, cat, key, msg, sev="", detail=""):
        self.status = status      # PASS / FAIL / WARN / INFO
        self.sev    = sev         # CRIT/HIGH/MED/LOW (cho FAIL/WARN)
        self.cat    = cat
        self.key    = key         # định danh ổn định để so drift
        self.msg    = msg
        self.detail = detail


# ─── BASELINE / STATE ─────────────────────────────────────
def load_state():
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {"baseline": {}, "prev": {}}

def save_state(state):
    try:
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        os.chmod(STATE_FILE, 0o600)
    except Exception:
        pass


# ─── THU THẬP SNAPSHOT (cho drift) ────────────────────────
def snap_ports():
    _, out, _ = run("ss -tlnH 2>/dev/null")
    ports = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            ports.add(parts[3])            # local addr:port
    return ports

def snap_exposed_ports(ports):
    return {p for p in ports if not re.match(r"^(127\.|\[::1\]|::1)", p)}

def snap_shell_users():
    _, out, _ = run("awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)/{print $1}' /etc/passwd")
    return set(u for u in out.splitlines() if u)

def snap_suid():
    _, out, _ = run(r"find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null "
                    r"| grep -vE '^/(proc|sys)|containers' | head -200")
    return set(l for l in out.splitlines() if l)

def snap_enabled_services():
    _, out, _ = run("systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}'")
    return set(l for l in out.splitlines() if l)

def snap_cron():
    lines = set()
    for path in ["/etc/crontab"] + \
                (list(Path("/etc/cron.d").glob("*")) if Path("/etc/cron.d").exists() else []):
        try:
            for l in Path(path).read_text(errors="replace").splitlines():
                l = l.strip()
                if l and not l.startswith("#"):
                    lines.add(f"{Path(path).name}:{l}")
        except Exception:
            pass
    _, out, _ = run("crontab -l 2>/dev/null")
    for l in out.splitlines():
        if l.strip() and not l.strip().startswith("#"):
            lines.add(f"user:{l.strip()}")
    return lines


# ─── CÁC CHECK (trả list[Finding]) ────────────────────────
def check_updates():
    f = []
    rc, _, _ = run("dpkg -l unattended-upgrades 2>/dev/null | grep '^ii'")
    f.append(Finding("PASS" if rc == 0 else "FAIL", "updates", "updates.unattended",
                     "Tự động cập nhật bảo mật" + ("" if rc == 0 else " chưa bật"),
                     sev="MED", detail="sudo apt install unattended-upgrades"))
    _, out, _ = run("apt list --upgradable 2>/dev/null | grep -c '/'")
    try:
        n = int(out or 0)
        if n == 0:
            f.append(Finding("PASS", "updates", "updates.pending", "Không có gói chờ cập nhật"))
        else:
            sev = "HIGH" if n > 20 else "MED"
            f.append(Finding("WARN", "updates", "updates.pending",
                             f"{n} gói chờ cập nhật", sev=sev, detail="sudo apt upgrade -y"))
    except ValueError:
        pass
    if Path("/var/run/reboot-required").exists():
        f.append(Finding("WARN", "updates", "updates.reboot",
                         "Cần khởi động lại (kernel/lib đã cập nhật)", sev="LOW"))
    return f

def check_users(state):
    f = []
    _, out, _ = run("awk -F: '$3==0 && $1!=\"root\"{print $1}' /etc/passwd")
    if out:
        f.append(Finding("FAIL", "users", "users.uid0",
                         f"Tài khoản UID=0 lạ: {out}", sev="CRIT"))
    else:
        f.append(Finding("PASS", "users", "users.uid0", "Chỉ root có UID=0"))
    if is_root():
        # CHỈ báo tài khoản có trường mật khẩu RỖNG ($2 == "") = đăng nhập không cần pass.
        # '*' và '!' / '!!' là tài khoản BỊ KHOÁ (an toàn) — KHÔNG tính là lỗi.
        _, out, _ = run("awk -F: '$2==\"\" && $1!=\"root\"{print $1}' /etc/shadow")
        if out:
            f.append(Finding("FAIL", "users", "users.nopass",
                             f"Tài khoản KHÔNG mật khẩu (login không cần pass): {out}", sev="CRIT"))
        else:
            f.append(Finding("PASS", "users", "users.nopass",
                             "Không có tài khoản nào đăng nhập được mà thiếu mật khẩu"))
    # drift: user mới
    cur = snap_shell_users()
    base = set(state["baseline"].get("users", []))
    new = cur - base
    if base and new:
        f.append(Finding("FAIL", "users", "users.new",
                         f"USER MỚI xuất hiện: {', '.join(sorted(new))}", sev="HIGH",
                         detail="Kiểm tra xem có phải tài khoản backdoor không"))
    return f

def check_ssh():
    f = []
    rc, _, _ = run("systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null")
    if rc != 0:
        return [Finding("INFO", "ssh", "ssh.state", "SSH không chạy (bỏ qua)")]
    cfg = Path("/etc/ssh/sshd_config")
    if not cfg.exists():
        return [Finding("WARN", "ssh", "ssh.cfg", "SSH chạy nhưng thiếu sshd_config", sev="MED")]
    c = cfg.read_text(errors="replace")
    def val(p):
        m = re.search(rf"^\s*{p}\s+(\S+)", c, re.MULTILINE | re.IGNORECASE)
        return m.group(1).lower() if m else None
    rules = [("PermitRootLogin", "no", "HIGH"), ("PasswordAuthentication", "no", "MED"),
             ("PermitEmptyPasswords", "no", "CRIT")]
    for p, exp, sev in rules:
        v = val(p)
        ok = (v == exp)
        f.append(Finding("PASS" if ok else "FAIL", "ssh", f"ssh.{p.lower()}",
                         f"SSH {p}={v or 'chưa đặt'}", sev=sev))
    return f

def check_firewall():
    f = []
    if run("command -v ufw")[0] != 0:
        return [Finding("FAIL", "firewall", "fw.installed", "UFW chưa cài", sev="HIGH",
                        detail="sudo apt install ufw && sudo ufw enable")]
    rc, out, _ = run("ufw status verbose 2>/dev/null")
    active = None
    if rc == 0 and "Status:" in out:
        active = "status: active" in out.lower()
        deny_in = "deny (incoming)" in out.lower()
    else:
        _, sysd, _ = run("systemctl is-active ufw 2>/dev/null")
        active, deny_in = (sysd.strip() == "active"), True
    if active:
        f.append(Finding("PASS", "firewall", "fw.active", "UFW đang hoạt động"))
        if not deny_in:
            f.append(Finding("WARN", "firewall", "fw.denyin",
                             "UFW chưa mặc định deny incoming", sev="MED",
                             detail="sudo ufw default deny incoming"))
    else:
        f.append(Finding("FAIL", "firewall", "fw.active", "UFW KHÔNG hoạt động", sev="HIGH",
                         detail="sudo ufw enable"))
    return f

def check_ports(state):
    f = []
    ports = snap_ports()
    exposed = snap_exposed_ports(ports)
    f.append(Finding("INFO", "ports", "ports.count",
                     f"{len(ports)} cổng đang nghe ({len(exposed)} phơi ra ngoài)"))
    # drift: cổng phơi ra ngoài MỚI
    base = set(state["baseline"].get("exposed", []))
    new = exposed - base
    if base and new:
        f.append(Finding("FAIL", "ports", "ports.new_exposed",
                         f"CỔNG MỚI phơi ra ngoài: {', '.join(sorted(new))}", sev="HIGH",
                         detail="Cổng lạ mở ra mạng = dấu hiệu bị cài dịch vụ. Kiểm tra ss -tlnp"))
    return f

def check_persistence(state):
    f = []
    # service enabled mới
    cur_s = snap_enabled_services()
    base_s = set(state["baseline"].get("services", []))
    new_s = cur_s - base_s
    if base_s and new_s:
        f.append(Finding("WARN", "persistence", "persist.service",
                         f"SERVICE tự-khởi-động MỚI: {', '.join(sorted(new_s))}", sev="MED",
                         detail="Malware hay tự thêm service để tồn tại qua reboot"))
    # cron mới
    cur_c = snap_cron()
    base_c = set(state["baseline"].get("cron", []))
    new_c = cur_c - base_c
    if base_c and new_c:
        f.append(Finding("FAIL", "persistence", "persist.cron",
                         f"CRON MỚI: {len(new_c)} mục", sev="HIGH",
                         detail="Cron lạ = cách cài cắm phổ biến. Xem /etc/crontab, /etc/cron.d/"))
    if not new_s and not new_c and (base_s or base_c):
        f.append(Finding("PASS", "persistence", "persist.ok", "Không có cron/service tự-khởi-động lạ"))
    return f

def check_suid(state):
    f = []
    cur = snap_suid()
    base = set(state["baseline"].get("suid", []))
    new = cur - base
    if base and new:
        f.append(Finding("FAIL", "suid", "suid.new",
                         f"FILE SUID/SGID MỚI: {', '.join(sorted(new))}", sev="HIGH",
                         detail="SUID mới = dấu hiệu leo thang quyền / cài cắm"))
    else:
        f.append(Finding("PASS", "suid", "suid.ok", f"{len(cur)} file SUID/SGID (không có cái mới)"))
    return f

def check_file_perms():
    f = []
    perms = [("/etc/shadow", "640", "HIGH"), ("/etc/passwd", "644", "MED"),
             ("/etc/sudoers", "440", "HIGH")]
    for path, exp, sev in perms:
        p = Path(path)
        if not p.exists():
            continue
        actual = oct(p.stat().st_mode)[-3:]
        # shadow có thể là 640 hoặc 600 tuỳ distro — chấp nhận chặt hơn
        ok = actual == exp or (path == "/etc/shadow" and actual in ("600", "640"))
        f.append(Finding("PASS" if ok else "FAIL", "fileperm", f"perm{path}",
                         f"{path}: {actual}" + ("" if ok else f" (nên {exp})"),
                         sev=sev, detail=f"sudo chmod {exp} {path}"))
    _, out, _ = run("find /etc -type f -perm -o+w 2>/dev/null | head -5")
    if out:
        f.append(Finding("FAIL", "fileperm", "perm.worldwrite",
                         f"File world-writable trong /etc: {out.splitlines()[0]}...", sev="HIGH"))
    else:
        f.append(Finding("PASS", "fileperm", "perm.worldwrite", "Không có file world-writable trong /etc"))
    return f

def check_kernel():
    f = []
    checks = [("kernel.randomize_va_space", "2", "ASLR", "MED"),
              ("kernel.kptr_restrict", "1", "kptr_restrict", "LOW"),
              ("kernel.dmesg_restrict", "1", "dmesg_restrict", "LOW")]
    for key, want, label, sev in checks:
        _, out, _ = run(f"sysctl -n {key} 2>/dev/null")
        ok = out.strip() == want
        f.append(Finding("PASS" if ok else "WARN", "kernel", f"kern.{label}",
                         f"{label} = {out.strip() or '?'}" + ("" if ok else f" (nên {want})"),
                         sev=sev, detail=f"sudo sysctl -w {key}={want}"))
    return f

def check_apparmor():
    rc, out, _ = run("aa-status --enabled 2>/dev/null; echo $?")
    _, prof, _ = run("aa-status 2>/dev/null | grep 'profiles are loaded' | head -1")
    if "0" in out.splitlines()[-1:] or prof:
        return [Finding("PASS", "mac", "mac.apparmor", f"AppArmor bật ({prof or 'loaded'})")]
    return [Finding("WARN", "mac", "mac.apparmor", "AppArmor không hoạt động", sev="MED")]

def check_encryption():
    rc, out, _ = run("lsblk -o TYPE 2>/dev/null | grep -c crypt")
    if out and out != "0":
        return [Finding("PASS", "crypto", "crypto.disk", "Có phân vùng mã hoá (LUKS)")]
    return [Finding("INFO", "crypto", "crypto.disk",
                    "Không phát hiện mã hoá disk (khó bật sau cài — cân nhắc khi cài lại)")]

def check_dangerous_services():
    f = []
    bad = ["telnet", "rsh", "rlogin", "vsftpd", "tftpd-hpa", "finger"]
    found = [s for s in bad if run(f"systemctl is-active {s} 2>/dev/null")[0] == 0]
    if found:
        for s in found:
            f.append(Finding("FAIL", "services", f"svc.{s}",
                             f"Dịch vụ nguy hiểm đang chạy: {s}", sev="HIGH",
                             detail=f"sudo systemctl disable --now {s}"))
    else:
        f.append(Finding("PASS", "services", "svc.dangerous", "Không có dịch vụ nguy hiểm (telnet/rsh...)"))
    return f


# ─── RUNNER ───────────────────────────────────────────────
CHECKS_NO_STATE = [check_updates, check_ssh, check_firewall, check_file_perms,
                   check_kernel, check_apparmor, check_encryption, check_dangerous_services]
CHECKS_STATE    = [check_users, check_ports, check_persistence, check_suid]

def run_all(state):
    findings = []
    for fn in CHECKS_NO_STATE:
        try: findings += fn()
        except Exception as e: findings.append(Finding("INFO", "error", f"err.{fn.__name__}", f"Lỗi check {fn.__name__}: {e}"))
    for fn in CHECKS_STATE:
        try: findings += fn(state)
        except Exception as e: findings.append(Finding("INFO", "error", f"err.{fn.__name__}", f"Lỗi check {fn.__name__}: {e}"))
    return findings

def update_baseline(state):
    ports = snap_ports()
    state["baseline"] = {
        "users":    sorted(snap_shell_users()),
        "exposed":  sorted(snap_exposed_ports(ports)),
        "suid":     sorted(snap_suid()),
        "services": sorted(snap_enabled_services()),
        "cron":     sorted(snap_cron()),
        "established_at": datetime.now().isoformat(),
    }

def compute_score(findings):
    penalty = sum(PENALTY.get(f.sev, 0) for f in findings if f.status in ("FAIL", "WARN"))
    score = max(0, 100 - penalty)
    grade = ("A" if score >= 90 else "B" if score >= 75 else
             "C" if score >= 60 else "D" if score >= 40 else "F")
    return score, grade


# ─── ĐẨY VÀO ZuSIEM (chỉ vấn đề MỚI / đã khắc phục) ───────
def push_deltas(findings, state):
    prev = state.get("prev", {})
    cur = {f.key: f.status for f in findings}
    fmap = {f.key: f for f in findings}
    new_problems, resolved = [], []
    for key, st in cur.items():
        if st in ("FAIL", "WARN") and prev.get(key) not in ("FAIL", "WARN"):
            new_problems.append(fmap[key])
    for key, st in prev.items():
        if st in ("FAIL", "WARN") and cur.get(key) not in ("FAIL", "WARN"):
            resolved.append(key)
    for f in new_problems:
        lvl = "CRITICAL" if f.sev in ("CRIT", "HIGH") else "WARNING"
        insert_event("zucheck", lvl, "POSTURE",
                     f"[{f.sev}] {f.msg}",
                     raw=f"key={f.key} cat={f.cat} detail={f.detail}",
                     ip="127.0.0.1", score=SIEM_SCORE.get(f.sev, 3), mitre="")
    for key in resolved:
        insert_event("zucheck", "INFO", "POSTURE_RESOLVED",
                     f"Đã khắc phục: {key}", raw=f"key={key}", ip="127.0.0.1", score=0, mitre="")
    state["prev"] = cur
    return len(new_problems), len(resolved)


# ─── HTML REPORT ──────────────────────────────────────────
def write_html(findings, score, grade):
    sev_color = {"CRIT": "#dc2626", "HIGH": "#ea580c", "MED": "#ca8a04", "LOW": "#0891b2"}
    grade_color = {"A": "#16a34a", "B": "#65a30d", "C": "#ca8a04", "D": "#ea580c", "F": "#dc2626"}
    problems = [f for f in findings if f.status in ("FAIL", "WARN")]
    passes   = [f for f in findings if f.status == "PASS"]
    infos    = [f for f in findings if f.status == "INFO"]
    order = {"CRIT": 0, "HIGH": 1, "MED": 2, "LOW": 3, "": 4}
    problems.sort(key=lambda f: order.get(f.sev, 9))

    def esc(s): return html.escape(str(s))
    rows = ""
    for f in problems:
        rows += f"""<tr>
          <td><span class="badge" style="background:{sev_color.get(f.sev,'#666')}">{f.sev or '-'}</span></td>
          <td>{esc(f.cat)}</td><td>{esc(f.msg)}</td>
          <td class="fix">{esc(f.detail)}</td></tr>"""
    pass_rows = "".join(f"<li>{esc(f.msg)}</li>" for f in passes)
    info_rows = "".join(f"<li>{esc(f.msg)}</li>" for f in infos)

    doc = f"""<!DOCTYPE html><html lang="vi"><head><meta charset="utf-8">
<title>ZuCheck Report</title><style>
*{{box-sizing:border-box}}body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
margin:0;background:#0f172a;color:#e2e8f0;padding:32px}}
.wrap{{max-width:960px;margin:0 auto}}
h1{{font-size:22px;margin:0 0 4px}}.sub{{color:#94a3b8;font-size:13px;margin-bottom:24px}}
.top{{display:flex;gap:24px;align-items:center;background:#1e293b;border-radius:16px;padding:24px;margin-bottom:24px}}
.gauge{{width:120px;height:120px;border-radius:50%;display:flex;align-items:center;justify-content:center;
flex-direction:column;background:conic-gradient({grade_color[grade]} {score*3.6}deg,#334155 0);flex-shrink:0}}
.gauge .inner{{width:96px;height:96px;border-radius:50%;background:#1e293b;display:flex;align-items:center;
justify-content:center;flex-direction:column}}
.score{{font-size:32px;font-weight:700;color:{grade_color[grade]}}}.grade{{font-size:13px;color:#94a3b8}}
.stats{{display:flex;gap:16px;flex-wrap:wrap}}.stat{{background:#0f172a;border-radius:10px;padding:12px 18px}}
.stat b{{font-size:22px;display:block}}.stat span{{font-size:12px;color:#94a3b8}}
table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:12px;overflow:hidden;margin-bottom:24px}}
th,td{{text-align:left;padding:10px 14px;font-size:13px;border-bottom:1px solid #334155;vertical-align:top}}
th{{background:#0f172a;color:#94a3b8;font-weight:600}}
.badge{{color:#fff;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700}}
.fix{{color:#64748b;font-family:ui-monospace,monospace;font-size:12px}}
details{{background:#1e293b;border-radius:12px;padding:14px 18px;margin-bottom:12px}}
summary{{cursor:pointer;color:#94a3b8}}ul{{margin:8px 0 0;padding-left:20px;font-size:13px;line-height:1.7}}
.ok{{color:#16a34a}}</style></head><body><div class="wrap">
<h1>🛡️ ZuCheck — Security Posture Report</h1>
<div class="sub">{esc(socket.gethostname())} · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
<div class="top">
  <div class="gauge"><div class="inner"><span class="score">{score}</span><span class="grade">hạng {grade}</span></div></div>
  <div class="stats">
    <div class="stat"><b style="color:#dc2626">{len(problems)}</b><span>Vấn đề</span></div>
    <div class="stat"><b class="ok">{len(passes)}</b><span>Đạt</span></div>
    <div class="stat"><b style="color:#0891b2">{len(infos)}</b><span>Thông tin</span></div>
  </div></div>
{"<table><tr><th>Mức</th><th>Nhóm</th><th>Vấn đề</th><th>Khắc phục</th></tr>"+rows+"</table>" if problems else '<div class="top ok">✔ Không phát hiện vấn đề bảo mật nào.</div>'}
<details><summary>✔ {len(passes)} mục đạt chuẩn</summary><ul>{pass_rows}</ul></details>
<details><summary>ℹ {len(infos)} thông tin</summary><ul>{info_rows}</ul></details>
</div></body></html>"""
    try:
        REPORT_FILE.write_text(doc, encoding="utf-8")
    except Exception:
        pass


# ─── CONSOLE OUTPUT ───────────────────────────────────────
def print_console(findings, score, grade, new_p, resolved):
    gc = GRN if grade in "AB" else YLW if grade == "C" else RED
    print(f"\n{CYN}{BD}  ZuCheck — {socket.gethostname()} — {datetime.now().strftime('%H:%M:%S')}{R}")
    print(f"  {BD}Điểm: {gc}{score}/100 (hạng {grade}){R}")
    sc = {"CRIT": RED, "HIGH": RED, "MED": YLW, "LOW": CYN}
    probs = [f for f in findings if f.status in ("FAIL", "WARN")]
    probs.sort(key=lambda f: {"CRIT":0,"HIGH":1,"MED":2,"LOW":3}.get(f.sev,9))
    if probs:
        print(f"\n  {BD}Vấn đề:{R}")
        for f in probs:
            print(f"  {sc.get(f.sev,DIM)}[{f.sev or '-':>4}]{R} {f.msg}")
            if f.detail: print(f"         {DIM}→ {f.detail}{R}")
    else:
        print(f"\n  {GRN}✔ Không phát hiện vấn đề.{R}")
    print(f"\n  {DIM}Đẩy SIEM: {new_p} vấn đề mới, {resolved} đã khắc phục | "
          f"Report: {REPORT_FILE.name}{R}\n")


# ─── SCAN CYCLE ───────────────────────────────────────────
def scan_once(console=False):
    init_db()
    state = load_state()
    first_run = not state.get("baseline")
    findings = run_all(state)
    score, grade = compute_score(findings)

    if first_run:
        update_baseline(state)
        findings.append(Finding("INFO", "baseline", "baseline.init",
                                "Baseline vừa được thiết lập — lần sau sẽ phát hiện thay đổi"))
        state["prev"] = {f.key: f.status for f in findings}
        new_p = resolved = 0
        save_state(state)
    else:
        new_p, resolved = push_deltas(findings, state)
        save_state(state)

    write_html(findings, score, grade)
    try:
        with HISTORY_FILE.open("a") as _hf:
            _hf.write(json.dumps(
                {"ts": datetime.now().isoformat(), "score": score, "grade": grade}) + "\n")
    except Exception:
        pass
    if console:
        print_console(findings, score, grade, new_p, resolved)
    else:
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] ZuCheck: điểm {score}/100 ({grade}) | "
              f"{new_p} vấn đề mới, {resolved} khắc phục", flush=True)
    return score, grade


def main():
    args = sys.argv[1:]
    if "--reset" in args:
        STATE_FILE.unlink(missing_ok=True)
        print("Đã xoá baseline. Lần quét tới sẽ thiết lập lại.")
        return
    if "--once" in args:
        scan_once(console=True)
        return
    # chế độ nền
    print("=" * 56)
    print("  ZuCheck v3 — security posture & drift auditor")
    print(f"  quét mỗi {SCAN_INTERVAL}s | SIEM: {'có' if _HAS_SIEM else 'không'} | report: {REPORT_FILE.name}")
    print("=" * 56, flush=True)
    while True:
        try:
            scan_once(console=False)
        except Exception as e:
            print(f"[!] scan error: {e}", flush=True)
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
