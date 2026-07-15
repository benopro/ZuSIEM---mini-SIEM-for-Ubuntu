#!/usr/bin/env python3
"""
netguard - mini-IPS phát hiện & chặn flood/DoS trong mạng LAN, ghép vào ZuSIEM.

PHÁT HIỆN (đa tín hiệu):
  - Connection flood : nhiều kết nối established đồng thời từ 1 IP.
  - SYN flood        : nhiều gói half-open (syn-recv) từ 1 IP — dấu hiệu SYN flood kinh điển.
  - Rate flood       : tốc độ kết nối MỚI/giây cao bất thường.
  - Baseline tự học  : học mức "bình thường" của từng IP lúc khởi động -> giảm báo nhầm.

PHẢN ỨNG (leo thang, tự gỡ):
  - L1 cảnh cáo : ban ngắn (mặc định 2 phút).
  - L2 tái phạm : ban dài (15 phút).
  - L3 lì đòn   : ban vĩnh viễn.
  - Tự gỡ ban khi hết hạn -> lỡ nhầm thì tự tha, không khoá oan mãi.

CHỐNG ĐƯỢC: DoS từ 1-vài nguồn trong LAN (thứ máy cá nhân đỡ được).
KHÔNG chống được: DDoS botnet internet thật (nghẽn đường truyền, ngoài tầm máy).
AN TOÀN: chỉ đọc `ss` + chạy `ufw`. Tự bảo vệ gateway/IP máy/loopback + whitelist.
"""
import os
import sys
import time
import subprocess
import threading
from collections import deque, defaultdict
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from siem_engine import insert_event, init_db, alert, load_config  # noqa: E402

# ─── CẤU HÌNH (đọc từ siem.conf, fallback về default) ────
_cfg             = load_config()
AUTO_BAN         = _cfg.getboolean("netguard", "auto_ban",        fallback=True)
CONN_THRESHOLD   = _cfg.getint("netguard",    "conn_threshold",   fallback=60)
SYN_THRESHOLD    = _cfg.getint("netguard",    "syn_threshold",    fallback=30)
RATE_THRESHOLD   = _cfg.getint("netguard",    "rate_threshold",   fallback=40)
HARD_THRESHOLD   = _cfg.getint("netguard",    "hard_threshold",   fallback=200)

SAMPLE_INTERVAL  = 2        # giây giữa mỗi lần lấy mẫu
WINDOW_SAMPLES   = 4        # số mẫu trong cửa sổ trượt
TRIGGER_SAMPLES  = 2        # cần vượt ngưỡng >= bấy nhiêu mẫu/cửa sổ mới hành động

# Baseline tự học
BASELINE_WARMUP  = 30       # giây đầu: học mức bình thường, không ban
BASELINE_MULT    = 3.0      # ngưỡng hiệu dụng = max(ngưỡng, baseline * hệ số)

# Leo thang + TTL ban (giây); None = vĩnh viễn
BAN_TTL = {1: 120, 2: 900, 3: None}
OFFENSE_MEMORY   = 3600     # quên "tiền án" của IP sau bấy nhiêu giây im lặng

THROTTLE_WINDOW  = 60       # gộp event SIEM cùng IP
STATS_INTERVAL   = 300      # in thống kê mỗi 5 phút
WHITELIST_FILE   = Path(__file__).parent / "netguard_whitelist.txt"

HP_MITRE = "T1498"          # Network Denial of Service
HP_SCORE = 8


# ─── WHITELIST / TỰ BẢO VỆ ────────────────────────────────
def _protected_ips():
    ips = {"127.0.0.1", "::1", "0.0.0.0"}
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
    # whitelist thủ công (mỗi dòng 1 IP)
    try:
        if WHITELIST_FILE.exists():
            for line in WHITELIST_FILE.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    ips.add(line)
    except Exception:
        pass
    return ips

PROTECTED = _protected_ips()

# ─── TRẠNG THÁI ───────────────────────────────────────────
_lock       = threading.Lock()
_est_win    = defaultdict(lambda: deque(maxlen=WINDOW_SAMPLES))   # ip -> established counts
_syn_win    = defaultdict(lambda: deque(maxlen=WINDOW_SAMPLES))   # ip -> syn-recv counts
_rate_win   = defaultdict(lambda: deque(maxlen=WINDOW_SAMPLES))   # ip -> new-conn deltas
_prev_est   = {}                                                  # ip -> established mẫu trước
_baseline   = {}                                                  # ip -> mức bình thường (max lúc warmup)
_offense    = {}                                                  # ip -> {"level":int, "ts":float}
_active_ban = {}                                                  # ip -> {"expire":float|None, "level":int}
_agg        = {}                                                  # ip -> last_event (throttle)
_stats      = defaultdict(int)                                    # ip -> tổng số lần bị gắn cờ
_start_time = time.time()


# ─── LẤY MẪU ──────────────────────────────────────────────
def sample():
    """Trả (established: ip->count, synrecv: ip->count)."""
    est, syn = defaultdict(int), defaultdict(int)
    for state, bucket in (("established", est), ("syn-recv", syn)):
        try:
            out = subprocess.run(["ss", "-tn", "state", state],
                                 capture_output=True, text=True, timeout=5)
        except Exception:
            continue
        for line in out.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            ip = parts[-1].rsplit(":", 1)[0].strip("[]")
            if ip and ip not in PROTECTED:
                bucket[ip] += 1
    return est, syn


# ─── UFW BAN / UNBAN ──────────────────────────────────────
def _ufw(*args):
    try:
        subprocess.run(["ufw", *args], capture_output=True, text=True, timeout=10)
        return True
    except Exception:
        return False

def _ban(ip, level):
    if not AUTO_BAN or ip in PROTECTED:
        return False
    ttl = BAN_TTL.get(level)
    expire = None if ttl is None else time.time() + ttl
    with _lock:
        _active_ban[ip] = {"expire": expire, "level": level}
    _ufw("insert", "1", "deny", "from", ip, "comment", f"netguard-L{level}")
    return True

def _unban(ip):
    _ufw("delete", "deny", "from", ip)
    # Không dùng _lock ở đây — caller luôn giữ _lock rồi (tránh deadlock)
    _active_ban.pop(ip, None)

def reap_expired():
    now = time.time()
    for ip, info in list(_active_ban.items()):
        exp = info.get("expire")
        if exp is not None and now >= exp:
            lvl = info["level"]
            _unban(ip)
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] UNBAN {ip} (hết hạn L{lvl})", flush=True)
            insert_event("netguard", "INFO", "AUTO_UNBAN",
                         f"Tự gỡ ban IP {ip} (L{lvl} hết hạn)",
                         ip=ip, score=0, mitre="")


# ─── ĐÁNH GIÁ ─────────────────────────────────────────────
def _threshold(ip, base):
    """Ngưỡng hiệu dụng: nới theo baseline đã học của IP đó."""
    b = _baseline.get(ip, 0)
    return max(base, b * BASELINE_MULT)

def _count_over(win, thr):
    return sum(1 for v in win if v >= thr)

def _next_level(ip):
    now = time.time()
    o = _offense.get(ip)
    if o and now - o["ts"] <= OFFENSE_MEMORY:
        lvl = min(o["level"] + 1, 3)
    else:
        lvl = 1
    _offense[ip] = {"level": lvl, "ts": now}
    return lvl

def _should_emit(ip):
    now = time.time()
    a = _agg.get(ip)
    if a is None or now - a >= THROTTLE_WINDOW:
        _agg[ip] = now
        return True
    return False

def evaluate(est, syn, warmup):
    now_ips = set(est) | set(syn)

    # cập nhật cửa sổ + tính rate (kết nối mới = delta established dương)
    for ip in now_ips:
        e = est.get(ip, 0); s = syn.get(ip, 0)
        delta = max(0, e - _prev_est.get(ip, e))
        _prev_est[ip] = e
        _est_win[ip].append(e)
        _syn_win[ip].append(s)
        _rate_win[ip].append(delta)

    # giai đoạn học: chỉ ghi baseline, không ban
    if warmup:
        for ip in now_ips:
            _baseline[ip] = max(_baseline.get(ip, 0), est.get(ip, 0))
        return

    for ip in now_ips:
        if ip in PROTECTED or ip in _active_ban:
            continue
        conn_thr = _threshold(ip, CONN_THRESHOLD)
        e_now = est.get(ip, 0); s_now = syn.get(ip, 0)
        r_now = _rate_win[ip][-1] if _rate_win[ip] else 0

        # tín hiệu
        sig = []
        if _count_over(_est_win[ip], conn_thr) >= TRIGGER_SAMPLES: sig.append(f"CONN({e_now})")
        if _count_over(_syn_win[ip], SYN_THRESHOLD) >= TRIGGER_SAMPLES: sig.append(f"SYN({s_now})")
        if _count_over(_rate_win[ip], RATE_THRESHOLD) >= TRIGGER_SAMPLES: sig.append(f"RATE({r_now})")
        hard = e_now >= HARD_THRESHOLD or s_now >= HARD_THRESHOLD

        if not sig and not hard:
            continue

        level = 3 if hard else _next_level(ip)
        banned = _ban(ip, level)
        _stats[ip] += 1

        if _should_emit(ip):
            kinds = "+".join(sig) if sig else f"HARD(est={e_now},syn={s_now})"
            ttl = BAN_TTL.get(level)
            ttl_s = "vĩnh viễn" if ttl is None else f"{ttl}s"
            msg = f"LAN flood: {ip} [{kinds}] -> ban L{level} ({ttl_s})"
            raw = (f"src={ip} est={e_now} syn={s_now} rate={r_now} "
                   f"signals={kinds} level={level} banned={banned}")
            insert_event("netguard", "CRITICAL", "LAN_FLOOD", msg,
                         raw=raw, ip=ip, score=HP_SCORE, mitre=HP_MITRE)
            alert("CRITICAL", f"LAN Flood từ {ip}", msg)
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] FLOOD {ip:<16} {'+'.join(sig) or 'HARD':<28} -> BAN L{level}", flush=True)

    # dọn trạng thái cho IP đã biến mất
    for store in (_est_win, _syn_win, _rate_win):
        for ip in list(store):
            if ip not in now_ips and ip not in _active_ban:
                store.pop(ip, None); _prev_est.pop(ip, None)


def print_stats():
    with _lock:
        top = sorted(_stats.items(), key=lambda x: -x[1])[:5]
        active = len(_active_ban)
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] --- STATS --- đang ban: {active} | top kẻ phá: "
          + (", ".join(f"{ip}({n})" for ip, n in top) if top else "chưa có"), flush=True)


# ─── MAIN ─────────────────────────────────────────────────
def main():
    init_db()
    print("=" * 60)
    print("  netguard — mini-IPS chống flood LAN")
    print(f"  ngưỡng: conn>={CONN_THRESHOLD} syn>={SYN_THRESHOLD} rate>={RATE_THRESHOLD} "
          f"hard>={HARD_THRESHOLD}")
    print(f"  cửa sổ: {WINDOW_SAMPLES} mẫu x {SAMPLE_INTERVAL}s | warmup {BASELINE_WARMUP}s")
    print(f"  ban: L1={BAN_TTL[1]}s L2={BAN_TTL[2]}s L3=vĩnh viễn | auto-ban {'on' if AUTO_BAN else 'off'}")
    print(f"  protected: {', '.join(sorted(PROTECTED))}")
    print("=" * 60)
    print(f"  Đang học baseline {BASELINE_WARMUP}s (chưa ban)...  Ctrl+C để dừng.\n")

    last_stats = time.time()
    try:
        while True:
            warmup = (time.time() - _start_time) < BASELINE_WARMUP
            est, syn = sample()
            with _lock:
                evaluate(est, syn, warmup)
                reap_expired()
            if not warmup and time.time() - last_stats >= STATS_INTERVAL:
                print_stats(); last_stats = time.time()
            time.sleep(SAMPLE_INTERVAL)
    except KeyboardInterrupt:
        print("\nĐã dừng. (Lưu ý: luật ban trong UFW vẫn còn — tự hết hạn hoặc gỡ tay.)")


if __name__ == "__main__":
    main()
