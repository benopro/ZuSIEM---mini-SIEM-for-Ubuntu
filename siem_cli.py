#!/usr/bin/env python3
"""
ZuSIEM CLI - Terminal interface
"""
import sys
import os
import time
import argparse
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
import json
from siem_engine import (
    init_db, get_events, get_summary, get_stats,
    analyze_with_ollama, get_recent_events_text,
    check_ollama_status, export_events,
    ack_event, ack_all_events,
    get_whitelist, add_to_whitelist, remove_from_whitelist,
    get_db_stats, cleanup_old_events, COL,
)

RED    = '\033[0;31m'
YELLOW = '\033[1;33m'
GREEN  = '\033[0;32m'
CYAN   = '\033[0;36m'
BLUE   = '\033[0;34m'
PURPLE = '\033[0;35m'
ORANGE = '\033[38;5;208m'
BOLD   = '\033[1m'
DIM    = '\033[2m'
NC     = '\033[0m'

LEVEL_COLOR = {"CRITICAL": RED, "WARNING": YELLOW, "INFO": BLUE}
SCORE_COLOR = lambda s: RED if s >= 7 else YELLOW if s >= 4 else BLUE

def clear(): os.system("clear")

def print_header():
    print(f"{CYAN}{BOLD}")
    print("╔══════════════════════════════════════════════════════╗")
    print("║        ZuSIEM - Security Monitor + AI               ║")
    print(f"║  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  Ubuntu Desktop            ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(f"{NC}")

def print_summary():
    s = get_summary()
    print(f"{BOLD}{'─'*56}{NC}")
    print(f"  {CYAN}Sự kiện 1h qua :{NC}  {BOLD}{s['last_1h']}{NC}")
    print(f"  {CYAN}Sự kiện 24h    :{NC}  {BOLD}{s['last_24h']}{NC}")
    print(f"  {RED}Critical 24h   :{NC}  {BOLD}{RED}{s['critical_24h']}{NC}")
    print(f"  {YELLOW}Warning 24h    :{NC}  {BOLD}{YELLOW}{s['warning_24h']}{NC}")
    unacked = s['unacked']
    unacked_color = RED if unacked > 0 else GREEN
    print(f"  {ORANGE}Chưa xử lý    :{NC}  {BOLD}{unacked_color}{unacked}{NC}")

    if s['top_ips']:
        print(f"\n  {BOLD}Top IP đáng ngờ:{NC}")
        for ip, cnt in s['top_ips']:
            print(f"    {CYAN}{ip:<20}{NC} {cnt} lần")

    if s['top_users']:
        print(f"\n  {BOLD}Top Users:{NC}")
        for user, cnt in s['top_users']:
            print(f"    {PURPLE}{user:<20}{NC} {cnt} lần")
    print(f"{BOLD}{'─'*56}{NC}\n")

def _score_str(score):
    color = SCORE_COLOR(score)
    return f"{color}{score:>2}{NC}"

def print_events(events, show_raw=False):
    if not events:
        print(f"  {DIM}Không có sự kiện nào.{NC}")
        return
    for e in events:
        level    = e[COL["level"]]
        source   = e[COL["source"]]
        message  = e[COL["message"]]
        ts       = e[COL["timestamp"]]
        user     = e[COL["user"]]
        ip       = e[COL["ip"]]
        raw      = e[COL["raw"]]
        ack      = e[COL["ack"]]
        score    = e[COL["score"]]
        mitre    = e[COL["mitre"]]
        eid      = e[COL["id"]]

        color    = LEVEL_COLOR.get(level, NC)
        ts_short = ts[5:] if ts else ""
        user_str = f" {PURPLE}[{user}]{NC}" if user else ""
        ip_str   = f" {CYAN}[{ip}]{NC}"     if ip   else ""
        ack_str  = f" {GREEN}[ACK]{NC}"     if ack  else ""
        mitre_str= f" {DIM}{mitre}{NC}"     if mitre else ""
        score_str= f" [{_score_str(score)}]"

        print(f"  {DIM}#{eid:<5}{NC} {DIM}{ts_short}{NC}  "
              f"{color}{BOLD}{level:<8}{NC}  "
              f"{GREEN}{source:<10}{NC}  "
              f"{message}{user_str}{ip_str}{score_str}{mitre_str}{ack_str}")
        if show_raw and raw:
            print(f"    {DIM}{raw[:140]}{NC}")

# ─── COMMANDS ────────────────────────────────────────────

def cmd_status(args):
    clear()
    print_header()
    print_summary()

def cmd_events(args):
    level  = args.level.upper() if args.level else None
    source = args.source
    hours  = args.hours or 24
    limit  = args.limit or 50
    unacked_only = getattr(args, 'unacked', False)
    print_header()
    events = get_events(limit=limit, level=level, source=source,
                        hours=hours, unacked_only=unacked_only)
    filter_info = []
    if level:   filter_info.append(f"level={level}")
    if source:  filter_info.append(f"source={source}")
    if unacked_only: filter_info.append("unacked-only")
    filter_str = f" [{', '.join(filter_info)}]" if filter_info else ""
    print(f"  Hiển thị {len(events)} sự kiện ({hours}h qua){filter_str}\n")
    print_events(events, show_raw=args.raw)

def cmd_watch(args):
    level    = args.level.upper() if args.level else None
    source   = args.source
    seen_ids = set()
    print_header()
    print(f"  {CYAN}Live mode{NC} — Ctrl+C để thoát\n")
    try:
        while True:
            events     = get_events(limit=50, level=level, source=source, hours=1)
            new_events = [e for e in events if e[COL["id"]] not in seen_ids]
            for e in reversed(new_events):
                seen_ids.add(e[COL["id"]])
                level_   = e[COL["level"]]
                source_  = e[COL["source"]]
                message  = e[COL["message"]]
                ts       = e[COL["timestamp"]]
                user     = e[COL["user"]]
                ip_      = e[COL["ip"]]
                score    = e[COL["score"]]
                mitre    = e[COL["mitre"]]
                color    = LEVEL_COLOR.get(level_, NC)
                ts_short = ts[5:] if ts else ""
                user_str = f" {PURPLE}[{user}]{NC}" if user else ""
                ip_str   = f" {CYAN}[{ip_}]{NC}"    if ip_  else ""
                mitre_s  = f" {DIM}{mitre}{NC}"      if mitre else ""
                print(f"  {DIM}{ts_short}{NC}  {color}{BOLD}{level_:<8}{NC}  "
                      f"{GREEN}{source_:<10}{NC}  {message}{user_str}{ip_str}"
                      f" [{_score_str(score)}]{mitre_s}")
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n{DIM}Đã thoát.{NC}")

# ─── ACK COMMANDS ────────────────────────────────────────

def cmd_ack(args):
    if args.all:
        n = ack_all_events()
        print(f"  {GREEN}Đã xác nhận {n} alerts.{NC}")
    elif args.event_id:
        ok = ack_event(args.event_id)
        if ok:
            print(f"  {GREEN}Đã ACK event #{args.event_id}{NC}")
        else:
            print(f"  {RED}Không tìm thấy event #{args.event_id}{NC}")
    else:
        print(f"  {YELLOW}Dùng: zusiem ack <id>  hoặc  zusiem ack --all{NC}")

# ─── WHITELIST COMMANDS ──────────────────────────────────

def cmd_whitelist(args):
    if args.action == "list" or args.action is None:
        rows = get_whitelist()
        if not rows:
            print(f"  {DIM}Whitelist trống.{NC}")
            return
        print(f"\n  {BOLD}IP Whitelist:{NC}")
        print(f"  {'IP':<20} {'Lý do':<25} {'Thêm lúc'}")
        print(f"  {'─'*20} {'─'*25} {'─'*20}")
        for ip, reason, added_at in rows:
            print(f"  {CYAN}{ip:<20}{NC} {DIM}{(reason or '-'):<25}{NC} {added_at or '-'}")
        print()

    elif args.action == "add":
        if not args.ip:
            print(f"  {RED}Thiếu IP. Dùng: zusiem whitelist add <ip> [-r reason]{NC}")
            return
        reason = args.reason or "cli"
        add_to_whitelist(args.ip, reason)
        print(f"  {GREEN}Đã thêm {args.ip} vào whitelist ({reason}){NC}")

    elif args.action == "remove":
        if not args.ip:
            print(f"  {RED}Thiếu IP. Dùng: zusiem whitelist remove <ip>{NC}")
            return
        ok = remove_from_whitelist(args.ip)
        if ok:
            print(f"  {GREEN}Đã xóa {args.ip} khỏi whitelist{NC}")
        else:
            print(f"  {YELLOW}{args.ip} không có trong whitelist DB (có thể trong siem.conf){NC}")

# ─── DB COMMANDS ─────────────────────────────────────────

def cmd_db(args):
    print_header()
    stats = get_db_stats()
    print(f"{BOLD}{'─'*40}{NC}")
    print(f"  {CYAN}Tổng events    :{NC}  {BOLD}{stats['total']}{NC}")
    print(f"  {RED}Critical total :{NC}  {BOLD}{stats['critical']}{NC}")
    print(f"  {ORANGE}Chưa xử lý    :{NC}  {BOLD}{stats['unacked']}{NC}")
    print(f"  {GREEN}Whitelist IPs  :{NC}  {BOLD}{stats['whitelist']}{NC}")
    print(f"  {CYAN}DB size        :{NC}  {BOLD}{stats['size_mb']} MB{NC}")
    print(f"{BOLD}{'─'*40}{NC}\n")

    if getattr(args, 'cleanup', False):
        deleted = cleanup_old_events()
        print(f"  {GREEN}Đã xóa {deleted} events cũ.{NC}")

# ─── EXPORT ──────────────────────────────────────────────

def cmd_export(args):
    hours  = args.hours or 24
    level  = args.level.upper() if args.level else None
    source = args.source
    out    = args.output
    data   = export_events(hours=hours, limit=5000, level=level, source=source)
    if out:
        with open(out, "w") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"  {GREEN}Xuất {len(data)} sự kiện ra {out}{NC}")
    else:
        print(json.dumps(data, ensure_ascii=False, indent=2))

# ─── OLLAMA COMMANDS ─────────────────────────────────────

def cmd_ai_status(args):
    print_header()
    status = check_ollama_status()
    if status["running"]:
        print(f"  {GREEN}{BOLD}Ollama đang chạy{NC}  {DIM}{status['host']}{NC}")
        models = status.get("models", [])
        if models:
            print(f"\n  {BOLD}Models có sẵn:{NC}")
            for m in models:
                print(f"    {CYAN}•{NC} {m}")
        else:
            print(f"  {YELLOW}Chưa có model. Tải: ollama pull qwen2.5-coder:7b{NC}")
    else:
        print(f"  {RED}{BOLD}Ollama không chạy{NC}")
        print(f"  {DIM}Khởi động: ollama serve{NC}")
        print(f"  {DIM}Tải model : ollama pull qwen2.5-coder:7b{NC}")

def cmd_ai_ask(args):
    status = check_ollama_status()
    if not status["running"]:
        print(f"  {RED}Ollama không chạy! Chạy: ollama serve{NC}")
        return
    hours    = getattr(args, 'hours', 1) or 1
    question = " ".join(args.question) if getattr(args, 'question', None) else None
    events   = get_recent_events_text(hours=hours)
    print(f"\n  {CYAN}{BOLD}Ollama AI đang phân tích...{NC}\n")
    result = analyze_with_ollama(events, question)
    print(f"  {BOLD}Kết quả:{NC}\n")
    for line in result.splitlines():
        print(f"  {line}")
    print()

# ─── MAIN ────────────────────────────────────────────────

def main():
    init_db()
    parser = argparse.ArgumentParser(
        prog="zusiem",
        description="ZuSIEM CLI — Security Monitor + AI"
    )
    sub = parser.add_subparsers(dest="cmd")

    # status
    p = sub.add_parser("status", help="Xem tổng quan")
    p.set_defaults(func=cmd_status)

    # events
    p = sub.add_parser("events", help="Xem sự kiện")
    p.add_argument("-l", "--level",   help="CRITICAL/WARNING/INFO")
    p.add_argument("-s", "--source",  help="auth.log/ufw/auditd/scanner/nginx")
    p.add_argument("-H", "--hours",   type=int, default=24)
    p.add_argument("-n", "--limit",   type=int, default=50)
    p.add_argument("-r", "--raw",     action="store_true", help="Hiển thị raw log")
    p.add_argument("-u", "--unacked", action="store_true", help="Chỉ hiện chưa xử lý")
    p.set_defaults(func=cmd_events)

    # watch
    p = sub.add_parser("watch", help="Live monitoring")
    p.add_argument("-l", "--level",  help="Filter mức")
    p.add_argument("-s", "--source", help="Filter nguồn")
    p.set_defaults(func=cmd_watch)

    # ack
    p = sub.add_parser("ack", help="Xác nhận (acknowledge) alert")
    p.add_argument("event_id", type=int, nargs="?", help="ID sự kiện")
    p.add_argument("--all", action="store_true", help="Xác nhận tất cả")
    p.set_defaults(func=cmd_ack)

    # whitelist
    p = sub.add_parser("whitelist", help="Quản lý IP whitelist")
    p.add_argument("action", nargs="?", choices=["list", "add", "remove"],
                   default="list")
    p.add_argument("ip",     nargs="?", help="Địa chỉ IP")
    p.add_argument("-r", "--reason", help="Lý do thêm vào whitelist")
    p.set_defaults(func=cmd_whitelist)

    # db
    p = sub.add_parser("db", help="Thống kê và bảo trì database")
    p.add_argument("--cleanup", action="store_true", help="Xóa events cũ")
    p.set_defaults(func=cmd_db)

    # ai ask
    p = sub.add_parser("ai", help="Hỏi Ollama AI về bảo mật")
    p.add_argument("question", nargs="*", help="Câu hỏi (bỏ trống = phân tích tự động)")
    p.add_argument("-H", "--hours", type=int, default=1, help="Số giờ log (default: 1)")
    p.set_defaults(func=cmd_ai_ask)

    # ai status
    p = sub.add_parser("ai-status", help="Kiểm tra trạng thái Ollama")
    p.set_defaults(func=cmd_ai_status)

    # export
    p = sub.add_parser("export", help="Xuất sự kiện ra JSON")
    p.add_argument("-l", "--level",  help="CRITICAL/WARNING/INFO")
    p.add_argument("-s", "--source", help="Nguồn log")
    p.add_argument("-H", "--hours",  type=int, default=24)
    p.add_argument("-o", "--output", help="File đầu ra (mặc định: stdout)")
    p.set_defaults(func=cmd_export)

    args = parser.parse_args()
    if not args.cmd:
        cmd_status(args)
    else:
        args.func(args)

if __name__ == "__main__":
    main()
