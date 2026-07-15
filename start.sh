#!/bin/bash
# ============================================================
#  ZuSIEM - Launcher & Setup Script
# ============================================================

SIEM_DIR="$(cd "$(dirname "$0")" && pwd)"
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "$1"; }
info() { log "${CYAN}[*]${NC} $1"; }
ok()   { log "${GREEN}[+]${NC} $1"; }
warn() { log "${YELLOW}[!]${NC} $1"; }
err()  { log "${RED}[!]${NC} $1"; }

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║   ZuSIEM - Mini SIEM for Ubuntu      ║"
    echo "  ╚══════════════════════════════════════╝"
    echo -e "${NC}"
}

cmd_setup() {
    print_banner
    info "Cài đặt dependencies..."

    # Tạo venv nếu chưa có
    if [[ ! -x "$SIEM_DIR/venv/bin/python3" ]]; then
        info "Tạo virtual environment..."
        python3 -m venv "$SIEM_DIR/venv"
        ok "Venv đã tạo"
    fi

    # Cài dependencies vào venv
    NEED_INSTALL=0
    "$SIEM_DIR/venv/bin/python3" -c "import flask"        2>/dev/null || NEED_INSTALL=1
    "$SIEM_DIR/venv/bin/python3" -c "import cryptography" 2>/dev/null || NEED_INSTALL=1
    if [[ $NEED_INSTALL -eq 0 ]]; then
        ok "Flask + cryptography đã có trong venv"
    else
        info "Cài flask + cryptography vào venv..."
        "$SIEM_DIR/venv/bin/pip" install flask cryptography --quiet
        ok "Dependencies đã cài"
    fi

    mkdir -p "$SIEM_DIR/logs"

    # Tạo systemd service cho engine
    info "Tạo systemd service (kèm sandbox hardening)..."

    # Hardening dùng chung cho mọi service — không đụng vào chức năng
    # (không dùng ProtectSystem/ProtectHome ở đây vì cần khai báo ReadWritePaths riêng từng service)
    read -r -d '' HARDEN_COMMON <<'EOC' || true
NoNewPrivileges=true
ProtectHostname=true
ProtectClock=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
RemoveIPC=true
PrivateTmp=true
EOC

    # Sandbox filesystem: toàn hệ thống read-only, chỉ ghi được vào SIEM_DIR
    # (+ /etc/ufw cho service nào tự gọi lệnh ufw để ban IP)
    sudo tee /etc/systemd/system/zusiem-engine.service > /dev/null <<EOF
[Unit]
Description=ZuSIEM Security Engine
After=network.target auditd.service

[Service]
Type=simple
User=root
ExecStart=${SIEM_DIR}/venv/bin/python3 ${SIEM_DIR}/siem_engine.py
Restart=always
RestartSec=5
${HARDEN_COMMON}
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${SIEM_DIR} /etc/ufw

[Install]
WantedBy=multi-user.target
EOF

    sudo tee /etc/systemd/system/zusiem-web.service > /dev/null <<EOF
[Unit]
Description=ZuSIEM Web Dashboard
After=zusiem-engine.service

[Service]
Type=simple
User=$(whoami)
ExecStart=${SIEM_DIR}/venv/bin/python3 ${SIEM_DIR}/siem_web.py
Restart=always
RestartSec=5
${HARDEN_COMMON}
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${SIEM_DIR}

[Install]
WantedBy=multi-user.target
EOF

    sudo tee /etc/systemd/system/zusiem-honeypot.service > /dev/null <<EOF
[Unit]
Description=ZuSIEM Honeypot (bẫy kẻ xâm nhập)
After=network.target zusiem-engine.service

[Service]
Type=simple
User=root
ExecStart=${SIEM_DIR}/venv/bin/python3 ${SIEM_DIR}/netsvc.py
Restart=always
RestartSec=5
${HARDEN_COMMON}
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${SIEM_DIR} /etc/ufw

[Install]
WantedBy=multi-user.target
EOF

    sudo tee /etc/systemd/system/zusiem-netguard.service > /dev/null <<EOF
[Unit]
Description=ZuSIEM NetGuard (LAN IPS / chống flood)
After=network.target zusiem-engine.service

[Service]
Type=simple
User=root
ExecStart=${SIEM_DIR}/venv/bin/python3 ${SIEM_DIR}/netguard.py
Restart=always
RestartSec=5
${HARDEN_COMMON}
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${SIEM_DIR} /etc/ufw

[Install]
WantedBy=multi-user.target
EOF

    sudo tee /etc/systemd/system/zusiem-zucheck.service > /dev/null <<EOF
[Unit]
Description=ZuSIEM ZuCheck (kiểm tra bảo mật định kỳ)
After=zusiem-engine.service

[Service]
Type=simple
User=root
ExecStart=${SIEM_DIR}/venv/bin/python3 ${SIEM_DIR}/zucheck.py
Restart=always
RestartSec=30
${HARDEN_COMMON}
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${SIEM_DIR}

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    ok "Systemd services đã tạo"

    # Bảo vệ file config (chứa token nhạy cảm)
    chmod 600 "$SIEM_DIR/siem.conf" 2>/dev/null && ok "siem.conf quyền 600"

    # Quyền đọc log
    info "Cấp quyền đọc log..."
    sudo usermod -aG adm $(whoami) 2>/dev/null || true
    sudo chmod 644 /var/log/kern.log 2>/dev/null || true

    ok "Setup hoàn tất!"
    echo ""
    echo -e "  ${BOLD}Bước tiếp theo:${NC}"
    echo -e "  1. Sửa ${CYAN}siem.conf${NC} — điền Telegram token, điều chỉnh ngưỡng"
    echo -e "  2. ${CYAN}sudo systemctl enable zusiem-engine zusiem-web zusiem-honeypot zusiem-netguard zusiem-zucheck${NC}"
    echo -e "  3. ${CYAN}sudo systemctl start  zusiem-engine zusiem-web zusiem-honeypot zusiem-netguard zusiem-zucheck${NC}"
    echo -e "  4. Mở:  ${CYAN}http://localhost:5000${NC}"
    echo ""
    echo -e "  ${BOLD}5 service:${NC}"
    echo -e "  ${CYAN}zusiem-engine${NC}   — SIEM core (phân tích log, alert Telegram)"
    echo -e "  ${CYAN}zusiem-web${NC}      — Dashboard http://localhost:5000"
    echo -e "  ${CYAN}zusiem-honeypot${NC} — Bẫy kẻ xâm nhập (SSH/FTP/MySQL/RDP/VNC...)"
    echo -e "  ${CYAN}zusiem-netguard${NC} — Mini-IPS chống flood LAN"
    echo -e "  ${CYAN}zusiem-zucheck${NC}  — Kiểm tra bảo mật định kỳ (điểm bảo mật)"
}

_find_python() {
    # Preferă python3 din PATH (are flask instalat în user site)
    for py in python3 python3.14 python3.12; do
        if command -v "$py" &>/dev/null && "$py" -c "import flask" 2>/dev/null; then
            echo "$py"; return
        fi
    done
    # Fallback: venv nếu có
    [[ -x "$SIEM_DIR/venv/bin/python3" ]] && echo "$SIEM_DIR/venv/bin/python3" && return
    err "Không tìm thấy python3 có Flask! Chạy: bash start.sh setup"; exit 1
}

cmd_start() {
    print_banner
    info "Khởi động ZuSIEM..."

    if systemctl is-enabled zusiem-engine &>/dev/null 2>&1; then
        for svc in zusiem-engine zusiem-web zusiem-honeypot zusiem-netguard zusiem-zucheck; do
            sudo systemctl start "$svc" 2>/dev/null
            STATUS=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
            [[ "$STATUS" == "active" ]] && ok "$svc: $STATUS" || warn "$svc: $STATUS"
        done
    else
        PYTHON="$(_find_python)"
        info "Dùng Python: $PYTHON"

        # Dừng tiến trình cũ nếu còn
        for svc in engine web honeypot netguard zucheck; do
            [[ -f "$SIEM_DIR/${svc}.pid" ]] && kill "$(cat "$SIEM_DIR/${svc}.pid")" 2>/dev/null
            rm -f "$SIEM_DIR/${svc}.pid"
        done

        # Engine (cần group adm để đọc log)
        "$PYTHON" "$SIEM_DIR/siem_engine.py" >> "$SIEM_DIR/engine.log" 2>&1 &
        echo $! > "$SIEM_DIR/engine.pid"

        # Web dashboard
        "$PYTHON" "$SIEM_DIR/siem_web.py" >> "$SIEM_DIR/web.log" 2>&1 &
        echo $! > "$SIEM_DIR/web.pid"

        # Honeypot (cần root cho port < 1024 + UFW)
        sudo "$PYTHON" "$SIEM_DIR/netsvc.py" >> "$SIEM_DIR/honeypot.log" 2>&1 &
        echo $! > "$SIEM_DIR/honeypot.pid"

        # NetGuard IPS (cần root cho UFW)
        sudo "$PYTHON" "$SIEM_DIR/netguard.py" >> "$SIEM_DIR/netguard.log" 2>&1 &
        echo $! > "$SIEM_DIR/netguard.pid"

        # ZuCheck posture auditor (cần root cho /etc/shadow)
        sudo "$PYTHON" "$SIEM_DIR/zucheck.py" >> "$SIEM_DIR/zucheck.log" 2>&1 &
        echo $! > "$SIEM_DIR/zucheck.pid"

        sleep 1
        for svc in engine web honeypot netguard zucheck; do
            PID=$(cat "$SIEM_DIR/${svc}.pid" 2>/dev/null)
            kill -0 "$PID" 2>/dev/null && ok "$svc PID: $PID" || err "$svc crash! Xem: tail -20 $SIEM_DIR/${svc}.log"
        done
    fi

    echo ""
    ok "Dashboard: ${CYAN}http://localhost:5000${NC}"
    ok "CLI:       ${CYAN}python3 siem_cli.py status${NC}"
    ok "Logs:      ${CYAN}tail -f $SIEM_DIR/engine.log${NC}"
}

cmd_stop() {
    info "Dừng ZuSIEM..."
    if systemctl is-enabled zusiem-engine &>/dev/null 2>&1; then
        sudo systemctl stop zusiem-engine zusiem-web zusiem-honeypot zusiem-netguard zusiem-zucheck 2>/dev/null
    else
        for svc in engine web honeypot netguard zucheck; do
            [[ -f "$SIEM_DIR/${svc}.pid" ]] && sudo kill "$(cat "$SIEM_DIR/${svc}.pid")" 2>/dev/null
            rm -f "$SIEM_DIR/${svc}.pid"
        done
    fi
    ok "ZuSIEM đã dừng"
}

cmd_status() {
    print_banner
    echo -e "  ${BOLD}Trạng thái dịch vụ:${NC}"
    declare -A SVC_LABEL=(
        [zusiem-engine]="Engine     "
        [zusiem-web]="Web        "
        [zusiem-honeypot]="Honeypot   "
        [zusiem-netguard]="NetGuard   "
        [zusiem-zucheck]="ZuCheck    "
    )
    for svc in zusiem-engine zusiem-web zusiem-honeypot zusiem-netguard zusiem-zucheck; do
        STATUS=$(systemctl is-active "$svc" 2>/dev/null || echo "manual")
        LABEL="${SVC_LABEL[$svc]}"
        if [[ "$STATUS" == "active" ]]; then
            echo -e "  ${LABEL}: ${GREEN}running${NC}"
        else
            PID_FILE="$SIEM_DIR/${svc#zusiem-}.pid"
            PID=$(cat "$PID_FILE" 2>/dev/null)
            if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
                echo -e "  ${LABEL}: ${GREEN}running${NC} (manual PID $PID)"
            else
                echo -e "  ${LABEL}: ${RED}stopped${NC}"
            fi
        fi
    done
    echo ""
    "$SIEM_DIR/venv/bin/python3" "$SIEM_DIR/siem_cli.py" status
}

cmd_enable() {
    info "Bật tự động khởi động cùng hệ thống..."
    sudo systemctl enable zusiem-engine zusiem-web zusiem-honeypot zusiem-netguard zusiem-zucheck
    ok "Tất cả 5 service ZuSIEM sẽ tự khởi động khi boot"
}

case "$1" in
    setup)  cmd_setup  ;;
    start)  cmd_start  ;;
    stop)   cmd_stop   ;;
    status) cmd_status ;;
    enable) cmd_enable ;;
    *)
        print_banner
        echo -e "  ${BOLD}Cách dùng:${NC}"
        echo -e "  ${CYAN}bash start.sh setup${NC}   — Cài đặt lần đầu"
        echo -e "  ${CYAN}bash start.sh start${NC}   — Khởi động SIEM"
        echo -e "  ${CYAN}bash start.sh stop${NC}    — Dừng SIEM"
        echo -e "  ${CYAN}bash start.sh status${NC}  — Xem trạng thái"
        echo -e "  ${CYAN}bash start.sh enable${NC}  — Tự khởi động khi boot"
        echo ""
        ;;
esac
