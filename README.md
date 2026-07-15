# ZuSIEM — mini SIEM for Ubuntu

Một bộ giám sát an ninh (SIEM) nhỏ gọn cho Ubuntu, viết bằng Python thuần. Gồm phân tích log, honeypot bẫy kẻ tấn công, kiểm tra security posture, quét malware và dashboard web — tất cả trong một.

> ⚠️ **Đọc phần [Cảnh báo an toàn](#-cảnh-báo-an-toàn) trước khi chạy.** Một số thành phần (honeypot) cố tình phơi dịch vụ ra mạng và **không nên** chạy trên máy chứa dữ liệu quan trọng.

---

## Tính năng

| Thành phần | Chức năng |
|---|---|
| **siem_engine** | Lõi SIEM: đọc `auth.log`/UFW/auditd, phát hiện brute-force & port scan, lưu SQLite, cảnh báo (desktop/Telegram), auto-ban qua UFW |
| **netsvc** (honeypot) | Giả banner SSH/FTP/Telnet/MySQL/RDP/VNC/HTTP để bẫy & ghi lại kẻ tấn công |
| **netguard** | Mini-IPS phát hiện & chặn flood/DoS trong LAN (SYN/connection/rate flood) |
| **zucheck** | Kiểm tra security posture: chấm điểm hardening, phát hiện drift (user/cron/SUID/service lạ) |
| **zuscan** | Quét malware 2 lớp: VirusTotal (qua hash) + phân tích tĩnh offline |
| **siem_web** | Dashboard web (Flask) — xem sự kiện, IP đáng ngờ, điểm bảo mật |
| **siem_cli** | Giao diện dòng lệnh: status, events, whitelist, export, ai |

Ánh xạ kỹ thuật theo **MITRE ATT&CK**, chấm điểm rủi ro cho mỗi sự kiện.

---

## Yêu cầu

- Ubuntu (20.04+), Python 3.10+
- `ufw`, `auditd` (khuyến nghị)
- Python packages: `flask`, `cryptography`

---

## Cài đặt

```bash
git clone https://github.com/benopro/ZuSIEM---mini-SIEM-for-Ubuntu.git
cd ZuSIEM---mini-SIEM-for-Ubuntu

# tạo config từ mẫu
cp siem.conf.example siem.conf

# cài & tạo systemd service (kèm sandbox hardening)
bash start.sh setup
```

### Cấu hình secret (Telegram token, mật khẩu web)

Secret được mã hoá AES-256-GCM, **không** lưu plaintext:

```bash
python3 secrets_manager.py init-key          # tạo khoá (lưu ở ~/.config/zusiem/secret.key)
python3 secrets_manager.py encrypt           # mã hoá 1 secret → dán chuỗi enc:... vào siem.conf
```

> 🔑 **Sao lưu `secret.key` nơi an toàn.** Mất khoá = mất toàn bộ secret đã mã hoá. Khoá này **không** nằm trong repo và **không** được commit.

### Chạy

```bash
# chọn service muốn bật (KHÔNG bắt buộc bật honeypot — xem cảnh báo bên dưới)
sudo systemctl enable --now zusiem-engine zusiem-web zusiem-zucheck
```

Dashboard: `http://localhost:5000` (mặc định chỉ nghe localhost — xem qua SSH tunnel nếu ở xa).

---

## Cách dùng CLI

```bash
python3 siem_cli.py status              # tổng quan
python3 siem_cli.py events -H 24 -r     # sự kiện 24h qua kèm raw log
python3 siem_cli.py whitelist add <IP>  # thêm IP vào whitelist
python3 siem_cli.py export -H 24 -o log.json   # xuất JSON để phân tích
```

---

## ⚠️ Cảnh báo an toàn

Đây là công cụ học tập / phòng thủ. Dùng sai chỗ có thể phản tác dụng hoặc gây rủi ro:

### Về honeypot (`netsvc`)
- Honeypot **cố tình mở** nhiều cổng dịch vụ (21/23/25/80/2222/3306/3389/5900/8080) để dụ kẻ tấn công. Nó **KHÔNG bảo vệ máy** — nó là công cụ *quan sát*, và làm tăng bề mặt tấn công.
- **Chỉ chạy honeypot trên máy "vứt-đi-được"** (VPS riêng, VM cách ly). **Đừng** chạy trên máy cá nhân / máy chứa dữ liệu quan trọng.
- Nếu phơi ra internet: chặn egress, dùng VPS riêng, coi máy như có thể bị đốt bất cứ lúc nào.

### Về auto-ban
- **Whitelist IP của bạn TRƯỚC khi bật honeypot/netguard**, nếu không công cụ có thể tự ban chính bạn khỏi máy:
  ```bash
  python3 siem_cli.py whitelist add <IP_của_bạn> -r "my IP"
  ```
- IP động (nhà mạng) có thể đổi → nếu mất SSH đột ngột, kiểm tra `ufw status` xem có tự ban nhầm không.

### Trên desktop cá nhân
- Nên **tắt honeypot** (`enabled = false` trong `[honeypot]`) và để `netguard auto_ban = false`. Chỉ giữ engine + zucheck + zuscan cho mục đích phòng thủ.

### Bảo mật khi deploy
- **Không commit** `siem.conf` thật, `secret.key`, `vt_api.key` (đã có trong `.gitignore`).
- Nếu dùng VirusTotal: để API key qua biến môi trường `VT_API_KEY`, không lưu file trong repo.
- Siết SSH: dùng key thay mật khẩu, `PasswordAuthentication no`.

---

## Giấy phép

MIT License — xem file [LICENSE](LICENSE).

---

## Ghi chú

Dự án cá nhân, phục vụ học tập về blue team / an ninh mạng phòng thủ. Không đảm bảo cho môi trường production. Đóng góp & góp ý luôn hoan nghênh.
