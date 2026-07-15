#!/usr/bin/env python3
"""
ZuSIEM - Web Dashboard Server
Flask-based web UI cho SIEM
"""

import re
import sys
import hmac
import time
import threading
from functools import wraps
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent))
from siem_engine import (
    init_db, get_events, get_stats, get_summary, get_trend,
    analyze_with_ollama, get_recent_events_text, check_ollama_status,
    list_ollama_models, export_events, load_config,
    ack_event, ack_all_events,
    get_whitelist, add_to_whitelist, remove_from_whitelist,
    get_db_stats,
)
from secrets_manager import decrypt

try:
    from flask import Flask, jsonify, render_template_string, request, Response
except ImportError:
    print("[!] Flask chưa cài: pip install flask --break-system-packages")
    sys.exit(1)

app = Flask(__name__)

# ─── SECURITY HEADERS ─────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]          = "no-referrer"
    # inline scripts/styles cần thiết cho dashboard — giới hạn nguồn bên ngoài
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' fonts.googleapis.com; "
        "font-src fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response

# ─── BASIC AUTH ───────────────────────────────────────────
def _check_credentials(username, password):
    cfg      = load_config()
    expected_user = cfg.get("web", "username", fallback="admin")
    expected_pass = decrypt(cfg.get("web", "password", fallback="zusiem"))
    return (hmac.compare_digest(username, expected_user)
            and hmac.compare_digest(password, expected_pass))

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        cfg = load_config()
        if not cfg.getboolean("web", "auth_enabled", fallback=False):
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or not _check_credentials(auth.username, auth.password):
            return Response(
                "Authentication required", 401,
                {"WWW-Authenticate": 'Basic realm="ZuSIEM Dashboard"'}
            )
        return f(*args, **kwargs)
    return decorated

# ─── RATE LIMITING ────────────────────────────────────────
_rate_counts = defaultdict(list)
_rate_lock   = threading.Lock()

def _is_rate_limited(ip, max_req=120, window=60):
    now = time.time()
    with _rate_lock:
        _rate_counts[ip] = [t for t in _rate_counts[ip] if now - t < window]
        if len(_rate_counts[ip]) >= max_req:
            return True
        _rate_counts[ip].append(now)
        return False

@app.before_request
def check_rate_limit():
    ip = request.remote_addr or "unknown"
    if _is_rate_limited(ip):
        return jsonify({"error": "Rate limit exceeded"}), 429

# ─── INPUT VALIDATION ────────────────────────────────────
_IP_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')

def _valid_ip(ip):
    m = _IP_RE.match(ip or "")
    return bool(m) and all(0 <= int(g) <= 255 for g in m.groups())

# ─── DASHBOARD HTML ───────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZuSIEM Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:      #080c10; --bg2: #0d1117; --bg3: #111820;
    --border:  #1e3a4a; --accent: #00d4ff; --accent2: #00ff88;
    --red:     #ff3b5c; --yellow: #ffcc00; --blue: #4488ff;
    --muted:   #4a6278; --text: #c8dde8;
    --mono:    'Share Tech Mono', monospace;
    --sans:    'Exo 2', sans-serif;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:var(--bg); color:var(--text); font-family:var(--sans); min-height:100vh; overflow-x:hidden; }
  body::before {
    content:''; position:fixed; inset:0; pointer-events:none; z-index:9999;
    background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,212,255,.015) 2px,rgba(0,212,255,.015) 4px);
  }
  header {
    background:var(--bg2); border-bottom:1px solid var(--border);
    padding:14px 28px; display:flex; align-items:center; justify-content:space-between;
    position:sticky; top:0; z-index:100;
  }
  .logo { font-family:var(--mono); font-size:1.3rem; color:var(--accent); letter-spacing:3px; text-shadow:0 0 20px var(--accent); }
  .logo span { color:var(--accent2); }
  .status-bar { display:flex; gap:20px; align-items:center; font-family:var(--mono); font-size:.75rem; color:var(--muted); }
  .status-dot { width:8px; height:8px; border-radius:50%; background:var(--accent2); box-shadow:0 0 8px var(--accent2); animation:pulse 2s infinite; display:inline-block; margin-right:6px; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
  .main { padding:24px 28px; max-width:1400px; margin:0 auto; }
  .stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:16px; margin-bottom:28px; }
  .stat-card { background:var(--bg2); border:1px solid var(--border); border-radius:8px; padding:20px; position:relative; overflow:hidden; transition:border-color .2s; }
  .stat-card:hover { border-color:var(--accent); }
  .stat-card::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; }
  .stat-card.critical::before { background:var(--red); }
  .stat-card.warning::before  { background:var(--yellow); }
  .stat-card.info::before     { background:var(--blue); }
  .stat-card.total::before    { background:var(--accent); }
  .stat-card.unacked::before  { background:#ff6b35; }
  .stat-label { font-family:var(--mono); font-size:.65rem; color:var(--muted); letter-spacing:2px; text-transform:uppercase; margin-bottom:10px; }
  .stat-value { font-family:var(--mono); font-size:2.2rem; font-weight:700; line-height:1; }
  .stat-card.critical .stat-value { color:var(--red);    text-shadow:0 0 20px var(--red); }
  .stat-card.warning  .stat-value { color:var(--yellow); text-shadow:0 0 20px var(--yellow); }
  .stat-card.info     .stat-value { color:var(--blue); }
  .stat-card.total    .stat-value { color:var(--accent); text-shadow:0 0 20px var(--accent); }
  .stat-card.unacked  .stat-value { color:#ff6b35; text-shadow:0 0 20px #ff6b35; }
  .stat-card.score::before  { background:#a78bfa; }
  .stat-card.score  .stat-value { color:#a78bfa; text-shadow:0 0 20px #a78bfa; }
  .stat-sub { font-size:.72rem; color:var(--muted); margin-top:6px; }
  .panel { background:var(--bg2); border:1px solid var(--border); border-radius:8px; margin-bottom:20px; overflow:hidden; }
  .panel-header { padding:14px 20px; border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; background:var(--bg3); }
  .panel-title { font-family:var(--mono); font-size:.78rem; color:var(--accent); letter-spacing:2px; text-transform:uppercase; }
  .filter-bar { display:flex; gap:10px; align-items:center; padding:12px 20px; border-bottom:1px solid var(--border); background:var(--bg3); flex-wrap:wrap; }
  .filter-btn { background:transparent; border:1px solid var(--border); color:var(--muted); padding:5px 14px; border-radius:4px; font-family:var(--mono); font-size:.72rem; cursor:pointer; transition:all .2s; letter-spacing:1px; }
  .filter-btn:hover,.filter-btn.active { border-color:var(--accent); color:var(--accent); background:rgba(0,212,255,.08); }
  .filter-btn.critical.active { border-color:var(--red);    color:var(--red);    background:rgba(255,59,92,.08); }
  .filter-btn.warning.active  { border-color:var(--yellow); color:var(--yellow); background:rgba(255,204,0,.08); }
  .filter-btn.unacked.active  { border-color:#ff6b35;       color:#ff6b35;       background:rgba(255,107,53,.08); }
  .events-table { width:100%; border-collapse:collapse; font-size:.82rem; }
  .events-table th { font-family:var(--mono); font-size:.65rem; color:var(--muted); letter-spacing:2px; text-transform:uppercase; padding:10px 12px; text-align:left; border-bottom:1px solid var(--border); background:var(--bg3); }
  .events-table td { padding:8px 12px; border-bottom:1px solid rgba(30,58,74,.4); font-family:var(--mono); vertical-align:top; }
  .events-table tr:hover td { background:rgba(0,212,255,.04); }
  .events-table tr.acked td { opacity:.45; }
  .badge { display:inline-block; padding:2px 8px; border-radius:3px; font-size:.65rem; font-family:var(--mono); letter-spacing:1px; font-weight:600; }
  .badge-critical { background:rgba(255,59,92,.15);  color:var(--red);    border:1px solid var(--red); }
  .badge-warning  { background:rgba(255,204,0,.15);  color:var(--yellow); border:1px solid var(--yellow); }
  .badge-info     { background:rgba(68,136,255,.15); color:var(--blue);   border:1px solid var(--blue); }
  .score-badge { display:inline-block; width:22px; text-align:center; border-radius:3px; font-size:.65rem; font-family:var(--mono); font-weight:700; }
  .score-high   { background:rgba(255,59,92,.2);  color:var(--red); }
  .score-medium { background:rgba(255,204,0,.2);  color:var(--yellow); }
  .score-low    { background:rgba(68,136,255,.2); color:var(--blue); }
  .mitre-tag { font-size:.62rem; color:var(--muted); font-family:var(--mono); }
  .ts       { color:var(--muted); font-size:.72rem; white-space:nowrap; }
  .src      { color:var(--accent2); }
  .msg      { color:var(--text); word-break:break-all; max-width:320px; }
  .ip-tag   { color:var(--accent); font-size:.72rem; }
  .user-tag { color:#a78bfa; font-size:.72rem; }
  .ack-btn { background:transparent; border:1px solid var(--border); color:var(--muted); padding:2px 8px; border-radius:3px; font-family:var(--mono); font-size:.65rem; cursor:pointer; transition:all .2s; }
  .ack-btn:hover         { border-color:var(--accent2); color:var(--accent2); }
  .ack-btn.done          { border-color:var(--accent2); color:var(--accent2); cursor:default; }
  .two-col { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:20px; }
  @media (max-width:900px) { .two-col { grid-template-columns:1fr; } }
  .chart-wrap { padding:14px 16px; }
  .chart-canvas { width:100%; height:220px; border:1px solid rgba(30,58,74,.4); border-radius:6px; background:#0a0f14; }
  .mini-table { width:100%; border-collapse:collapse; font-size:.8rem; }
  .mini-table td { padding:8px 16px; border-bottom:1px solid rgba(30,58,74,.4); font-family:var(--mono); }
  .mini-table tr:hover td { background:rgba(0,212,255,.04); }
  .mini-table .rank { color:var(--muted); font-size:.7rem; width:30px; }
  .mini-table .cnt  { text-align:right; color:var(--accent); font-weight:600; }
  .refresh-btn { background:transparent; border:1px solid var(--accent); color:var(--accent); padding:5px 14px; border-radius:4px; font-family:var(--mono); font-size:.7rem; cursor:pointer; letter-spacing:1px; transition:all .2s; }
  .refresh-btn:hover { background:rgba(0,212,255,.1); }
  .refresh-btn.danger { border-color:var(--red); color:var(--red); }
  .refresh-btn.danger:hover { background:rgba(255,59,92,.1); }
  .auto-refresh { font-family:var(--mono); font-size:.7rem; color:var(--muted); }
  .empty { padding:40px; text-align:center; color:var(--muted); font-family:var(--mono); font-size:.8rem; }
  .scrollable { max-height:500px; overflow-y:auto; }
  .scrollable::-webkit-scrollbar { width:4px; }
  .scrollable::-webkit-scrollbar-track { background:var(--bg); }
  .scrollable::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }
  .search-input { background:var(--bg); border:1px solid var(--border); color:var(--text); padding:5px 12px; border-radius:4px; font-family:var(--mono); font-size:.75rem; outline:none; width:200px; transition:border-color .2s; }
  .search-input:focus { border-color:var(--accent); }
  .search-input::placeholder { color:var(--muted); }
  #toast-container { position:fixed; top:70px; right:20px; z-index:9998; display:flex; flex-direction:column; gap:8px; }
  .toast { background:var(--bg2); border:1px solid var(--red); border-left:4px solid var(--red); padding:12px 16px; border-radius:6px; min-width:280px; font-family:var(--mono); font-size:.78rem; color:var(--text); box-shadow:0 4px 20px rgba(0,0,0,.6); animation:slideIn .3s ease; }
  .toast .toast-title { color:var(--red); font-weight:700; margin-bottom:4px; }
  .toast .toast-close { float:right; cursor:pointer; color:var(--muted); }
  @keyframes slideIn { from{transform:translateX(120%);opacity:0} to{transform:none;opacity:1} }
  .raw-row td { background:rgba(0,0,0,.4) !important; color:var(--muted) !important; font-size:.7rem !important; padding:4px 12px 8px !important; word-break:break-all; border-bottom:1px solid var(--border) !important; }
  .events-table tr.clickable { cursor:pointer; }
  /* Whitelist panel */
  .wl-form { display:flex; gap:8px; padding:12px 16px; border-bottom:1px solid var(--border); background:var(--bg3); flex-wrap:wrap; }
  .wl-input { background:var(--bg); border:1px solid var(--border); color:var(--text); padding:5px 12px; border-radius:4px; font-family:var(--mono); font-size:.78rem; outline:none; flex:1; min-width:160px; }
  .wl-input:focus { border-color:var(--accent2); }
  .del-btn { background:transparent; border:1px solid var(--red); color:var(--red); padding:2px 10px; border-radius:3px; font-family:var(--mono); font-size:.7rem; cursor:pointer; }
  .del-btn:hover { background:rgba(255,59,92,.1); }
  /* Ollama */
  #ollama-panel { max-width:1400px; margin:0 auto 20px; padding:0 28px; }
  .ollama-msg { margin-bottom:14px; }
  .ollama-msg.user   { color:var(--accent); }
  .ollama-msg.user::before { content:"👤 Bạn: "; font-weight:700; }
  .ollama-msg.ai     { color:var(--text); border-left:2px solid var(--accent2); padding-left:10px; white-space:pre-wrap; }
  .ollama-msg.ai::before { content:"🦙 AI: "; color:var(--accent2); font-weight:700; }
  .ollama-msg.loading { color:var(--muted); font-style:italic; animation:blink 1s infinite; }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.4} }
</style>
</head>
<body>

<div id="toast-container"></div>

<header>
  <div class="logo">Zu<span>SIEM</span> <span style="font-size:.7rem;color:var(--muted)">v3.0</span></div>
  <div class="status-bar">
    <span><span class="status-dot"></span>LIVE</span>
    <span id="clock">--:--:--</span>
    <span id="hostname">...</span>
  </div>
</header>

<div class="main">

  <!-- Stats -->
  <div class="stats-grid">
    <div class="stat-card total">
      <div class="stat-label">Tổng 24h</div>
      <div class="stat-value" id="s-total">--</div>
      <div class="stat-sub" id="s-1h">-- trong 1h</div>
    </div>
    <div class="stat-card critical">
      <div class="stat-label">Critical</div>
      <div class="stat-value" id="s-critical">--</div>
      <div class="stat-sub">Nghiêm trọng</div>
    </div>
    <div class="stat-card warning">
      <div class="stat-label">Warning</div>
      <div class="stat-value" id="s-warning">--</div>
      <div class="stat-sub">Cảnh báo</div>
    </div>
    <div class="stat-card info">
      <div class="stat-label">Info</div>
      <div class="stat-value" id="s-info">--</div>
      <div class="stat-sub">Thông tin</div>
    </div>
    <div class="stat-card unacked">
      <div class="stat-label">Chưa xử lý</div>
      <div class="stat-value" id="s-unacked">--</div>
      <div class="stat-sub">Cần acknowledge</div>
    </div>
    <div class="stat-card score">
      <div class="stat-label">Bảo mật</div>
      <div class="stat-value" id="s-score">--</div>
      <div class="stat-sub" id="s-grade">ZuCheck</div>
    </div>
  </div>

  <!-- Top IPs & Users -->
  <div class="two-col">
    <div class="panel">
      <div class="panel-header"><span class="panel-title">⚡ Top IP đáng ngờ (24h)</span></div>
      <table class="mini-table" id="top-ips"><tr><td class="empty">Đang tải...</td></tr></table>
    </div>
    <div class="panel">
      <div class="panel-header"><span class="panel-title">👤 Top User hoạt động (24h)</span></div>
      <table class="mini-table" id="top-users"><tr><td class="empty">Đang tải...</td></tr></table>
    </div>
  </div>

  <!-- Chart -->
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">📈 Biểu đồ sự kiện</span>
      <div style="display:flex;gap:8px">
        <button class="filter-btn active" id="btn-hourly" onclick="setTrendMode('hour')">Theo giờ</button>
        <button class="filter-btn"        id="btn-daily"  onclick="setTrendMode('day')">Theo ngày</button>
      </div>
    </div>
    <div class="chart-wrap">
      <canvas id="trend-chart" class="chart-canvas" width="1200" height="240"></canvas>
    </div>
  </div>

  <!-- Events log -->
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">📋 Sự kiện gần đây</span>
      <div style="display:flex;gap:8px;align-items:center">
        <span class="auto-refresh" id="next-refresh">Refresh: 10s</span>
        <button class="refresh-btn danger" onclick="ackAllEvents()" title="Acknowledge tất cả alerts">✓ Ack All</button>
        <button class="refresh-btn" onclick="exportEvents()">⬇ Export</button>
        <button class="refresh-btn" onclick="loadAll()">⟳ Refresh</button>
      </div>
    </div>
    <div class="filter-bar" id="filters">
      <button class="filter-btn active"   onclick="setFilter('ALL',this)">ALL</button>
      <button class="filter-btn critical" onclick="setFilter('CRITICAL',this)">CRITICAL</button>
      <button class="filter-btn warning"  onclick="setFilter('WARNING',this)">WARNING</button>
      <button class="filter-btn"          onclick="setFilter('INFO',this)">INFO</button>
      <button class="filter-btn unacked"  onclick="setFilter('UNACKED',this)">UNACKED</button>
      <button class="filter-btn"          onclick="setFilter('auth.log',this)" data-src="auth.log">AUTH</button>
      <button class="filter-btn"          onclick="setFilter('ufw',this)"      data-src="ufw">UFW</button>
      <button class="filter-btn"          onclick="setFilter('auditd',this)"   data-src="auditd">AUDIT</button>
      <button class="filter-btn"          onclick="setFilter('scanner',this)"  data-src="scanner">SCANNER</button>
      <button class="filter-btn"          onclick="setFilter('nginx',this)"    data-src="nginx">NGINX</button>
      <button class="filter-btn"          onclick="setFilter('honeypot',this)" data-src="honeypot">HONEYPOT</button>
      <button class="filter-btn"          onclick="setFilter('netguard',this)" data-src="netguard">NETGUARD</button>
      <button class="filter-btn"          onclick="setFilter('zucheck',this)"  data-src="zucheck">ZUCHECK</button>
      <button class="filter-btn"          onclick="setFilter('zuscan',this)"   data-src="zuscan">ZUSCAN</button>
      <input class="search-input" id="search-input" placeholder="🔍 Tìm kiếm..." oninput="applySearch()" />
    </div>
    <div class="scrollable">
      <table class="events-table">
        <thead>
          <tr>
            <th>Thời gian</th><th>Mức</th><th>Score</th><th>Nguồn</th>
            <th>Loại</th><th>Thông điệp</th><th>IP</th><th>User</th>
            <th>MITRE</th><th>Ack</th><th style="width:16px"></th>
          </tr>
        </thead>
        <tbody id="events-body"><tr><td colspan="11" class="empty">Đang tải...</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- Whitelist Management -->
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">🛡️ IP Whitelist</span>
      <button class="refresh-btn" onclick="loadWhitelist()">⟳ Refresh</button>
    </div>
    <div class="wl-form">
      <input class="wl-input" id="wl-ip"     placeholder="IP (e.g. 192.168.1.1)" />
      <input class="wl-input" id="wl-reason" placeholder="Lý do (tùy chọn)" style="max-width:200px" />
      <button class="refresh-btn" onclick="addWhitelist()">+ Thêm IP</button>
    </div>
    <div class="scrollable" style="max-height:220px">
      <table class="events-table">
        <thead><tr><th>IP</th><th>Lý do</th><th>Thêm lúc</th><th></th></tr></thead>
        <tbody id="wl-body"><tr><td colspan="4" class="empty">Đang tải...</td></tr></tbody>
      </table>
    </div>
  </div>

</div>

<!-- Ollama AI Panel -->
<div class="panel" id="ollama-panel">
  <div class="panel-header">
    <span class="panel-title">🦙 Ollama AI — Phân tích bảo mật (Offline)</span>
    <div style="display:flex;gap:8px;align-items:center">
      <span id="ollama-status-badge" style="font-family:var(--mono);font-size:.7rem;padding:3px 10px;border-radius:4px;background:rgba(0,0,0,.3)">Đang kiểm tra...</span>
      <button class="refresh-btn" onclick="ollamaAutoAnalyze()">⚡ Phân tích tự động</button>
    </div>
  </div>
  <div style="padding:12px 16px;border-bottom:1px solid var(--border);background:var(--bg3);display:flex;gap:8px;align-items:center;flex-wrap:wrap">
    <select id="ollama-model" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:4px;font-family:var(--mono);font-size:.78rem">
      <option value="">Chọn model...</option>
    </select>
    <select id="ollama-hours" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:4px;font-family:var(--mono);font-size:.78rem">
      <option value="1">1h qua</option><option value="6">6h qua</option><option value="24" selected>24h qua</option>
    </select>
    <span style="color:var(--muted);font-family:var(--mono);font-size:.72rem">⚡ Chạy hoàn toàn offline</span>
  </div>
  <div style="padding:12px 16px;display:flex;gap:10px;border-bottom:1px solid var(--border);background:var(--bg3)">
    <input id="ollama-input" type="text"
      placeholder="Hỏi AI về bảo mật... (VD: có dấu hiệu tấn công không?)"
      style="flex:1;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:8px 14px;border-radius:4px;font-family:var(--mono);font-size:.82rem;outline:none;"
      onkeydown="if(event.key==='Enter')ollamaAsk()">
    <button class="refresh-btn" onclick="ollamaAsk()">Gửi ↵</button>
  </div>
  <div id="ollama-messages" style="padding:16px;min-height:140px;max-height:450px;overflow-y:auto;font-family:var(--mono);font-size:.82rem;line-height:1.8">
    <div style="color:var(--muted)">Nhấn "Phân tích tự động" hoặc gõ câu hỏi để bắt đầu...</div>
  </div>
</div>

<script>
let currentFilter = 'ALL';
let countdown = 10;
let countdownTimer;
let trendMode = 'hour';
let allEvents = [];
let lastCriticalId = 0;

// ── Escape HTML ───────────────────────────────────────────
function esc(t) {
  return String(t||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Filter & Search ───────────────────────────────────────
function setFilter(f, btn) {
  currentFilter = f;
  document.querySelectorAll('#filters .filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  loadEvents();
}

function applySearch() {
  const q = document.getElementById('search-input').value.toLowerCase();
  renderEvents(q ? allEvents.filter(e =>
    [e[2],e[4],e[5],e[8],e[9]].some(v => v && String(v).toLowerCase().includes(q))
  ) : allEvents);
}

// ── Load data ─────────────────────────────────────────────
async function loadSummary() {
  try {
    const d = await fetch('/api/summary').then(r => r.json());
    document.getElementById('s-total').textContent    = d.last_24h;
    document.getElementById('s-1h').textContent       = `${d.last_1h} trong 1h`;
    document.getElementById('s-critical').textContent = d.critical_24h;
    document.getElementById('s-warning').textContent  = d.warning_24h;
    document.getElementById('s-info').textContent     = Math.max(0, d.last_24h - d.critical_24h - d.warning_24h);
    document.getElementById('s-unacked').textContent  = d.unacked;

    const unackedVal = document.getElementById('s-unacked');
    unackedVal.style.animation = d.unacked > 0 ? 'pulse 1.5s infinite' : 'none';

    const ipTable   = document.getElementById('top-ips');
    const userTable = document.getElementById('top-users');
    ipTable.innerHTML   = d.top_ips.length   === 0 ? '<tr><td class="empty">Không có dữ liệu</td></tr>' :
      d.top_ips.map((r,i) => `<tr><td class="rank">#${i+1}</td><td class="ip-tag">${esc(r[0])}</td><td class="cnt">${r[1]}</td></tr>`).join('');
    userTable.innerHTML = d.top_users.length === 0 ? '<tr><td class="empty">Không có dữ liệu</td></tr>' :
      d.top_users.map((r,i) => `<tr><td class="rank">#${i+1}</td><td class="user-tag">${esc(r[0])}</td><td class="cnt">${r[1]}</td></tr>`).join('');
  } catch(e) { console.error(e); }
}

async function loadEvents() {
  try {
    let url = '/api/events?limit=300';
    if (['CRITICAL','WARNING','INFO'].includes(currentFilter)) url += `&level=${currentFilter}`;
    else if (currentFilter === 'UNACKED') url += '&unacked=1';
    else if (currentFilter !== 'ALL') url += `&source=${currentFilter}`;
    allEvents = await fetch(url).then(r => r.json());
    applySearch();

    const criticals = allEvents.filter(e => e[3] === 'CRITICAL');
    if (criticals.length > 0 && criticals[0][0] > lastCriticalId) {
      const newOnes = criticals.filter(e => e[0] > lastCriticalId && !e[11]);
      newOnes.slice(0, 3).forEach(e => showToast(e[4], e[5], e[9], e[0]));
      lastCriticalId = criticals[0][0];
    } else if (lastCriticalId === 0 && criticals.length > 0) {
      lastCriticalId = criticals[0][0];
    }
  } catch(e) { console.error(e); }
}

// col indices: 0=id,1=ts,2=src,3=level,4=cat,5=msg,6=raw,7=host,8=user,9=ip,10=alerted,11=ack,12=score,13=mitre
function renderEvents(events) {
  const tbody = document.getElementById('events-body');
  if (events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="11" class="empty">Không có sự kiện nào</td></tr>';
    return;
  }
  tbody.innerHTML = events.map(e => {
    const [id,ts,src,level,cat,msg,raw,,user,ip,,ack,score,mitre] = e;
    const badge    = `<span class="badge badge-${level.toLowerCase()}">${level}</span>`;
    const scoreClass = score >= 7 ? 'score-high' : score >= 4 ? 'score-medium' : 'score-low';
    const scoreBadge = `<span class="score-badge ${scoreClass}">${score}</span>`;
    const ipTag    = ip   ? `<span class="ip-tag">${esc(ip)}</span>`     : '<span style="color:var(--muted)">-</span>';
    const userTag  = user ? `<span class="user-tag">${esc(user)}</span>` : '<span style="color:var(--muted)">-</span>';
    const mitreTag = mitre ? `<span class="mitre-tag">${esc(mitre)}</span>` : '-';
    const ackBtn   = ack
      ? `<button class="ack-btn done" disabled title="Đã xử lý">✓</button>`
      : `<button class="ack-btn" onclick="doAck(${id},this,event)" title="Đánh dấu đã xử lý">ACK</button>`;
    const hasRaw   = raw && raw.trim();
    const expand   = hasRaw ? `<span style="color:var(--muted);font-size:.8rem;cursor:pointer">▶</span>` : '';
    const rawAttr  = hasRaw ? `data-raw="${esc(raw)}"` : '';
    const ackedCls = ack ? ' acked' : '';
    return `<tr class="clickable${ackedCls}" ${rawAttr} onclick="toggleRaw(this)">
      <td class="ts">${esc(ts.slice(5))}</td>
      <td>${badge}</td>
      <td>${scoreBadge}</td>
      <td class="src">${esc(src)}</td>
      <td style="color:var(--muted);font-size:.72rem">${esc(cat)}</td>
      <td class="msg">${esc(msg)}</td>
      <td>${ipTag}</td>
      <td>${userTag}</td>
      <td>${mitreTag}</td>
      <td onclick="event.stopPropagation()">${ackBtn}</td>
      <td>${expand}</td>
    </tr>`;
  }).join('');
}

function toggleRaw(row) {
  const raw = row.dataset.raw;
  if (!raw) return;
  const next = row.nextSibling;
  if (next && next.classList && next.classList.contains('raw-row')) { next.remove(); return; }
  const tr = document.createElement('tr');
  tr.className = 'raw-row';
  tr.innerHTML = `<td colspan="11">${esc(raw)}</td>`;
  row.after(tr);
}

// ── Acknowledge ───────────────────────────────────────────
async function doAck(id, btn, evt) {
  evt.stopPropagation();
  try {
    await fetch(`/api/events/${id}/ack`, {method:'POST'});
    btn.textContent = '✓';
    btn.classList.add('done');
    btn.disabled = true;
    const row = btn.closest('tr');
    if (row) row.classList.add('acked');
    loadSummary();
  } catch(e) { console.error(e); }
}

async function ackAllEvents() {
  if (!confirm('Xác nhận tất cả unacked alerts?')) return;
  await fetch('/api/events/ack-all', {method:'POST'});
  loadAll();
}

// ── Trend chart ───────────────────────────────────────────
function setTrendMode(mode) {
  trendMode = mode;
  document.getElementById('btn-hourly').classList.toggle('active', mode === 'hour');
  document.getElementById('btn-daily').classList.toggle('active',  mode === 'day');
  loadTrend();
}

async function loadTrend() {
  try {
    const span = trendMode === 'hour' ? 24 : 7;
    renderTrend(await fetch(`/api/trend?by=${trendMode}&span=${span}`).then(r => r.json()));
  } catch(e) { console.error(e); }
}

function renderTrend(rows) {
  const cvs = document.getElementById('trend-chart');
  const ctx = cvs.getContext('2d');
  const w = cvs.width, h = cvs.height;
  ctx.clearRect(0,0,w,h);
  ctx.fillStyle='#0a0f14'; ctx.fillRect(0,0,w,h);
  const padL=48,padR=20,padT=16,padB=28;
  const values=rows.map(r=>r.count), maxV=Math.max(5,...values);
  const xStep=(w-padL-padR)/Math.max(1,rows.length-1);
  ctx.font='10px monospace';
  for(let i=0;i<=4;i++){
    const y=padT+((h-padT-padB)*i/4);
    ctx.strokeStyle='#1e3a4a';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(padL,y);ctx.lineTo(w-padR,y);ctx.stroke();
    ctx.fillStyle='#4a6278';ctx.fillText(Math.round(maxV*(1-i/4)),2,y+4);
  }
  ctx.beginPath();
  rows.forEach((r,i)=>{
    const x=padL+i*xStep,y=padT+(h-padT-padB)*(1-r.count/maxV);
    i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);
  });
  ctx.lineTo(padL+(rows.length-1)*xStep,h-padB);ctx.lineTo(padL,h-padB);ctx.closePath();
  ctx.fillStyle='rgba(0,212,255,.06)';ctx.fill();
  ctx.strokeStyle='#00d4ff';ctx.lineWidth=2;ctx.beginPath();
  rows.forEach((r,i)=>{
    const x=padL+i*xStep,y=padT+(h-padT-padB)*(1-r.count/maxV);
    i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);
  });
  ctx.stroke();
  ctx.fillStyle='#00ff88';
  rows.forEach((r,i)=>{
    const x=padL+i*xStep,y=padT+(h-padT-padB)*(1-r.count/maxV);
    ctx.beginPath();ctx.arc(x,y,3,0,Math.PI*2);ctx.fill();
    if(i%Math.ceil(rows.length/8)===0||i===rows.length-1){
      ctx.fillStyle='#4a6278';ctx.font='10px monospace';
      ctx.fillText(r.bucket.slice(-5),x-18,h-6);
      ctx.fillStyle='#00ff88';
    }
  });
}

// ── Toast notifications ───────────────────────────────────
function showToast(title, message, ip, id) {
  const div = document.createElement('div');
  div.className = 'toast';
  div.innerHTML = `
    <span class="toast-close" onclick="this.parentElement.remove()">✕</span>
    <div class="toast-title">🚨 ${esc(title)}</div>
    <div>${esc(message.slice(0,100))}</div>
    ${ip ? `<div style="color:var(--muted);margin-top:4px;font-size:.7rem">IP: ${esc(ip)}</div>` : ''}
    <button class="ack-btn" style="margin-top:6px" onclick="doAck(${id},this,event);this.parentElement.remove()">ACK</button>`;
  document.getElementById('toast-container').appendChild(div);
  setTimeout(() => div.remove(), 10000);
}

// ── Whitelist management ──────────────────────────────────
async function loadWhitelist() {
  try {
    const rows = await fetch('/api/whitelist').then(r => r.json());
    const tbody = document.getElementById('wl-body');
    tbody.innerHTML = rows.length === 0
      ? '<tr><td colspan="4" class="empty">Whitelist trống</td></tr>'
      : rows.map(r => `<tr>
          <td class="ip-tag">${esc(r[0])}</td>
          <td style="color:var(--muted);font-size:.78rem">${esc(r[1]||'-')}</td>
          <td class="ts">${esc(r[2]||'-')}</td>
          <td><button class="del-btn" onclick="delWhitelist('${esc(r[0])}')">✕ Xóa</button></td>
        </tr>`).join('');
  } catch(e) { console.error(e); }
}

async function addWhitelist() {
  const ip     = document.getElementById('wl-ip').value.trim();
  const reason = document.getElementById('wl-reason').value.trim() || 'web-ui';
  if (!ip) return;
  const r = await fetch('/api/whitelist', {
    method: 'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ip, reason})
  });
  const d = await r.json();
  if (d.ok) {
    document.getElementById('wl-ip').value = '';
    document.getElementById('wl-reason').value = '';
    loadWhitelist();
  } else {
    alert('Lỗi: ' + (d.error || 'unknown'));
  }
}

async function delWhitelist(ip) {
  await fetch('/api/whitelist/' + encodeURIComponent(ip), {method:'DELETE'});
  loadWhitelist();
}

// ── Export ────────────────────────────────────────────────
async function exportEvents() {
  try {
    let url = '/api/events/export?hours=24';
    if (['CRITICAL','WARNING','INFO'].includes(currentFilter)) url += `&level=${currentFilter}`;
    else if (currentFilter !== 'ALL' && currentFilter !== 'UNACKED') url += `&source=${currentFilter}`;
    const data = await fetch(url).then(r => r.json());
    const blob = new Blob([JSON.stringify(data,null,2)], {type:'application/json'});
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `zusiem-${new Date().toISOString().slice(0,10)}.json`;
    a.click();
  } catch(e) { alert('Export thất bại: ' + e.message); }
}

// ── Orchestration ─────────────────────────────────────────
async function loadSecurityScore() {
  try {
    const d = await fetch('/api/security-score').then(r => r.json());
    const el = document.getElementById('s-score');
    const gr = document.getElementById('s-grade');
    if (d.score !== null && d.score !== undefined) {
      el.textContent = d.score;
      gr.textContent = `Hạng ${d.grade || '?'} · ZuCheck`;
      el.style.color = d.score >= 90 ? 'var(--accent2)' : d.score >= 75 ? 'var(--yellow)' : 'var(--red)';
      el.style.textShadow = d.score >= 90 ? '0 0 20px var(--accent2)' : d.score >= 75 ? '0 0 20px var(--yellow)' : '0 0 20px var(--red)';
    }
  } catch(e) {}
}

function loadAll() { loadSummary(); loadEvents(); loadTrend(); loadWhitelist(); loadSecurityScore(); resetCountdown(); }

function resetCountdown() {
  countdown = 10;
  clearInterval(countdownTimer);
  countdownTimer = setInterval(() => {
    countdown--;
    document.getElementById('next-refresh').textContent = `Refresh: ${countdown}s`;
    if (countdown <= 0) loadAll();
  }, 1000);
}

setInterval(() => { document.getElementById('clock').textContent = new Date().toLocaleTimeString('vi-VN'); }, 1000);
fetch('/api/info').then(r=>r.json()).then(d => { document.getElementById('hostname').textContent = d.hostname; });

loadAll();

// ── Ollama ────────────────────────────────────────────────
async function loadOllamaStatus() {
  try {
    const d     = await fetch('/api/ollama/status').then(r=>r.json());
    const badge = document.getElementById('ollama-status-badge');
    if (d.running) {
      badge.style.background = 'rgba(0,255,136,.15)'; badge.style.color = 'var(--accent2)'; badge.textContent = '● Online';
      const sel = document.getElementById('ollama-model');
      sel.innerHTML = '<option value="">Chọn model...</option>';
      d.models.forEach(m => { const o=document.createElement('option'); o.value=m; o.textContent=m; sel.appendChild(o); });
      if (d.models.length > 0) sel.value = d.models[0];
    } else {
      badge.style.background = 'rgba(255,59,92,.15)'; badge.style.color = 'var(--red)'; badge.textContent = '● Offline';
    }
  } catch(e) {
    const badge = document.getElementById('ollama-status-badge');
    badge.style.color = 'var(--red)'; badge.textContent = '● Lỗi';
  }
}

async function ollamaAsk() {
  const input = document.getElementById('ollama-input');
  const q = input.value.trim();
  if (!q) return;
  input.value = '';
  const hours = document.getElementById('ollama-hours').value;
  addOllamaMsg('user', q);
  addOllamaMsg('loading', '🦙 AI đang suy nghĩ...');
  try {
    const d = await fetch('/api/ollama/analyze', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({question:q, hours:parseInt(hours)})
    }).then(r=>r.json());
    removeOllamaLoading(); addOllamaMsg('ai', d.result);
  } catch(e) { removeOllamaLoading(); addOllamaMsg('ai', 'Lỗi kết nối. Kiểm tra: ollama serve'); }
}

async function ollamaAutoAnalyze() {
  const hours = document.getElementById('ollama-hours').value;
  addOllamaMsg('user', `Phân tích tự động ${hours}h qua`);
  addOllamaMsg('loading', '🦙 AI đang phân tích log...');
  try {
    const d = await fetch('/api/ollama/analyze', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({hours:parseInt(hours)})
    }).then(r=>r.json());
    removeOllamaLoading(); addOllamaMsg('ai', d.result);
  } catch(e) { removeOllamaLoading(); addOllamaMsg('ai', 'Lỗi kết nối. Kiểm tra: ollama serve'); }
}

function addOllamaMsg(type, text) {
  const box = document.getElementById('ollama-messages');
  const div = document.createElement('div');
  div.className = `ollama-msg ${type}`;
  div.textContent = text;
  if (type === 'loading') div.dataset.loading = '1';
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}
function removeOllamaLoading() { document.querySelectorAll('[data-loading]').forEach(e=>e.remove()); }

loadOllamaStatus();
setInterval(loadOllamaStatus, 30000);
</script>
</body>
</html>
"""

# ─── ROUTES ───────────────────────────────────────────────
@app.route("/")
@require_auth
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/events")
@require_auth
def api_events():
    limit        = min(int(request.args.get("limit", 100)), 1000)
    level        = request.args.get("level")
    source       = request.args.get("source")
    hours        = int(request.args.get("hours", 24))
    unacked_only = request.args.get("unacked") == "1"
    events       = get_events(limit=limit, level=level, source=source,
                               hours=hours, unacked_only=unacked_only)
    return jsonify(events)

@app.route("/api/events/<int:event_id>/ack", methods=["POST"])
@require_auth
def api_ack_event(event_id):
    ok = ack_event(event_id)
    return jsonify({"ok": ok})

@app.route("/api/events/ack-all", methods=["POST"])
@require_auth
def api_ack_all():
    n = ack_all_events()
    return jsonify({"ok": True, "count": n})

@app.route("/api/events/export")
@require_auth
def api_events_export():
    hours  = int(request.args.get("hours", 24))
    level  = request.args.get("level")
    source = request.args.get("source")
    limit  = min(int(request.args.get("limit", 2000)), 10000)
    data   = export_events(hours=hours, limit=limit, level=level, source=source)
    return jsonify(data)

@app.route("/api/summary")
@require_auth
def api_summary():
    return jsonify(get_summary())

@app.route("/api/stats")
@require_auth
def api_stats():
    days = int(request.args.get("days", 7))
    return jsonify(get_stats(days=days))

@app.route("/api/info")
@require_auth
def api_info():
    import socket
    return jsonify({"hostname": socket.gethostname(), "version": "3.0"})

@app.route("/api/trend")
@require_auth
def api_trend():
    by   = request.args.get("by", "hour")
    span = max(1, min(int(request.args.get("span", 24)), 168))
    return jsonify(get_trend(hours=span, by=by))

# ─── WHITELIST API ────────────────────────────────────────
@app.route("/api/whitelist", methods=["GET"])
@require_auth
def api_whitelist_get():
    return jsonify(get_whitelist())

@app.route("/api/whitelist", methods=["POST"])
@require_auth
def api_whitelist_add():
    data   = request.get_json() or {}
    ip     = (data.get("ip") or "").strip()
    reason = (data.get("reason") or "web-ui").strip()[:100]
    if not ip or not _valid_ip(ip):
        return jsonify({"ok": False, "error": "IP không hợp lệ"}), 400
    add_to_whitelist(ip, reason)
    return jsonify({"ok": True})

@app.route("/api/whitelist/<path:ip>", methods=["DELETE"])
@require_auth
def api_whitelist_delete(ip):
    if not _valid_ip(ip):
        return jsonify({"ok": False, "error": "IP không hợp lệ"}), 400
    ok = remove_from_whitelist(ip)
    return jsonify({"ok": ok})

# ─── OLLAMA API ───────────────────────────────────────────
@app.route("/api/ollama/analyze", methods=["POST"])
@require_auth
def api_ollama_analyze():
    try:
        data        = request.get_json() or {}
        question    = (data.get("question") or "").strip()[:500]
        hours       = max(1, min(int(data.get("hours", 1)), 168))
        events_text = get_recent_events_text(hours=hours)
        result      = analyze_with_ollama(events_text, question if question else None)
        return jsonify({"ok": True, "result": result})
    except Exception as e:
        return jsonify({"ok": False, "result": str(e)})

@app.route("/api/ollama/status")
@require_auth
def api_ollama_status():
    return jsonify(check_ollama_status())

@app.route("/api/ollama/models")
@require_auth
def api_ollama_models():
    return jsonify(list_ollama_models())

# ─── SECURITY SCORE (ZuCheck) ─────────────────────────────
@app.route("/api/security-score")
@require_auth
def api_security_score():
    from pathlib import Path as _Path
    import json as _json
    history = _Path(__file__).parent / "zucheck_history.jsonl"
    try:
        lines = history.read_text().strip().splitlines()
        if lines:
            last = _json.loads(lines[-1])
            return jsonify({"ok": True, "score": last.get("score"),
                            "grade": last.get("grade"), "ts": last.get("ts")})
    except Exception:
        pass
    return jsonify({"ok": False, "score": None, "grade": None, "ts": None})

# ─── DB STATS ─────────────────────────────────────────────
@app.route("/api/db/stats")
@require_auth
def api_db_stats():
    return jsonify(get_db_stats())

# ─── MAIN ─────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    cfg  = load_config()
    host = cfg.get("web", "host", fallback="127.0.0.1")
    port = cfg.getint("web", "port", fallback=5000)
    auth = cfg.getboolean("web", "auth_enabled", fallback=False)
    print(f"[*] ZuSIEM Web Dashboard: http://{host}:{port}")
    if auth:
        print(f"[*] Basic auth: BẬT (user: {cfg.get('web','username',fallback='admin')})")
    else:
        print("[!] Basic auth: TẮT — bật trong siem.conf nếu expose ra mạng")
    app.run(host=host, port=port, debug=False)
