#!/usr/bin/env python3
"""
netwatch dashboard — Flask backend
Run: sudo python3 app.py
Visit: http://localhost:5000
"""

import subprocess, sys, os, json, socket, re, ipaddress, threading, time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template_string, jsonify, request, Response, stream_with_context

app = Flask(__name__)

# ── shared scan state ──────────────────────────────────────────────────────────
scan_state = {
    "status":   "idle",       # idle | scanning | done | error
    "progress": 0,
    "total":    0,
    "devices":  [],
    "log":      [],
    "started":  None,
    "finished": None,
}
scan_lock = threading.Lock()

# ── OUI / device logic (same as CLI tool) ─────────────────────────────────────
OUI_MAP = {
    "00:50:56": "VMware",        "08:00:27": "VirtualBox",
    "b8:27:eb": "Raspberry Pi",  "dc:a6:32": "Raspberry Pi",
    "00:0c:29": "VMware",        "00:1a:11": "Google",
    "3c:5a:b4": "Google",        "f4:f5:d8": "Google",
    "b4:ce:f6": "Apple",         "a4:c3:f0": "Apple",
    "3c:22:fb": "Apple",         "f8:ff:c2": "Apple",
    "00:1b:63": "Apple",         "00:26:bb": "Apple",
    "28:cd:c1": "Apple",         "00:50:f2": "Microsoft",
    "28:d2:44": "Microsoft",     "00:17:88": "Philips Hue",
    "00:1d:c9": "Hikvision",     "44:19:b6": "Hikvision",
    "c0:56:e3": "Hikvision",     "bc:ad:28": "Dahua",
    "a0:23:9f": "Samsung",       "00:16:6b": "Samsung",
    "18:67:b0": "Amazon",        "fc:a6:67": "Amazon",
    "00:13:10": "Cisco",         "00:1a:a1": "Cisco",
    "00:e0:4c": "Realtek",       "00:1f:c6": "Intel",
    "8c:8d:28": "Intel",
}

DEVICE_TYPES = {
    "hikvision": ("cctv",    "CCTV Camera"),
    "dahua":     ("cctv",    "CCTV Camera"),
    "axis":      ("cctv",    "CCTV Camera"),
    "apple":     ("phone",   "Apple Device"),
    "samsung":   ("phone",   "Samsung Device"),
    "raspberry": ("iot",     "Raspberry Pi"),
    "cisco":     ("router",  "Cisco Network Device"),
    "philips":   ("iot",     "Philips Hue"),
    "amazon":    ("iot",     "Amazon Echo"),
    "google":    ("iot",     "Google Home"),
    "vmware":    ("vm",      "Virtual Machine"),
    "microsoft": ("laptop",  "Windows Device"),
    "intel":     ("laptop",  "Laptop / Desktop"),
}

PORT_LABELS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS",
    445:"SMB", 554:"RTSP", 3389:"RDP", 5353:"mDNS",
    5555:"ADB", 5900:"VNC", 548:"AFP", 8000:"Hikvision-SDK",
    8080:"HTTP-Alt", 8883:"MQTT-SSL", 1883:"MQTT",
    37777:"Dahua-SDK", 62078:"iPhone-Sync", 9100:"Printer",
}

SCAN_PORTS = list(PORT_LABELS.keys())

def vendor_from_mac(mac):
    if not mac or mac == "N/A": return "Unknown"
    prefix = mac[:8].lower()
    for oui, vendor in OUI_MAP.items():
        if prefix.startswith(oui.lower()):
            return vendor
    return "Unknown"

def classify_device(vendor, open_ports):
    vl = vendor.lower()
    for kw, (dtype, label) in DEVICE_TYPES.items():
        if kw in vl:
            return dtype, label
    if 554 in open_ports or 8000 in open_ports or 37777 in open_ports:
        return "cctv",   "IP Camera"
    if 62078 in open_ports:
        return "phone",  "iPhone"
    if 5555 in open_ports:
        return "phone",  "Android Device"
    if 3389 in open_ports or 445 in open_ports:
        return "laptop", "Windows PC"
    if 5900 in open_ports or 548 in open_ports:
        return "laptop", "Mac / Unix"
    if 22 in open_ports:
        return "server", "Linux Server"
    if 1883 in open_ports or 8883 in open_ports:
        return "iot",    "IoT Device"
    return "unknown", "Unknown Device"

def scan_ports(ip, timeout=0.4):
    open_ports = []
    def check(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                s.close(); return port
        except: pass
        return None
    with ThreadPoolExecutor(max_workers=60) as ex:
        for r in as_completed({ex.submit(check, p): p for p in SCAN_PORTS}):
            res = r.result()
            if res: open_ports.append(res)
    return sorted(open_ports)

def get_hostname(ip):
    try:
        h = socket.getfqdn(ip)
        return h if h != ip else ""
    except: return ""

def get_local_subnet():
    try:
        r = subprocess.run(["ip","route","show","default"], capture_output=True, text=True)
        iface = re.search(r"dev (\S+)", r.stdout)
        if iface:
            r2 = subprocess.run(["ip","-4","addr","show",iface.group(1)], capture_output=True, text=True)
            cidr = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", r2.stdout)
            if cidr:
                return str(ipaddress.IPv4Network(cidr.group(1), strict=False))
    except: pass
    return "192.168.1.0/24"

def discover_hosts(target):
    try:
        r = subprocess.run(["arp-scan", target, "--retry=2"], capture_output=True, text=True)
        hosts = []
        for line in r.stdout.splitlines():
            m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([\da-f:]{17})\s*(.*)", line, re.I)
            if m:
                ip, mac, vendor = m.group(1), m.group(2), m.group(3).strip()
                if not vendor: vendor = vendor_from_mac(mac)
                hosts.append({"ip":ip,"mac":mac,"vendor":vendor})
        return hosts
    except:
        pass
    # fallback: nmap
    try:
        r = subprocess.run(["nmap","-sn","-T4",target,"--oG","-"], capture_output=True, text=True)
        hosts = []; ip_now = None
        for line in r.stdout.splitlines():
            im = re.search(r"Host: (\d+\.\d+\.\d+\.\d+)", line)
            mm = re.search(r"MAC Address: ([\dA-F:]{17})\s*\(([^)]*)\)", line)
            if im:
                ip_now = im.group(1)
                hosts.append({"ip":ip_now,"mac":"N/A","vendor":"Unknown"})
            if mm and hosts:
                hosts[-1]["mac"]    = mm.group(1)
                hosts[-1]["vendor"] = mm.group(2) or vendor_from_mac(mm.group(1))
        return hosts
    except:
        return []

def run_scan(target):
    global scan_state
    with scan_lock:
        scan_state.update({"status":"scanning","progress":0,"total":0,
                           "devices":[],"log":[],"started":datetime.now().isoformat(),"finished":None})

    def log(msg):
        with scan_lock:
            scan_state["log"].append({"ts": datetime.now().strftime("%H:%M:%S"), "msg": msg})

    try:
        log(f"Starting host discovery on {target}")
        hosts = discover_hosts(target)
        if not hosts:
            log("No hosts found. Check network/permissions.")
            with scan_lock: scan_state["status"] = "error"
            return

        log(f"Found {len(hosts)} host(s) alive — starting port scan")
        with scan_lock: scan_state["total"] = len(hosts)

        devices = []
        for i, h in enumerate(hosts, 1):
            ip = h["ip"]
            log(f"Scanning {ip} ...")
            ports    = scan_ports(ip)
            hostname = get_hostname(ip)
            dtype, dlabel = classify_device(h["vendor"], ports)
            risk = "high" if any(p in ports for p in [23,21,3389,5555]) else \
                   "medium" if ports else "low"
            port_info = [{"port": p, "label": PORT_LABELS.get(p, "unknown")} for p in ports]
            device = {
                "ip":       ip,
                "hostname": hostname,
                "mac":      h["mac"],
                "vendor":   h["vendor"],
                "type":     dtype,
                "label":    dlabel,
                "ports":    port_info,
                "risk":     risk,
                "scanned":  datetime.now().isoformat(),
            }
            devices.append(device)
            log(f"{ip} → {dlabel} | {len(ports)} open ports | risk: {risk}")
            with scan_lock:
                scan_state["devices"] = list(devices)
                scan_state["progress"] = i

        with scan_lock:
            scan_state.update({"status":"done","finished":datetime.now().isoformat()})
        log("Scan complete.")
    except Exception as e:
        log(f"Error: {e}")
        with scan_lock: scan_state["status"] = "error"

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data   = request.get_json(silent=True) or {}
    target = data.get("target", "").strip() or get_local_subnet()
    with scan_lock:
        if scan_state["status"] == "scanning":
            return jsonify({"error": "Scan already in progress"}), 409
    t = threading.Thread(target=run_scan, args=(target,), daemon=True)
    t.start()
    return jsonify({"ok": True, "target": target})

@app.route("/api/state")
def api_state():
    with scan_lock:
        return jsonify(dict(scan_state))

@app.route("/api/subnet")
def api_subnet():
    return jsonify({"subnet": get_local_subnet()})

@app.route("/api/export")
def api_export():
    with scan_lock:
        devices = list(scan_state["devices"])
    return jsonify(devices)

# ── HTML / CSS / JS (single-file template) ────────────────────────────────────
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NETWATCH — Network Intelligence Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:       #030a0f;
    --panel:    #071018;
    --border:   #0d2233;
    --accent:   #00d4ff;
    --accent2:  #00ff9d;
    --warn:     #ffb800;
    --danger:   #ff3c5a;
    --text:     #c8dce8;
    --dim:      #3a5568;
    --glow:     0 0 18px rgba(0,212,255,0.35);
    --glow2:    0 0 18px rgba(0,255,157,0.3);
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Rajdhani', sans-serif;
    font-size: 15px;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* ── scanline overlay ── */
  body::before {
    content: "";
    position: fixed; inset: 0; z-index: 9999;
    background: repeating-linear-gradient(
      0deg, transparent, transparent 2px,
      rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px
    );
    pointer-events: none;
  }

  /* ── grid bg ── */
  body::after {
    content: "";
    position: fixed; inset: 0; z-index: 0;
    background-image:
      linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
  }

  /* ── header ── */
  header {
    position: relative; z-index: 10;
    display: flex; align-items: center; justify-content: space-between;
    padding: 18px 32px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(180deg, rgba(0,212,255,0.05) 0%, transparent 100%);
  }
  .logo {
    font-family: 'Share Tech Mono', monospace;
    font-size: 22px;
    color: var(--accent);
    text-shadow: var(--glow);
    letter-spacing: 3px;
  }
  .logo span { color: var(--accent2); }
  .header-meta {
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: var(--dim);
    text-align: right;
    line-height: 1.6;
  }
  #clock { color: var(--accent2); }

  /* ── layout ── */
  .main { position: relative; z-index: 1; display: grid; grid-template-columns: 300px 1fr; height: calc(100vh - 62px); }

  /* ── sidebar ── */
  .sidebar {
    border-right: 1px solid var(--border);
    display: flex; flex-direction: column;
    background: var(--panel);
    overflow: hidden;
  }
  .scan-panel { padding: 20px; border-bottom: 1px solid var(--border); }
  .section-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px; letter-spacing: 3px;
    color: var(--dim); margin-bottom: 12px;
  }
  .target-input {
    width: 100%; padding: 9px 12px;
    background: rgba(0,212,255,0.05);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--accent);
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    outline: none;
    transition: border-color .2s, box-shadow .2s;
    margin-bottom: 10px;
  }
  .target-input:focus { border-color: var(--accent); box-shadow: var(--glow); }

  .btn-scan {
    width: 100%; padding: 12px;
    background: transparent;
    border: 1px solid var(--accent);
    border-radius: 4px;
    color: var(--accent);
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px; letter-spacing: 3px;
    cursor: pointer;
    transition: all .2s;
    position: relative; overflow: hidden;
  }
  .btn-scan::before {
    content: ""; position: absolute; inset: 0;
    background: var(--accent); opacity: 0;
    transition: opacity .2s;
  }
  .btn-scan:hover { box-shadow: var(--glow); }
  .btn-scan:hover::before { opacity: 0.08; }
  .btn-scan:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-scan.scanning {
    border-color: var(--warn); color: var(--warn);
    animation: pulse-border 1s infinite;
  }
  @keyframes pulse-border {
    0%,100% { box-shadow: 0 0 6px rgba(255,184,0,0.3); }
    50%      { box-shadow: 0 0 20px rgba(255,184,0,0.7); }
  }

  /* progress bar */
  .progress-wrap { margin-top: 12px; display: none; }
  .progress-wrap.visible { display: block; }
  .progress-bar-bg {
    height: 3px; background: var(--border); border-radius: 2px; overflow: hidden;
  }
  .progress-bar-fill {
    height: 100%; background: var(--accent); border-radius: 2px;
    transition: width .3s ease;
    box-shadow: 0 0 8px var(--accent);
  }
  .progress-text {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px; color: var(--dim);
    margin-top: 6px; text-align: right;
  }

  /* stats */
  .stats-grid {
    display: grid; grid-template-columns: 1fr 1fr;
    gap: 1px; background: var(--border);
    border-bottom: 1px solid var(--border);
  }
  .stat-cell {
    background: var(--panel);
    padding: 14px; text-align: center;
  }
  .stat-num {
    font-family: 'Share Tech Mono', monospace;
    font-size: 24px; line-height: 1;
  }
  .stat-lbl { font-size: 11px; color: var(--dim); letter-spacing: 1px; margin-top: 4px; }
  .stat-cell.total  .stat-num { color: var(--accent); text-shadow: var(--glow); }
  .stat-cell.cctv   .stat-num { color: #ff6b9d; }
  .stat-cell.phones .stat-num { color: var(--accent2); }
  .stat-cell.laptops .stat-num { color: var(--warn); }

  /* log */
  .log-panel { flex: 1; overflow: hidden; display: flex; flex-direction: column; }
  .log-body {
    flex: 1; overflow-y: auto; padding: 12px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px; line-height: 1.7;
    scroll-behavior: smooth;
  }
  .log-body::-webkit-scrollbar { width: 4px; }
  .log-body::-webkit-scrollbar-thumb { background: var(--border); }
  .log-entry { display: flex; gap: 8px; }
  .log-ts { color: var(--dim); flex-shrink: 0; }
  .log-msg { color: #7ca8c0; }
  .log-entry.new .log-msg { color: var(--accent); }

  /* filter bar */
  .filter-bar {
    display: flex; gap: 6px; padding: 14px 24px;
    border-bottom: 1px solid var(--border);
    background: var(--panel);
    flex-wrap: wrap;
    position: relative; z-index: 1;
  }
  .filter-btn {
    padding: 5px 14px;
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 20px;
    color: var(--dim);
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px; letter-spacing: 1px;
    cursor: pointer; transition: all .2s;
  }
  .filter-btn:hover { border-color: var(--accent); color: var(--accent); }
  .filter-btn.active { background: rgba(0,212,255,0.1); border-color: var(--accent); color: var(--accent); box-shadow: var(--glow); }
  .spacer { flex: 1; }
  .btn-export {
    padding: 5px 16px;
    background: transparent;
    border: 1px solid var(--accent2);
    border-radius: 20px;
    color: var(--accent2);
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px; letter-spacing: 1px;
    cursor: pointer; transition: all .2s;
  }
  .btn-export:hover { box-shadow: var(--glow2); background: rgba(0,255,157,0.07); }

  /* device grid */
  .content { overflow-y: auto; position: relative; }
  .content::-webkit-scrollbar { width: 6px; }
  .content::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

  .device-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 16px;
    padding: 24px;
  }

  .device-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 18px;
    position: relative; overflow: hidden;
    cursor: default;
    transition: transform .2s, border-color .2s, box-shadow .2s;
    animation: card-in .4s ease both;
  }
  @keyframes card-in {
    from { opacity: 0; transform: translateY(12px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  .device-card:hover {
    transform: translateY(-3px);
    border-color: var(--accent);
    box-shadow: var(--glow);
  }
  .device-card::before {
    content: "";
    position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: var(--accent);
    opacity: 0; transition: opacity .2s;
  }
  .device-card:hover::before { opacity: 1; }

  /* risk stripe */
  .device-card.risk-high   { border-left: 3px solid var(--danger); }
  .device-card.risk-medium { border-left: 3px solid var(--warn); }
  .device-card.risk-low    { border-left: 3px solid var(--accent2); }

  .card-header { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 14px; }
  .device-icon {
    width: 44px; height: 44px;
    background: rgba(0,212,255,0.06);
    border: 1px solid var(--border);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px; flex-shrink: 0;
  }
  .device-info { flex: 1; min-width: 0; }
  .device-label { font-size: 14px; font-weight: 700; color: #e8f4fc; }
  .device-ip {
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px; color: var(--accent);
  }
  .risk-badge {
    font-family: 'Share Tech Mono', monospace;
    font-size: 9px; letter-spacing: 2px;
    padding: 2px 8px; border-radius: 10px;
    flex-shrink: 0;
  }
  .risk-badge.high   { background: rgba(255,60,90,0.15); color: var(--danger); border: 1px solid rgba(255,60,90,0.3); }
  .risk-badge.medium { background: rgba(255,184,0,0.12); color: var(--warn);   border: 1px solid rgba(255,184,0,0.3); }
  .risk-badge.low    { background: rgba(0,255,157,0.1);  color: var(--accent2);border: 1px solid rgba(0,255,157,0.25); }

  .card-row { display: flex; gap: 6px; align-items: baseline; margin-bottom: 4px; }
  .card-key { font-size: 11px; color: var(--dim); letter-spacing: 1px; min-width: 64px; flex-shrink: 0; }
  .card-val { font-size: 12px; color: var(--text); word-break: break-all; font-family: 'Share Tech Mono', monospace; }

  .port-list { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 10px; }
  .port-tag {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px; padding: 2px 7px;
    background: rgba(0,212,255,0.06);
    border: 1px solid rgba(0,212,255,0.15);
    border-radius: 3px; color: var(--accent);
  }
  .port-tag.danger { border-color: rgba(255,60,90,0.3); color: #ff7090; background: rgba(255,60,90,0.06); }
  .no-ports { font-family: 'Share Tech Mono', monospace; font-size: 10px; color: var(--dim); margin-top: 8px; }

  /* empty state */
  .empty-state {
    grid-column: 1/-1;
    display: flex; flex-direction: column; align-items: center;
    justify-content: center; padding: 80px 0;
    color: var(--dim);
  }
  .empty-icon { font-size: 48px; margin-bottom: 16px; opacity: 0.4; }
  .empty-text { font-family: 'Share Tech Mono', monospace; font-size: 13px; letter-spacing: 2px; }

  /* scanning overlay */
  .scan-overlay {
    grid-column: 1/-1;
    display: none; flex-direction: column;
    align-items: center; justify-content: center; padding: 80px 0;
  }
  .scan-overlay.visible { display: flex; }
  .radar {
    width: 120px; height: 120px;
    position: relative; margin-bottom: 24px;
  }
  .radar-circle {
    position: absolute; border-radius: 50%;
    border: 1px solid rgba(0,212,255,0.2);
    inset: 0;
  }
  .radar-circle:nth-child(2) { inset: 20%; }
  .radar-circle:nth-child(3) { inset: 40%; }
  .radar-sweep {
    position: absolute; inset: 0;
    border-radius: 50%;
    background: conic-gradient(from 0deg, transparent 270deg, rgba(0,212,255,0.6) 360deg);
    animation: sweep 2s linear infinite;
  }
  @keyframes sweep { to { transform: rotate(360deg); } }
  .scan-text {
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px; color: var(--accent);
    letter-spacing: 3px;
    animation: blink 1.2s step-end infinite;
  }
  @keyframes blink { 50% { opacity: 0; } }
</style>
</head>
<body>

<header>
  <div class="logo">NET<span>WATCH</span></div>
  <div class="header-meta">
    NETWORK INTELLIGENCE DASHBOARD v1.0<br>
    <span id="clock"></span>
  </div>
</header>

<div class="main">
  <!-- ── SIDEBAR ── -->
  <aside class="sidebar">
    <div class="scan-panel">
      <div class="section-label">// TARGET NETWORK</div>
      <input class="target-input" id="targetInput" placeholder="e.g. 192.168.1.0/24" autocomplete="off">
      <button class="btn-scan" id="scanBtn" onclick="startScan()">[ INITIATE SCAN ]</button>
      <div class="progress-wrap" id="progressWrap">
        <div class="progress-bar-bg"><div class="progress-bar-fill" id="progressFill" style="width:0%"></div></div>
        <div class="progress-text" id="progressText">0 / 0</div>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-cell total">
        <div class="stat-num" id="statTotal">0</div>
        <div class="stat-lbl">TOTAL</div>
      </div>
      <div class="stat-cell cctv">
        <div class="stat-num" id="statCctv">0</div>
        <div class="stat-lbl">CAMERAS</div>
      </div>
      <div class="stat-cell phones">
        <div class="stat-num" id="statPhones">0</div>
        <div class="stat-lbl">PHONES</div>
      </div>
      <div class="stat-cell laptops">
        <div class="stat-num" id="statLaptops">0</div>
        <div class="stat-lbl">LAPTOPS</div>
      </div>
    </div>

    <div class="log-panel">
      <div class="section-label" style="padding: 12px 12px 0">// SCAN LOG</div>
      <div class="log-body" id="logBody"></div>
    </div>
  </aside>

  <!-- ── MAIN CONTENT ── -->
  <div style="display:flex;flex-direction:column;overflow:hidden;">
    <div class="filter-bar">
      <button class="filter-btn active" onclick="setFilter('all', this)">ALL</button>
      <button class="filter-btn" onclick="setFilter('cctv', this)">📷 CAMERAS</button>
      <button class="filter-btn" onclick="setFilter('phone', this)">📱 PHONES</button>
      <button class="filter-btn" onclick="setFilter('laptop', this)">💻 LAPTOPS</button>
      <button class="filter-btn" onclick="setFilter('iot', this)">🔌 IOT</button>
      <button class="filter-btn" onclick="setFilter('server', this)">🖥 SERVERS</button>
      <button class="filter-btn" onclick="setFilter('high', this)">🔴 HIGH RISK</button>
      <div class="spacer"></div>
      <button class="btn-export" onclick="exportJSON()">⬇ EXPORT JSON</button>
    </div>

    <div class="content">
      <div class="device-grid" id="deviceGrid">
        <div class="empty-state" id="emptyState">
          <div class="empty-icon">◎</div>
          <div class="empty-text">AWAITING SCAN INITIALIZATION</div>
        </div>
        <div class="scan-overlay" id="scanOverlay">
          <div class="radar">
            <div class="radar-circle"></div>
            <div class="radar-circle"></div>
            <div class="radar-circle"></div>
            <div class="radar-sweep"></div>
          </div>
          <div class="scan-text">SCANNING NETWORK...</div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
const ICONS = {
  cctv:"📷", phone:"📱", laptop:"💻", iot:"🔌",
  server:"🖥️", router:"🔀", vm:"🖥️", unknown:"❓"
};
const DANGER_PORTS = [21,23,3389,5555,7547];

let allDevices = [];
let activeFilter = "all";
let pollTimer = null;

// clock
function updateClock() {
  const n = new Date();
  document.getElementById("clock").textContent =
    n.toLocaleString("en-US",{hour12:false}).toUpperCase();
}
setInterval(updateClock, 1000);
updateClock();

// fetch subnet on load
fetch("/api/subnet").then(r=>r.json()).then(d=>{
  document.getElementById("targetInput").placeholder = d.subnet;
  document.getElementById("targetInput").value = d.subnet;
});

function startScan() {
  const target = document.getElementById("targetInput").value.trim();
  fetch("/api/scan", {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({target})
  }).then(r=>r.json()).then(d=>{
    if (d.error) { addLog("ERROR: "+d.error); return; }
    document.getElementById("emptyState").style.display = "none";
    document.getElementById("scanOverlay").classList.add("visible");
    document.getElementById("scanBtn").textContent = "[ SCANNING... ]";
    document.getElementById("scanBtn").classList.add("scanning");
    document.getElementById("scanBtn").disabled = true;
    document.getElementById("progressWrap").classList.add("visible");
    clearCardsBut();
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(pollState, 800);
  });
}

function clearCardsBut() {
  const grid = document.getElementById("deviceGrid");
  [...grid.querySelectorAll(".device-card")].forEach(c=>c.remove());
}

function pollState() {
  fetch("/api/state").then(r=>r.json()).then(s=>{
    // update log
    const logBody = document.getElementById("logBody");
    const existing = logBody.querySelectorAll(".log-entry").length;
    if (s.log && s.log.length > existing) {
      s.log.slice(existing).forEach((e,i) => {
        const el = document.createElement("div");
        el.className = "log-entry" + (i === s.log.slice(existing).length-1 ? " new" : "");
        el.innerHTML = `<span class="log-ts">${e.ts}</span><span class="log-msg">${e.msg}</span>`;
        logBody.appendChild(el);
        setTimeout(()=>el.classList.remove("new"), 1500);
      });
      logBody.scrollTop = logBody.scrollHeight;
    }

    // update progress
    if (s.total > 0) {
      const pct = Math.round(s.progress / s.total * 100);
      document.getElementById("progressFill").style.width = pct+"%";
      document.getElementById("progressText").textContent = `${s.progress} / ${s.total} hosts`;
    }

    // update devices
    allDevices = s.devices || [];
    updateStats(allDevices);
    renderCards(allDevices, activeFilter);

    // done?
    if (s.status === "done" || s.status === "error") {
      clearInterval(pollTimer);
      document.getElementById("scanOverlay").classList.remove("visible");
      document.getElementById("scanBtn").textContent = "[ SCAN AGAIN ]";
      document.getElementById("scanBtn").classList.remove("scanning");
      document.getElementById("scanBtn").disabled = false;
      if (allDevices.length === 0) {
        document.getElementById("emptyState").style.display = "flex";
      }
    }
  });
}

function updateStats(devices) {
  document.getElementById("statTotal").textContent  = devices.length;
  document.getElementById("statCctv").textContent   = devices.filter(d=>d.type==="cctv").length;
  document.getElementById("statPhones").textContent = devices.filter(d=>d.type==="phone").length;
  document.getElementById("statLaptops").textContent= devices.filter(d=>["laptop","vm"].includes(d.type)).length;
}

let renderedIds = new Set();
function renderCards(devices, filter) {
  const grid = document.getElementById("deviceGrid");
  const filtered = filter==="all" ? devices :
    filter==="high" ? devices.filter(d=>d.risk==="high") :
    devices.filter(d=>d.type===filter);

  filtered.forEach((d, idx) => {
    const id = "card-"+d.ip.replace(/\./g,"_");
    if (renderedIds.has(id)) return;
    renderedIds.add(id);

    const card = document.createElement("div");
    card.className = `device-card risk-${d.risk}`;
    card.id = id;
    card.dataset.type = d.type;
    card.dataset.risk = d.risk;
    card.style.animationDelay = (idx*0.05)+"s";

    const portTags = d.ports.map(p => {
      const cls = DANGER_PORTS.includes(p.port) ? " danger" : "";
      return `<span class="port-tag${cls}">${p.port}/${p.label}</span>`;
    }).join("") || `<span class="no-ports">no open ports detected</span>`;

    card.innerHTML = `
      <div class="card-header">
        <div class="device-icon">${ICONS[d.type]||"❓"}</div>
        <div class="device-info">
          <div class="device-label">${d.label}</div>
          <div class="device-ip">${d.ip}</div>
        </div>
        <span class="risk-badge ${d.risk}">${d.risk.toUpperCase()}</span>
      </div>
      <div class="card-row"><span class="card-key">HOSTNAME</span><span class="card-val">${d.hostname||"—"}</span></div>
      <div class="card-row"><span class="card-key">MAC</span><span class="card-val">${d.mac}</span></div>
      <div class="card-row"><span class="card-key">VENDOR</span><span class="card-val">${d.vendor}</span></div>
      <div class="port-list">${portTags}</div>
    `;
    grid.appendChild(card);
  });

  // hide/show existing cards based on filter
  grid.querySelectorAll(".device-card").forEach(card => {
    const t = card.dataset.type, r = card.dataset.risk;
    const show = filter==="all" || (filter==="high" && r==="high") || t===filter;
    card.style.display = show ? "" : "none";
  });
}

function setFilter(f, btn) {
  activeFilter = f;
  document.querySelectorAll(".filter-btn").forEach(b=>b.classList.remove("active"));
  btn.classList.add("active");
  renderCards(allDevices, f);
}

function addLog(msg) {
  const logBody = document.getElementById("logBody");
  const ts = new Date().toLocaleTimeString("en-US",{hour12:false});
  const el = document.createElement("div");
  el.className = "log-entry new";
  el.innerHTML = `<span class="log-ts">${ts}</span><span class="log-msg">${msg}</span>`;
  logBody.appendChild(el);
  logBody.scrollTop = logBody.scrollHeight;
  setTimeout(()=>el.classList.remove("new"), 1500);
}

function exportJSON() {
  fetch("/api/export").then(r=>r.json()).then(data=>{
    const a = document.createElement("a");
    a.href = "data:application/json,"+encodeURIComponent(JSON.stringify(data,null,2));
    a.download = "netwatch_scan_"+Date.now()+".json";
    a.click();
    addLog("Exported "+data.length+" device(s) to JSON");
  });
}
</script>
</body>
</html>
"""

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("\n⚠️  Some scan features need root. Run with: sudo python3 app.py\n")
    print("  ┌─────────────────────────────────────────┐")
    print("  │  NETWATCH Dashboard                     │")
    print("  │  Open: http://localhost:5000            │")
    print("  └─────────────────────────────────────────┘\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
