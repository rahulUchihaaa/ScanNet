#!/usr/bin/env python3
"""
ScanNet — Target & Config Manager + Port Scanner
Fixed, fast, fully working single-file edition.
"""

import ipaddress
import json
import os
import re
import select
import socket
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse

# ─────────────────────────────────────────────────────────────────────────────
# PORT / SERVICE MAPS
# ─────────────────────────────────────────────────────────────────────────────

COMMON_PORTS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",111:"RPCbind",135:"MSRPC",
    139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",
    587:"SMTP-TLS",993:"IMAPS",995:"POP3S",
    1433:"MSSQL",1521:"Oracle",1723:"PPTP",
    2049:"NFS",2181:"Zookeeper",3000:"Dev-Server",
    3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
    5900:"VNC",6379:"Redis",6443:"Kubernetes",
    8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"Jupyter",
    9200:"Elasticsearch",11211:"Memcached",27017:"MongoDB",
}

UDP_PORTS = {
    53:"DNS",67:"DHCP",68:"DHCP-Client",69:"TFTP",
    123:"NTP",161:"SNMP",162:"SNMP-Trap",500:"IKE",
    514:"Syslog",1194:"OpenVPN",5353:"mDNS",4500:"NAT-T",
}

TOP100_TCP = sorted(set([
    7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,
    119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,
    515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,
    1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,
    2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,
    5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,
    8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,
]))

# ─────────────────────────────────────────────────────────────────────────────
# TARGET VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

def validate_target(target: str):
    target = target.strip()
    if not target:
        return []
    # Plain IP
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass
    # CIDR
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = list(network.hosts())
        if not hosts:
            return [str(network.network_address)]
        return [str(ip) for ip in hosts]
    except ValueError:
        pass
    # Domain
    domain_re = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    if domain_re.match(target):
        try:
            resolved = socket.gethostbyname(target)
            return [resolved]
        except socket.gaierror:
            return []
    return []

# ─────────────────────────────────────────────────────────────────────────────
# PORT PARSING
# ─────────────────────────────────────────────────────────────────────────────

def parse_port_range(port_str: str):
    if not port_str or not port_str.strip():
        return []
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                lo_i = max(1, int(lo.strip()))
                hi_i = min(65535, int(hi.strip()))
                ports.update(range(lo_i, hi_i + 1))
            except ValueError:
                pass
        elif part.isdigit():
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)

# ─────────────────────────────────────────────────────────────────────────────
# TCP SCANNER  (non-blocking connect via select for maximum speed)
# ─────────────────────────────────────────────────────────────────────────────

def tcp_scan_port(ip: str, port: int, timeout: float = 0.8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        try:
            s.connect((ip, port))
        except BlockingIOError:
            pass
        except Exception:
            s.close()
            return None

        ready = select.select([], [s], [s], timeout)
        if s in ready[1]:
            err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err == 0:
                banner = ""
                try:
                    s.setblocking(True)
                    s.settimeout(0.3)
                    if port in (80, 8080, 8000, 8008, 8081):
                        s.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
                    raw = s.recv(256)
                    banner = raw.decode("utf-8", errors="replace").strip().splitlines()[0][:100]
                except Exception:
                    pass
                s.close()
                return {
                    "port": port,
                    "state": "open",
                    "service": COMMON_PORTS.get(port, "Unknown"),
                    "protocol": "tcp",
                    "banner": banner,
                }
        s.close()
    except Exception:
        pass
    return None

# ─────────────────────────────────────────────────────────────────────────────
# UDP SCANNER
# ─────────────────────────────────────────────────────────────────────────────

UDP_PROBES = {
    53:  b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123: b'\x1b' + b'\x00' * 47,
    161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    69:  b"\x00\x01test.txt\x00netascii\x00",
}

def udp_scan_port(ip: str, port: int, timeout: float = 1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        payload = UDP_PROBES.get(port, b"\x00" * 8)
        s.sendto(payload, (ip, port))
        try:
            s.recvfrom(1024)
            s.close()
            return {"port": port, "state": "open",
                    "service": UDP_PORTS.get(port, "Unknown"),
                    "protocol": "udp", "banner": ""}
        except socket.timeout:
            s.close()
            return {"port": port, "state": "open|filtered",
                    "service": UDP_PORTS.get(port, "Unknown"),
                    "protocol": "udp", "banner": ""}
        except ConnectionResetError:
            s.close()
            return None
    except Exception:
        pass
    return None

# ─────────────────────────────────────────────────────────────────────────────
# HOSTNAME RESOLVER
# ─────────────────────────────────────────────────────────────────────────────

def resolve_hostname(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

# ─────────────────────────────────────────────────────────────────────────────
# SCAN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

def scan_target(ip, tcp_ports, udp_ports, timeout, max_workers, progress_cb=None):
    open_ports = []
    total = len(tcp_ports) + len(udp_ports)
    done_count = [0]
    cb_lock = threading.Lock()

    def mark_done():
        with cb_lock:
            done_count[0] += 1
            if progress_cb:
                progress_cb(done_count[0], total)

    workers = min(max_workers, max(total, 1), 1000)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {}
        for p in tcp_ports:
            futures[ex.submit(tcp_scan_port, ip, p, timeout)] = p
        for p in udp_ports:
            futures[ex.submit(udp_scan_port, ip, p, timeout)] = p

        for f in as_completed(futures):
            mark_done()
            try:
                res = f.result()
                if res:
                    open_ports.append(res)
            except Exception:
                pass

    open_ports.sort(key=lambda x: (x["protocol"], x["port"]))
    hostname = resolve_hostname(ip)

    return {
        "ip": ip,
        "hostname": hostname,
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "tcp_ports_scanned": len(tcp_ports),
        "udp_ports_scanned": len(udp_ports),
        "open_ports": open_ports,
        "open_count": len([p for p in open_ports if p["state"] == "open"]),
    }

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL STATE
# ─────────────────────────────────────────────────────────────────────────────

scan_results_store  = {}
scan_progress_store = {}
scan_error_store    = {}
scan_lock           = threading.Lock()

# ─────────────────────────────────────────────────────────────────────────────
# HTML PAGE
# ─────────────────────────────────────────────────────────────────────────────

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>ScanNet — Port Scanner</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&family=Exo+2:wght@300;400;700&display=swap" rel="stylesheet"/>
<style>
:root{
  --bg:#050a0f;--surface:#0a1520;--panel:#0d1c2e;--border:#1a3050;
  --accent:#00d4ff;--accent2:#00ff9d;--accent3:#ff6b35;--warn:#ffb700;
  --text:#c8e0f0;--muted:#4a7090;
  --glow:0 0 20px rgba(0,212,255,.4);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Exo 2',sans-serif;min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,212,255,.015) 2px,rgba(0,212,255,.015) 4px);pointer-events:none;z-index:9999}
.grid-bg{position:fixed;inset:0;z-index:0;background-image:linear-gradient(rgba(0,212,255,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.04) 1px,transparent 1px);background-size:40px 40px;animation:gridMove 20s linear infinite}
@keyframes gridMove{0%{background-position:0 0}100%{background-position:40px 40px}}
.wrapper{position:relative;z-index:1;max-width:1300px;margin:0 auto;padding:24px}
header{display:flex;align-items:center;justify-content:space-between;padding:16px 32px;border-bottom:1px solid var(--border);background:rgba(10,21,32,.92);backdrop-filter:blur(12px);position:sticky;top:0;z-index:100;margin-bottom:28px}
.logo{font-family:'Share Tech Mono',monospace;font-size:1.5rem;color:var(--accent);text-shadow:var(--glow);letter-spacing:4px}
.logo span{color:var(--accent2)}
.status-bar{font-family:'Share Tech Mono',monospace;font-size:.7rem;color:var(--muted);text-align:right}
.status-dot{display:inline-block;width:8px;height:8px;background:var(--accent2);border-radius:50%;margin-right:6px;box-shadow:0 0 8px var(--accent2);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.main-grid{display:grid;grid-template-columns:370px 1fr;gap:22px}
@media(max-width:900px){.main-grid{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:4px;overflow:hidden;position:relative}
.panel::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--accent),transparent)}
.panel-header{padding:12px 20px;border-bottom:1px solid var(--border);font-family:'Rajdhani',sans-serif;font-size:.78rem;font-weight:700;letter-spacing:3px;color:var(--accent);text-transform:uppercase;display:flex;align-items:center;gap:10px}
.panel-body{padding:18px}
label{display:block;font-size:.7rem;font-weight:700;letter-spacing:2px;color:var(--muted);text-transform:uppercase;margin-bottom:5px;font-family:'Rajdhani',sans-serif}
textarea,input[type=text],input[type=number]{width:100%;background:rgba(0,0,0,.45);border:1px solid var(--border);border-radius:3px;color:var(--text);font-family:'Share Tech Mono',monospace;font-size:.82rem;padding:9px 13px;outline:none;transition:border-color .2s,box-shadow .2s;margin-bottom:14px}
textarea{resize:vertical;min-height:100px}
textarea:focus,input:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(0,212,255,.12)}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.chip-group{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:14px}
.chip{padding:5px 12px;border-radius:2px;border:1px solid var(--border);font-family:'Share Tech Mono',monospace;font-size:.68rem;cursor:pointer;color:var(--muted);background:transparent;transition:all .15s}
.chip:hover{border-color:var(--accent);color:var(--accent)}
.chip.active{border-color:var(--accent2);color:var(--accent2);background:rgba(0,255,157,.08)}
.btn-scan{width:100%;padding:13px;background:transparent;border:2px solid var(--accent);border-radius:3px;color:var(--accent);font-family:'Rajdhani',sans-serif;font-size:1.05rem;font-weight:700;letter-spacing:4px;text-transform:uppercase;cursor:pointer;position:relative;overflow:hidden;transition:all .2s}
.btn-scan::before{content:'';position:absolute;inset:0;background:var(--accent);transform:translateX(-100%);transition:transform .25s ease;z-index:0}
.btn-scan:hover::before{transform:translateX(0)}
.btn-scan:hover{color:var(--bg);box-shadow:var(--glow)}
.btn-scan span{position:relative;z-index:1}
.btn-scan:disabled{opacity:.4;cursor:not-allowed;pointer-events:none}
.progress-wrap{margin-top:14px;display:none}
.progress-wrap.visible{display:block}
.progress-label{font-family:'Share Tech Mono',monospace;font-size:.7rem;color:var(--muted);margin-bottom:5px;display:flex;justify-content:space-between}
.progress-track{height:4px;background:rgba(255,255,255,.05);border-radius:2px;overflow:hidden}
.progress-bar{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:2px;width:0%;transition:width .3s ease;box-shadow:0 0 10px var(--accent)}
.results-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;flex-wrap:wrap;gap:10px}
.scan-stats{display:flex;gap:14px;flex-wrap:wrap}
.stat-box{text-align:center;padding:8px 16px;border:1px solid var(--border);border-radius:3px;background:rgba(0,0,0,.3)}
.stat-val{font-family:'Share Tech Mono',monospace;font-size:1.4rem;color:var(--accent);display:block;line-height:1}
.stat-lbl{font-family:'Rajdhani',sans-serif;font-size:.62rem;color:var(--muted);letter-spacing:2px;text-transform:uppercase;display:block;margin-top:3px}
.stat-box.green .stat-val{color:var(--accent2)}
.stat-box.orange .stat-val{color:var(--accent3)}
.btn-export{padding:7px 18px;background:transparent;border:1px solid var(--accent2);border-radius:3px;color:var(--accent2);font-family:'Rajdhani',sans-serif;font-size:.75rem;font-weight:700;letter-spacing:2px;text-transform:uppercase;cursor:pointer;transition:all .2s}
.btn-export:hover{background:rgba(0,255,157,.1)}
.btn-export:disabled{opacity:.3;cursor:not-allowed}
.target-card{border:1px solid var(--border);border-radius:3px;margin-bottom:10px;overflow:hidden;animation:slideIn .25s ease}
@keyframes slideIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
.target-card-header{padding:11px 16px;background:rgba(0,0,0,.3);display:flex;align-items:center;justify-content:space-between;cursor:pointer;transition:background .2s;user-select:none}
.target-card-header:hover{background:rgba(0,212,255,.05)}
.target-info{display:flex;align-items:center;gap:10px;min-width:0}
.target-ip{font-family:'Share Tech Mono',monospace;font-size:.9rem;color:var(--accent);white-space:nowrap}
.target-host{font-size:.73rem;color:var(--muted);font-family:'Share Tech Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.target-badges{display:flex;gap:8px;align-items:center;flex-shrink:0}
.badge{padding:3px 9px;border-radius:2px;font-family:'Share Tech Mono',monospace;font-size:.64rem}
.badge-open{background:rgba(0,255,157,.12);color:var(--accent2);border:1px solid rgba(0,255,157,.28)}
.badge-filtered{background:rgba(255,183,0,.1);color:var(--warn);border:1px solid rgba(255,183,0,.28)}
.badge-none{background:rgba(255,107,53,.1);color:var(--accent3);border:1px solid rgba(255,107,53,.28)}
.chevron{color:var(--muted);font-size:.73rem;transition:transform .22s;margin-left:8px;flex-shrink:0}
.chevron.open{transform:rotate(90deg)}
.target-card-body{display:none;padding:0 16px 14px}
.target-card-body.open{display:block}
.port-table{width:100%;border-collapse:collapse;margin-top:10px}
.port-table th{font-family:'Rajdhani',sans-serif;font-size:.67rem;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--muted);padding:7px 10px;border-bottom:1px solid var(--border);text-align:left}
.port-table td{padding:6px 10px;font-family:'Share Tech Mono',monospace;font-size:.75rem;border-bottom:1px solid rgba(26,48,80,.4)}
.port-table tr:last-child td{border-bottom:none}
.port-table tr:hover td{background:rgba(0,212,255,.03)}
.port-num{color:var(--accent)}
.proto-tcp{color:#60a0ff}
.proto-udp{color:var(--warn)}
.state-open{color:var(--accent2)}
.state-filtered{color:var(--warn)}
.banner-cell{color:var(--muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.empty-state{text-align:center;padding:60px 20px;color:var(--muted);font-family:'Share Tech Mono',monospace;font-size:.82rem}
.empty-icon{font-size:2.8rem;margin-bottom:14px;opacity:.35}
.empty-state p{line-height:2.2}
.log-box{background:rgba(0,0,0,.55);border:1px solid var(--border);border-radius:3px;padding:10px 12px;font-family:'Share Tech Mono',monospace;font-size:.68rem;color:var(--muted);max-height:130px;overflow-y:auto;margin-top:12px}
.log-box p{line-height:1.9}
.log-ok{color:var(--accent2)}.log-warn{color:var(--warn)}.log-err{color:var(--accent3)}.log-info{color:var(--accent)}
.sdiv{display:flex;align-items:center;gap:10px;margin-bottom:14px;color:var(--muted);font-family:'Rajdhani',sans-serif;font-size:.67rem;letter-spacing:2px;text-transform:uppercase}
.sdiv::before,.sdiv::after{content:'';flex:1;height:1px;background:var(--border)}
.scan-time{font-family:'Share Tech Mono',monospace;font-size:.64rem;color:var(--muted)}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
</style>
</head>
<body>
<div class="grid-bg"></div>
<header>
  <div class="logo">SCAN<span>NET</span></div>
  <div class="status-bar"><span class="status-dot"></span>ENGINE ONLINE<br><span id="sysTime"></span></div>
</header>
<div class="wrapper">
<div class="main-grid">

<!-- LEFT: CONFIG -->
<div>
<div class="panel">
<div class="panel-header">⬡ TARGET CONFIG</div>
<div class="panel-body">
  <label>Targets (IP / CIDR / Domain / Range)</label>
  <textarea id="targets" placeholder="192.168.1.1&#10;10.0.0.0/24&#10;example.com&#10;192.168.1.1-20"></textarea>

  <div class="sdiv">Port Selection</div>
  <label>Preset Profile</label>
  <div class="chip-group" id="presetChips">
    <button class="chip active" data-preset="common" onclick="selectPreset(this)">Common</button>
    <button class="chip" data-preset="top100" onclick="selectPreset(this)">Top 100</button>
    <button class="chip" data-preset="full" onclick="selectPreset(this)">1-1024</button>
    <button class="chip" data-preset="web" onclick="selectPreset(this)">Web</button>
    <button class="chip" data-preset="custom" onclick="selectPreset(this)">Custom</button>
  </div>
  <div id="customPortWrap" style="display:none">
    <label>TCP Ports</label>
    <input type="text" id="tcpPorts" placeholder="22,80,443,8080-8090"/>
    <label>UDP Ports</label>
    <input type="text" id="udpPorts" placeholder="53,161,500"/>
  </div>

  <div class="sdiv">Options</div>
  <div class="form-row">
    <div>
      <label>Timeout (s)</label>
      <input type="number" id="timeout" value="0.8" step="0.1" min="0.1" max="10"/>
    </div>
    <div>
      <label>Threads</label>
      <input type="number" id="threads" value="300" min="10" max="1000"/>
    </div>
  </div>

  <label>Scan Mode</label>
  <div class="chip-group" id="modeChips">
    <button class="chip active" data-mode="tcp" onclick="selectMode(this)">TCP Only</button>
    <button class="chip" data-mode="udp" onclick="selectMode(this)">UDP Only</button>
    <button class="chip" data-mode="both" onclick="selectMode(this)">TCP + UDP</button>
  </div>

  <button class="btn-scan" id="scanBtn" onclick="startScan()">
    <span id="btnText">▶ INITIALIZE SCAN</span>
  </button>

  <div class="progress-wrap" id="progressWrap">
    <div class="progress-label">
      <span id="progressLabel">Scanning…</span>
      <span id="progressPct">0%</span>
    </div>
    <div class="progress-track"><div class="progress-bar" id="progressBar"></div></div>
  </div>

  <div class="log-box" id="logBox">
    <p class="log-info">[ScanNet] Ready. Enter targets and press scan.</p>
  </div>
</div>
</div>
</div>

<!-- RIGHT: RESULTS -->
<div>
<div class="panel" style="min-height:580px">
<div class="panel-header">
  ◈ SCAN RESULTS
  <span style="margin-left:auto">
    <button class="btn-export" id="exportBtn" onclick="exportJSON()" disabled>⬇ EXPORT JSON</button>
  </span>
</div>
<div class="panel-body">
  <div class="results-top">
    <div class="scan-stats">
      <div class="stat-box"><span class="stat-val" id="statTargets">—</span><span class="stat-lbl">Targets</span></div>
      <div class="stat-box green"><span class="stat-val" id="statOpen">—</span><span class="stat-lbl">Open Ports</span></div>
      <div class="stat-box orange"><span class="stat-val" id="statTime">—</span><span class="stat-lbl">Elapsed (s)</span></div>
    </div>
    <span class="scan-time" id="scanTimestamp"></span>
  </div>
  <div id="resultsArea">
    <div class="empty-state">
      <div class="empty-icon">◎</div>
      <p>No scan results yet.<br>Configure targets on the left<br>and press Initialize Scan.</p>
    </div>
  </div>
</div>
</div>
</div>

</div>
</div>

<script>
// ── Presets ────────────────────────────────────────────────────────────────
const COMMON_TCP = "21,22,23,25,53,80,110,111,135,139,143,443,445,587,993,995,1433,1521,1723,2049,2181,3000,3306,3389,5432,5900,6379,6443,8080,8443,8888,9200,11211,27017";
const COMMON_UDP = "53,67,68,69,123,161,162,500,514,1194,4500,5353";
const TOP100_TCP = "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152";
const WEB_TCP   = "80,443,8080,8443,8000,8008,8081,3000,5000,9000,9090,10000,4200,3001";

const PRESETS = {
  common:{ tcp:COMMON_TCP, udp:COMMON_UDP },
  top100:{ tcp:TOP100_TCP, udp:"53,67,69,123,161,500" },
  full:  { tcp:"1-1024",   udp:"53,67,69,123,161,500" },
  web:   { tcp:WEB_TCP,    udp:"" },
  custom:null,
};

let currentPreset = 'common';
let currentMode   = 'tcp';
let scanData      = null;

function selectPreset(el){
  document.querySelectorAll('#presetChips .chip').forEach(c=>c.classList.remove('active'));
  el.classList.add('active');
  currentPreset = el.dataset.preset;
  document.getElementById('customPortWrap').style.display = currentPreset==='custom'?'block':'none';
}
function selectMode(el){
  document.querySelectorAll('#modeChips .chip').forEach(c=>c.classList.remove('active'));
  el.classList.add('active');
  currentMode = el.dataset.mode;
}

// ── Log ────────────────────────────────────────────────────────────────────
function log(msg, type=''){
  const box = document.getElementById('logBox');
  const p   = document.createElement('p');
  if(type) p.className='log-'+type;
  p.textContent='['+new Date().toTimeString().slice(0,8)+'] '+msg;
  box.appendChild(p);
  box.scrollTop=box.scrollHeight;
}
function updateProgress(pct, label){
  document.getElementById('progressBar').style.width=Math.min(100,pct)+'%';
  document.getElementById('progressPct').textContent=Math.round(Math.min(100,pct))+'%';
  if(label) document.getElementById('progressLabel').textContent=label;
}

// ── Start scan ─────────────────────────────────────────────────────────────
async function startScan(){
  const raw = document.getElementById('targets').value.trim();
  if(!raw){ log('No targets entered.','err'); return; }

  document.getElementById('scanBtn').disabled=true;
  document.getElementById('btnText').textContent='⟳ SCANNING…';
  document.getElementById('progressWrap').classList.add('visible');
  document.getElementById('exportBtn').disabled=true;
  document.getElementById('resultsArea').innerHTML='<div class="empty-state"><div class="empty-icon">⟳</div><p>Scan in progress…<br>Results will appear here.</p></div>';
  updateProgress(1,'Initializing…');

  let tcpPorts='', udpPorts='';
  if(currentPreset!=='custom'){
    const p=PRESETS[currentPreset];
    if(currentMode!=='udp') tcpPorts=p.tcp;
    if(currentMode!=='tcp') udpPorts=p.udp||'';
  } else {
    if(currentMode!=='udp') tcpPorts=document.getElementById('tcpPorts').value.trim();
    if(currentMode!=='tcp') udpPorts=document.getElementById('udpPorts').value.trim();
  }

  const payload={
    targets:   raw,
    tcp_ports: tcpPorts,
    udp_ports: udpPorts,
    timeout:   parseFloat(document.getElementById('timeout').value)||0.8,
    threads:   parseInt(document.getElementById('threads').value)||300,
  };

  log('Sending scan request…','info');
  let scanId;
  try{
    const r=await fetch('/api/scan',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload),
    });
    const d=await r.json();
    if(d.error){ log('Server error: '+d.error,'err'); resetBtn(); return; }
    scanId=d.scan_id;
    log('Scan queued — ID: '+scanId,'ok');
  } catch(e){
    log('Cannot reach server: '+e,'err');
    resetBtn();
    return;
  }

  const startTime=Date.now();
  let lastPct=0;

  async function poll(){
    try{
      const r=await fetch('/api/scan/'+scanId);
      const d=await r.json();
      if(d.progress!==undefined && d.progress>lastPct){
        lastPct=d.progress;
        updateProgress(d.progress,'Scanning… '+Math.round(d.progress)+'%');
      }
      if(d.status==='done'){
        const elapsed=((Date.now()-startTime)/1000).toFixed(1);
        renderResults(d.results, elapsed);
        scanData=d.results;
        document.getElementById('exportBtn').disabled=false;
        resetBtn();
        updateProgress(100,'Complete ✓');
        let totalOpen=d.results.reduce((s,r)=>s+(r.open_count||0),0);
        log('Scan complete — '+d.results.length+' targets, '+totalOpen+' open ports, '+elapsed+'s','ok');
        return;
      }
      if(d.status==='error'){
        log('Scan error: '+(d.message||'unknown'),'err');
        resetBtn();
        return;
      }
    } catch(e){ /* retry */ }
    setTimeout(poll, 600);
  }
  setTimeout(poll, 800);
}

function resetBtn(){
  document.getElementById('scanBtn').disabled=false;
  document.getElementById('btnText').textContent='▶ INITIALIZE SCAN';
}

// ── Render ─────────────────────────────────────────────────────────────────
function escH(s){
  if(!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function renderResults(results, elapsed){
  const totalOpen=results.reduce((s,r)=>s+(r.open_count||0),0);
  document.getElementById('statTargets').textContent=results.length;
  document.getElementById('statOpen').textContent=totalOpen;
  document.getElementById('statTime').textContent=elapsed;
  document.getElementById('scanTimestamp').textContent=new Date().toLocaleString();

  const area=document.getElementById('resultsArea');
  area.innerHTML='';

  if(!results.length){
    area.innerHTML='<div class="empty-state"><div class="empty-icon">◎</div><p>No valid targets resolved.</p></div>';
    return;
  }

  results.forEach((r,idx)=>{
    const openP=(r.open_ports||[]).filter(p=>p.state==='open');
    const filtP=(r.open_ports||[]).filter(p=>p.state.includes('filtered'));
    const badgeCls=openP.length?'badge-open':filtP.length?'badge-filtered':'badge-none';
    const badgeTxt=openP.length?openP.length+' OPEN':filtP.length?filtP.length+' FILTERED':'CLOSED';

    const rows=(r.open_ports||[]).map(p=>
      '<tr>'+
      '<td class="port-num">'+p.port+'</td>'+
      '<td class="'+(p.protocol==='tcp'?'proto-tcp':'proto-udp')+'">'+p.protocol.toUpperCase()+'</td>'+
      '<td class="'+(p.state==='open'?'state-open':'state-filtered')+'">'+p.state+'</td>'+
      '<td>'+escH(p.service)+'</td>'+
      '<td class="banner-cell" title="'+escH(p.banner)+'">'+(p.banner?escH(p.banner):'—')+'</td>'+
      '</tr>'
    ).join('');

    const isOpen=idx===0;
    const card=document.createElement('div');
    card.className='target-card';
    card.innerHTML=
      '<div class="target-card-header" onclick="toggleCard(this)">'+
        '<div class="target-info">'+
          '<span class="target-ip">'+escH(r.ip)+'</span>'+
          (r.hostname?'<span class="target-host">'+escH(r.hostname)+'</span>':'')+
        '</div>'+
        '<div class="target-badges">'+
          '<span class="badge '+badgeCls+'">'+badgeTxt+'</span>'+
          '<span class="chevron'+(isOpen?' open':'')+'">▶</span>'+
        '</div>'+
      '</div>'+
      '<div class="target-card-body'+(isOpen?' open':'')+'">'+
        (rows
          ?'<table class="port-table"><thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Banner</th></tr></thead><tbody>'+rows+'</tbody></table>'
          :'<p style="color:var(--muted);font-size:.78rem;padding-top:8px">No open ports detected.</p>')+
      '</div>';
    area.appendChild(card);
  });
}

function toggleCard(hdr){
  hdr.nextElementSibling.classList.toggle('open');
  hdr.querySelector('.chevron').classList.toggle('open');
}

function exportJSON(){
  if(!scanData) return;
  const blob=new Blob([JSON.stringify(scanData,null,2)],{type:'application/json'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='scannet_'+Date.now()+'.json';
  a.click();
}

setInterval(()=>{
  document.getElementById('sysTime').textContent=
    new Date().toISOString().replace('T',' ').slice(0,19)+' UTC';
},1000);
</script>
</body>
</html>"""

# ─────────────────────────────────────────────────────────────────────────────
# THREADED HTTP SERVER
# ─────────────────────────────────────────────────────────────────────────────

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

class ScanHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress server logs

    def send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html: str):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self.send_html(HTML_PAGE)
        elif path.startswith("/api/scan/"):
            scan_id = path[len("/api/scan/"):]
            with scan_lock:
                in_res  = scan_id in scan_results_store
                in_prog = scan_id in scan_progress_store
                in_err  = scan_id in scan_error_store
                pct     = scan_progress_store.get(scan_id, {}).get("pct", 0)
                results = scan_results_store.get(scan_id)
                err_msg = scan_error_store.get(scan_id)

            if in_err:
                self.send_json({"status": "error", "message": err_msg})
            elif in_res:
                self.send_json({"status": "done", "results": results, "progress": 100})
            elif in_prog:
                self.send_json({"status": "running", "progress": pct})
            else:
                self.send_json({"error": "Unknown scan ID"}, 404)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path != "/api/scan":
            self.send_response(404); self.end_headers(); return
        try:
            length  = int(self.headers.get("Content-Length", 0))
            body    = self.rfile.read(length)
            payload = json.loads(body)
        except Exception as e:
            self.send_json({"error": "Bad request: " + str(e)}, 400)
            return

        scan_id = f"scan_{int(time.time()*1000)}"
        with scan_lock:
            scan_progress_store[scan_id] = {"pct": 0}

        threading.Thread(target=_run_scan, args=(scan_id, payload), daemon=True).start()
        self.send_json({"scan_id": scan_id})

# ─────────────────────────────────────────────────────────────────────────────
# BACKGROUND SCAN WORKER
# ─────────────────────────────────────────────────────────────────────────────

def _run_scan(scan_id, payload):
    try:
        raw_targets  = payload.get("targets", "").strip()
        tcp_port_str = payload.get("tcp_ports", "").strip()
        udp_port_str = payload.get("udp_ports", "").strip()
        timeout      = float(payload.get("timeout", 0.8))
        max_workers  = max(10, min(1000, int(payload.get("threads", 300))))

        print(f"[ScanNet] Scan {scan_id} started | targets={repr(raw_targets[:60])} tcp={repr(tcp_port_str[:40])} udp={repr(udp_port_str[:40])}", flush=True)

        # Expand targets
        all_ips = []
        for line in raw_targets.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r'^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$', line)
            if m:
                base, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
                for i in range(lo, min(hi, lo + 256) + 1):
                    all_ips.extend(validate_target(f"{base}{i}"))
            else:
                resolved = validate_target(line)
                if not resolved:
                    print(f"[ScanNet] Could not resolve: {line}", flush=True)
                all_ips.extend(resolved)

        # Deduplicate
        seen, unique_ips = set(), []
        for ip in all_ips:
            if ip not in seen:
                seen.add(ip); unique_ips.append(ip)

        print(f"[ScanNet] Resolved {len(unique_ips)} unique IP(s)", flush=True)

        if not unique_ips:
            with scan_lock:
                scan_results_store[scan_id] = []
                scan_progress_store.pop(scan_id, None)
            print(f"[ScanNet] No valid IPs — scan done with empty results", flush=True)
            return

        # Parse ports — fallback to common if empty
        tcp_ports = parse_port_range(tcp_port_str) if tcp_port_str else []
        udp_ports = parse_port_range(udp_port_str) if udp_port_str else []

        if not tcp_ports and not udp_ports:
            tcp_ports = list(COMMON_PORTS.keys())
            print(f"[ScanNet] No ports specified — using common TCP ports", flush=True)

        print(f"[ScanNet] Scanning {len(tcp_ports)} TCP + {len(udp_ports)} UDP ports per target", flush=True)

        total_targets = len(unique_ips)
        results = []

        for i, ip in enumerate(unique_ips):
            total_ports = len(tcp_ports) + len(udp_ports)
            done_lock   = threading.Lock()
            done_box    = [0]

            def _pcb(d, tot, i=i):
                with done_lock:
                    done_box[0] = d
                raw_pct = ((i + d / max(tot, 1)) / total_targets) * 100
                pct = round(min(raw_pct, 99.0), 1)
                with scan_lock:
                    scan_progress_store[scan_id] = {"pct": pct}

            result = scan_target(ip, tcp_ports, udp_ports, timeout, max_workers, _pcb)
            results.append(result)
            print(f"[ScanNet] {ip} → {result['open_count']} open ports", flush=True)

            with scan_lock:
                scan_progress_store[scan_id] = {"pct": round(((i+1)/total_targets)*99, 1)}

        with scan_lock:
            scan_results_store[scan_id] = results
            scan_progress_store.pop(scan_id, None)

        print(f"[ScanNet] Scan {scan_id} complete", flush=True)

    except Exception as e:
        import traceback
        traceback.print_exc()
        with scan_lock:
            scan_error_store[scan_id] = str(e)
            scan_progress_store.pop(scan_id, None)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # Raise fd limit for high concurrency (Linux/macOS)
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(hard, 65536)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        print(f"[ScanNet] File descriptor limit: {target}", flush=True)
    except Exception:
        pass

    port = int(os.environ.get("PORT", 8765))
    server = ThreadedHTTPServer(("0.0.0.0", port), ScanHandler)

    print(f"""
╔══════════════════════════════════════════════════════╗
║        ScanNet — Port Scanner & Config Manager       ║
╠══════════════════════════════════════════════════════╣
║  Web UI  →  http://localhost:{port}                  
║  Press   →  Ctrl+C to stop                          
╚══════════════════════════════════════════════════════╝
""", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[ScanNet] Stopped.")
        server.server_close()
        sys.exit(0)

if __name__ == "__main__":
    main()
