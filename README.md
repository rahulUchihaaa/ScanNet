# ScanNet

A single-file, multi-threaded port scanner with a built-in web dashboard. ScanNet accepts IPs, domains, CIDR ranges, and IP ranges as targets, scans them over TCP and/or UDP, and shows live progress and results in a browser — no dependencies beyond the Python standard library.

## Features

- **Flexible targets** — single IPs, hostnames (auto-resolved via DNS), CIDR blocks (e.g. `192.168.1.0/24`), and dash-style IP ranges (e.g. `192.168.1.1-50`)
- **TCP scanning** — fast, non-blocking connect scans via `select()`, with lightweight banner grabbing on common web ports
- **UDP scanning** — protocol-aware probes for DNS, NTP, SNMP, and TFTP, plus a generic probe for other ports; reports `open` vs `open|filtered`
- **Custom or common ports** — scan specific ports/ranges (`22,80,8000-8100`) or fall back to a built-in list of common TCP ports when none are specified
- **Configurable concurrency** — tune thread count and per-port timeout per scan
- **Live web UI** — submit scans, watch progress update in real time, and browse results in an expandable per-host view
- **JSON export** — download full scan results as JSON directly from the dashboard
- **Zero external dependencies** — pure Python standard library, single file

## Requirements

- Python 3.7+
- No third-party packages required

## Getting Started

```bash
git clone https://github.com/rahulUchihaaa/ScanNet.git
cd ScanNet
python3 scanner.py
```

By default the server starts on port `8765`. Open your browser to:

```
http://localhost:8765
```

To use a different port:

```bash
PORT=9000 python3 scanner.py
```

## Usage

1. Start the server as shown above.
2. Open the web dashboard in your browser.
3. Enter your scan parameters:
   - **Targets** — one per line: IPs, domains, CIDR ranges, or IP ranges (e.g. `10.0.0.1-20`). Lines starting with `#` are ignored.
   - **TCP ports** — e.g. `22,80,443,8000-8100` (leave blank to scan common TCP ports)
   - **UDP ports** — e.g. `53,123,161` (optional)
   - **Threads** — number of concurrent workers (10–1000)
   - **Timeout** — per-port timeout in seconds
4. Submit the scan and watch progress update live.
5. Expand each host in the results view to see open ports, detected services, and grabbed banners.
6. Click **Export JSON** to download the full result set.

## API

The web UI talks to a small JSON API you can also call directly:

- `POST /api/scan` — start a scan. Body:
  ```json
  {
    "targets": "192.168.1.0/24",
    "tcp_ports": "22,80,443",
    "udp_ports": "53,161",
    "threads": 300,
    "timeout": 0.8
  }
  ```
  Returns `{"scan_id": "scan_<timestamp>"}`.

- `GET /api/scan/<scan_id>` — poll scan status. Returns one of:
  - `{"status": "running", "progress": <percent>}`
  - `{"status": "done", "results": [...], "progress": 100}`
  - `{"status": "error", "message": "..."}`

Each host result includes `ip`, `hostname`, `scan_time`, ports scanned, and an `open_ports` list with `port`, `state`, `protocol`, `service`, and `banner`.

## Disclaimer

ScanNet is intended for scanning systems and networks you own or have explicit authorization to test. Port scanning networks or hosts without permission may be illegal in your jurisdiction. Use responsibly.

---

## 👤 Author

📍 Gudivada, Andhra Pradesh, India  
🎯 Aspiring Security Researcher | KAIST Masters Applicant  
🔗 [LinkedIn — Rahul Sonti](https://www.linkedin.com/in/rahul-sonti-b49288322/)

---

## 📄 License

MIT License
