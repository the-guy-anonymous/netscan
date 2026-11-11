# NETSCAN developed by MR.X [OFFICIAL]

An advanced, high-performance terminal TCP network, port scanner, OS & device reconnaissance engine with zero external dependencies.

---

## Key Advanced Technologies

1. **Context-Aware Deep OS & Device Identification Engine (`-O` / `--os`)**:
   - **Local Host Auto-Recognition**: When scanning `127.0.0.1`, `localhost`, or the machine's own network adapter IP (e.g. `192.168.x.x`), automatically identifies the host device name and exact kernel OS (e.g., `Windows 11 Pro [x64]` with **100% confidence**).
   - **Default Gateway & Wi-Fi Router Detection**: Automatically detects when an IP is the network's default gateway and identifies the router firmware.
   - **TCP/IP Stack TTL Fingerprinting**: Probes initial packet Time-to-Live (TTL ≈ 128 for Windows, TTL ≈ 64 for Linux/Unix/Android/macOS, TTL ≈ 255 for Cisco/Switches).
   - **Hardware MAC & Vendor OUI Resolution**: Reads the local ARP cache table to extract physical MAC addresses and matches the manufacturer (Apple, Samsung, Intel, TP-Link, Cisco, Raspberry Pi, Dell, etc.).
   - **Role Classification**: Accurately classifies devices into **Local Workstations**, **Wi-Fi Routers**, **Linux Cloud Servers**, **Network Printers**, **IP Security Cameras**, and **Android/Apple Mobile Devices**.

2. **Deep Protocol Fingerprinting**:
   - **TLS/SSL Handshake & Certificate Inspection**: Extracts Subject Common Name (`CN`), Organization (`O`), and expiration date.
   - **HTTP/Web Stack Extraction**: Probes `Server:` headers, HTML `<title>`, and `X-Powered-By` runtime headers.
   - **Application State Probing**: Recognizes Redis auth states (`PONG` vs `NOAUTH`), SSH versions, and mail server greeting banners.

3. **Security Risk & Exposure Heuristics Engine**:
   - Analyzes discovered services and flags exposure risks (e.g. cleartext FTP, unencrypted Telnet, exposed SMB/RDP, unauthenticated Redis/MongoDB databases, exposed Android ADB).

4. **Local LAN Auto-Discovery (`--local` / `-l`)**:
   - Automatically probes physical network adapters and calculates your local subnet (e.g. `192.168.1.0/24`) for instant 1-click network auditing.

5. **Timing Profiles (`-T1` through `-T5`)**:
   - `-T1` (*Paranoid*): Serial, high timeout for sensitive embedded devices.
   - `-T3` (*Normal*): Standard 50-worker pool (default).
   - `-T4` (*Aggressive*): 100 workers, 800ms timeout for high-speed local networks.
   - `-T5` (*Insane*): 150 workers, 500ms timeout for gigabit environments.

6. **Triple Export Formats**:
   - **Interactive HTML Dashboard** (`--html <file.html>`): Generates a dark-mode web report with a Device Matrix, OS badges, and real-time search.
   - **CSV Export** (`-o <file.csv>`): Spreadsheet-ready format with device type, OS, and MAC addresses.
   - **JSON Export** (`-o <file.json>`): Complete machine-readable structured payload.

---

## Installation

Clone the repository and link it globally:

```bash
git clone https://github.com/the-guy-anonymous/netscan.git
cd netscan
npm link
```

## Quick Start

### 1. Direct Terminal Command
```bash
# Scan a single host with OS and device identification
netscan 127.0.0.1

# Auto-detect your local LAN subnet, sweep live hosts, and detect device types
netscan --local --sweep

# Fast scan top 100 ports with Aggressive timing (-T4) and export HTML report
netscan 192.168.1.1 -F -T4 --html network_audit.html
```

### 2. Interactive Setup Wizard
Run without arguments to launch the interactive prompt:
```bash
netscan
```

---

## CLI Command Reference

| Flag | Argument | Description | Default |
|---|---|---|---|
| `-O`, `--os` | — | Deep OS & device reconnaissance (Enabled by default) | `true` |
| `-p`, `--ports` | `<spec>` | Ports to scan (`top`, `fast`, `1-1000`, `80,443`) | `top` (35+) |
| `-F`, `--fast` | — | Fast scan mode (Top 100 most common ports) | `false` |
| `-l`, `--local` | — | Auto-detect and scan local LAN interface subnet | `false` |
| `-s`, `--sweep` | — | Host discovery sweep mode (quick active host mapping) | `false` |
| `-T <1-5>` | `<level>` | Timing profile: `1` (Paranoid) to `5` (Insane) | `3` (Normal) |
| `-t`, `--timeout` | `<ms>` | Timeout per connection in milliseconds | `1200` |
| `-c`, `--concurrency` | `<n>` | Maximum parallel socket workers | `50` |
| `--html <file>` | `<path>` | Export an interactive HTML dashboard report | — |
| `-o`, `--output` | `<path>` | Export to HTML (`.html`), JSON (`.json`), or CSV (`.csv`) | — |
| `-v`, `--verbose` | — | Display closed & filtered ports in terminal output | `false` |
| `--no-banner` | — | Disable deep banner grabbing for maximum scan speed | `false` |
| `-h`, `--help` | — | Display the help menu | — |
