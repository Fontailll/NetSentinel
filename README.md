# NetSentinel

**Network Incident Response Tool** — Scan active TCP/UDP connections, calculate risk scores, export to JSON, block with firewall.
NOTE: Idk why but only compiling from source works on linux right now,I will try to fix it in future updates and Theres a prebuilt version for windows if theres something wrong again.

Cross-platform (Linux + Windows), C++17.

[![Build](https://github.com/Fontailll/NetSentinel/actions/workflows/build.yml/badge.svg)](https://github.com/Fontailll/NetSentinel/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/Fontailll/NetSentinel)](https://github.com/Fontailll/NetSentinel/releases/latest)
[![License](https://img.shields.io/github/license/Fontailll/NetSentinel)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-blue)]()
[![C++](https://img.shields.io/badge/C%2B%2B-17-informational)]()
[![Downloads](https://img.shields.io/github/downloads/Fontailll/NetSentinel/total)](https://github.com/Fontailll/NetSentinel/releases/latest)
[![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)]()

---

## Quick Start (One-Liner)

### Linux

```bash
# Auto-detect distro, download pre-built binary or build from source
curl -sL https://raw.githubusercontent.com/Fontailll/NetSentinel/main/install.sh | sudo bash

# Scan with all features
sudo netsentinel --all
```

### Windows (PowerShell as Admin)

```powershell
# 1. Download & install MSYS2 from https://www.msys2.org
# 2. Open "MSYS2 UCRT64" from Start Menu
# 3. Update packages:
pacman -Syu
# 4. Install GCC, CMake, and Ninja (pacman is MSYS2's package manager):
pacman -S mingw-w64-ucrt-x86_64-gcc cmake ninja
# 5. Build:
cd /c/Users/(username)/Desktop/netsentinel
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja
# 6. Run:
./netsentinel.exe --all
```

---

## Linux Installation

### Option 1 — Automatic (Recommended)

```bash
curl -sL https://raw.githubusercontent.com/Fontailll/NetSentinel/main/install.sh | sudo bash
sudo netsentinel --all
```

The script:
1. Tries to download a **fully static pre-built binary** from GitHub Releases
2. If that fails, detects your distro, installs dependencies, and builds from source
3. Installs to `/usr/local/bin/netsentinel`

### Option 2 — Pre-built Binary

```bash
curl -sL https://github.com/Fontailll/NetSentinel/releases/latest/download/netsentinel-linux-x86_64 -o netsentinel
chmod +x netsentinel
sudo ./netsentinel --all
```

The binary is **statically linked** — works on any Linux distro without dependencies.

### Option 3 — Build from Source

```bash
# Dependencies
# Debian/Ubuntu:  sudo apt install build-essential cmake
# Fedora:         sudo dnf install gcc-c++ cmake make
# Arch:           sudo pacman -S gcc cmake make
# Alpine:         sudo apk add g++ cmake make
# openSUSE:       sudo zypper install gcc-c++ cmake make

git clone https://github.com/Fontailll/NetSentinel.git
cd NetSentinel
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo ./netsentinel --all
```

### Install as a Service

#### systemd (Fedora, Debian 8+, Ubuntu 16+, Arch)

```bash
sudo ./netsentinel --install-service systemd > /etc/systemd/system/netsentinel.service
sudo systemctl daemon-reload
sudo systemctl enable --now netsentinel
sudo systemctl status netsentinel
```

#### runit (Void Linux, Artix)

```bash
sudo mkdir -p /etc/sv/netsentinel
sudo ./netsentinel --install-service runit > /etc/sv/netsentinel/run
sudo chmod +x /etc/sv/netsentinel/run
sudo ln -s /etc/sv/netsentinel /var/service/
```

#### OpenRC (Gentoo, Alpine)

```bash
sudo ./netsentinel --install-service openrc > /etc/init.d/netsentinel
sudo chmod +x /etc/init.d/netsentinel
sudo rc-update add netsentinel default
sudo rc-service netsentinel start
```

#### Auto-detect

```bash
sudo ./netsentinel --install-service auto
```

### Daemon Mode

```bash
sudo ./netsentinel --watch --daemon --pidfile /run/netsentinel.pid --logfile /var/log/netsentinel.log
```

---

## Windows Installation

### Prerequisites

Install [MSYS2](https://www.msys2.org) (UCRT64 variant recommended).

### Build

Open **MSYS2 UCRT64** terminal and run:

```bash
# First-time setup (if not done yet)
pacman -Syu                          # Update package database
pacman -S mingw-w64-ucrt-x86_64-gcc cmake ninja   # Install toolchain

# Build
cd /c/Users/(username)/Desktop/netsentinel   # Use /c/ for C:\
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja
```

### Run

```cmd
netsentinel.exe              # Colored table output
netsentinel.exe --all        # All features (signature + detail)
netsentinel.exe --json       # JSON output (pipe-friendly)
netsentinel.exe --export report.json
netsentinel.exe --watch      # Real-time monitoring
```

**Notes:**
- Run as **Administrator** for full connection visibility
- Signature verification uses WinVerifyTrust (Authenticode)
- Binary is statically linked — no MSYS2 DLLs needed
- Press Enter to exit after scan (stays open when double-clicked)

---

## Usage

```
Usage: netsentinel [OPTIONS]

Options:
  --export <file.json>    Export connections to JSON file
  --json                  Print connections as JSON to stdout
  --detail                Show detailed info for high-risk connections
  --verify-sig            Enable digital signature verification
  --geoip                 Enable GeoIP country lookup
  --geoip-db <file>       Path to GeoIP CSV database (implies --geoip)
  --watch                 Real-time monitoring mode
  --watch-interval <sec>  Watch polling interval (default: 5)
  --all                   Enable all features (--verify-sig --geoip --detail)
  --daemon                Run as daemon (Linux, requires --watch)
  --pidfile <path>        PID file path (for --daemon)
  --logfile <path>        Log file path (for --daemon)
  --install-service <type> Print service template (systemd/runit/openrc/auto)
  --version               Show version and platform info
  --help, -h              Show this help
```

---

## Risk Scoring Engine

| Rule | Score | Description |
|------|-------|-------------|
| Unsigned executable | +30 | Process is unsigned (requires `--verify-sig`) |
| Temp folder | +25 | Running from Temp or AppData\Local\Temp |
| Malware port | +20 | Connected to known C2/malware port |
| Unknown publisher | +15 | Signed binary with no publisher name |
| Suspicious process name | +15 | powershell, cmd, curl, wget, etc. |
| Hidden process | +10 | PID exists but name is empty |
| Unusual listening port | +10 | Listening on a non-standard low port |
| Foreign connection | +5 | Remote IP is outside private ranges (requires `--geoip`) |

**Risk levels:** LOW (0-29) · MEDIUM (30-59) · HIGH (60-79) · CRITICAL (80+)

---

## Project Structure

```
netsentinel/
├── include/           # Common headers (interfaces)
│   ├── scanner.h      IScanner interface (scan_tcp, scan_udp)
│   ├── connection.h   Connection struct + enums
│   ├── risk.h         RiskEngine (modular rules)
│   ├── output.h       Table, detail, help, version output
│   ├── json_export.h  Minimal JSON writer
│   ├── firewall.h     IFirewall interface
│   ├── process.h      ProcessInfo struct
│   ├── geoip.h        GeoIP lookup module
│   ├── daemon.h       Daemonize + service templates
│   └── utils.h        String helpers
├── src/               # Cross-platform implementation
│   ├── main.cpp       CLI parser, scan pipeline
│   ├── scanner.cpp    IScanner::scan() + factory
│   ├── risk.cpp       8 modular risk rules
│   ├── output.cpp     Colored table, detail cards, help
│   ├── json_export.cpp
│   ├── geoip.cpp
│   ├── daemon.cpp     fork/setsid + systemd/runit/openrc
│   ├── firewall.cpp   IFirewall factory
│   └── utils.cpp
├── platform/
│   ├── windows/       Win32 API (GetExtendedTcpTable, WinVerifyTrust, COM)
│   └── linux/         /proc/net, iptables/nftables
├── tests/             Catch2 unit tests (21 tests)
└── install.sh         One-liner Linux installer
```

---

## License

MIT
