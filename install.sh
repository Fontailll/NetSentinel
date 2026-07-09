#!/bin/sh
# NetWatch Installer — Linux
# Usage: curl -sL https://git.io/J-xxxx | sudo bash
#   or:  chmod +x install.sh && sudo ./install.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

REPO="Fontailll/NetWatch"
BIN="/usr/local/bin/netwatch"

# --- Detect package manager ---
install_deps() {
    printf "${CYAN}[*] Installing build dependencies...${NC}\n"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq build-essential cmake
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y gcc-c++ cmake make
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Syu --noconfirm gcc cmake make
    elif command -v zypper >/dev/null 2>&1; then
        zypper install -y gcc-c++ cmake make
    elif command -v apk >/dev/null 2>&1; then
        apk add g++ cmake make
    else
        printf "${RED}[!] Package manager not detected. Install g++ and cmake manually.${NC}\n"
        exit 1
    fi
}

# --- Try pre-built binary first ---
try_prebuilt() {
    local arch
    arch=$(uname -m)
    [ "$arch" = "x86_64" ] || return 1

    local url="https://github.com/${REPO}/releases/latest/download/netwatch-linux-x86_64"

    printf "${CYAN}[*] Downloading pre-built binary...${NC}\n"
    if command -v curl >/dev/null 2>&1; then
        curl -sL "$url" -o "$BIN"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$BIN"
    else
        return 1
    fi

    [ -s "$BIN" ] || return 1
    chmod +x "$BIN"
    return 0
}

# --- Build from source ---
build_from_source() {
    printf "${CYAN}[*] Building from source...${NC}\n"

    local tmpdir
    tmpdir=$(mktemp -d)
    cd "$tmpdir"

    if command -v git >/dev/null 2>&1; then
        git clone --depth=1 "https://github.com/${REPO}.git"
    else
        install_deps  # ensure cmake is available
        local tarball="https://github.com/${REPO}/archive/refs/heads/main.tar.gz"
        if command -v curl >/dev/null 2>&1; then
            curl -sL "$tarball" | tar xz
            cd NetWatch-main
        else
            wget -q -O - "$tarball" | tar xz
            cd NetWatch-main
        fi
    fi

    cd NetWatch 2>/dev/null || cd NetWatch-main 2>/dev/null || true

    mkdir -p build && cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j"$(nproc 2>/dev/null || echo 1)"
    cp netwatch "$BIN"

    cd / && rm -rf "$tmpdir"
}

# --- Main ---
if [ "$(id -u)" -ne 0 ]; then
    printf "${RED}[!] Run as root: curl -sL ... | sudo bash${NC}\n"
    exit 1
fi

printf "${CYAN}  NetWatch Installer${NC}\n\n"

if try_prebuilt; then
    printf "${GREEN}[✓] Installed: ${BIN}${NC}\n"
else
    install_deps
    build_from_source
    printf "${GREEN}[✓] Built and installed: ${BIN}${NC}\n"
fi

printf "\n${CYAN}Usage:${NC}\n"
printf "  sudo netwatch           # Scan connections\n"
printf "  sudo netwatch --all     # Full scan\n"
printf "  sudo netwatch --watch   # Real-time monitoring\n"
printf "  netwatch --help         # Options\n\n"
