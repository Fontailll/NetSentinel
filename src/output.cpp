#include "output.h"
#include "utils.h"
#include <cstdio>
#include <algorithm>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <cinttypes>

#ifdef _WIN32
#include <windows.h>
#endif

static const char* color_reset   = "\033[0m";
static const char* color_red     = "\033[91m";
static const char* color_green   = "\033[92m";
static const char* color_yellow  = "\033[93m";
static const char* color_blue    = "\033[94m";
static const char* color_magenta = "\033[95m";
static const char* color_cyan    = "\033[96m";
static const char* color_gray    = "\033[90m";
static const char* color_bold    = "\033[1m";
static const char* color_dim     = "\033[2m";

static void enable_ansi() {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &mode)) {
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, mode);
    }
#endif
}

static const char* risk_color(RiskLevel r) {
    switch (r) {
        case RiskLevel::LOW:      return color_green;
        case RiskLevel::MEDIUM:   return color_yellow;
        case RiskLevel::HIGH:     return color_red;
        case RiskLevel::CRITICAL: return color_magenta;
    }
    return color_reset;
}

static const char* state_color(const std::string& state) {
    if (state == "ESTABLISHED") return color_green;
    if (state == "LISTENING")   return color_cyan;
    if (state == "TIME_WAIT")   return color_yellow;
    if (state == "CLOSE_WAIT")  return color_red;
    return color_gray;
}

static std::string truncate(const std::string& s, size_t max) {
    if (s.size() <= max) return s;
    if (max <= 3) return s.substr(0, max);
    return s.substr(0, max - 3) + "...";
}

void print_banner() {
    enable_ansi();
    printf("\n");
    printf("  %s▗▄▄▄▖▗▖   ▗▄▄▄▖▗▄▄▖ ▗▄▖ ▗▖  ▗▖▗▄▄▄▄▖%s\n", color_cyan, color_reset);
    printf("  %s  ▗▖▐▌   ▐▌   ▐▌ ▐▌▐▌ ▐▌▐▛▚▖▐▌  ▗▌  %s\n", color_cyan, color_reset);
    printf("  %s ▗▛▀▜▌▐▌   ▐▛▀▀▘▐▛▀▘▐▌ ▐▌▐▌ ▝▜▌  ▜▀  %s\n", color_cyan, color_reset);
    printf("  %s▐▌  ▐▌▐▙▄▄▖▐▙▄▄▖▐▌  ▝▚▄▞▘▐▌  ▐▌▐▄▄▄▄▖%s\n", color_cyan, color_reset);
    printf("  %s  NetSentinel v1.0%s\n", color_gray, color_reset);
    printf("  %s  Cross-platform · C++17%s\n\n", color_dim, color_reset);
}

void print_connection_table(const std::vector<Connection>& conns, bool detail) {
    enable_ansi();

    if (conns.empty()) {
        printf("  %sNo connections found.%s\n", color_yellow, color_reset);
        printf("  %sTry running as administrator/root.%s\n\n", color_dim, color_reset);
        return;
    }

    int pid_w = 7, proc_w = 20, proto_w = 6, local_w = 22, remote_w = 22, state_w = 12, risk_w = 10;

    auto print_sep = [&]() {
        int total = pid_w + proc_w + proto_w + local_w + remote_w + state_w + risk_w + 16;
        printf("  +");
        for (int i = 0; i < total; ++i) printf("-");
        printf("+\n");
    };

    print_sep();
    printf("  | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s |\n",
        pid_w, "PID",
        proc_w, "Process",
        proto_w, "Proto",
        local_w, "Local",
        remote_w, "Remote",
        state_w, "State",
        risk_w, "Risk");
    print_sep();

    int high = 0, med = 0, low = 0, crit = 0;

    for (const auto& c : conns) {
        auto risk_col = risk_color(c.risk);
        auto st_col = state_color(c.state_str);

        std::string local = c.local_ip + ":" + std::to_string(c.local_port);
        std::string remote = c.remote_ip + ":" + std::to_string(c.remote_port);

        printf("  | %s%*u%s | %-*s | %-*s | %-*s | %-*s | %s%-*s%s | %s%-*s%s |\n",
            color_gray, pid_w, c.pid, color_reset,
            proc_w, truncate(c.process_name, proc_w).c_str(),
            proto_w, protocol_str(c.protocol),
            local_w, local.c_str(),
            remote_w, remote.c_str(),
            st_col, state_w, c.state_str.c_str(), color_reset,
            risk_col, risk_w, risk_level_str(c.risk), color_reset);

        if (!c.risk_flags.empty()) {
            printf("  %-*s", pid_w + proc_w + proto_w + local_w + remote_w + state_w + risk_w + 21, "");
            for (size_t i = 0; i < c.risk_flags.size() && i < 2; ++i) {
                printf("%s[!] %s%s", color_yellow, c.risk_flags[i].c_str(),
                       i + 1 < c.risk_flags.size() ? "; " : "");
            }
            printf("%s\n", color_reset);
        }

        if (detail && (c.risk == RiskLevel::HIGH || c.risk == RiskLevel::CRITICAL)) {
            print_connection_detail(c);
        }

        switch (c.risk) {
            case RiskLevel::CRITICAL: ++crit; break;
            case RiskLevel::HIGH:     ++high; break;
            case RiskLevel::MEDIUM:   ++med;  break;
            case RiskLevel::LOW:      ++low;  break;
        }
    }

    print_sep();

    printf("  Total: %zu  ", conns.size());
    if (crit > 0) printf("%sCRITICAL: %d%s  ", color_magenta, crit, color_reset);
    if (high > 0) printf("%sHIGH: %d%s  ", color_red, high, color_reset);
    if (med > 0)  printf("%sMEDIUM: %d%s  ", color_yellow, med, color_reset);
    printf("%sLOW: %d%s\n\n", color_green, low, color_reset);
}

void print_connection_detail(const Connection& conn) {
    enable_ansi();

    auto risk_col = risk_color(conn.risk);

    printf("  %s──────────────────────────────────%s\n", color_cyan, color_reset);
    printf("  %s Connection Detail%s\n", color_bold, color_reset);
    printf("  %s──────────────────────────────────%s\n", color_cyan, color_reset);
    printf("  PID:       %u\n", conn.pid);
    printf("  Process:   %s\n", conn.process_name.c_str());
    printf("  Path:      %s\n", conn.process_path.c_str());
    printf("  Protocol:  %s\n", protocol_str(conn.protocol));
    printf("  Local:     %s:%u\n", conn.local_ip.c_str(), conn.local_port);
    printf("  Remote:    %s:%u\n", conn.remote_ip.c_str(), conn.remote_port);
    printf("  State:     %s%s%s\n", state_color(conn.state_str), conn.state_str.c_str(), color_reset);
    printf("  Risk:      %s%s%s (score: %u)\n", risk_col, risk_level_str(conn.risk), color_reset, conn.risk_score);

    if (!conn.country.empty()) {
        printf("  Country:   %s\n", conn.country.c_str());
    }
    if (!conn.publisher.empty()) {
        printf("  Publisher: %s\n", conn.publisher.c_str());
    }
    printf("  Signed:    %s\n", conn.signed_binary ? "Yes" : "No");

    if (!conn.risk_flags.empty()) {
        printf("  Flags:\n");
        for (const auto& f : conn.risk_flags) {
            printf("    %s[!]%s %s\n", color_yellow, color_reset, f.c_str());
        }
    }
    printf("  %s──────────────────────────────────%s\n\n", color_cyan, color_reset);
}

void print_help() {
    printf("Usage: netsentinel [OPTIONS]\n\n");
    printf("Options:\n");
    printf("  --export <file.json>    Export connections to JSON file\n");
    printf("  --json                  Print connections as JSON to stdout\n");
    printf("  --detail                Show detailed info for high-risk connections\n");
    printf("  --verify-sig            Enable digital signature verification\n");
    printf("  --geoip                 Enable GeoIP country lookup\n");
    printf("  --geoip-db <file>       Path to GeoIP CSV database (implies --geoip)\n");
    printf("  --watch                 Real-time monitoring mode\n");
    printf("  --watch-interval <sec>  Watch polling interval (default: 5)\n");
    printf("  --all                   Enable all features (--verify-sig --geoip --detail)\n");
    printf("  --version               Show version and platform info\n");
    printf("  --daemon                Run as daemon (Linux, requires --watch)\n");
    printf("  --pidfile <path>        PID file path (for --daemon)\n");
    printf("  --logfile <path>        Log file path (for --daemon)\n");
    printf("  --install-service <type> Print service template (systemd/runit/openrc/auto)\n");
    printf("  --help, -h              Show this help\n\n");
    printf("Without options, netsentinel scans and displays active connections.\n");
}

void print_version_info() {
    print_banner();
    printf("  %sBuild Info:%s\n", color_bold, color_reset);
#ifdef _WIN32
    printf("  Platform:   Windows\n");
    printf("  Compiler:   MinGW-w64 / MSYS2\n");
    printf("  Build:      cmake -G Ninja -DCMAKE_BUILD_TYPE=Release ..\n");
    printf("              ninja\n");
#else
    printf("  Platform:   Linux\n");

    auto read_file = [](const std::string& path) -> std::string {
        std::ifstream file(path);
        if (!file) return {};
        return std::string((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
    };

    std::string os_release = read_file("/etc/os-release");
    if (!os_release.empty()) {
        std::istringstream stream(os_release);
        std::string line;
        while (std::getline(stream, line)) {
            auto eq = line.find('=');
            if (eq != std::string::npos) {
                std::string key = line.substr(0, eq);
                std::string val = line.substr(eq + 1);
                if (!val.empty() && val.front() == '"' && val.back() == '"')
                    val = val.substr(1, val.size() - 2);
                if (key == "ID") {
                    printf("  Distro:     %s\n", val.c_str());
                } else if (key == "VERSION_ID") {
                    printf("  Version:    %s\n", val.c_str());
                }
            }
        }
    }

    printf("\n  %sBuild on Linux:%s\n", color_bold, color_reset);
    printf("  Debian/Ubuntu:\n");
    printf("    sudo apt install build-essential cmake\n");
    printf("    mkdir build && cd build\n");
    printf("    cmake .. -DCMAKE_BUILD_TYPE=Release\n");
    printf("    make -j$(nproc)\n\n");
    printf("  Fedora:\n");
    printf("    sudo dnf install gcc-c++ cmake make\n");
    printf("    mkdir build && cd build\n");
    printf("    cmake .. -DCMAKE_BUILD_TYPE=Release\n");
    printf("    make -j$(nproc)\n\n");
    printf("  Arch:\n");
    printf("    sudo pacman -S gcc cmake make\n");
    printf("    mkdir build && cd build\n");
    printf("    cmake .. -DCMAKE_BUILD_TYPE=Release\n");
    printf("    make -j$(nproc)\n\n");
    printf("  %sNote:%s Run with sudo for full process visibility.\n", color_yellow, color_reset);
#endif
    printf("\n");
}
