#include "scanner.h"
#include "risk.h"
#include "output.h"
#include "json_export.h"
#include "geoip.h"
#include "daemon.h"
#include "utils.h"
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include <thread>
#include <chrono>
#include <map>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

struct Args {
    bool help = false;
    bool version = false;
    bool json_stdout = false;
    bool detail = false;
    bool verify_sig = false;
    bool geoip = false;
    bool watch = false;
    bool all = false;
    bool daemon = false;
    bool install_service = false;
    int watch_interval = 5;
    std::string export_path;
    std::string geoip_db;
    std::string pidfile_path;
    std::string logfile_path;
    std::string service_type;
};

static Args parse_args(int argc, char* argv[]) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            args.help = true;
        } else if (arg == "--json") {
            args.json_stdout = true;
        } else if (arg == "--detail") {
            args.detail = true;
        } else if (arg == "--verify-sig") {
            args.verify_sig = true;
        } else if (arg == "--geoip") {
            args.geoip = true;
        } else if (arg == "--geoip-db" && i + 1 < argc) {
            args.geoip = true;
            args.geoip_db = argv[++i];
        } else if (arg == "--watch") {
            args.watch = true;
        } else if (arg == "--watch-interval" && i + 1 < argc) {
            args.watch = true;
            args.watch_interval = std::atoi(argv[++i]);
            if (args.watch_interval < 1) args.watch_interval = 1;
        } else if (arg == "--all") {
            args.all = true;
            args.verify_sig = true;
            args.geoip = true;
            args.detail = true;
        } else if (arg == "--version" || arg == "-V") {
            args.version = true;
        } else if (arg == "--daemon") {
            args.daemon = true;
        } else if (arg == "--pidfile" && i + 1 < argc) {
            args.pidfile_path = argv[++i];
        } else if (arg == "--logfile" && i + 1 < argc) {
            args.logfile_path = argv[++i];
        } else if (arg == "--install-service" && i + 1 < argc) {
            args.install_service = true;
            args.service_type = argv[++i];
        } else if (arg == "--export" && i + 1 < argc) {
            args.export_path = argv[++i];
        }
    }
    return args;
}

#ifdef _WIN32
static bool is_elevated() {
    BOOL elevated = FALSE;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION te;
        DWORD size = sizeof(te);
        if (GetTokenInformation(hToken, TokenElevation, &te, size, &size)) {
            elevated = te.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return elevated == TRUE;
}
#endif

static bool operator<(const Connection& a, const Connection& b) {
    if (a.pid != b.pid) return a.pid < b.pid;
    if (a.protocol != b.protocol) return a.protocol < b.protocol;
    if (a.local_ip != b.local_ip) return a.local_ip < b.local_ip;
    if (a.local_port != b.local_port) return a.local_port < b.local_port;
    if (a.remote_ip != b.remote_ip) return a.remote_ip < b.remote_ip;
    return a.remote_port < b.remote_port;
}

using ConnMap = std::map<Connection, bool>;

static ConnMap to_map(const std::vector<Connection>& conns) {
    ConnMap m;
    for (const auto& c : conns) m[c] = true;
    return m;
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    Args args = parse_args(argc, argv);

    if (args.help) {
        print_banner();
        print_help();
        return 0;
    }

    if (args.version) {
        print_version_info();
#ifdef _WIN32
        printf("  Press Enter to exit...\n");
        getchar();
#endif
        return 0;
    }

    if (args.install_service) {
        print_banner();
        if (args.service_type == "auto") {
            std::string detected;
            if (detect_init_system(detected)) {
                printf("  Detected init system: %s\n\n", detected.c_str());
                print_service_template(detected);
            } else {
                printf("  Could not detect init system.\n");
                print_service_templates();
            }
        } else if (!print_service_template(args.service_type)) {
            fprintf(stderr, "Unknown service type: %s\n", args.service_type.c_str());
            print_service_templates();
            return 1;
        }
        return 0;
    }

    auto scanner = create_scanner();
    RiskEngine risk_engine;
    std::unique_ptr<GeoIP> geoip;

    if (args.geoip) {
        geoip = std::make_unique<GeoIP>();
        if (!args.geoip_db.empty()) {
            if (!geoip->load_csv(args.geoip_db)) {
                fprintf(stderr, "Warning: Could not load GeoIP database: %s\n", args.geoip_db.c_str());
            }
        }
    }

    if (args.verify_sig) risk_engine.set_verify_signatures(true);
    if (args.geoip) risk_engine.set_geoip(true);

    auto run_scan = [&]() -> std::vector<Connection> {
        auto connections = scanner->scan();

        if (geoip) {
            for (auto& conn : connections) {
                conn.country = geoip->lookup(conn.remote_ip);
            }
        }

        for (auto& conn : connections) {
            risk_engine.assess(conn);
        }

        std::sort(connections.begin(), connections.end(),
            [](const Connection& a, const Connection& b) {
                if (a.risk != b.risk) return a.risk > b.risk;
                return a.risk_score > b.risk_score;
            });

        return connections;
    };

    if (args.json_stdout) {
        auto connections = run_scan();
        export_json_stdout(connections);
        return 0;
    }

    if (!args.export_path.empty()) {
        auto connections = run_scan();
        bool ok = export_json(args.export_path, connections);
        if (ok) {
            printf("Exported %zu connections to %s\n",
                   connections.size(), args.export_path.c_str());
        } else {
            fprintf(stderr, "Failed to export to %s\n", args.export_path.c_str());
            return 1;
        }
        return 0;
    }

    print_banner();

#ifdef _WIN32
    if (!is_elevated()) {
        printf("  %s⚠ WARNING:%s Not running as administrator.\n",
               "\033[93m", "\033[0m");
        printf("  %s  Some connections may not be visible.%s\n\n",
               "\033[90m", "\033[0m");
    }
#endif

    if (args.daemon) {
#ifndef _WIN32
        if (!args.watch) {
            fprintf(stderr, "  --daemon requires --watch mode.\n");
            return 1;
        }
        if (daemonize(args.logfile_path, args.pidfile_path)) {
            printf("  Daemon started (PID: %d)\n", getpid());
        } else {
            fprintf(stderr, "  Failed to daemonize.\n");
            return 1;
        }
#else
        fprintf(stderr, "  --daemon is not supported on Windows.\n");
        return 1;
#endif
    }

    if (args.watch) {
        printf("  %sWatch mode enabled (interval: %ds). Press Ctrl+C to stop.%s\n\n",
               "\033[90m", args.watch_interval, "\033[0m");

        auto prev = run_scan();
        print_connection_table(prev, args.detail);

        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(args.watch_interval));

            auto curr = run_scan();
            auto prev_map = to_map(prev);
            auto curr_map = to_map(curr);

            std::vector<Connection> new_conns, gone_conns;

            for (const auto& c : curr) {
                if (!prev_map.count(c)) new_conns.push_back(c);
            }
            for (const auto& c : prev) {
                if (!curr_map.count(c)) gone_conns.push_back(c);
            }

            if (new_conns.empty() && gone_conns.empty()) {
                printf("  %s[%s] No changes.%s\n",
                       "\033[90m", utils::timestamp().c_str(), "\033[0m");
                continue;
            }

            printf("\n  %s[%s] Change detected:%s\n",
                   "\033[93m", utils::timestamp().c_str(), "\033[0m");

            if (!new_conns.empty()) {
                printf("  %sNew connections (%zu):%s\n",
                       "\033[92m", new_conns.size(), "\033[0m");
                print_connection_table(new_conns, args.detail);
            }

            if (!gone_conns.empty()) {
                printf("  %sDisappeared connections (%zu):%s\n",
                       "\033[91m", gone_conns.size(), "\033[0m");
                print_connection_table(gone_conns, args.detail);
            }

            prev = std::move(curr);
        }
    } else {
        auto connections = run_scan();
        print_connection_table(connections, args.detail);

#ifdef _WIN32
        printf("  Press Enter to exit...\n");
        getchar();
#endif
    }

    return 0;
}
