#include "linux_scanner.h"
#include "utils.h"
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <arpa/inet.h>

static std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) return {};
    return std::string((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
}

static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

std::string LinuxScanner::ip_hex_to_string(const std::string& hex) const {
    if (hex.length() < 8) return "0.0.0.0";
    unsigned char bytes[4];
    for (int i = 0; i < 4; ++i) {
        int idx = i * 2;
        bytes[i] = static_cast<unsigned char>(
            (hex_char_to_int(hex[idx]) << 4) | hex_char_to_int(hex[idx + 1]));
    }
    char buf[INET_ADDRSTRLEN];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
    return buf;
}

std::string LinuxScanner::ipv6_hex_to_string(const std::string& hex) const {
    if (hex.length() < 32) return "::";
    unsigned char bytes[16];
    for (int i = 0; i < 16; ++i) {
        int idx = i * 2;
        bytes[i] = static_cast<unsigned char>(
            (hex_char_to_int(hex[idx]) << 4) | hex_char_to_int(hex[idx + 1]));
    }
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, bytes, buf, sizeof(buf));
    return buf;
}

uint16_t LinuxScanner::port_hex_to_uint16(const std::string& hex) const {
    if (hex.length() < 4) return 0;
    return static_cast<uint16_t>(
        (hex_char_to_int(hex[0]) << 12) |
        (hex_char_to_int(hex[1]) << 8) |
        (hex_char_to_int(hex[2]) << 4) |
        hex_char_to_int(hex[3]));
}

std::string LinuxScanner::tcp_state_to_string(uint8_t state) const {
    static const char* states[] = {
        "UNKNOWN", "ESTABLISHED", "SYN_SENT", "SYN_RCVD",
        "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE_WAIT",
        "LAST_ACK", "LISTENING", "CLOSING"
    };
    if (state <= 10) return states[state];
    return "UNKNOWN";
}

ConnState LinuxScanner::tcp_state_to_enum(uint8_t state) const {
    switch (state) {
        case 1:  return ConnState::ESTABLISHED;
        case 2:  return ConnState::SYN_SENT;
        case 3:  return ConnState::SYN_RCVD;
        case 4:  return ConnState::FIN_WAIT1;
        case 5:  return ConnState::FIN_WAIT2;
        case 6:  return ConnState::TIME_WAIT;
        case 7:  return ConnState::CLOSE_WAIT;
        case 8:  return ConnState::LAST_ACK;
        case 9:  return ConnState::LISTENING;
        case 10: return ConnState::CLOSED;
        default: return ConnState::UNKNOWN;
    }
}

std::unordered_map<uint64_t, uint32_t> LinuxScanner::build_inode_map() {
    std::unordered_map<uint64_t, uint32_t> map;

    DIR* proc = opendir("/proc");
    if (!proc) return map;

    struct dirent* entry;
    while ((entry = readdir(proc)) != nullptr) {
        uint32_t pid = 0;
        for (const char* p = entry->d_name; *p; ++p) {
            if (*p < '0' || *p > '9') { pid = 0; break; }
            pid = pid * 10 + (*p - '0');
        }
        if (pid == 0) continue;

        std::string fd_dir = "/proc/" + std::to_string(pid) + "/fd";
        DIR* fd = opendir(fd_dir.c_str());
        if (!fd) continue;

        struct dirent* fd_entry;
        while ((fd_entry = readdir(fd)) != nullptr) {
            std::string link_path = fd_dir + "/" + fd_entry->d_name;
            char link_target[256] = {};
            ssize_t len = readlink(link_path.c_str(), link_target, sizeof(link_target) - 1);
            if (len > 0) {
                link_target[len] = '\0';
                std::string target(link_target);
                auto pos = target.find("socket:");
                if (pos != std::string::npos) {
                    auto inode_str = target.substr(pos + 7);
                    inode_str = utils::trim(inode_str);
                    if (!inode_str.empty() && inode_str.front() == '[') {
                        inode_str = inode_str.substr(1);
                    }
                    if (!inode_str.empty() && inode_str.back() == ']') {
                        inode_str.pop_back();
                    }
                    inode_str = utils::trim(inode_str);
                    try {
                        uint64_t inode = std::stoull(inode_str);
                        map[inode] = pid;
                    } catch (...) {}
                }
            }
        }
        closedir(fd);
    }
    closedir(proc);
    return map;
}

void LinuxScanner::parse_conn_line(
    Connection& conn,
    const std::string& line,
    const std::unordered_map<uint64_t, uint32_t>& inode_map,
    bool is_ipv6)
{
    auto parts = utils::split(line, ' ');
    if (parts.size() < 10) return;

    auto addr_parts = utils::split(parts[1], ':');
    auto rem_parts = utils::split(parts[2], ':');

    if (addr_parts.size() >= (is_ipv6 ? 4u : 2u)) {
        if (is_ipv6) {
            conn.local_ip = ipv6_hex_to_string(addr_parts[0] + addr_parts[1] +
                                                addr_parts[2] + addr_parts[3]);
            conn.local_port = port_hex_to_uint16(addr_parts[4]);
        } else {
            conn.local_ip = ip_hex_to_string(addr_parts[0]);
            conn.local_port = port_hex_to_uint16(addr_parts[1]);
        }
    }
    if (rem_parts.size() >= (is_ipv6 ? 4u : 2u)) {
        if (is_ipv6) {
            conn.remote_ip = ipv6_hex_to_string(rem_parts[0] + rem_parts[1] +
                                                 rem_parts[2] + rem_parts[3]);
            conn.remote_port = port_hex_to_uint16(rem_parts[4]);
        } else {
            conn.remote_ip = ip_hex_to_string(rem_parts[0]);
            conn.remote_port = port_hex_to_uint16(rem_parts[1]);
        }
    }

    if (conn.protocol == Protocol::TCP) {
        uint8_t state = 0;
        try { state = static_cast<uint8_t>(std::stoul(parts[3])); } catch (...) {}
        conn.state = tcp_state_to_enum(state);
        conn.state_str = tcp_state_to_string(state);
    }

    uint64_t inode = 0;
    try { inode = std::stoull(parts[9]); } catch (...) {}

    if (inode > 0) {
        auto it = inode_map.find(inode);
        if (it != inode_map.end()) {
            conn.pid = it->second;
            auto info = get_process_info(conn.pid);
            if (info.has_value()) {
                conn.process_name = info->name;
                conn.process_path = info->path;
                conn.signed_binary = info->signed_binary;
                conn.publisher = info->publisher;
            }
        }
    }
}

std::vector<Connection> LinuxScanner::scan_tcp() {
    std::vector<Connection> result;
    auto inode_map = build_inode_map();

    auto parse_file = [&](const std::string& path, bool ipv6) {
        auto content = read_file(path);
        if (content.empty()) return;
        std::istringstream stream(content);
        std::string line;
        std::getline(stream, line);
        while (std::getline(stream, line)) {
            line = utils::trim(line);
            if (line.empty()) continue;
            Connection conn;
            conn.protocol = Protocol::TCP;
            parse_conn_line(conn, line, inode_map, ipv6);
            result.push_back(std::move(conn));
        }
    };

    parse_file("/proc/net/tcp", false);
    parse_file("/proc/net/tcp6", true);
    return result;
}

std::vector<Connection> LinuxScanner::scan_udp() {
    std::vector<Connection> result;
    auto inode_map = build_inode_map();

    auto parse_file = [&](const std::string& path, bool ipv6) {
        auto content = read_file(path);
        if (content.empty()) return;
        std::istringstream stream(content);
        std::string line;
        std::getline(stream, line);
        while (std::getline(stream, line)) {
            line = utils::trim(line);
            if (line.empty()) continue;
            Connection conn;
            conn.protocol = Protocol::UDP;
            conn.state = ConnState::ESTABLISHED;
            conn.state_str = "ACTIVE";
            parse_conn_line(conn, line, inode_map, ipv6);
            result.push_back(std::move(conn));
        }
    };

    parse_file("/proc/net/udp", false);
    parse_file("/proc/net/udp6", true);
    return result;
}
