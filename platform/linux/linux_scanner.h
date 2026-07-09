#pragma once

#include "scanner.h"
#include "../../include/process.h"
#include <string>
#include <vector>
#include <unordered_map>

class LinuxScanner : public IScanner {
public:
    LinuxScanner() = default;
    ~LinuxScanner() override = default;

    std::vector<Connection> scan_tcp() override;
    std::vector<Connection> scan_udp() override;

private:
    std::unordered_map<uint64_t, uint32_t> build_inode_map();
    void parse_conn_line(Connection& conn, const std::string& line,
                         const std::unordered_map<uint64_t, uint32_t>& inode_map,
                         bool is_ipv6);
    std::string ip_hex_to_string(const std::string& hex) const;
    std::string ipv6_hex_to_string(const std::string& hex) const;
    uint16_t port_hex_to_uint16(const std::string& hex) const;
    std::string tcp_state_to_string(uint8_t state) const;
    ConnState tcp_state_to_enum(uint8_t state) const;
};
