#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "../../include/firewall.h"

class LinuxFirewall : public IFirewall {
public:
    LinuxFirewall() = default;
    ~LinuxFirewall() override = default;

    bool block_ip(const std::string& ip) override;
    bool unblock_ip(const std::string& ip) override;
    bool block_port(uint16_t port) override;
    bool list_rules(std::vector<std::string>& rules) override;

private:
    bool has_iptables() const;
    bool has_nftables() const;
    bool exec_iptables(const std::string& args) const;
    bool exec_nft(const std::string& args) const;
};
