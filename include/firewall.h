#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

class IFirewall {
public:
    virtual ~IFirewall() = default;
    virtual bool block_ip(const std::string& ip) = 0;
    virtual bool unblock_ip(const std::string& ip) = 0;
    virtual bool block_port(uint16_t port) = 0;
    virtual bool list_rules(std::vector<std::string>& rules) = 0;
};

std::unique_ptr<IFirewall> create_firewall();
