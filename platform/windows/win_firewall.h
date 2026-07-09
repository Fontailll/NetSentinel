#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "../../include/firewall.h"

class WindowsFirewall : public IFirewall {
public:
    WindowsFirewall();
    ~WindowsFirewall() override;

    bool block_ip(const std::string& ip) override;
    bool unblock_ip(const std::string& ip) override;
    bool block_port(uint16_t port) override;
    bool list_rules(std::vector<std::string>& rules) override;

private:
    bool initialized_ = false;

    bool initialize();
};
