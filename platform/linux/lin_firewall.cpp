#include "lin_firewall.h"
#include <cstdio>
#include <memory>
#include <array>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>

static bool exec_pipe(const std::string& cmd) {
    FILE* pipe = popen((cmd + " 2>/dev/null").c_str(), "r");
    if (!pipe) return false;
    int rc = pclose(pipe);
    return rc == 0;
}

static std::string exec_output(const std::string& cmd) {
    std::array<char, 4096> buffer;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return {};
    std::string result;
    while (fgets(buffer.data(), buffer.size(), pipe)) {
        result += buffer.data();
    }
    pclose(pipe);
    return result;
}

bool LinuxFirewall::has_iptables() const {
    return exec_pipe("which iptables 2>/dev/null");
}

bool LinuxFirewall::has_nftables() const {
    return exec_pipe("which nft 2>/dev/null");
}

static bool ensure_nft_chain() {
    exec_pipe("nft add table inet netsentinel 2>/dev/null");
    exec_pipe("nft add chain inet netsentinel input { type filter hook input priority 0 \\; } 2>/dev/null");
    exec_pipe("nft add chain inet netsentinel output { type filter hook output priority 0 \\; } 2>/dev/null");
    return true;
}

static bool ensure_ipt_chain() {
    exec_pipe("iptables -N NETSENTINEL 2>/dev/null");
    exec_pipe("iptables -A INPUT -j NETSENTINEL 2>/dev/null");
    exec_pipe("iptables -A OUTPUT -j NETSENTINEL 2>/dev/null");
    return true;
}

bool LinuxFirewall::block_ip(const std::string& ip) {
    if (has_nftables()) {
        ensure_nft_chain();
        std::string in_rule = "nft add rule inet netsentinel input ip saddr " + ip + " drop";
        std::string out_rule = "nft add rule inet netsentinel output ip daddr " + ip + " drop";
        return exec_pipe(in_rule) && exec_pipe(out_rule);
    }

    if (has_iptables()) {
        ensure_ipt_chain();
        return exec_pipe("iptables -A NETSENTINEL -s " + ip + " -j DROP") &&
               exec_pipe("iptables -A NETSENTINEL -d " + ip + " -j DROP");
    }

    return false;
}

bool LinuxFirewall::unblock_ip(const std::string& ip) {
    if (has_nftables()) {
        std::string output = exec_output("nft -a list chain inet netsentinel input 2>/dev/null");
        std::istringstream stream(output);
        std::string line;
        while (std::getline(stream, line)) {
            if (line.find(ip) != std::string::npos) {
                auto pos = line.find("handle ");
                if (pos != std::string::npos) {
                    std::string handle = line.substr(pos + 7);
                    handle = handle.substr(0, handle.find_first_not_of("0123456789") == std::string::npos ?
                        handle.length() : handle.find_first_not_of("0123456789"));
                    exec_pipe("nft delete rule inet netsentinel input handle " + handle);
                }
            }
        }
        output = exec_output("nft -a list chain inet netsentinel output 2>/dev/null");
        stream = std::istringstream(output);
        while (std::getline(stream, line)) {
            if (line.find(ip) != std::string::npos) {
                auto pos = line.find("handle ");
                if (pos != std::string::npos) {
                    std::string handle = line.substr(pos + 7);
                    handle = handle.substr(0, handle.find_first_not_of("0123456789") == std::string::npos ?
                        handle.length() : handle.find_first_not_of("0123456789"));
                    exec_pipe("nft delete rule inet netsentinel output handle " + handle);
                }
            }
        }
        return true;
    }

    if (has_iptables()) {
        exec_pipe("iptables -D NETSENTINEL -s " + ip + " -j DROP");
        exec_pipe("iptables -D NETSENTINEL -d " + ip + " -j DROP");
        return true;
    }

    return false;
}

bool LinuxFirewall::block_port(uint16_t port) {
    std::string port_str = std::to_string(port);

    if (has_nftables()) {
        ensure_nft_chain();
        return exec_pipe("nft add rule inet netsentinel input tcp dport " + port_str + " drop");
    }

    if (has_iptables()) {
        ensure_ipt_chain();
        return exec_pipe("iptables -A NETSENTINEL -p tcp --dport " + port_str + " -j DROP");
    }

    return false;
}

bool LinuxFirewall::list_rules(std::vector<std::string>& rules) {
    if (has_nftables()) {
        std::string output = exec_output("nft list table inet netsentinel 2>/dev/null");
        std::istringstream stream(output);
        std::string line;
        while (std::getline(stream, line)) {
            if (!line.empty()) rules.push_back(line);
        }
        return !rules.empty();
    }

    if (has_iptables()) {
        std::string output = exec_output("iptables -L NETSENTINEL -n 2>/dev/null");
        std::istringstream stream(output);
        std::string line;
        while (std::getline(stream, line)) {
            if (!line.empty()) rules.push_back(line);
        }
        return !rules.empty();
    }

    return false;
}
