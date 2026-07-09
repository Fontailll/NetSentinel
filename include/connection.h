#pragma once

#include <cstdint>
#include <string>
#include <vector>

enum class Protocol : uint8_t { TCP, UDP };

enum class ConnState : uint8_t {
    LISTENING,
    ESTABLISHED,
    SYN_SENT,
    SYN_RCVD,
    FIN_WAIT1,
    FIN_WAIT2,
    TIME_WAIT,
    CLOSE_WAIT,
    LAST_ACK,
    CLOSED,
    UNKNOWN
};

enum class RiskLevel : uint8_t {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct Connection {
    uint32_t pid = 0;
    std::string process_name;
    std::string process_path;
    std::string local_ip;
    uint16_t local_port = 0;
    std::string remote_ip;
    uint16_t remote_port = 0;
    Protocol protocol = Protocol::TCP;
    ConnState state = ConnState::UNKNOWN;
    std::string state_str;
    RiskLevel risk = RiskLevel::LOW;
    uint32_t risk_score = 0;
    std::vector<std::string> risk_flags;
    bool signed_binary = false;
    std::string publisher;
    std::string country;
};

inline const char* risk_level_str(RiskLevel r) {
    switch (r) {
        case RiskLevel::LOW:      return "LOW";
        case RiskLevel::MEDIUM:   return "MEDIUM";
        case RiskLevel::HIGH:     return "HIGH";
        case RiskLevel::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

inline const char* protocol_str(Protocol p) {
    return p == Protocol::TCP ? "TCP" : "UDP";
}
