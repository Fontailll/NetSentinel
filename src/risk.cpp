#include "risk.h"
#include "utils.h"
#include <algorithm>

RiskEngine::RiskEngine() {
    rules_ = {
        {"Unsigned executable", 30, true,
            [this](const Connection& c) -> uint32_t {
                if (!verify_signatures_) return 0;
                if (c.process_path.empty()) return 0;
                if (!c.signed_binary) return 30;
                return 0;
            }
        },

        {"Executable inside Temp folder", 25, true,
            [](const Connection& c) -> uint32_t {
                auto path = utils::lower(c.process_path);
                if (path.find("\\temp\\") != std::string::npos ||
                    path.find("/tmp/") != std::string::npos ||
                    path.find("/temp/") != std::string::npos) {
                    return 25;
                }

                if (path.find("\\appdata\\local\\temp\\") != std::string::npos ||
                    path.find("\\windows\\temp\\") != std::string::npos) {
                    return 25;
                }
                return 0;
            }
        },

        {"Known malware port", 20, true,
            [](const Connection& c) -> uint32_t {
                static const uint16_t bad_ports[] = {
                    4444, 4445, 4446, 5555, 6666, 6667, 6668, 6669,
                    1337, 31337, 12345, 12346, 54321, 61777, 61778,
                    8808, 1604, 4782, 50050, 3333, 14444, 53, 7443
                };
                for (auto p : bad_ports) {
                    if (c.remote_port == p) return 20;
                }
                return 0;
            }
        },

        {"Unknown publisher", 15, true,
            [this](const Connection& c) -> uint32_t {
                if (!verify_signatures_) return 0;
                if (c.process_path.empty()) return 0;
                if (c.signed_binary && c.publisher.empty()) return 15;
                return 0;
            }
        },

        {"Suspicious process name", 15, true,
            [](const Connection& c) -> uint32_t {
                auto name = utils::lower(c.process_name);
                static const char* sus_names[] = {
                    "powershell", "cmd", "rundll32", "regsvr32", "mshta",
                    "wscript", "cscript", "certutil", "bitsadmin",
                    "schtasks", "nslookup", "vssadmin", "bcedit",
                    "wevtutil", "wmic", "curl", "wget"
                };
                for (auto sn : sus_names) {
                    if (name.find(sn) != std::string::npos) return 15;
                }
                return 0;
            }
        },

        {"Hidden process", 10, true,
            [](const Connection& c) -> uint32_t {
                if (c.process_name.empty() && c.pid > 0 && c.pid != 4) return 10;
                return 0;
            }
        },

        {"Listening service on unusual port", 10, true,
            [](const Connection& c) -> uint32_t {
                if (c.state == ConnState::LISTENING) {
                    if (c.local_port < 1024 && c.local_port != 80 &&
                        c.local_port != 443 && c.local_port != 22 &&
                        c.local_port != 21 && c.local_port != 25 &&
                        c.local_port != 53 && c.local_port != 110 &&
                        c.local_port != 143 && c.local_port != 587 &&
                        c.local_port != 993 && c.local_port != 995 &&
                        c.local_port != 3306 && c.local_port != 5432 &&
                        c.local_port != 3389 && c.local_port != 8080) {
                        return 10;
                    }
                }
                return 0;
            }
        },

        {"GeoIP foreign connection", 5, true,
            [this](const Connection& c) -> uint32_t {
                if (!geoip_enabled_) return 0;
                if (c.country.empty() || c.country == "Unknown") return 0;
                if (c.country.find("Private") != std::string::npos ||
                    c.country == "Localhost") return 0;
                return 5;
            }
        },
    };
}

void RiskEngine::assess(Connection& conn) const {
    uint32_t total = 0;
    conn.risk_flags.clear();

    for (const auto& rule : rules_) {
        if (!rule.enabled) continue;
        uint32_t score = rule.evaluate(conn);
        if (score > 0) {
            total += score;
            conn.risk_flags.push_back(rule.name + " (+" + std::to_string(score) + ")");
        }
    }

    conn.risk_score = total;

    if (total >= 80)
        conn.risk = RiskLevel::CRITICAL;
    else if (total >= 60)
        conn.risk = RiskLevel::HIGH;
    else if (total >= 30)
        conn.risk = RiskLevel::MEDIUM;
    else
        conn.risk = RiskLevel::LOW;
}

void RiskEngine::add_rule(RiskRule rule) {
    rules_.push_back(std::move(rule));
}

void RiskEngine::enable_rule(const std::string& name) {
    for (auto& r : rules_) {
        if (r.name == name) { r.enabled = true; return; }
    }
}

void RiskEngine::disable_rule(const std::string& name) {
    for (auto& r : rules_) {
        if (r.name == name) { r.enabled = false; return; }
    }
}

void RiskEngine::enable_all() {
    for (auto& r : rules_) r.enabled = true;
}

void RiskEngine::disable_all() {
    for (auto& r : rules_) r.enabled = false;
}

void RiskEngine::set_verify_signatures(bool v) {
    verify_signatures_ = v;
}

void RiskEngine::set_geoip(bool v) {
    geoip_enabled_ = v;
}
