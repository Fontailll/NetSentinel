#pragma once

#include "connection.h"
#include <vector>
#include <string>
#include <functional>

struct RiskRule {
    std::string name;
    uint32_t score;
    bool enabled = true;
    std::function<uint32_t(const Connection&)> evaluate;
};

class RiskEngine {
public:
    RiskEngine();
    void assess(Connection& conn) const;
    void add_rule(RiskRule rule);
    void enable_rule(const std::string& name);
    void disable_rule(const std::string& name);
    void enable_all();
    void disable_all();
    void set_verify_signatures(bool v);
    void set_geoip(bool v);

private:
    std::vector<RiskRule> rules_;
    bool verify_signatures_ = false;
    bool geoip_enabled_ = false;
};
