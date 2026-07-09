#pragma once

#include <string>
#include <vector>
#include <cstdint>

class GeoIP {
public:
    GeoIP();
    ~GeoIP();

    bool load_csv(const std::string& path);
    std::string lookup(const std::string& ip) const;
    bool is_loaded() const;

private:
    struct GeoRange {
        uint32_t start;
        uint32_t end;
        std::string country;
    };

    static uint32_t ip_to_u32(const std::string& ip);
    std::string lookup_private(const std::string& ip) const;

    std::vector<GeoRange> ranges_;
    bool loaded_ = false;
};
