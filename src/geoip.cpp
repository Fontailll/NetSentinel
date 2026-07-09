#include "geoip.h"
#include "utils.h"
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>

GeoIP::GeoIP() = default;
GeoIP::~GeoIP() = default;

uint32_t GeoIP::ip_to_u32(const std::string& ip) {
    if (ip == "0.0.0.0" || ip.empty()) return 0;
    unsigned int a, b, c, d;
    if (std::sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

std::string GeoIP::lookup_private(const std::string& ip) const {
    auto n = ip_to_u32(ip);
    if (n == 0) return "Unknown";

    if ((n & 0xFF000000) == 0x0A000000) return "Private (10.x.x.x)";
    if ((n & 0xFFF00000) == 0xAC100000) return "Private (172.16-31.x.x)";
    if ((n & 0xFFFF0000) == 0xC0A80000) return "Private (192.168.x.x)";
    if (n == 0x7F000001) return "Localhost";
    if ((n & 0xFFFFFFFF) == 0xFFFFFFFF) return "Broadcast";

    return "";
}

bool GeoIP::load_csv(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    ranges_.clear();
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::vector<std::string> parts = utils::split(line, ',');
        if (parts.size() < 3) continue;

        try {
            GeoRange range;
            range.start = static_cast<uint32_t>(std::stoul(parts[0]));
            range.end = static_cast<uint32_t>(std::stoul(parts[1]));
            range.country = parts[2];
            ranges_.push_back(range);
        } catch (...) {
            continue;
        }
    }

    std::sort(ranges_.begin(), ranges_.end(),
        [](const GeoRange& a, const GeoRange& b) { return a.start < b.start; });

    loaded_ = !ranges_.empty();
    return loaded_;
}

bool GeoIP::is_loaded() const {
    return loaded_;
}

std::string GeoIP::lookup(const std::string& ip) const {
    auto priv = lookup_private(ip);
    if (!priv.empty()) return priv;

    if (!loaded_) return "Unknown";

    auto n = ip_to_u32(ip);
    if (n == 0) return "Unknown";

    auto it = std::upper_bound(ranges_.begin(), ranges_.end(), n,
        [](uint32_t val, const GeoRange& r) { return val < r.start; });

    if (it != ranges_.begin()) --it;
    if (it != ranges_.end() && n >= it->start && n <= it->end) {
        return it->country;
    }

    return "Unknown";
}
