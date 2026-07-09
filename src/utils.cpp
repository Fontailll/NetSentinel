#include "utils.h"
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <chrono>
#include <ctime>

namespace utils {

std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::istringstream iss(s);
    std::string token;
    while (std::getline(iss, token, delim)) {
        if (!token.empty())
            parts.push_back(token);
    }
    return parts;
}

uint32_t hex_to_u32(const std::string& hex) {
    uint32_t val = 0;
    std::istringstream iss(hex);
    iss >> std::hex >> val;
    return val;
}

std::string timestamp() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), ::tolower);
    return out;
}

bool iequals(const std::string& a, const std::string& b) {
    return lower(a) == lower(b);
}

} // namespace utils
