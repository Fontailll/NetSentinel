#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace utils {

std::string trim(const std::string& s);
std::vector<std::string> split(const std::string& s, char delim);
uint32_t hex_to_u32(const std::string& hex);
std::string timestamp();
std::string lower(const std::string& s);
bool iequals(const std::string& a, const std::string& b);

} // namespace utils
