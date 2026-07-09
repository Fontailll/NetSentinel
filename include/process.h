#pragma once

#include <string>
#include <cstdint>
#include <optional>

struct ProcessInfo {
    uint32_t pid = 0;
    std::string name;
    std::string path;
    std::string publisher;
    bool signed_binary = false;
};

std::optional<ProcessInfo> get_process_info(uint32_t pid);
