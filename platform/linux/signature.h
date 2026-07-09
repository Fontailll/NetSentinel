#pragma once

#include <string>
#include <cstdint>
#include <optional>

struct SignatureInfo {
    bool signed_binary = false;
    std::string publisher;
    std::string product;
    std::string description;
};

std::optional<SignatureInfo> verify_signature(const std::string& path);
