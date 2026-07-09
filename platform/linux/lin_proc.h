#pragma once

#include <optional>
#include <cstdint>
#include "../../include/process.h"

std::optional<ProcessInfo> get_process_info(uint32_t pid);
