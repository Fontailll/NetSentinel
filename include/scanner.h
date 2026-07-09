#pragma once

#include "connection.h"
#include <vector>
#include <memory>
#include <functional>

class IScanner {
public:
    virtual ~IScanner() = default;
    virtual std::vector<Connection> scan_tcp() = 0;
    virtual std::vector<Connection> scan_udp() = 0;

    std::vector<Connection> scan();
};

std::unique_ptr<IScanner> create_scanner();
