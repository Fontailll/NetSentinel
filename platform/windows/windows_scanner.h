#pragma once

#include "scanner.h"
#include "../../include/process.h"
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <vector>
#include <string>

class WindowsScanner : public IScanner {
public:
    WindowsScanner();
    ~WindowsScanner() override;

    std::vector<Connection> scan_tcp() override;
    std::vector<Connection> scan_udp() override;

private:
    WSADATA wsa_data_;
    bool wsa_initialized_ = false;

    Connection tcp_row_to_connection(const MIB_TCPROW_OWNER_MODULE& row);
    Connection udp_row_to_connection(const MIB_UDPROW_OWNER_MODULE& row);
    std::string ip_to_string(DWORD ip) const;
    std::string tcp_state_to_string(DWORD state) const;
    ConnState tcp_state_to_enum(DWORD state) const;
};
