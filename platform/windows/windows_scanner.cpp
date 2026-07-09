#include "windows_scanner.h"
#include <ws2tcpip.h>
#include <memory>
#include <cstring>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

WindowsScanner::WindowsScanner() {
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa_data_);
    wsa_initialized_ = (rc == 0);
}

WindowsScanner::~WindowsScanner() {
    if (wsa_initialized_) {
        WSACleanup();
    }
}

std::string WindowsScanner::tcp_state_to_string(DWORD state) const {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTENING";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        default:                       return "UNKNOWN";
    }
}

ConnState WindowsScanner::tcp_state_to_enum(DWORD state) const {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return ConnState::CLOSED;
        case MIB_TCP_STATE_LISTEN:     return ConnState::LISTENING;
        case MIB_TCP_STATE_SYN_SENT:   return ConnState::SYN_SENT;
        case MIB_TCP_STATE_SYN_RCVD:   return ConnState::SYN_RCVD;
        case MIB_TCP_STATE_ESTAB:      return ConnState::ESTABLISHED;
        case MIB_TCP_STATE_FIN_WAIT1:  return ConnState::FIN_WAIT1;
        case MIB_TCP_STATE_FIN_WAIT2:  return ConnState::FIN_WAIT2;
        case MIB_TCP_STATE_CLOSE_WAIT: return ConnState::CLOSE_WAIT;
        case MIB_TCP_STATE_LAST_ACK:   return ConnState::LAST_ACK;
        case MIB_TCP_STATE_TIME_WAIT:  return ConnState::TIME_WAIT;
        default:                       return ConnState::UNKNOWN;
    }
}

std::string WindowsScanner::ip_to_string(DWORD ip) const {
    struct in_addr addr;
    addr.S_un.S_addr = ip;
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

Connection WindowsScanner::tcp_row_to_connection(const MIB_TCPROW_OWNER_MODULE& row) {
    Connection conn;
    conn.pid = row.dwOwningPid;
    conn.protocol = Protocol::TCP;
    conn.local_ip = ip_to_string(row.dwLocalAddr);
    conn.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
    conn.remote_ip = ip_to_string(row.dwRemoteAddr);
    conn.remote_port = ntohs(static_cast<u_short>(row.dwRemotePort));
    conn.state = tcp_state_to_enum(row.dwState);
    conn.state_str = tcp_state_to_string(row.dwState);

    auto info = get_process_info(conn.pid);
    if (info.has_value()) {
        conn.process_name = info->name;
        conn.process_path = info->path;
        conn.signed_binary = info->signed_binary;
        conn.publisher = info->publisher;
    }

    return conn;
}

Connection WindowsScanner::udp_row_to_connection(const MIB_UDPROW_OWNER_MODULE& row) {
    Connection conn;
    conn.pid = row.dwOwningPid;
    conn.protocol = Protocol::UDP;
    conn.local_ip = "0.0.0.0";
    conn.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
    conn.remote_ip = "0.0.0.0";
    conn.remote_port = 0;
    conn.state = ConnState::ESTABLISHED;
    conn.state_str = "ACTIVE";

    auto info = get_process_info(conn.pid);
    if (info.has_value()) {
        conn.process_name = info->name;
        conn.process_path = info->path;
        conn.signed_binary = info->signed_binary;
        conn.publisher = info->publisher;
    }

    return conn;
}

std::vector<Connection> WindowsScanner::scan_tcp() {
    std::vector<Connection> result;

    ULONG size = 0;
    DWORD rc = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                                    TCP_TABLE_OWNER_MODULE_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return result;
    }

    auto buf = std::make_unique<char[]>(size);
    auto table = reinterpret_cast<MIB_TCPTABLE_OWNER_MODULE*>(buf.get());

    rc = GetExtendedTcpTable(table, &size, FALSE, AF_INET,
                              TCP_TABLE_OWNER_MODULE_ALL, 0);
    if (rc != NO_ERROR) {
        return result;
    }

    result.reserve(table->dwNumEntries);
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        result.push_back(tcp_row_to_connection(table->table[i]));
    }

    return result;
}

std::vector<Connection> WindowsScanner::scan_udp() {
    std::vector<Connection> result;

    ULONG size = 0;
    DWORD rc = GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET,
                                    UDP_TABLE_OWNER_MODULE, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return result;
    }

    auto buf = std::make_unique<char[]>(size);
    auto table = reinterpret_cast<MIB_UDPTABLE_OWNER_MODULE*>(buf.get());

    rc = GetExtendedUdpTable(table, &size, FALSE, AF_INET,
                              UDP_TABLE_OWNER_MODULE, 0);
    if (rc != NO_ERROR) {
        return result;
    }

    result.reserve(table->dwNumEntries);
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        result.push_back(udp_row_to_connection(table->table[i]));
    }

    return result;
}
