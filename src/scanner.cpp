#include "scanner.h"

#ifdef _WIN32
#include "windows_scanner.h"
#else
#include "linux_scanner.h"
#endif

std::vector<Connection> IScanner::scan() {
    auto tcp = scan_tcp();
    auto udp = scan_udp();
    std::vector<Connection> all;
    all.reserve(tcp.size() + udp.size());
    all.insert(all.end(), tcp.begin(), tcp.end());
    all.insert(all.end(), udp.begin(), udp.end());
    return all;
}

std::unique_ptr<IScanner> create_scanner() {
#ifdef _WIN32
    return std::make_unique<WindowsScanner>();
#else
    return std::make_unique<LinuxScanner>();
#endif
}
