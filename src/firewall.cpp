#include "firewall.h"

#ifdef _WIN32
#include "win_firewall.h"
#else
#include "lin_firewall.h"
#endif

std::unique_ptr<IFirewall> create_firewall() {
#ifdef _WIN32
    return std::make_unique<WindowsFirewall>();
#else
    return std::make_unique<LinuxFirewall>();
#endif
}
