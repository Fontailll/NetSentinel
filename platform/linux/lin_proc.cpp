#include "lin_proc.h"
#include "signature.h"
#include "../../include/utils.h"
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <string>
#include <vector>

static std::string read_file_line(const std::string& path) {
    std::ifstream file(path);
    if (!file) return {};
    std::string line;
    std::getline(file, line);
    return line;
}

std::optional<ProcessInfo> get_process_info(uint32_t pid) {
    ProcessInfo info;
    info.pid = pid;

    std::string proc_dir = "/proc/" + std::to_string(pid);

    info.name = read_file_line(proc_dir + "/comm");
    info.name = utils::trim(info.name);

    std::string cmdline;
    {
        std::ifstream file(proc_dir + "/cmdline");
        if (file) {
            std::vector<char> buf(4096, 0);
            file.read(buf.data(), buf.size() - 1);
            cmdline = buf.data();
            for (size_t i = 0; i < cmdline.size(); ++i) {
                if (cmdline[i] == '\0') cmdline[i] = ' ';
            }
        }
    }

    if (!cmdline.empty()) {
        auto parts = utils::split(cmdline, ' ');
        if (!parts.empty()) {
            info.path = parts[0];
        }
    }

    if (info.path.empty()) {
        char link[4096] = {};
        ssize_t len = readlink((proc_dir + "/exe").c_str(), link, sizeof(link) - 1);
        if (len > 0) {
            link[len] = '\0';
            info.path = link;
        }
    }

    if (!info.path.empty()) {
        auto sig = verify_signature(info.path);
        if (sig.has_value()) {
            info.signed_binary = sig->signed_binary;
            info.publisher = sig->publisher;
        }
    }

    return info;
}
