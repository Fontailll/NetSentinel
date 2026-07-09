#include "daemon.h"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#endif

static bool write_pid_file(const std::string& path) {
#ifdef _WIN32
    (void)path;
    return true;
#else
    std::ofstream file(path);
    if (!file) return false;
    file << getpid() << std::endl;
    return file.good();
#endif
}

bool daemonize(const std::string& logfile, const std::string& pidfile) {
#ifdef _WIN32
    (void)logfile;
    (void)pidfile;
    fprintf(stderr, "Daemon mode not supported on Windows. Run normally.\n");
    return false;
#else
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid > 0) _exit(0);

    if (setsid() < 0) return false;

    pid = fork();
    if (pid < 0) return false;
    if (pid > 0) _exit(0);

    chdir("/");
    umask(0);

    if (!pidfile.empty()) {
        write_pid_file(pidfile);
    }

    int fd = open(logfile.empty() ? "/dev/null" : logfile.c_str(),
                  O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) fd = open("/dev/null", O_WRONLY);

    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > 2) close(fd);

    return true;
#endif
}

static void print_runit_template() {
    printf("# runit service: /etc/sv/netwatch/run\n");
    printf("#!/bin/sh\n");
    printf("exec /usr/local/bin/netwatch --watch --logfile /var/log/netwatch.log"
           " --pidfile /run/netwatch.pid 2>&1\n");
    printf("\n# Install:\n");
    printf("#   sudo mkdir -p /etc/sv/netwatch\n");
    printf("#   sudo cp netwatch /usr/local/bin/\n");
    printf("#   (save this as /etc/sv/netwatch/run)\n");
    printf("#   sudo chmod +x /etc/sv/netwatch/run\n");
    printf("#   sudo ln -s /etc/sv/netwatch /var/service/\n");
    printf("#   sudo mkdir -p /var/log/netwatch\n");
}

static void print_systemd_template() {
    printf("# systemd service: /etc/systemd/system/netwatch.service\n");
    printf("[Unit]\n");
    printf("Description=NetWatch Network Incident Response\n");
    printf("After=network.target\n\n");
    printf("[Service]\n");
    printf("Type=simple\n");
    printf("ExecStart=/usr/local/bin/netwatch --watch"
           " --logfile /var/log/netwatch.log"
           " --pidfile /run/netwatch.pid\n");
    printf("Restart=always\n");
    printf("RestartSec=10\n");
    printf("StandardOutput=append:/var/log/netwatch.log\n");
    printf("StandardError=append:/var/log/netwatch.log\n");
    printf("PIDFile=/run/netwatch.pid\n\n");
    printf("[Install]\n");
    printf("WantedBy=multi-user.target\n");
    printf("\n# Install:\n");
    printf("#   sudo cp netwatch /usr/local/bin/\n");
    printf("#   sudo cp netwatch.service /etc/systemd/system/\n");
    printf("#   sudo systemctl daemon-reload\n");
    printf("#   sudo systemctl enable --now netwatch\n");
}

static void print_openrc_template() {
    printf("# OpenRC: /etc/init.d/netwatch\n");
    printf("#!/sbin/openrc-run\n\n");
    printf("command=\"/usr/local/bin/netwatch\"\n");
    printf("command_args=\"--watch --logfile /var/log/netwatch.log"
           " --pidfile /run/netwatch.pid\"\n");
    printf("command_background=true\n");
    printf("pidfile=\"/run/netwatch.pid\"\n\n");
    printf("depend() {\n");
    printf("    need net\n");
    printf("}\n");
    printf("\n# Install:\n");
    printf("#   sudo cp netwatch /usr/local/bin/\n");
    printf("#   sudo cp netwatch /etc/init.d/\n");
    printf("#   sudo chmod +x /etc/init.d/netwatch\n");
    printf("#   sudo rc-update add netwatch default\n");
    printf("#   sudo rc-service netwatch start\n");
}

bool detect_init_system(std::string& out_type) {
#ifdef _WIN32
    (void)out_type;
    return false;
#else
    auto exists = [](const std::string& path) -> bool {
        struct stat st;
        return stat(path.c_str(), &st) == 0;
    };

    if (exists("/run/systemd/system") || exists("/proc/1/comm")) {
        std::ifstream f("/proc/1/comm");
        std::string s;
        std::getline(f, s);
        if (s.find("systemd") != std::string::npos) {
            out_type = "systemd";
            return true;
        }
    }
    if (exists("/etc/sv")) {
        out_type = "runit";
        return true;
    }
    if (exists("/etc/init.d") && exists("/sbin/openrc-run")) {
        out_type = "openrc";
        return true;
    }
    if (exists("/etc/init.d")) {
        out_type = "openrc";
        return true;
    }
    return false;
#endif
}

bool print_service_template(const std::string& type) {
    if (type == "systemd") {
        print_systemd_template();
        return true;
    }
    if (type == "runit") {
        print_runit_template();
        return true;
    }
    if (type == "openrc") {
        print_openrc_template();
        return true;
    }
    return false;
}

void print_service_templates() {
    printf("\nAvailable service types:\n");
    printf("  systemd  -   systemd service unit\n");
    printf("  runit    -   runit run script\n");
    printf("  openrc   -   OpenRC init script\n");
    printf("\nUsage:\n");
    printf("  netwatch --install-service systemd\n");
    printf("  netwatch --install-service runit\n");
    printf("  netwatch --install-service openrc\n");
    printf("  netwatch --install-service auto\n");
}
