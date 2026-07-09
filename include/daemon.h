#pragma once

#include <string>
#include <vector>

bool daemonize(const std::string& logfile, const std::string& pidfile);
void print_service_templates();

bool detect_init_system(std::string& out_type);
bool print_service_template(const std::string& type);
