#pragma once

#include "connection.h"
#include <vector>

void print_banner();
void print_connection_table(const std::vector<Connection>& conns, bool detail = false);
void print_connection_detail(const Connection& conn);
void print_help();
void print_version_info();
