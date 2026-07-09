#define CATCH_CONFIG_RUNNER
#include "catch.hpp"
#include <cstdio>
#include <vector>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

int main(int argc, char* argv[]) {
    std::vector<char*> args;
    std::string prog = argv[0] ? argv[0] : "netwatch_tests";
    args.push_back(&prog[0]);

    std::string flag_s = "--success";

    bool has_custom_args = false;
    for (int i = 1; i < argc; ++i) {
        if (argv[i][0] == '-') { has_custom_args = true; break; }
    }

    if (!has_custom_args) {
        args.push_back(&flag_s[0]);
    } else {
        for (int i = 1; i < argc; ++i) args.push_back(argv[i]);
    }

    int result = Catch::Session().run(static_cast<int>(args.size()), args.data());

#ifdef _WIN32
    printf("\nPress Enter to exit...\n");
    getchar();
#endif

    return result;
}
