#include "catch.hpp"
#include "utils.h"

TEST_CASE("utils::trim removes whitespace", "[utils]") {
    REQUIRE(utils::trim("  hello  ") == "hello");
    REQUIRE(utils::trim("\thello\n") == "hello");
    REQUIRE(utils::trim("nochange") == "nochange");
    REQUIRE(utils::trim("") == "");
}

TEST_CASE("utils::split divides string by delimiter", "[utils]") {
    auto parts = utils::split("a,b,c", ',');
    REQUIRE(parts.size() == 3);
    REQUIRE(parts[0] == "a");
    REQUIRE(parts[1] == "b");
    REQUIRE(parts[2] == "c");

    parts = utils::split("single", ',');
    REQUIRE(parts.size() == 1);
    REQUIRE(parts[0] == "single");

    parts = utils::split("", ',');
    REQUIRE(parts.empty());
}

TEST_CASE("utils::hex_to_u32 parses hex strings", "[utils]") {
    REQUIRE(utils::hex_to_u32("0A") == 10);
    REQUIRE(utils::hex_to_u32("FF") == 255);
    REQUIRE(utils::hex_to_u32("0100007F") == 16777343);
    REQUIRE(utils::hex_to_u32("") == 0);
}

TEST_CASE("utils::lower converts to lowercase", "[utils]") {
    REQUIRE(utils::lower("HELLO") == "hello");
    REQUIRE(utils::lower("MixedCase") == "mixedcase");
    REQUIRE(utils::lower("") == "");
}

TEST_CASE("utils::iequals compares case-insensitively", "[utils]") {
    REQUIRE(utils::iequals("hello", "HELLO"));
    REQUIRE(utils::iequals("Test", "test"));
    REQUIRE_FALSE(utils::iequals("hello", "world"));
    REQUIRE(utils::iequals("", ""));
}

TEST_CASE("utils::timestamp returns non-empty string", "[utils]") {
    auto ts = utils::timestamp();
    REQUIRE_FALSE(ts.empty());
    REQUIRE((ts.find('-') != std::string::npos || ts.find(':') != std::string::npos));
}
