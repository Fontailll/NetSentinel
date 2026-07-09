#include "catch.hpp"
#include "geoip.h"

TEST_CASE("GeoIP identifies private IPs", "[geoip]") {
    GeoIP geo;

    REQUIRE(geo.lookup("192.168.1.1") == "Private (192.168.x.x)");
    REQUIRE(geo.lookup("10.0.0.5") == "Private (10.x.x.x)");
    REQUIRE(geo.lookup("172.16.0.1") == "Private (172.16-31.x.x)");
    REQUIRE(geo.lookup("172.31.255.255") == "Private (172.16-31.x.x)");
}

TEST_CASE("GeoIP identifies localhost", "[geoip]") {
    GeoIP geo;

    REQUIRE(geo.lookup("127.0.0.1") == "Localhost");
}

TEST_CASE("GeoIP returns Unknown for public IPs without database", "[geoip]") {
    GeoIP geo;

    REQUIRE(geo.lookup("93.184.216.34") == "Unknown");
    REQUIRE(geo.lookup("8.8.8.8") == "Unknown");
}

TEST_CASE("GeoIP handles invalid IPs", "[geoip]") {
    GeoIP geo;

    REQUIRE(geo.lookup("") == "Unknown");
    REQUIRE(geo.lookup("0.0.0.0") == "Unknown");
    REQUIRE(geo.lookup("not-an-ip") == "Unknown");
}

TEST_CASE("GeoIP load_csv returns false for missing file", "[geoip]") {
    GeoIP geo;
    REQUIRE_FALSE(geo.load_csv("nonexistent.csv"));
    REQUIRE_FALSE(geo.is_loaded());
}
