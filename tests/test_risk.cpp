#include "catch.hpp"
#include "risk.h"
#include "connection.h"

TEST_CASE("RiskEngine assesses LOW risk for clean connection", "[risk]") {
    RiskEngine re;
    Connection c;
    c.pid = 1234;
    c.process_name = "explorer.exe";
    c.process_path = "C:\\Windows\\explorer.exe";
    c.local_ip = "192.168.1.1";
    c.local_port = 50000;
    c.remote_ip = "93.184.216.34";
    c.remote_port = 443;
    c.protocol = Protocol::TCP;
    c.state = ConnState::ESTABLISHED;
    c.state_str = "ESTABLISHED";

    re.assess(c);

    REQUIRE(c.risk == RiskLevel::LOW);
    REQUIRE(c.risk_score == 0);
    REQUIRE(c.risk_flags.empty());
}

TEST_CASE("RiskEngine detects suspicious process names", "[risk]") {
    RiskEngine re;
    Connection c;
    c.pid = 5678;
    c.process_name = "powershell.exe";
    c.process_path = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

    re.assess(c);

    REQUIRE(c.risk_score >= 15);
    REQUIRE_FALSE(c.risk_flags.empty());

    bool found = false;
    for (const auto& f : c.risk_flags) {
        if (f.find("Suspicious process name") != std::string::npos) found = true;
    }
    REQUIRE(found);
}

TEST_CASE("RiskEngine detects malware ports", "[risk]") {
    RiskEngine re;
    Connection c;
    c.pid = 9999;
    c.remote_port = 4444;
    c.protocol = Protocol::TCP;
    c.state = ConnState::ESTABLISHED;

    re.assess(c);

    REQUIRE(c.risk_score >= 20);
}

TEST_CASE("RiskEngine thresholds: 30+ is MEDIUM", "[risk]") {
    RiskEngine re;
    Connection c;
    c.pid = 5678;
    c.process_name = "powershell.exe";

    re.assess(c);

    REQUIRE(c.risk_score >= 15);
    REQUIRE(c.risk == RiskLevel::LOW);

    c.remote_port = 4444;
    re.assess(c);

    REQUIRE(c.risk_score >= 35);
    REQUIRE(c.risk == RiskLevel::MEDIUM);
}

TEST_CASE("RiskEngine thresholds: 30-59 is MEDIUM", "[risk]") {
    RiskEngine re;
    Connection c;
    c.pid = 1;
    c.process_name = "";
    c.process_path = "C:\\Users\\test\\AppData\\Local\\Temp\\bad.exe";
    c.remote_port = 4444;

    re.assess(c);

    REQUIRE(c.risk_score >= 55);
    REQUIRE(c.risk_score < 60);
    REQUIRE(c.risk == RiskLevel::MEDIUM);
}

TEST_CASE("RiskEngine thresholds: 60-79 is HIGH", "[risk]") {
    RiskEngine re;
    Connection c;
    c.pid = 1;
    c.process_name = "powershell.exe";
    c.process_path = "C:\\Users\\test\\AppData\\Local\\Temp\\bad.exe";
    c.remote_port = 4444;
    c.local_port = 999;
    c.state = ConnState::LISTENING;

    re.assess(c);

    REQUIRE(c.risk_score >= 70);
    REQUIRE(c.risk_score < 80);
    REQUIRE(c.risk == RiskLevel::HIGH);
}

TEST_CASE("RiskEngine thresholds: 80+ is CRITICAL", "[risk]") {
    RiskEngine re;
    re.set_verify_signatures(true);

    Connection c;
    c.pid = 1;
    c.process_name = "powershell.exe";
    c.process_path = "C:\\Users\\test\\AppData\\Local\\Temp\\bad.exe";
    c.remote_port = 4444;
    c.local_port = 999;
    c.state = ConnState::LISTENING;

    re.assess(c);

    REQUIRE(c.risk_score >= 100);
    REQUIRE(c.risk == RiskLevel::CRITICAL);
}

TEST_CASE("RiskEngine enables/disables rules by name", "[risk]") {
    RiskEngine re;
    Connection c;
    c.pid = 5678;
    c.process_name = "powershell.exe";

    re.disable_rule("Suspicious process name");
    re.assess(c);
    REQUIRE(c.risk_score == 0);

    re.enable_rule("Suspicious process name");
    re.assess(c);
    REQUIRE(c.risk_score >= 15);
}

TEST_CASE("RiskEngine Temp folder detection", "[risk]") {
    RiskEngine re;
    Connection c;
    c.pid = 1111;
    c.process_path = "C:\\Users\\test\\AppData\\Local\\Temp\\malware.exe";

    re.assess(c);

    bool found = false;
    for (const auto& f : c.risk_flags) {
        if (f.find("Temp folder") != std::string::npos) found = true;
    }
    REQUIRE(found);
}

TEST_CASE("RiskEngine hidden process detection", "[risk]") {
    RiskEngine re;
    Connection c;
    c.pid = 1234;
    c.process_name = "";

    re.assess(c);

    bool found = false;
    for (const auto& f : c.risk_flags) {
        if (f.find("Hidden process") != std::string::npos) found = true;
    }
    REQUIRE(found);
}
