#include "json_export.h"
#include "utils.h"
#include <fstream>
#include <sstream>

void JsonWriter::begin_object() {
    if (needs_comma_) buffer_ += ",\n";
    buffer_ += "{";
    state_ = OBJECT;
    needs_comma_ = false;
}

void JsonWriter::end_object() {
    buffer_ += "\n}";
    needs_comma_ = true;
}

void JsonWriter::begin_array() {
    if (needs_comma_) buffer_ += ",\n";
    buffer_ += "[";
    state_ = ARRAY;
    needs_comma_ = false;
}

void JsonWriter::end_array() {
    buffer_ += "\n]";
    needs_comma_ = true;
}

void JsonWriter::key(const std::string& k) {
    if (needs_comma_) buffer_ += ",\n";
    buffer_ += "\n  \"" + k + "\": ";
    needs_comma_ = false;
}

void JsonWriter::value(const std::string& v) {
    value(v.c_str());
}

void JsonWriter::value(const char* v) {
    if (needs_comma_) buffer_ += ", ";
    std::string escaped;
    while (v && *v) {
        char c = *v++;
        if (c == '"') escaped += "\\\"";
        else if (c == '\\') escaped += "\\\\";
        else if (c == '\n') escaped += "\\n";
        else if (c == '\r') escaped += "\\r";
        else if (c == '\t') escaped += "\\t";
        else escaped += c;
    }
    buffer_ += "\"" + escaped + "\"";
    needs_comma_ = true;
}

void JsonWriter::value(int v) {
    if (needs_comma_) buffer_ += ", ";
    buffer_ += std::to_string(v);
    needs_comma_ = true;
}

void JsonWriter::value(unsigned int v) {
    if (needs_comma_) buffer_ += ", ";
    buffer_ += std::to_string(v);
    needs_comma_ = true;
}

void JsonWriter::comma() {
    needs_comma_ = true;
}

void JsonWriter::raw(const std::string& s) {
    if (needs_comma_) buffer_ += ", ";
    buffer_ += s;
    needs_comma_ = true;
}

std::string JsonWriter::str() const {
    return buffer_;
}

void JsonWriter::clear() {
    buffer_.clear();
    state_ = NONE;
    needs_comma_ = false;
}

static void write_connection(JsonWriter& jw, const Connection& c) {
    jw.begin_object();
    jw.key("pid");            jw.value(c.pid);
    jw.key("process");        jw.value(c.process_name);
    jw.key("path");           jw.value(c.process_path);
    jw.key("protocol");       jw.value(protocol_str(c.protocol));
    jw.key("local_ip");       jw.value(c.local_ip);
    jw.key("local_port");     jw.value(c.local_port);
    jw.key("remote_ip");      jw.value(c.remote_ip);
    jw.key("remote_port");    jw.value(c.remote_port);
    jw.key("state");          jw.value(c.state_str);
    jw.key("risk");           jw.value(risk_level_str(c.risk));
    jw.key("risk_score");     jw.value(c.risk_score);
    jw.key("signed");         jw.value(c.signed_binary ? "Yes" : "No");
    jw.key("publisher");      jw.value(c.publisher);
    jw.key("country");        jw.value(c.country);
    jw.end_object();
}

bool export_json(const std::string& path, const std::vector<Connection>& connections) {
    JsonWriter jw;
    jw.begin_object();
    jw.key("tool");        jw.value("NetSentinel");
    jw.key("version");     jw.value("1.0.0");
    jw.key("timestamp");   jw.value(utils::timestamp());
    jw.key("count");       jw.value(static_cast<uint32_t>(connections.size()));

    jw.key("connections");
    jw.begin_array();
    for (const auto& c : connections) {
        write_connection(jw, c);
    }
    jw.end_array();
    jw.end_object();

    std::ofstream file(path);
    if (!file) return false;
    file << jw.str() << "\n";
    return true;
}

bool export_json_stdout(const std::vector<Connection>& connections) {
    JsonWriter jw;
    jw.begin_object();
    jw.key("tool");        jw.value("NetSentinel");
    jw.key("version");     jw.value("1.0.0");
    jw.key("timestamp");   jw.value(utils::timestamp());
    jw.key("count");       jw.value(static_cast<uint32_t>(connections.size()));

    jw.key("connections");
    jw.begin_array();
    for (const auto& c : connections) {
        write_connection(jw, c);
    }
    jw.end_array();
    jw.end_object();

    printf("%s\n", jw.str().c_str());
    return true;
}
