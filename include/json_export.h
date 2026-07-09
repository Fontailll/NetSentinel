#pragma once

#include "connection.h"
#include <string>
#include <vector>

class JsonWriter {
public:
    JsonWriter() = default;

    void begin_object();
    void end_object();
    void begin_array();
    void end_array();
    void key(const std::string& k);
    void value(const std::string& v);
    void value(const char* v);
    void value(int v);
    void value(unsigned int v);
    void comma();
    void raw(const std::string& s);

    std::string str() const;
    void clear();

private:
    std::string buffer_;
    enum State { OBJECT, ARRAY, KEY, VALUE, NONE };
    State state_ = NONE;
    bool needs_comma_ = false;
};

bool export_json(const std::string& path, const std::vector<Connection>& connections);
bool export_json_stdout(const std::vector<Connection>& connections);
