#include "payload_codec.h"

#include <cinttypes>
#include <cstdio>

namespace payload_codec {

const char *status_to_string(Status status) noexcept {
    switch (status) {
        case Status::OK:
            return "OK";
        case Status::RESTRICTED:
            return "RESTRICTED";
        case Status::UNSUPPORTED:
            return "UNSUPPORTED";
        case Status::ERROR:
            return "ERROR";
    }
    return "ERROR";
}

bool is_valid_key(std::string_view key) noexcept {
    if (key.empty()) {
        return false;
    }
    for (const char ch : key) {
        if (ch == '\t' || ch == '\n' || ch == '\r' || ch == '=' || ch == '\\' || ch == '\0') {
            return false;
        }
    }
    return true;
}

std::string escape_value(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (const char ch : value) {
        switch (ch) {
            case '\\':
                escaped.append("\\\\");
                break;
            case '\t':
                escaped.append("\\t");
                break;
            case '\n':
                escaped.append("\\n");
                break;
            case '\r':
                escaped.append("\\r");
                break;
            case '=':
                escaped.append("\\=");
                break;
            default:
                escaped.push_back(ch);
                break;
        }
    }
    return escaped;
}

std::string unescape_value(std::string_view encoded) {
    std::string out;
    out.reserve(encoded.size());
    size_t i = 0;
    while (i < encoded.size()) {
        const char ch = encoded[i];
        if (ch != '\\' || i + 1 >= encoded.size()) {
            out.push_back(ch);
            ++i;
            continue;
        }
        const char next = encoded[i + 1];
        switch (next) {
            case '\\':
                out.push_back('\\');
                break;
            case 't':
                out.push_back('\t');
                break;
            case 'n':
                out.push_back('\n');
                break;
            case 'r':
                out.push_back('\r');
                break;
            case '=':
                out.push_back('=');
                break;
            default:
                out.push_back(ch);
                out.push_back(next);
                break;
        }
        i += 2;
    }
    return out;
}

RecordBuilder &RecordBuilder::add(std::string_view key, std::string_view value) {
    if (!is_valid_key(key)) {
        return *this;
    }
    if (!line_.empty()) {
        line_.push_back('\t');
    }
    line_.append(key.data(), key.size());
    line_.push_back('=');
    const std::string escaped = escape_value(value);
    line_.append(escaped);
    return *this;
}

RecordBuilder &RecordBuilder::add_int(std::string_view key, int64_t value) {
    char buf[32] = {};
    const int n = std::snprintf(buf, sizeof(buf), "%" PRId64, value);
    if (n > 0 && static_cast<size_t>(n) < sizeof(buf)) {
        add(key, std::string_view(buf, static_cast<size_t>(n)));
    }
    return *this;
}

RecordBuilder &RecordBuilder::add_uint(std::string_view key, uint64_t value) {
    char buf[32] = {};
    const int n = std::snprintf(buf, sizeof(buf), "%" PRIu64, value);
    if (n > 0 && static_cast<size_t>(n) < sizeof(buf)) {
        add(key, std::string_view(buf, static_cast<size_t>(n)));
    }
    return *this;
}

RecordBuilder &RecordBuilder::add_bool(std::string_view key, bool value) {
    return add(key, value ? "1" : "0");
}

PayloadBuilder::PayloadBuilder(Status status, int err_no)
        : status_(status), err_no_(err_no) {}

PayloadBuilder &PayloadBuilder::set_status(Status status, int err_no) noexcept {
    status_ = status;
    err_no_ = err_no;
    return *this;
}

PayloadBuilder &PayloadBuilder::add_header(std::string_view key, std::string_view value) {
    if (key == "status" || key == "errno") {
        return *this;
    }
    header_extras_.add(key, value);
    return *this;
}

PayloadBuilder &PayloadBuilder::add_header_int(std::string_view key, int64_t value) {
    if (key == "status" || key == "errno") {
        return *this;
    }
    header_extras_.add_int(key, value);
    return *this;
}

PayloadBuilder &PayloadBuilder::add_record(const RecordBuilder &record) {
    if (!record.empty()) {
        records_.push_back(record.str());
    }
    return *this;
}

std::string PayloadBuilder::build() const {
    RecordBuilder header;
    header.add("status", status_to_string(status_));
    header.add_int("errno", err_no_);

    std::string out = header.str();
    if (!header_extras_.empty()) {
        out.push_back('\t');
        out.append(header_extras_.str());
    }
    for (const auto &rec : records_) {
        out.push_back('\n');
        out.append(rec);
    }
    return out;
}

}  // namespace payload_codec
