#ifndef RISKENGINE_PAYLOAD_CODEC_H
#define RISKENGINE_PAYLOAD_CODEC_H

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

/**
 * Escaped KEY=value\t wire codec shared with Java NativePayloadCodec.
 *
 * Frame layout:
 * - Line 0 (header): status=<OK|RESTRICTED|UNSUPPORTED|ERROR>\terrno=<int>[\tKEY=escaped_val...]
 * - Line 1..N (records): KEY=escaped_val[\tKEY=escaped_val...]
 *
 * Escaped characters inside values:
 *   '\\' -> "\\\\"
 *   '\t' -> "\\t"
 *   '\n' -> "\\n"
 *   '\r' -> "\\r"
 *   '='  -> "\\="
 */
namespace payload_codec {

enum class Status : uint8_t {
    OK = 0,
    RESTRICTED = 1,
    UNSUPPORTED = 2,
    ERROR = 3,
};

const char *status_to_string(Status status) noexcept;
bool is_valid_key(std::string_view key) noexcept;
std::string escape_value(std::string_view value);
std::string unescape_value(std::string_view encoded);

class RecordBuilder {
public:
    RecordBuilder &add(std::string_view key, std::string_view value);
    RecordBuilder &add_int(std::string_view key, int64_t value);
    RecordBuilder &add_uint(std::string_view key, uint64_t value);
    RecordBuilder &add_bool(std::string_view key, bool value);

    bool empty() const noexcept { return line_.empty(); }
    const std::string &str() const noexcept { return line_; }
    std::string build() const { return line_; }

private:
    std::string line_;
};

class PayloadBuilder {
public:
    explicit PayloadBuilder(Status status = Status::OK, int err_no = 0);

    PayloadBuilder &set_status(Status status, int err_no = 0) noexcept;
    PayloadBuilder &add_header(std::string_view key, std::string_view value);
    PayloadBuilder &add_header_int(std::string_view key, int64_t value);
    PayloadBuilder &add_record(const RecordBuilder &record);

    std::string build() const;

private:
    Status status_ = Status::OK;
    int err_no_ = 0;
    RecordBuilder header_extras_;
    std::vector<std::string> records_;
};

}  // namespace payload_codec

#endif  // RISKENGINE_PAYLOAD_CODEC_H
