#include "apk_sig_native.h"

#include "../util/crypto_mini.h"
#include "../util/maps_parser.h"
#include "../util/obf_str.h"
#include "../util/payload_codec.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <vector>

namespace {

constexpr uint32_t kZipEocdMagic = 0x06054b50u;
constexpr uint32_t kZip64EocdLocatorMagic = 0x07064b50u;
constexpr uint32_t kZipCdHeaderMagic = 0x02014b50u;
constexpr size_t kZipEocdMinSize = 22u;
constexpr size_t kZipMaxCommentLen = 65535u;
constexpr size_t kZipEocdMaxWindow = kZipEocdMinSize + kZipMaxCommentLen;
constexpr size_t kApkSigBlockFooterSize = 24u;
constexpr size_t kApkSigBlockMinSize = 32u;

constexpr uint32_t kSchemeV2BlockId = 0x7109871au;
constexpr uint32_t kSchemeV3BlockId = 0xf05368c0u;
constexpr uint32_t kSchemeV31BlockId = 0x1b93ad61u;
constexpr uint32_t kProofOfRotationAttrId = 0x3ba06f8cu;
constexpr uint32_t kProofOfRotationVersion = 1u;

constexpr size_t kMaxSigBlockPairs = 1024u;
constexpr size_t kMaxSchemeBlockBytes = 2u * 1024u * 1024u;
constexpr size_t kMaxSignersPerScheme = 64u;
constexpr size_t kMaxAttrsPerSigner = 256u;
constexpr size_t kMaxLineageLevels = 64u;
constexpr size_t kMaxTotalLineageRecords = 256u;
constexpr size_t kMaxCertBytes = 256u * 1024u;

class ScopedRawFd {
public:
    explicit ScopedRawFd(int fd) noexcept : fd_(fd) {}
    ~ScopedRawFd() noexcept {
        if (fd_ >= 0) {
            my_close(fd_);
        }
    }
    ScopedRawFd(const ScopedRawFd &) = delete;
    ScopedRawFd &operator=(const ScopedRawFd &) = delete;

    int get() const noexcept { return fd_; }
    bool valid() const noexcept { return fd_ >= 0; }

private:
    int fd_ = -1;
};

struct SignerRecord {
    const char *scheme = "";
    uint32_t index = 0;
    bool has_sdk_range = false;
    int32_t min_sdk = 0;
    int32_t max_sdk = 0;
    std::string sha256_hex;
    std::string sha256_b64;
};

struct LineageRecord {
    const char *scheme = "";
    uint32_t signer_index = 0;
    uint32_t level = 0;
    std::string sha256_hex;
    std::string sha256_b64;
};

static inline uint16_t read_le16(const uint8_t *p) noexcept {
    return static_cast<uint16_t>(p[0])
         | (static_cast<uint16_t>(p[1]) << 8);
}

static inline uint32_t read_le32(const uint8_t *p) noexcept {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

static inline uint64_t read_le64(const uint8_t *p) noexcept {
    return static_cast<uint64_t>(read_le32(p))
         | (static_cast<uint64_t>(read_le32(p + 4)) << 32);
}

class SliceReader {
public:
    SliceReader() noexcept = default;
    SliceReader(const uint8_t *data, size_t size) noexcept
            : data_(data), size_(size), pos_(0) {}

    size_t remaining() const noexcept { return size_ - pos_; }
    bool empty() const noexcept { return pos_ >= size_; }
    const uint8_t *current() const noexcept { return data_ + pos_; }

    bool read_u32(uint32_t &out) noexcept {
        if (remaining() < 4u) {
            return false;
        }
        out = read_le32(data_ + pos_);
        pos_ += 4u;
        return true;
    }

    bool read_prefixed_slice(SliceReader &sub) noexcept {
        uint32_t len = 0;
        if (!read_u32(len)) {
            return false;
        }
        if (static_cast<size_t>(len) > remaining()) {
            return false;
        }
        sub = SliceReader(data_ + pos_, static_cast<size_t>(len));
        pos_ += static_cast<size_t>(len);
        return true;
    }

    bool skip_prefixed_slice() noexcept {
        SliceReader ignored;
        return read_prefixed_slice(ignored);
    }

    bool read_prefixed_bytes(const uint8_t *&ptr, size_t &len) noexcept {
        uint32_t raw_len = 0;
        if (!read_u32(raw_len)) {
            return false;
        }
        if (static_cast<size_t>(raw_len) > remaining()) {
            return false;
        }
        ptr = data_ + pos_;
        len = static_cast<size_t>(raw_len);
        pos_ += len;
        return true;
    }

private:
    const uint8_t *data_ = nullptr;
    size_t size_ = 0;
    size_t pos_ = 0;
};

static std::string to_hex_lower(const uint8_t *bytes, size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2u);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2u] = kHex[(bytes[i] >> 4) & 0x0fu];
        out[i * 2u + 1u] = kHex[bytes[i] & 0x0fu];
    }
    return out;
}

static std::string to_base64_std(const uint8_t *bytes, size_t len) {
    static constexpr char kTable[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2u) / 3u) * 4u);
    size_t i = 0;
    while (i < len) {
        const uint32_t b0 = bytes[i++];
        const bool has_b1 = i < len;
        const uint32_t b1 = has_b1 ? bytes[i++] : 0u;
        const bool has_b2 = i < len;
        const uint32_t b2 = has_b2 ? bytes[i++] : 0u;
        const uint32_t triple = (b0 << 16) | (b1 << 8) | b2;
        out.push_back(kTable[(triple >> 18) & 0x3fu]);
        out.push_back(kTable[(triple >> 12) & 0x3fu]);
        out.push_back(has_b1 ? kTable[(triple >> 6) & 0x3fu] : '=');
        out.push_back(has_b2 ? kTable[triple & 0x3fu] : '=');
    }
    return out;
}

static void hash_cert_der(const uint8_t *cert,
                          size_t cert_len,
                          std::string &out_hex,
                          std::string &out_b64) {
    uint8_t digest[crypto_mini::kSha256DigestSize] = {};
    crypto_mini::Sha256 sha;
    sha.update(cert, cert_len);
    sha.final(digest);
    out_hex = to_hex_lower(digest, sizeof(digest));
    out_b64 = to_base64_std(digest, sizeof(digest));
    crypto_mini::secure_zero(digest, sizeof(digest));
}

static bool is_plausible_der_cert(const uint8_t *cert, size_t cert_len) noexcept {
    // X.509 DER certificates are ASN.1 SEQUENCEs (tag 0x30) and never empty.
    return cert != nullptr
            && cert_len >= 4u
            && cert_len <= kMaxCertBytes
            && cert[0] == 0x30u;
}

static bool fstat_fd_with_retry(int fd, const char *path, struct stat &st, int &err_out) {
    st = {};
    long ret = -1;
#ifdef AT_EMPTY_PATH
    do {
        ret = my_fstatat(fd, "", &st, AT_EMPTY_PATH);
    } while (ret < 0 && raw_last_error() == EINTR);
    if (ret >= 0) {
        err_out = 0;
        return true;
    }
    const int first_err = raw_last_error();
    if (first_err != EINVAL && first_err != ENOSYS && first_err != EPERM && first_err != EACCES) {
        err_out = first_err;
        return false;
    }
#else
    (void) fd;
#endif
    st = {};
    do {
        ret = my_fstatat(AT_FDCWD, path, &st, 0);
    } while (ret < 0 && raw_last_error() == EINTR);
    if (ret >= 0) {
        err_out = 0;
        return true;
    }
    err_out = raw_last_error();
    return false;
}

static bool pread_exact(int fd,
                        uint64_t offset,
                        uint8_t *dst,
                        size_t len,
                        uint64_t file_size,
                        int &err_out) {
    if (offset > file_size || static_cast<uint64_t>(len) > file_size - offset) {
        err_out = EINVAL;
        return false;
    }
    size_t got = 0;
    while (got < len) {
        const long n = my_pread64(
                fd, dst + got, len - got, offset + static_cast<uint64_t>(got));
        if (n < 0) {
            const int err = raw_last_error();
            if (err == EINTR) {
                continue;
            }
            err_out = err;
            return false;
        }
        if (n == 0) {
            err_out = EIO;
            return false;
        }
        got += static_cast<size_t>(n);
    }
    err_out = 0;
    return true;
}

static bool ends_with(std::string_view s, std::string_view suffix) noexcept {
    return s.size() >= suffix.size()
            && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static bool starts_with(std::string_view s, std::string_view prefix) noexcept {
    return s.size() >= prefix.size()
            && s.compare(0, prefix.size(), prefix) == 0;
}

static std::string read_self_process_pkg() {
    const auto cmdline_path = OBF("/proc/self/cmdline");
    char buf[256] = {};
    const int fd = static_cast<int>(
            my_openat(AT_FDCWD, cmdline_path.c_str(), O_RDONLY | O_CLOEXEC, 0));
    if (fd < 0) {
        return std::string();
    }
    ScopedRawFd guard(fd);
    size_t total = 0;
    while (total + 1u < sizeof(buf)) {
        const long n = my_read(fd, buf + total, sizeof(buf) - 1u - total);
        if (n < 0) {
            if (raw_last_error() == EINTR) {
                continue;
            }
            break;
        }
        if (n == 0) {
            break;
        }
        total += static_cast<size_t>(n);
    }
    size_t pkg_len = 0;
    while (pkg_len < total && buf[pkg_len] != '\0' && buf[pkg_len] != ':') {
        ++pkg_len;
    }
    if (pkg_len == 0) {
        return std::string();
    }
    std::string pkg(buf, pkg_len);
    crypto_mini::secure_zero(buf, sizeof(buf));
    return pkg;
}

struct ApkLocation {
    std::string path;
    const char *source = "none";
    int maps_base_apk_count = 0;
};

static bool path_matches_package(std::string_view path, std::string_view pkg) noexcept {
    if (pkg.empty()) {
        return false;
    }
    size_t pos = 0;
    while ((pos = path.find(pkg, pos)) != std::string_view::npos) {
        const bool left_ok = (pos > 0 && path[pos - 1u] == '/');
        const size_t after = pos + pkg.size();
        const bool right_ok = (after < path.size()
                && (path[after] == '-' || path[after] == '/'));
        if (left_ok && right_ok) {
            return true;
        }
        pos += 1u;
    }
    return false;
}

static ApkLocation locate_base_apk(const char *fallback_source_dir) {
    ApkLocation loc;
    const std::string fallback =
            (fallback_source_dir != nullptr) ? std::string(fallback_source_dir) : std::string();
    const std::string proc_pkg = read_self_process_pkg();
    const auto base_apk_suffix = OBF("/base.apk");
    const auto data_app_prefix = OBF("/data/app/");
    const auto mnt_expand_prefix = OBF("/mnt/expand/");
    const auto deleted_suffix = OBF(" (deleted)");

    std::string exact_pkg_match;
    std::string data_app_match;
    std::string fallback_maps_match;
    std::vector<std::string> seen_base_apks;

    for_each_self_map([&](const MapEntry &entry) -> bool {
        if (entry.path.empty() || entry.path[0] != '/') {
            return true;
        }
        std::string_view p = entry.path;
        if (ends_with(p, deleted_suffix.view())) {
            return true;
        }
        if (ends_with(p, base_apk_suffix.view())) {
            bool already_seen = false;
            for (const auto &seen : seen_base_apks) {
                if (seen == p) {
                    already_seen = true;
                    break;
                }
            }
            if (!already_seen && seen_base_apks.size() < 32u) {
                seen_base_apks.emplace_back(p);
            }
            const bool is_user_install_root =
                    starts_with(p, data_app_prefix.view())
                    || starts_with(p, mnt_expand_prefix.view());
            if (exact_pkg_match.empty()
                    && is_user_install_root
                    && path_matches_package(p, proc_pkg)) {
                exact_pkg_match.assign(p);
            } else if (data_app_match.empty() && starts_with(p, data_app_prefix.view())) {
                data_app_match.assign(p);
            }
        }
        if (fallback_maps_match.empty() && !fallback.empty() && p == fallback) {
            fallback_maps_match.assign(p);
        }
        return true;
    });

    loc.maps_base_apk_count = static_cast<int>(seen_base_apks.size());
    if (!exact_pkg_match.empty()) {
        loc.path = std::move(exact_pkg_match);
        loc.source = "maps";
    } else if (!fallback_maps_match.empty()) {
        loc.path = std::move(fallback_maps_match);
        loc.source = "maps";
    } else if (!data_app_match.empty()) {
        loc.path = std::move(data_app_match);
        loc.source = "maps";
    } else if (!fallback.empty()) {
        loc.path = fallback;
        loc.source = "fallback";
    }
    return loc;
}

static bool parse_proof_of_rotation(SliceReader attr_val,
                                    const char *scheme,
                                    uint32_t signer_index,
                                    std::vector<LineageRecord> &lineage_out) {
    uint32_t version = 0;
    if (!attr_val.read_u32(version) || version != kProofOfRotationVersion) {
        return false;
    }
    uint32_t level_idx = 0;
    while (!attr_val.empty()) {
        if (level_idx >= kMaxLineageLevels
                || lineage_out.size() >= kMaxTotalLineageRecords) {
            return false;
        }
        SliceReader level;
        if (!attr_val.read_prefixed_slice(level)) {
            return false;
        }
        SliceReader signed_data;
        if (!level.read_prefixed_slice(signed_data)) {
            return false;
        }
        const uint8_t *cert = nullptr;
        size_t cert_len = 0;
        if (!signed_data.read_prefixed_bytes(cert, cert_len)
                || !is_plausible_der_cert(cert, cert_len)) {
            return false;
        }
        uint32_t inner_alg = 0;
        if (!signed_data.read_u32(inner_alg)) {
            return false;
        }
        uint32_t flags = 0;
        uint32_t outer_alg = 0;
        if (!level.read_u32(flags)
                || !level.read_u32(outer_alg)
                || !level.skip_prefixed_slice()) {
            return false;
        }
        LineageRecord rec;
        rec.scheme = scheme;
        rec.signer_index = signer_index;
        rec.level = level_idx;
        hash_cert_der(cert, cert_len, rec.sha256_hex, rec.sha256_b64);
        lineage_out.push_back(std::move(rec));
        ++level_idx;
    }
    return level_idx > 0;
}

static bool parse_scheme_v2_block(const uint8_t *data,
                                  size_t len,
                                  std::vector<SignerRecord> &signers_out) {
    SliceReader root(data, len);
    SliceReader signers;
    if (!root.read_prefixed_slice(signers)) {
        return false;
    }
    uint32_t idx = 0;
    while (!signers.empty()) {
        if (idx >= kMaxSignersPerScheme) {
            return false;
        }
        SliceReader signer;
        if (!signers.read_prefixed_slice(signer)) {
            return false;
        }
        SliceReader signed_data;
        if (!signer.read_prefixed_slice(signed_data)) {
            return false;
        }
        // Validate outer signatures and public_key bounds inside signer.
        if (!signer.skip_prefixed_slice() || !signer.skip_prefixed_slice()) {
            return false;
        }
        // Inside v2 signed_data: digests, certificates, additional_attributes.
        if (!signed_data.skip_prefixed_slice()) {
            return false;
        }
        SliceReader certs;
        if (!signed_data.read_prefixed_slice(certs) || certs.empty()) {
            return false;
        }
        const uint8_t *leaf_cert = nullptr;
        size_t leaf_cert_len = 0;
        if (!certs.read_prefixed_bytes(leaf_cert, leaf_cert_len)
                || !is_plausible_der_cert(leaf_cert, leaf_cert_len)) {
            return false;
        }
        if (!signed_data.skip_prefixed_slice()) {
            return false;
        }
        SignerRecord rec;
        rec.scheme = "v2";
        rec.index = idx;
        rec.has_sdk_range = false;
        hash_cert_der(leaf_cert, leaf_cert_len, rec.sha256_hex, rec.sha256_b64);
        signers_out.push_back(std::move(rec));
        ++idx;
    }
    return idx > 0;
}

static bool parse_scheme_v3_block(const uint8_t *data,
                                  size_t len,
                                  const char *scheme_label,
                                  std::vector<SignerRecord> &signers_out,
                                  std::vector<LineageRecord> &lineage_out) {
    SliceReader root(data, len);
    SliceReader signers;
    if (!root.read_prefixed_slice(signers)) {
        return false;
    }
    uint32_t idx = 0;
    while (!signers.empty()) {
        if (idx >= kMaxSignersPerScheme) {
            return false;
        }
        SliceReader signer;
        if (!signers.read_prefixed_slice(signer)) {
            return false;
        }
        SliceReader signed_data;
        if (!signer.read_prefixed_slice(signed_data)) {
            return false;
        }
        uint32_t outer_min_sdk = 0;
        uint32_t outer_max_sdk = 0;
        if (!signer.read_u32(outer_min_sdk)
                || !signer.read_u32(outer_max_sdk)
                || !signer.skip_prefixed_slice()
                || !signer.skip_prefixed_slice()) {
            return false;
        }

        // Inside v3/v3.1 signed_data: digests, certificates, minSdk, maxSdk, additional_attributes.
        if (!signed_data.skip_prefixed_slice()) {
            return false;
        }
        SliceReader certs;
        if (!signed_data.read_prefixed_slice(certs) || certs.empty()) {
            return false;
        }
        const uint8_t *leaf_cert = nullptr;
        size_t leaf_cert_len = 0;
        if (!certs.read_prefixed_bytes(leaf_cert, leaf_cert_len)
                || !is_plausible_der_cert(leaf_cert, leaf_cert_len)) {
            return false;
        }
        uint32_t inner_min_sdk = 0;
        uint32_t inner_max_sdk = 0;
        if (!signed_data.read_u32(inner_min_sdk) || !signed_data.read_u32(inner_max_sdk)) {
            return false;
        }
        if (inner_min_sdk != outer_min_sdk || inner_max_sdk != outer_max_sdk) {
            return false;
        }
        const auto min_sdk_signed = static_cast<int32_t>(inner_min_sdk);
        const auto max_sdk_signed = static_cast<int32_t>(inner_max_sdk);
        if (min_sdk_signed < 0 || max_sdk_signed < 0 || min_sdk_signed > max_sdk_signed) {
            return false;
        }

        SliceReader attrs;
        if (!signed_data.read_prefixed_slice(attrs)) {
            return false;
        }
        size_t attr_count = 0;
        bool seen_por = false;
        while (!attrs.empty()) {
            if (++attr_count > kMaxAttrsPerSigner) {
                return false;
            }
            SliceReader attr;
            if (!attrs.read_prefixed_slice(attr)) {
                return false;
            }
            uint32_t attr_id = 0;
            if (!attr.read_u32(attr_id)) {
                return false;
            }
            if (attr_id == kProofOfRotationAttrId) {
                if (seen_por) {
                    return false;
                }
                seen_por = true;
                if (!parse_proof_of_rotation(attr, scheme_label, idx, lineage_out)) {
                    return false;
                }
            }
        }

        SignerRecord rec;
        rec.scheme = scheme_label;
        rec.index = idx;
        rec.has_sdk_range = true;
        rec.min_sdk = min_sdk_signed;
        rec.max_sdk = max_sdk_signed;
        hash_cert_der(leaf_cert, leaf_cert_len, rec.sha256_hex, rec.sha256_b64);
        signers_out.push_back(std::move(rec));
        ++idx;
    }
    return idx > 0;
}

static std::string build_error_payload(payload_codec::Status status,
                                       int err_no,
                                       std::string_view reason,
                                       std::string_view path_source,
                                       std::string_view apk_path,
                                       uint64_t file_size,
                                       int maps_base_apk_count) {
    payload_codec::PayloadBuilder builder(status, err_no);
    builder.add_header("reason", reason)
           .add_header("path_source", path_source)
           .add_header("apk_path", apk_path)
           .add_header_int("file_size", static_cast<int64_t>(file_size))
           .add_header("schemes", "")
           .add_header("has_v2", "0")
           .add_header("has_v3", "0")
           .add_header("has_v31", "0")
           .add_header_int("maps_base_apk_count", maps_base_apk_count);
    return builder.build();
}

}  // namespace

std::string native_parse_apk_signing_file(
        const char *apk_path, const char *path_source, int maps_base_apk_count) {
    const std::string_view src =
            (path_source != nullptr && path_source[0] != '\0') ? path_source : "none";
    if (apk_path == nullptr || apk_path[0] == '\0') {
        return build_error_payload(
                payload_codec::Status::UNSUPPORTED, 0, "apk_not_found", src, "", 0,
                maps_base_apk_count);
    }
    const std::string_view path_sv(apk_path);

    const int raw_fd = static_cast<int>(
            my_openat(AT_FDCWD, apk_path, O_RDONLY | O_CLOEXEC, 0));
    if (raw_fd < 0) {
        const int err = raw_last_error();
        const payload_codec::Status st =
                (err == EACCES || err == EPERM)
                        ? payload_codec::Status::RESTRICTED
                        : payload_codec::Status::ERROR;
        return build_error_payload(
                st, err, "open_failed", src, path_sv, 0, maps_base_apk_count);
    }
    ScopedRawFd fd_guard(raw_fd);

    struct stat st {};
    int stat_err = 0;
    if (!fstat_fd_with_retry(raw_fd, apk_path, st, stat_err)) {
        const payload_codec::Status st_code =
                (stat_err == EACCES || stat_err == EPERM)
                        ? payload_codec::Status::RESTRICTED
                        : payload_codec::Status::ERROR;
        return build_error_payload(
                st_code, stat_err, "stat_failed", src, path_sv, 0, maps_base_apk_count);
    }
    if (!S_ISREG(st.st_mode) || st.st_size <= 0) {
        return build_error_payload(
                payload_codec::Status::ERROR, 0, "not_regular_file", src, path_sv, 0,
                maps_base_apk_count);
    }
    const uint64_t file_size = static_cast<uint64_t>(st.st_size);
    if (file_size < kZipEocdMinSize) {
        return build_error_payload(
                payload_codec::Status::ERROR, 0, "invalid_zip_too_small", src, path_sv,
                file_size, maps_base_apk_count);
    }

    // 1. Locate ZIP End of Central Directory (EOCD) from file tail.
    const size_t tail_len = static_cast<size_t>(
            std::min<uint64_t>(file_size, kZipEocdMaxWindow));
    const uint64_t tail_offset = file_size - static_cast<uint64_t>(tail_len);
    std::unique_ptr<uint8_t[]> tail_buf(new (std::nothrow) uint8_t[tail_len]);
    if (!tail_buf) {
        return build_error_payload(
                payload_codec::Status::ERROR, ENOMEM, "oom_tail", src, path_sv,
                file_size, maps_base_apk_count);
    }
    int io_err = 0;
    if (!pread_exact(raw_fd, tail_offset, tail_buf.get(), tail_len, file_size, io_err)) {
        return build_error_payload(
                payload_codec::Status::ERROR, io_err, "eocd_read_failed", src, path_sv,
                file_size, maps_base_apk_count);
    }

    bool eocd_found = false;
    uint64_t eocd_file_offset = 0;
    uint64_t cd_offset = 0;
    uint64_t cd_size = 0;

    for (size_t offset_from_end = kZipEocdMinSize; offset_from_end <= tail_len; ++offset_from_end) {
        const size_t pos = tail_len - offset_from_end;
        if (read_le32(tail_buf.get() + pos) != kZipEocdMagic) {
            continue;
        }
        const uint16_t comment_len = read_le16(tail_buf.get() + pos + 20u);
        if (static_cast<size_t>(comment_len) != offset_from_end - kZipEocdMinSize) {
            continue;
        }
        const uint32_t raw_cd_size = read_le32(tail_buf.get() + pos + 12u);
        const uint32_t raw_cd_offset = read_le32(tail_buf.get() + pos + 16u);
        eocd_file_offset = tail_offset + static_cast<uint64_t>(pos);

        if (raw_cd_offset == 0xFFFFFFFFu || raw_cd_size == 0xFFFFFFFFu) {
            return build_error_payload(
                    payload_codec::Status::UNSUPPORTED, 0, "zip64_unsupported", src, path_sv,
                    file_size, maps_base_apk_count);
        }
        // Also check for ZIP64 EOCD locator immediately preceding EOCD.
        if (eocd_file_offset >= 20u) {
            uint8_t loc_magic_bytes[4] = {};
            if (pread_exact(raw_fd, eocd_file_offset - 20u, loc_magic_bytes, 4u, file_size, io_err)
                    && read_le32(loc_magic_bytes) == kZip64EocdLocatorMagic) {
                return build_error_payload(
                        payload_codec::Status::UNSUPPORTED, 0, "zip64_unsupported", src, path_sv,
                        file_size, maps_base_apk_count);
            }
        }
        cd_offset = static_cast<uint64_t>(raw_cd_offset);
        cd_size = static_cast<uint64_t>(raw_cd_size);
        eocd_found = true;
        break;
    }
    tail_buf.reset();

    if (!eocd_found) {
        return build_error_payload(
                payload_codec::Status::ERROR, 0, "eocd_not_found", src, path_sv,
                file_size, maps_base_apk_count);
    }
    if (cd_offset > eocd_file_offset || cd_size != eocd_file_offset - cd_offset) {
        return build_error_payload(
                payload_codec::Status::ERROR, 0, "invalid_cd_bounds", src, path_sv,
                file_size, maps_base_apk_count);
    }
    if (cd_size >= 4u) {
        uint8_t cd_magic_bytes[4] = {};
        if (!pread_exact(raw_fd, cd_offset, cd_magic_bytes, 4u, file_size, io_err)
                || read_le32(cd_magic_bytes) != kZipCdHeaderMagic) {
            return build_error_payload(
                    payload_codec::Status::ERROR, io_err, "invalid_cd_magic", src, path_sv,
                    file_size, maps_base_apk_count);
        }
    }

    // 2. Verify APK Signing Block immediately before Central Directory.
    if (cd_offset < kApkSigBlockMinSize) {
        return build_error_payload(
                payload_codec::Status::UNSUPPORTED, 0, "no_apk_sig_block", src, path_sv,
                file_size, maps_base_apk_count);
    }
    uint8_t footer[kApkSigBlockFooterSize] = {};
    if (!pread_exact(raw_fd, cd_offset - kApkSigBlockFooterSize, footer,
                     sizeof(footer), file_size, io_err)) {
        return build_error_payload(
                payload_codec::Status::ERROR, io_err, "sig_footer_read_failed", src, path_sv,
                file_size, maps_base_apk_count);
    }

    const auto expected_magic = OBF("APK Sig Block 42");
    if (expected_magic.size() != 16u
            || std::memcmp(footer + 8u, expected_magic.data(), 16u) != 0) {
        return build_error_payload(
                payload_codec::Status::UNSUPPORTED, 0, "no_apk_sig_block", src, path_sv,
                file_size, maps_base_apk_count);
    }

    const uint64_t size_of_block_footer = read_le64(footer);
    if (size_of_block_footer < kApkSigBlockFooterSize
            || size_of_block_footer > cd_offset - 8u) {
        return build_error_payload(
                payload_codec::Status::ERROR, 0, "malformed_sig_block_size", src, path_sv,
                file_size, maps_base_apk_count);
    }
    const uint64_t block_start = cd_offset - 8u - size_of_block_footer;

    uint8_t header_size_bytes[8] = {};
    if (!pread_exact(raw_fd, block_start, header_size_bytes, sizeof(header_size_bytes),
                     file_size, io_err)) {
        return build_error_payload(
                payload_codec::Status::ERROR, io_err, "sig_header_read_failed", src, path_sv,
                file_size, maps_base_apk_count);
    }
    const uint64_t size_of_block_header = read_le64(header_size_bytes);
    if (size_of_block_header != size_of_block_footer) {
        return build_error_payload(
                payload_codec::Status::ERROR, 0, "sig_block_size_mismatch", src, path_sv,
                file_size, maps_base_apk_count);
    }

    // 3. Stream ID-value pairs inside [block_start + 8, cd_offset - 24).
    uint64_t cursor = block_start + 8u;
    const uint64_t pairs_end = cd_offset - kApkSigBlockFooterSize;
    bool has_v2 = false;
    bool has_v3 = false;
    bool has_v31 = false;
    std::vector<SignerRecord> signers;
    std::vector<LineageRecord> lineage;
    size_t pair_count = 0;

    while (cursor < pairs_end) {
        if (++pair_count > kMaxSigBlockPairs) {
            return build_error_payload(
                    payload_codec::Status::ERROR, 0, "too_many_sig_pairs", src, path_sv,
                    file_size, maps_base_apk_count);
        }
        if (pairs_end - cursor < 12u) {
            return build_error_payload(
                    payload_codec::Status::ERROR, 0, "truncated_sig_pair_header", src, path_sv,
                    file_size, maps_base_apk_count);
        }
        uint8_t pair_hdr[12] = {};
        if (!pread_exact(raw_fd, cursor, pair_hdr, sizeof(pair_hdr), file_size, io_err)) {
            return build_error_payload(
                    payload_codec::Status::ERROR, io_err, "sig_pair_read_failed", src, path_sv,
                    file_size, maps_base_apk_count);
        }
        const uint64_t pair_len = read_le64(pair_hdr);
        const uint32_t pair_id = read_le32(pair_hdr + 8u);
        if (pair_len < 4u || pair_len - 4u > pairs_end - (cursor + 12u)) {
            return build_error_payload(
                    payload_codec::Status::ERROR, 0, "invalid_sig_pair_len", src, path_sv,
                    file_size, maps_base_apk_count);
        }
        const uint64_t val_offset = cursor + 12u;
        const uint64_t val_len_u64 = pair_len - 4u;

        const bool is_v2 = (pair_id == kSchemeV2BlockId);
        const bool is_v3 = (pair_id == kSchemeV3BlockId);
        const bool is_v31 = (pair_id == kSchemeV31BlockId);

        if (is_v2 || is_v3 || is_v31) {
            if ((is_v2 && has_v2) || (is_v3 && has_v3) || (is_v31 && has_v31)) {
                return build_error_payload(
                        payload_codec::Status::ERROR, 0, "duplicate_scheme_block", src, path_sv,
                        file_size, maps_base_apk_count);
            }
            if (val_len_u64 == 0u || val_len_u64 > static_cast<uint64_t>(kMaxSchemeBlockBytes)) {
                return build_error_payload(
                        payload_codec::Status::ERROR, 0, "scheme_block_size_out_of_range", src,
                        path_sv, file_size, maps_base_apk_count);
            }
            const auto val_len = static_cast<size_t>(val_len_u64);
            std::unique_ptr<uint8_t[]> block_buf(new (std::nothrow) uint8_t[val_len]);
            if (!block_buf) {
                return build_error_payload(
                        payload_codec::Status::ERROR, ENOMEM, "oom_scheme_block", src, path_sv,
                        file_size, maps_base_apk_count);
            }
            if (!pread_exact(raw_fd, val_offset, block_buf.get(), val_len, file_size, io_err)) {
                return build_error_payload(
                        payload_codec::Status::ERROR, io_err, "scheme_block_read_failed", src,
                        path_sv, file_size, maps_base_apk_count);
            }

            bool parsed = false;
            if (is_v2) {
                has_v2 = true;
                parsed = parse_scheme_v2_block(block_buf.get(), val_len, signers);
            } else if (is_v3) {
                has_v3 = true;
                parsed = parse_scheme_v3_block(block_buf.get(), val_len, "v3", signers, lineage);
            } else {
                has_v31 = true;
                parsed = parse_scheme_v3_block(block_buf.get(), val_len, "v3.1", signers, lineage);
            }
            if (!parsed) {
                return build_error_payload(
                        payload_codec::Status::ERROR, 0, "malformed_scheme_block", src, path_sv,
                        file_size, maps_base_apk_count);
            }
        }

        cursor += 8u + pair_len;
    }

    if (!has_v2 && !has_v3 && !has_v31) {
        return build_error_payload(
                payload_codec::Status::UNSUPPORTED, 0, "no_v2_v3_scheme_block", src, path_sv,
                file_size, maps_base_apk_count);
    }
    if (signers.empty()) {
        return build_error_payload(
                payload_codec::Status::ERROR, 0, "no_valid_signers", src, path_sv,
                file_size, maps_base_apk_count);
    }

    std::string schemes;
    if (has_v2) {
        schemes += "v2";
    }
    if (has_v3) {
        if (!schemes.empty()) schemes.push_back(',');
        schemes += "v3";
    }
    if (has_v31) {
        if (!schemes.empty()) schemes.push_back(',');
        schemes += "v3.1";
    }

    payload_codec::PayloadBuilder builder(payload_codec::Status::OK, 0);
    builder.add_header("reason", "ok")
           .add_header("path_source", src)
           .add_header("apk_path", path_sv)
           .add_header_int("file_size", static_cast<int64_t>(file_size))
           .add_header("schemes", schemes)
           .add_header("has_v2", has_v2 ? "1" : "0")
           .add_header("has_v3", has_v3 ? "1" : "0")
           .add_header("has_v31", has_v31 ? "1" : "0")
           .add_header_int("maps_base_apk_count", maps_base_apk_count);

    for (const auto &s : signers) {
        payload_codec::RecordBuilder rec;
        rec.add("kind", "signer")
           .add("scheme", s.scheme)
           .add_uint("index", s.index);
        if (s.has_sdk_range) {
            rec.add_int("min_sdk", s.min_sdk)
               .add_int("max_sdk", s.max_sdk);
        }
        rec.add("cert_sha256_hex", s.sha256_hex)
           .add("cert_sha256_b64", s.sha256_b64);
        builder.add_record(rec);
    }

    for (const auto &l : lineage) {
        payload_codec::RecordBuilder rec;
        rec.add("kind", "lineage")
           .add("scheme", l.scheme)
           .add_uint("signer_index", l.signer_index)
           .add_uint("level", l.level)
           .add("cert_sha256_hex", l.sha256_hex)
           .add("cert_sha256_b64", l.sha256_b64);
        builder.add_record(rec);
    }

    return builder.build();
}

std::string native_get_apk_signing_info(const char *fallback_source_dir) {
    const ApkLocation loc = locate_base_apk(fallback_source_dir);
    return native_parse_apk_signing_file(
            loc.path.c_str(), loc.source, loc.maps_base_apk_count);
}
