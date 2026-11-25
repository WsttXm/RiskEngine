#include "mini_gtest.h"

#include "util/maps_parser.h"
#include "util/payload_codec.h"
#include "util/raw_dir.h"
#include "util/syscall_wrapper.h"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

// Deterministic virtual syscall harness driving REAL maps_parser.cpp and raw_dir.cpp.
struct MockSyscallState {
    int last_err = 0;
    int open_err = 0;
    int open_count = 0;
    int close_count = 0;

    // Virtual read stream for maps_parser
    std::string maps_stream;
    size_t maps_pos = 0;
    size_t max_read_chunk = 8192;
    size_t inject_eintr_every = 0;
    size_t read_calls = 0;

    // Virtual getdents64 batches for raw_dir
    std::vector<std::vector<uint8_t>> dirent_batches;
    size_t dirent_batch_idx = 0;
    long override_getdents_ret = -999999;
    int getdents_err = 0;

    void reset() {
        *this = MockSyscallState{};
    }
};

MockSyscallState g_mock;

constexpr int kFakeFd = 42;

struct TestLinuxDirent64 {
    uint64_t d_ino = 0;
    int64_t d_off = 0;
    uint16_t d_reclen = 0;
    uint8_t d_type = 0;
    char d_name[];
};

void append_dirent(std::vector<uint8_t> &buf,
                   uint64_t ino,
                   const std::string &name,
                   uint16_t override_reclen = 0,
                   bool include_nul = true) {
    constexpr size_t kNameOff = offsetof(TestLinuxDirent64, d_name);
    const size_t min_len = kNameOff + name.size() + (include_nul ? 1u : 0u);
    const size_t aligned = (min_len + 7u) & ~static_cast<size_t>(7u);
    const uint16_t reclen = override_reclen != 0 ? override_reclen : static_cast<uint16_t>(aligned);

    const size_t start = buf.size();
    const size_t write_len = std::max<size_t>(aligned, override_reclen == 0 ? aligned : min_len);
    buf.resize(start + write_len, 0u);

    std::memcpy(buf.data() + start + offsetof(TestLinuxDirent64, d_ino), &ino, sizeof(ino));
    int64_t off = static_cast<int64_t>(start + write_len);
    std::memcpy(buf.data() + start + offsetof(TestLinuxDirent64, d_off), &off, sizeof(off));
    std::memcpy(buf.data() + start + offsetof(TestLinuxDirent64, d_reclen), &reclen, sizeof(reclen));
    buf[start + offsetof(TestLinuxDirent64, d_type)] = 8u;
    std::memcpy(buf.data() + start + kNameOff, name.data(), name.size());
    if (!include_nul) {
        for (size_t i = kNameOff + name.size(); i < write_len; ++i) {
            buf[start + i] = 'X';
        }
    }
}

}  // namespace

extern "C" {

int raw_last_error(void) {
    return g_mock.last_err;
}

long my_openat(int, const char *, int, mode_t) {
    g_mock.open_count++;
    if (g_mock.open_err != 0) {
        g_mock.last_err = g_mock.open_err;
        return -1;
    }
    g_mock.last_err = 0;
    return kFakeFd;
}

long my_read(int fd, void *buf, size_t count) {
    if (fd != kFakeFd) {
        g_mock.last_err = EBADF;
        return -1;
    }
    g_mock.read_calls++;
    if (g_mock.inject_eintr_every > 0 && (g_mock.read_calls % g_mock.inject_eintr_every) == 0) {
        g_mock.last_err = EINTR;
        return -1;
    }
    if (g_mock.maps_pos >= g_mock.maps_stream.size()) {
        g_mock.last_err = 0;
        return 0;
    }
    const size_t avail = g_mock.maps_stream.size() - g_mock.maps_pos;
    const size_t n = std::min({count, avail, g_mock.max_read_chunk});
    std::memcpy(buf, g_mock.maps_stream.data() + g_mock.maps_pos, n);
    g_mock.maps_pos += n;
    g_mock.last_err = 0;
    return static_cast<long>(n);
}

long my_close(int) {
    g_mock.close_count++;
    return 0;
}

long my_getdents64(int fd, void *buf, size_t count) {
    if (fd != kFakeFd) {
        g_mock.last_err = EBADF;
        return -1;
    }
    if (g_mock.override_getdents_ret != -999999) {
        g_mock.last_err = g_mock.getdents_err;
        return g_mock.override_getdents_ret;
    }
    if (g_mock.dirent_batch_idx >= g_mock.dirent_batches.size()) {
        g_mock.last_err = 0;
        return 0;
    }
    const auto &batch = g_mock.dirent_batches[g_mock.dirent_batch_idx++];
    const size_t copy_len = std::min(count, batch.size());
    std::memcpy(buf, batch.data(), copy_len);
    g_mock.last_err = 0;
    return static_cast<long>(copy_len);
}

}  // extern "C"

TEST(MapsParser, StreamsOverFourMiBWithoutTruncationAndRetriesEintr) {
    g_mock.reset();
    // Build a >4.5 MiB /proc/self/maps fixture (65,536 entries ~ 5.2 MiB).
    constexpr size_t kLineCount = 65536;
    std::string big;
    big.reserve(kLineCount * 84);
    char line[128] = {};
    for (size_t i = 0; i < kLineCount; ++i) {
        const uint64_t start = 0x7000000000ULL + i * 0x4000ULL;
        const uint64_t end = start + 0x4000ULL;
        const char *perms = (i % 4 == 0) ? "r-xp" : "rw-p";
        const int n = std::snprintf(
                line, sizeof(line),
                "%012llx-%012llx %s 00004000 fe:01 %zu /apex/com.android.runtime/lib64/lib_%05zu.so\n",
                static_cast<unsigned long long>(start),
                static_cast<unsigned long long>(end),
                perms, i + 100, i);
        ASSERT_GT(n, 0);
        big.append(line, static_cast<size_t>(n));
    }
    ASSERT_GT(big.size(), static_cast<size_t>(4 * 1024 * 1024));

    g_mock.maps_stream = std::move(big);
    g_mock.max_read_chunk = 4093;  // Prime chunk size to stress line splits across reads.
    g_mock.inject_eintr_every = 17;

    size_t visited = 0;
    size_t rx_count = 0;
    std::string first_path;
    std::string last_path;
    uintptr_t last_start = 0;

    const bool ok = for_each_self_map([&](const MapEntry &entry) -> bool {
        if (visited == 0) first_path = entry.path;
        last_path = entry.path;
        last_start = entry.start;
        if (is_rx(entry)) rx_count++;
        visited++;
        return true;
    });

    EXPECT_TRUE(ok);
    EXPECT_EQ(visited, kLineCount);
    EXPECT_EQ(rx_count, kLineCount / 4);
    EXPECT_EQ(first_path, "/apex/com.android.runtime/lib64/lib_00000.so");
    EXPECT_EQ(last_path, "/apex/com.android.runtime/lib64/lib_65535.so");
    EXPECT_EQ(last_start, static_cast<uintptr_t>(0x7000000000ULL + 65535ULL * 0x4000ULL));
    EXPECT_EQ(g_mock.open_count, 1);
    EXPECT_EQ(g_mock.close_count, 1);
}

TEST(MapsParser, HandlesOverflowLinesMalformedLinesCrlfAndEarlyStop) {
    g_mock.reset();
    std::string fixture;
    // Valid line with CRLF
    fixture += "1000-2000 r-xp 00000000 fd:00 11 /system/lib64/libc.so\r\n";
    // Malformed lines (inverted range, missing dash, bad hex)
    fixture += "3000-2000 r-xp 00000000 fd:00 12 /bad/inverted.so\n";
    fixture += "notarange r-xp 00000000 fd:00 13 /bad/nodash.so\n";
    // Ultra-long >4096 byte line that MUST be discarded cleanly without corrupting next line
    fixture += "4000-5000 r-xp 00000000 fd:00 14 /" + std::string(5000, 'a') + ".so\n";
    // Anonymous pathless mapping + final line without trailing newline
    fixture += "6000-7000 rw-p 00000000 00:00 0\n";
    fixture += "8000-9000 r-xp 00004000 fd:00 99 /data/app/libtarget.so";

    g_mock.maps_stream = fixture;
    g_mock.max_read_chunk = 37;

    const std::vector<MapEntry> maps = read_self_maps();
    ASSERT_EQ(maps.size(), static_cast<size_t>(3));
    EXPECT_EQ(maps[0].start, static_cast<uintptr_t>(0x1000));
    EXPECT_EQ(maps[0].path, "/system/lib64/libc.so");
    EXPECT_TRUE(maps_path_contains(maps[0], "LIBC.SO"));
    EXPECT_EQ(maps[1].start, static_cast<uintptr_t>(0x6000));
    EXPECT_TRUE(maps[1].path.empty());
    EXPECT_FALSE(is_rx(maps[1]));
    EXPECT_EQ(maps[2].start, static_cast<uintptr_t>(0x8000));
    EXPECT_EQ(maps[2].offset, static_cast<uint64_t>(0x4000));
    EXPECT_EQ(maps[2].inode, static_cast<uint64_t>(99));
    EXPECT_EQ(maps[2].path, "/data/app/libtarget.so");

    const MapEntry *found_so = find_so_map(maps, "libtarget.so");
    ASSERT_NE(found_so, nullptr);
    EXPECT_EQ(found_so->start, static_cast<uintptr_t>(0x8000));
    EXPECT_NE(find_map_containing(maps, 0x8500), nullptr);
    EXPECT_EQ(find_map_containing(maps, 0x9000), nullptr);

    // Early stop via find_self_map_containing
    g_mock.maps_pos = 0;
    MapEntry hit;
    EXPECT_TRUE(find_self_map_containing(0x1500, hit));
    EXPECT_EQ(hit.path, "/system/lib64/libc.so");
}

TEST(RawDir, ListsValidEntriesAcrossBatchesAndFiltersDots) {
    g_mock.reset();
    std::vector<uint8_t> b1;
    append_dirent(b1, 1, ".");
    append_dirent(b1, 2, "..");
    append_dirent(b1, 3, "magisk");
    std::vector<uint8_t> b2;
    append_dirent(b2, 4, "ksud");
    append_dirent(b2, 5, "su");
    g_mock.dirent_batches = {b1, b2};

    const RawDirResult res = raw_list_dir("/fake/dir");
    EXPECT_TRUE(res.ok());
    ASSERT_EQ(res.names.size(), static_cast<size_t>(3));
    EXPECT_EQ(res.names[0], "magisk");
    EXPECT_EQ(res.names[1], "ksud");
    EXPECT_EQ(res.names[2], "su");
    EXPECT_EQ(g_mock.close_count, 1);
}

TEST(RawDir, FuzzMalformedRecLenZeroLenAndTruncationVectorsFailClosed) {
    // 1. nullptr path -> EFAULT
    g_mock.reset();
    EXPECT_EQ(raw_list_dir(nullptr).error, EFAULT);

    // 2. openat EACCES -> EACCES
    g_mock.reset();
    g_mock.open_err = EACCES;
    EXPECT_EQ(raw_list_dir("/root").error, EACCES);

    // 3. d_reclen == 0 (infinite-loop DoS vector) -> EIO
    {
        g_mock.reset();
        std::vector<uint8_t> buf(32, 0u);
        g_mock.dirent_batches = {buf};
        const RawDirResult r = raw_list_dir("/fuzz/zero_reclen");
        EXPECT_FALSE(r.ok());
        EXPECT_EQ(r.error, EIO);
    }

    // 4. d_reclen < offsetof(d_name) + 1 (e.g., 12 bytes) -> EIO
    {
        g_mock.reset();
        std::vector<uint8_t> buf;
        append_dirent(buf, 10, "ok", /*override_reclen=*/12u);
        g_mock.dirent_batches = {buf};
        const RawDirResult r = raw_list_dir("/fuzz/short_reclen");
        EXPECT_EQ(r.error, EIO);
    }

    // 5. d_reclen > bytes_read - pos (buffer overrun) -> EIO
    {
        g_mock.reset();
        std::vector<uint8_t> buf;
        append_dirent(buf, 11, "overrun", /*override_reclen=*/512u);
        g_mock.dirent_batches = {buf};
        const RawDirResult r = raw_list_dir("/fuzz/overrun_reclen");
        EXPECT_EQ(r.error, EIO);
    }

    // 6. Missing NUL terminator inside record -> EIO
    {
        g_mock.reset();
        std::vector<uint8_t> buf;
        append_dirent(buf, 12, "nonul", /*override_reclen=*/0u, /*include_nul=*/false);
        g_mock.dirent_batches = {buf};
        const RawDirResult r = raw_list_dir("/fuzz/missing_nul");
        EXPECT_EQ(r.error, EIO);
    }

    // 7. Truncated trailing bytes (< kNameOffset + 1) -> EIO
    {
        g_mock.reset();
        std::vector<uint8_t> buf(10, 0x41u);
        g_mock.dirent_batches = {buf};
        const RawDirResult r = raw_list_dir("/fuzz/truncated");
        EXPECT_EQ(r.error, EIO);
    }

    // 8. Oversized getdents64 return (> 4096) -> EIO
    {
        g_mock.reset();
        g_mock.override_getdents_ret = 8192;
        const RawDirResult r = raw_list_dir("/fuzz/oversize_ret");
        EXPECT_EQ(r.error, EIO);
    }
}

TEST(PayloadCodec, EscapingRoundTripAndPayloadFraming) {
    using namespace payload_codec;

    const std::string tricky = "path=/data/local\\tmp\tline1\nline2\rkey=val\\end";
    const std::string enc = escape_value(tricky);
    EXPECT_EQ(enc.find('\t'), std::string::npos);
    EXPECT_EQ(enc.find('\n'), std::string::npos);
    EXPECT_EQ(enc.find('\r'), std::string::npos);
    EXPECT_EQ(unescape_value(enc), tricky);

    // Unknown escape sequences and trailing backslash preserve literal bytes safely.
    EXPECT_EQ(unescape_value("abc\\qdef\\"), "abc\\qdef\\");

    EXPECT_TRUE(is_valid_key("probe_id"));
    EXPECT_FALSE(is_valid_key(""));
    EXPECT_FALSE(is_valid_key("bad=key"));
    EXPECT_FALSE(is_valid_key("bad\tkey"));
    EXPECT_FALSE(is_valid_key("bad\nkey"));
    EXPECT_FALSE(is_valid_key("bad\\key"));

    PayloadBuilder pb(Status::RESTRICTED, EACCES);
    pb.add_header("status", "OK");       // Must be ignored (reserved)
    pb.add_header("errno", "0");         // Must be ignored (reserved)
    pb.add_header("scope", "a=b\tc");
    pb.add_header_int("count", -7);

    RecordBuilder rec;
    rec.add("kind", "hit")
       .add("bad=key", "ignored")
       .add("path", "/a/b=c\td\ne")
       .add_int("delta", -42)
       .add_uint("uid", 10123ULL)
       .add_bool("hidden", true);
    pb.add_record(rec);

    const std::string frame = pb.build();
    const std::string expected_header =
            "status=RESTRICTED\terrno=" + std::to_string(EACCES)
            + "\tscope=a\\=b\\tc\tcount=-7";
    const std::string expected_rec =
            "kind=hit\tpath=/a/b\\=c\\td\\ne\tdelta=-42\tuid=10123\thidden=1";
    EXPECT_EQ(frame, expected_header + "\n" + expected_rec);
}

RISKENGINE_DEFINE_TEST_MAIN()
