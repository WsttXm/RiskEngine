#include "mini_gtest.h"

#include "detector/bionic_prop_area.h"
#include "util/maps_parser.h"
#include "util/safe_mem_read.h"
#include "util/syscall_wrapper.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

// Include REAL production native_integrity.cpp to test DiskElf + collect_exec_ranges directly.
#include "detector/native_integrity.cpp"

namespace safe_mem {
void ScopedFd::reset(int new_fd) noexcept {
    if (fd_ >= 0) ::close(fd_);
    fd_ = new_fd;
}
PagemapReader::PagemapReader() noexcept : fd_(-1) {}
bool PagemapReader::read_pages(uintptr_t, size_t, size_t, std::vector<PageResidency> &) const {
    return false;
}
bool PagemapReader::is_page_cow_anonymous(uintptr_t, size_t, bool &) const {
    return false;
}
PipeMemoryReader::PipeMemoryReader() noexcept : read_end_(-1), write_end_(-1) {}
bool PipeMemoryReader::read(uintptr_t, void *, size_t) noexcept { return false; }
void PipeMemoryReader::drain() noexcept {}
}  // namespace safe_mem

extern "C" {
int raw_last_error(void) { return errno; }
long my_openat(int dirfd, const char *path, int flags, mode_t mode) {
    return ::openat(dirfd, path, flags, mode);
}
long my_read(int fd, void *buf, size_t count) {
    return ::read(fd, buf, count);
}
long my_pread64(int fd, void *buf, size_t count, uint64_t offset) {
    return ::pread(fd, buf, count, static_cast<off_t>(offset));
}
long my_close(int fd) { return ::close(fd); }
long my_fstatat(int dirfd, const char *path, struct stat *st, int flags) {
    return ::fstatat(dirfd, path, st, flags);
}
long my_gettid(void) { return static_cast<long>(::getpid()); }
}  // extern "C"

namespace {

using namespace riskengine::prop_forensics;

struct PropAreaBuilder {
    std::vector<uint8_t> data;
    uint32_t root_children = 0;

    explicit PropAreaBuilder(bool reserve_dirty_backup = true) {
        data.resize(sizeof(DiskPropTrieNode), 0u);  // Root node at data offset 0
        if (reserve_dirty_backup) {
            data.resize(sizeof(DiskPropTrieNode) + kDirtyBackupAreaSize, 0u);
        }
    }

    static size_t align4(size_t n) {
        return (n + 3u) & ~static_cast<size_t>(3u);
    }

    uint32_t add_raw_hole(uint32_t hole_bytes) {
        const uint32_t off = static_cast<uint32_t>(data.size());
        data.resize(data.size() + align4(hole_bytes), 0u);
        return off;
    }

    uint32_t add_prop(const std::string &full_name,
                      const std::string &value,
                      uint32_t serial = 0,
                      const std::string &trailing_after_nul = "") {
        const uint32_t off = static_cast<uint32_t>(data.size());
        const size_t total = align4(sizeof(DiskPropInfo) + full_name.size() + 1u);
        data.resize(off + total, 0u);

        DiskPropInfo info{};
        info.serial = serial;
        if ((serial & kLongFlag) == 0) {
            const size_t copy_len = std::min(value.size(), kPropValueMax - 1u);
            std::memcpy(info.value, value.data(), copy_len);
            info.value[copy_len] = '\0';
            if (!trailing_after_nul.empty() && copy_len + 1u < kPropValueMax) {
                const size_t tail_len = std::min(
                        trailing_after_nul.size(), kPropValueMax - copy_len - 1u);
                std::memcpy(info.value + copy_len + 1u, trailing_after_nul.data(), tail_len);
            }
        } else {
            // Long property: fill error_message bytes to verify 0-FP on NUL-tail check,
            // and store the long value string immediately after this aligned prop record.
            std::memset(info.long_property.error_message, 'L',
                        sizeof(info.long_property.error_message));
            const std::string long_val = value.empty()
                    ? std::string(100, 'F')
                    : value;
            const size_t val_alloc = align4(long_val.size() + 1u);
            info.long_property.offset = static_cast<uint32_t>(total);
            data.resize(off + total + val_alloc, 0u);
            std::memcpy(data.data() + off + total, long_val.data(), long_val.size());
        }
        std::memcpy(data.data() + off, &info, sizeof(info));
        std::memcpy(data.data() + off + sizeof(DiskPropInfo),
                    full_name.data(), full_name.size());
        return off;
    }

    uint32_t add_trie_node(const std::string &segment,
                           uint32_t prop_off = 0,
                           uint32_t left = 0,
                           uint32_t right = 0,
                           uint32_t children = 0) {
        const uint32_t off = static_cast<uint32_t>(data.size());
        const size_t total = align4(sizeof(DiskPropTrieNode) + segment.size() + 1u);
        data.resize(off + total, 0u);

        DiskPropTrieNode node{};
        node.namelen = static_cast<uint32_t>(segment.size());
        node.prop = prop_off;
        node.left = left;
        node.right = right;
        node.children = children;
        std::memcpy(data.data() + off, &node, sizeof(node));
        std::memcpy(data.data() + off + sizeof(DiskPropTrieNode),
                    segment.data(), segment.size());
        return off;
    }

    std::vector<uint8_t> build() {
        DiskPropTrieNode root{};
        root.namelen = 0;
        root.children = root_children;
        std::memcpy(data.data(), &root, sizeof(root));

        std::vector<uint8_t> image(sizeof(DiskPropAreaHeader) + data.size(), 0u);
        DiskPropAreaHeader hdr{};
        hdr.bytes_used = static_cast<uint32_t>(data.size());
        hdr.serial = 1;
        hdr.magic = kPropAreaMagic;
        hdr.version = kPropAreaVersion;
        std::memcpy(image.data(), &hdr, sizeof(hdr));
        std::memcpy(image.data() + sizeof(DiskPropAreaHeader), data.data(), data.size());
        return image;
    }
};

struct ScopedTempFile {
    std::string path;

    explicit ScopedTempFile(const std::vector<uint8_t> &bytes) {
        char tmpl[] = "/tmp/riskengine_elf_test_XXXXXX";
        const int fd = ::mkstemp(tmpl);
        if (fd >= 0) {
            path = tmpl;
            size_t written = 0;
            while (written < bytes.size()) {
                const ssize_t n = ::write(fd, bytes.data() + written, bytes.size() - written);
                if (n <= 0) break;
                written += static_cast<size_t>(n);
            }
            ::close(fd);
        }
    }

    ~ScopedTempFile() {
        if (!path.empty()) {
            ::unlink(path.c_str());
        }
    }
};

std::vector<uint8_t> build_synthetic_elf(uint64_t base_offset,
                                         bool include_shdrs,
                                         uint64_t page_align = 0x4000) {
    // Layout inside ELF (relative to base_offset):
    //   0x0000: Ehdr + 2 Phdrs (PT_LOAD RX at offset 0x4000, vaddr 0x8000 to verify p_vaddr != p_offset!)
    //   0x4000..0x4FFF: RX PT_LOAD (4 KiB), with .text SHF_EXECINSTR at vaddr 0x8200..0x8A00 (file_off 0x4200)
    //   0x5000: optional 2 Shdrs (null + .text SHF_EXECINSTR)
    const uint64_t elf_size = 0x6000;
    std::vector<uint8_t> file(static_cast<size_t>(base_offset + elf_size), 0u);
    uint8_t *base = file.data() + base_offset;

    Ehdr ehdr{};
    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_ehsize = sizeof(Ehdr);
    ehdr.e_phoff = sizeof(Ehdr);
    ehdr.e_phentsize = sizeof(Phdr);
    ehdr.e_phnum = 2;
    if (include_shdrs) {
        ehdr.e_shoff = 0x5000;
        ehdr.e_shentsize = sizeof(Shdr);
        ehdr.e_shnum = 2;
    }

    Phdr ph0{};
    ph0.p_type = PT_LOAD;
    ph0.p_flags = PF_R;
    ph0.p_offset = 0;
    ph0.p_vaddr = 0;
    ph0.p_filesz = 0x1000;
    ph0.p_memsz = 0x1000;
    ph0.p_align = page_align;

    Phdr ph1{};
    ph1.p_type = PT_LOAD;
    ph1.p_flags = PF_R | PF_X;
    ph1.p_offset = 0x4000;
    ph1.p_vaddr = 0x8000;   // Distinct from p_offset to verify vaddr->file_off math!
    ph1.p_filesz = 0x1000;
    ph1.p_memsz = 0x1000;
    ph1.p_align = page_align;

    std::memcpy(base, &ehdr, sizeof(ehdr));
    std::memcpy(base + ehdr.e_phoff, &ph0, sizeof(ph0));
    std::memcpy(base + ehdr.e_phoff + sizeof(Phdr), &ph1, sizeof(ph1));

    // Fill .text bytes with identifiable pattern
    std::memset(base + 0x4200, 0x90, 0x800);

    if (include_shdrs) {
        Shdr sh0{};
        Shdr sh1{};
        sh1.sh_type = SHT_PROGBITS;
        sh1.sh_flags = SHF_EXECINSTR;
        sh1.sh_addr = 0x8200;
        sh1.sh_offset = 0x4200;
        sh1.sh_size = 0x800;
        std::memcpy(base + ehdr.e_shoff, &sh0, sizeof(sh0));
        std::memcpy(base + ehdr.e_shoff + sizeof(Shdr), &sh1, sizeof(sh1));
    }

    return file;
}

}  // namespace

TEST(BionicPropArea, CleanApi30ImageAndDirtyBackupGating) {
    PropAreaBuilder b(/*reserve_dirty_backup=*/true);
    const uint32_t prop_off = b.add_prop("ro.boot.verifiedbootstate", "green", /*serial=*/0u);
    b.root_children = b.add_trie_node("ro", prop_off);
    const std::vector<uint8_t> image = b.build();

    // On API 30+, the 92-byte dirty_backup_area is reserved -> 0 holes.
    const AreaAnalysisResult api30 = analyze_prop_area_image(image.data(), image.size(), 30);
    EXPECT_TRUE(api30.parsed);
    EXPECT_EQ(api30.ro_checked, static_cast<uint32_t>(1));
    EXPECT_TRUE(api30.holes.empty());
    EXPECT_TRUE(api30.serial_anomalies.empty());
    EXPECT_TRUE(api30.nul_tail_anomalies.empty());

    // On API 29, dirty_backup_area is NOT reserved -> exact 92-byte HoleRun at offset 20.
    const AreaAnalysisResult api29 = analyze_prop_area_image(image.data(), image.size(), 29);
    EXPECT_TRUE(api29.parsed);
    ASSERT_EQ(api29.holes.size(), static_cast<size_t>(1));
    EXPECT_EQ(api29.holes[0].offset, static_cast<uint32_t>(sizeof(DiskPropTrieNode)));
    EXPECT_EQ(api29.holes[0].length, static_cast<uint32_t>(kDirtyBackupAreaSize));
}

TEST(BionicPropArea, DetectsHoleRunDirtySerialNulTailAndSkipsLongPropTail) {
    PropAreaBuilder b(/*reserve_dirty_backup=*/true);

    // Unreferenced 128-byte gap simulating resetprop --delete
    const uint32_t hole_off = b.add_raw_hole(128u);

    // Dirty serial (write_count = 3 -> serial = 3 << 1 = 6) + dirty trailing bytes after NUL ("orange")
    const uint32_t p1 = b.add_prop(
            "ro.boot.verifiedbootstate", "green", /*serial=*/(3u << 1), "orange");
    // Long critical property (kLongFlag set) with dirty serial=0 -> must NOT trigger NUL-tail FP
    const uint32_t p2 = b.add_prop(
            "ro.build.fingerprint", "", /*serial=*/kLongFlag);

    const uint32_t n2 = b.add_trie_node("fingerprint", p2);
    const uint32_t n1 = b.add_trie_node("verifiedbootstate", p1, /*left=*/0, /*right=*/n2);
    b.root_children = n1;

    const std::vector<uint8_t> image = b.build();
    const AreaAnalysisResult res = analyze_prop_area_image(image.data(), image.size(), 36);

    EXPECT_TRUE(res.parsed);
    EXPECT_EQ(res.ro_checked, static_cast<uint32_t>(2));

    ASSERT_EQ(res.holes.size(), static_cast<size_t>(1));
    EXPECT_EQ(res.holes[0].offset, hole_off);
    EXPECT_EQ(res.holes[0].length, static_cast<uint32_t>(128));

    ASSERT_EQ(res.serial_anomalies.size(), static_cast<size_t>(1));
    EXPECT_EQ(res.serial_anomalies[0].prop_name, "ro.boot.verifiedbootstate");
    EXPECT_EQ(res.serial_anomalies[0].write_count, static_cast<uint32_t>(3));

    ASSERT_EQ(res.nul_tail_anomalies.size(), static_cast<size_t>(1));
    EXPECT_EQ(res.nul_tail_anomalies[0].prop_name, "ro.boot.verifiedbootstate");
    EXPECT_EQ(res.nul_tail_anomalies[0].clean_value, "green");
    EXPECT_EQ(res.nul_tail_anomalies[0].nonzero_trailing_bytes, static_cast<uint32_t>(6));
}

TEST(BionicPropArea, RejectsMalformedAndCyclicImages) {
    // Bad magic
    std::vector<uint8_t> bad(256, 0u);
    EXPECT_FALSE(analyze_prop_area_image(bad.data(), bad.size(), 34).parsed);

    // Self-loop cycle in trie node must terminate cleanly without hanging
    PropAreaBuilder b(true);
    const uint32_t node_off = b.add_trie_node("loop");
    // Patch node.left = node_off (cycle)
    DiskPropTrieNode patched{};
    std::memcpy(&patched, b.data.data() + node_off, sizeof(patched));
    patched.left = node_off;
    std::memcpy(b.data.data() + node_off, &patched, sizeof(patched));
    b.root_children = node_off;
    const auto img = b.build();
    const AreaAnalysisResult res = analyze_prop_area_image(img.data(), img.size(), 34);
    EXPECT_TRUE(res.parsed);  // visited_nodes breaks cycle deterministically

    // Out-of-bounds offset fails closed
    PropAreaBuilder bad_oob(true);
    bad_oob.root_children = 0xFFFFFF00u;
    const auto oob_img = bad_oob.build();
    EXPECT_FALSE(analyze_prop_area_image(oob_img.data(), oob_img.size(), 34).parsed);
}

TEST(BionicPropArea, ParsesPropertyInfoContextsAndFiltersUnsafePaths) {
    std::vector<uint8_t> img(256, 0u);
    const uint32_t ctx_table_off = 32u;
    const uint32_t s0_off = 64u;
    const uint32_t s1_off = 100u;
    const uint32_t s2_off = 140u;
    const uint32_t s3_off = 180u;

    const char *s0 = "u:object_r:default_prop:s0";
    const char *s1 = "../escape_attempt";
    const char *s2 = "u:object_r:adbd_config_prop:s0";
    const char *s3 = "u:object_r:default_prop:s0";  // duplicate

    std::memcpy(img.data() + s0_off, s0, std::strlen(s0) + 1);
    std::memcpy(img.data() + s1_off, s1, std::strlen(s1) + 1);
    std::memcpy(img.data() + s2_off, s2, std::strlen(s2) + 1);
    std::memcpy(img.data() + s3_off, s3, std::strlen(s3) + 1);

    uint32_t count = 4u;
    uint32_t offs[4] = {s0_off, s1_off, s2_off, s3_off};
    std::memcpy(img.data() + ctx_table_off, &count, sizeof(count));
    std::memcpy(img.data() + ctx_table_off + 4u, offs, sizeof(offs));

    DiskPropertyInfoHeader hdr{};
    hdr.current_version = 1;
    hdr.minimum_supported_version = 1;
    hdr.size = static_cast<uint32_t>(img.size());
    hdr.contexts_offset = ctx_table_off;
    std::memcpy(img.data(), &hdr, sizeof(hdr));

    std::vector<std::string> contexts;
    ASSERT_TRUE(parse_property_info_contexts(img.data(), img.size(), contexts));
    ASSERT_EQ(contexts.size(), static_cast<size_t>(2));
    EXPECT_EQ(contexts[0], "u:object_r:default_prop:s0");
    EXPECT_EQ(contexts[1], "u:object_r:adbd_config_prop:s0");
    EXPECT_TRUE(is_high_priority_hole_context(contexts[1].c_str(), contexts[1].size()));
    EXPECT_FALSE(is_high_priority_hole_context(contexts[0].c_str(), contexts[0].size()));
    EXPECT_TRUE(is_security_critical_ro_prop("ro.boot.verifiedbootstate", 25));
    EXPECT_FALSE(is_security_critical_ro_prop("ro.custom.benign", 16));
}

TEST(DiskElf, Parses16KbAlignedElfWithShfExecInstrAndApkBaseOffset) {
    // Embedded at 16 KiB offset inside a container (simulating extractNativeLibs=false base.apk).
    constexpr uint64_t kApkBaseOff = 0x4000;
    const auto bytes = build_synthetic_elf(kApkBaseOff, /*include_shdrs=*/true, /*page_align=*/0x4000);
    ScopedTempFile tmp(bytes);
    ASSERT_FALSE(tmp.path.empty());

    DiskElf elf;
    ASSERT_TRUE(elf.open(tmp.path, kApkBaseOff, /*mem_base=*/0x7100000000ULL));
    EXPECT_EQ(elf.load_bias, static_cast<uintptr_t>(0x7100000000ULL));
    EXPECT_EQ(elf.phdrs.size(), static_cast<size_t>(2));
    EXPECT_EQ(elf.shdrs.size(), static_cast<size_t>(2));

    uint64_t file_off = 0;
    ASSERT_TRUE(elf.vaddr_to_offset(0x8200, file_off));
    EXPECT_EQ(file_off, kApkBaseOff + 0x4200ULL);

    const std::vector<ExecRange> ranges = collect_exec_ranges(elf);
    ASSERT_EQ(ranges.size(), static_cast<size_t>(1));
    EXPECT_EQ(ranges[0].vaddr, static_cast<uint64_t>(0x8200));
    EXPECT_EQ(ranges[0].file_off, kApkBaseOff + 0x4200ULL);
    EXPECT_EQ(ranges[0].size, static_cast<uint64_t>(0x800));
}

TEST(DiskElf, FallsBackToPtLoadWhenSectionHeadersStrippedAndRejectsMalformed) {
    const auto stripped = build_synthetic_elf(0, /*include_shdrs=*/false, /*page_align=*/0x4000);
    ScopedTempFile tmp_stripped(stripped);
    ASSERT_FALSE(tmp_stripped.path.empty());

    DiskElf elf;
    ASSERT_TRUE(elf.open(tmp_stripped.path, 0, /*mem_base=*/0x7200000000ULL));
    EXPECT_TRUE(elf.shdrs.empty());

    const std::vector<ExecRange> ranges = collect_exec_ranges(elf);
    ASSERT_EQ(ranges.size(), static_cast<size_t>(1));
    EXPECT_EQ(ranges[0].vaddr, static_cast<uint64_t>(0x8000));
    EXPECT_EQ(ranges[0].file_off, static_cast<uint64_t>(0x4000));
    EXPECT_EQ(ranges[0].size, static_cast<uint64_t>(0x1000));

    // Corrupt ELF magic -> open must fail closed
    auto broken = stripped;
    broken[0] = 0x00;
    ScopedTempFile tmp_broken(broken);
    ASSERT_FALSE(tmp_broken.path.empty());
    DiskElf bad_elf;
    EXPECT_FALSE(bad_elf.open(tmp_broken.path, 0, 0x7200000000ULL));
}

RISKENGINE_DEFINE_TEST_MAIN()
