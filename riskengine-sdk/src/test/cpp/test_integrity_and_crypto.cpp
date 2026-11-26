#include "mini_gtest.h"

#include "util/crypto_mini.h"
#include "util/maps_parser.h"
#include "util/obf_str.h"
#include "util/safe_mem_read.h"
#include "util/syscall_wrapper.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

// Include the REAL production native_integrity.cpp with RISKENGINE_HOST_TEST=1
// so all 4 ABI trampoline decoders + branch_stays_in_image are tested directly.
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

std::string to_hex(const uint8_t *bytes, size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(bytes[i] >> 4) & 0xFu]);
        out.push_back(kHex[bytes[i] & 0xFu]);
    }
    return out;
}

std::string sha256_hex(const std::string &input, size_t step = 0) {
    crypto_mini::Sha256 sha;
    const auto *ptr = reinterpret_cast<const uint8_t *>(input.data());
    if (step == 0 || input.empty()) {
        sha.update(ptr, input.size());
    } else {
        size_t pos = 0;
        while (pos < input.size()) {
            const size_t chunk = std::min(step, input.size() - pos);
            sha.update(ptr + pos, chunk);
            pos += chunk;
        }
    }
    uint8_t digest[crypto_mini::kSha256DigestSize] = {};
    sha.final(digest);
    return to_hex(digest, sizeof(digest));
}

std::vector<MapEntry> make_contiguous_lib_maps() {
    MapEntry ro{};
    ro.start = 0x7000000000ULL;
    ro.end = 0x7000004000ULL;
    ro.inode = 12345;
    ro.perms = "r--p";
    ro.path = "/system/lib64/libdl.so";

    MapEntry rx1{};
    rx1.start = 0x7000004000ULL;
    rx1.end = 0x7000008000ULL;
    rx1.inode = 12345;
    rx1.perms = "r-xp";
    rx1.path = "/system/lib64/libdl.so";

    MapEntry rx2{};
    rx2.start = 0x7000008000ULL;
    rx2.end = 0x700000C000ULL;
    rx2.inode = 12345;
    rx2.perms = "r-xp";
    rx2.path = "/system/lib64/libdl.so";

    return {ro, rx1, rx2};
}

}  // namespace

TEST(CryptoMini, Sha256Fips180_4VectorsAndStreamingBoundaries) {
    // Empty message
    EXPECT_EQ(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    // "abc"
    EXPECT_EQ(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    // 56-byte (boundary requiring two-block padding)
    const std::string v56 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const std::string expected56 =
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    EXPECT_EQ(sha256_hex(v56), expected56);
    EXPECT_EQ(sha256_hex(v56, 1), expected56);
    EXPECT_EQ(sha256_hex(v56, 7), expected56);

    // 1,000,000 'a' characters (NIST standard long vector)
    const std::string million_a(1000000, 'a');
    EXPECT_EQ(
            sha256_hex(million_a, 1009),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(CryptoMini, ConstantTimeMemcmpAndSecureZero) {
    const uint8_t a[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint8_t b[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t c[8] = {1, 2, 3, 4, 5, 6, 7, 9};

    EXPECT_TRUE(crypto_mini::ct_memcmp(a, b, sizeof(a)));
    EXPECT_TRUE(crypto_mini::ct_memcmp(a, c, 0));
    EXPECT_FALSE(crypto_mini::ct_memcmp(a, c, sizeof(a)));
    c[7] = 8;
    c[0] = 0;
    EXPECT_FALSE(crypto_mini::ct_memcmp(a, c, sizeof(a)));

    uint8_t secret[32];
    std::memset(secret, 0xA5, sizeof(secret));
    crypto_mini::secure_zero(secret, sizeof(secret));
    for (uint8_t byte : secret) {
        EXPECT_EQ(byte, static_cast<uint8_t>(0));
    }
    // Null/zero-length safety
    crypto_mini::secure_zero(nullptr, 16);
    crypto_mini::secure_zero(secret, 0);
}

TEST(TrampolineArm64, DetectsHookPatternsAndGuardsIntraImageBranch) {
    const auto maps = make_contiguous_lib_maps();
    const uintptr_t addr = 0x7000005000ULL;
    const uintptr_t r_start = 0x7000004000ULL;
    const uintptr_t r_end = 0x7000008000ULL;

    auto run_arm64 = [&](const uint32_t insns[4]) {
        uint8_t bytes[16] = {};
        std::memcpy(bytes, insns, sizeof(bytes));
        return looks_like_trampoline_arm64(bytes, sizeof(bytes), addr, maps, r_start, r_end);
    };

    // Clean ARM64 prologue: STP X29, X30, [SP, #-16]!; MOV X29, SP; SUB SP, SP, #32; NOP
    const uint32_t clean[4] = {0xA9BF7BFDu, 0x910003FDu, 0xD10083FFu, 0xD503201Fu};
    EXPECT_FALSE(run_arm64(clean));

    // BRK #0
    const uint32_t brk[4] = {0xD4200000u, 0xD503201Fu, 0xD503201Fu, 0xD503201Fu};
    EXPECT_TRUE(run_arm64(brk));

    // LDR X16, [PC, #8]; BR X16 (Frida/Dobby classic trampoline)
    const uint32_t ldr_br[4] = {0x58000050u, 0xD61F0200u, 0x12345678u, 0x00000070u};
    EXPECT_TRUE(run_arm64(ldr_br));

    // Mismatched registers LDR X16; BR X17 -> must NOT trigger
    const uint32_t ldr_br_mismatch[4] = {0x58000050u, 0xD61F0220u, 0xD503201Fu, 0xD503201Fu};
    EXPECT_FALSE(run_arm64(ldr_br_mismatch));

    // ADRP X16, #0; ADD X16, X16, #0; BR X16
    const uint32_t adrp_add_br[4] = {0x90000010u, 0x91000210u, 0xD61F0200u, 0xD503201Fu};
    EXPECT_TRUE(run_arm64(adrp_add_br));

    // MOVZ X16, #0x1234; MOVK X16, #0x5678, LSL #16; BR X16
    const uint32_t movz_br[4] = {0xD2824690u, 0xF2AACF10u, 0xD61F0200u, 0xD503201Fu};
    EXPECT_TRUE(run_arm64(movz_br));

    // Direct B +0x4000 -> lands in rx2 (0x7000009000) same contiguous image -> FALSE (no LLVM FP)
    const uint32_t b_in_image[4] = {0x14000000u | (0x4000u >> 2), 0, 0, 0};
    EXPECT_FALSE(run_arm64(b_in_image));

    // Direct B +0x20000 -> lands outside image (0x7000025000) -> TRUE
    const uint32_t b_out_image[4] = {0x14000000u | (0x20000u >> 2), 0, 0, 0};
    EXPECT_TRUE(run_arm64(b_out_image));
}

TEST(TrampolineArm32, DetectsThumb2AndA32HooksAndGuardsIntraImageBranch) {
    const auto maps = make_contiguous_lib_maps();
    const uintptr_t addr_a32 = 0x7000005000ULL;
    const uintptr_t addr_thumb = addr_a32 | 1u;
    const uintptr_t r_start = 0x7000004000ULL;
    const uintptr_t r_end = 0x7000008000ULL;

    // Thumb 16-bit BKPT #0 (0xBE00)
    {
        const uint16_t thumb_bkpt[2] = {0xBE00u, 0xBF00u};
        uint8_t bytes[4] = {};
        std::memcpy(bytes, thumb_bkpt, sizeof(bytes));
        EXPECT_TRUE(looks_like_trampoline_arm32(bytes, sizeof(bytes), addr_thumb, maps, r_start, r_end));
    }

    // Thumb-2 LDR.W PC, [PC, #0] (F8DF F000)
    {
        const uint16_t thumb2_ldr[2] = {0xF8DFu, 0xF000u};
        uint8_t bytes[4] = {};
        std::memcpy(bytes, thumb2_ldr, sizeof(bytes));
        EXPECT_TRUE(looks_like_trampoline_arm32(bytes, sizeof(bytes), addr_thumb, maps, r_start, r_end));
    }

    // Thumb-2 B.W +0x4000 (stays inside contiguous image rx2) -> FALSE
    // Encoding T4: offset = +0x4000 => S=0, J1=1 (I1=0), J2=1 (I2=0), imm10=0x004, imm11=0x000
    {
        const uint16_t hw0 = 0xF004u;
        const uint16_t hw1 = 0xB800u;
        uint8_t bytes[4] = {};
        std::memcpy(bytes, &hw0, 2);
        std::memcpy(bytes + 2, &hw1, 2);
        EXPECT_FALSE(looks_like_trampoline_arm32(bytes, sizeof(bytes), addr_thumb, maps, r_start, r_end));
    }

    // Thumb-2 B.W +0x40000 (outside image) -> TRUE
    {
        const uint16_t hw0 = 0xF040u;
        const uint16_t hw1 = 0xB800u;
        uint8_t bytes[4] = {};
        std::memcpy(bytes, &hw0, 2);
        std::memcpy(bytes + 2, &hw1, 2);
        EXPECT_TRUE(looks_like_trampoline_arm32(bytes, sizeof(bytes), addr_thumb, maps, r_start, r_end));
    }

    // A32 LDR PC, [PC, #-4] (0xE51FF004) -> TRUE
    {
        const uint32_t a32_ldr = 0xE51FF004u;
        uint8_t bytes[4] = {};
        std::memcpy(bytes, &a32_ldr, 4);
        EXPECT_TRUE(looks_like_trampoline_arm32(bytes, sizeof(bytes), addr_a32, maps, r_start, r_end));
    }

    // A32 BX LR (0xE12FFF1E) -> FALSE (normal function return), BX r12 (0xE12FFF1C) -> TRUE
    {
        const uint32_t bx_lr = 0xE12FFF1Eu;
        const uint32_t bx_r12 = 0xE12FFF1Cu;
        uint8_t b_lr[4] = {};
        uint8_t b_r12[4] = {};
        std::memcpy(b_lr, &bx_lr, 4);
        std::memcpy(b_r12, &bx_r12, 4);
        EXPECT_FALSE(looks_like_trampoline_arm32(b_lr, 4, addr_a32, maps, r_start, r_end));
        EXPECT_TRUE(looks_like_trampoline_arm32(b_r12, 4, addr_a32, maps, r_start, r_end));
    }
}

TEST(TrampolineX86, DetectsX86_64AndX86HooksAndGuardsIntraImageJmp) {
    const auto maps = make_contiguous_lib_maps();
    const uintptr_t addr = 0x7000005000ULL;
    const uintptr_t r_start = 0x7000004000ULL;
    const uintptr_t r_end = 0x7000008000ULL;

    // Clean x86_64 prologue: push rbp; mov rbp, rsp; sub rsp, 0x20
    const uint8_t clean[12] = {0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x90, 0x90, 0x90, 0x90};
    EXPECT_FALSE(looks_like_trampoline_x86_common(clean, sizeof(clean), addr, maps, r_start, r_end, true));
    EXPECT_FALSE(looks_like_trampoline_x86_common(clean, sizeof(clean), addr, maps, r_start, r_end, false));

    // INT3
    const uint8_t int3[6] = {0xCC, 0x90, 0x90, 0x90, 0x90, 0x90};
    EXPECT_TRUE(looks_like_trampoline_x86_common(int3, sizeof(int3), addr, maps, r_start, r_end, true));

    // FF 25 [rip+disp32]
    const uint8_t ff25[6] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    EXPECT_TRUE(looks_like_trampoline_x86_common(ff25, sizeof(ff25), addr, maps, r_start, r_end, true));

    // PUSH imm32; RET
    const uint8_t push_ret[6] = {0x68, 0x78, 0x56, 0x34, 0x12, 0xC3};
    EXPECT_TRUE(looks_like_trampoline_x86_common(push_ret, sizeof(push_ret), addr, maps, r_start, r_end, false));

    // x86_64 MOVABS RAX, imm64; JMP RAX
    const uint8_t movabs_jmp[12] = {0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8, 0xFF, 0xE0};
    EXPECT_TRUE(looks_like_trampoline_x86_common(movabs_jmp, sizeof(movabs_jmp), addr, maps, r_start, r_end, true));
    EXPECT_FALSE(looks_like_trampoline_x86_common(movabs_jmp, sizeof(movabs_jmp), addr, maps, r_start, r_end, false));

    // x86 (32-bit) MOV EAX, imm32; JMP EAX
    const uint8_t mov32_jmp[7] = {0xB8, 0x11, 0x22, 0x33, 0x44, 0xFF, 0xE0};
    EXPECT_TRUE(looks_like_trampoline_x86_common(mov32_jmp, sizeof(mov32_jmp), addr, maps, r_start, r_end, false));
    EXPECT_FALSE(looks_like_trampoline_x86_common(mov32_jmp, sizeof(mov32_jmp), addr, maps, r_start, r_end, true));

    // E9 rel32 intra-image (+0x4000 -> rx2) -> FALSE
    uint8_t jmp_in[6] = {0xE9, 0, 0, 0, 0, 0x90};
    const int32_t disp_in = 0x4000 - 5;
    std::memcpy(jmp_in + 1, &disp_in, sizeof(disp_in));
    EXPECT_FALSE(looks_like_trampoline_x86_common(jmp_in, sizeof(jmp_in), addr, maps, r_start, r_end, true));

    // E9 rel32 out-of-image (+0x40000) -> TRUE
    uint8_t jmp_out[6] = {0xE9, 0, 0, 0, 0, 0x90};
    const int32_t disp_out = 0x40000;
    std::memcpy(jmp_out + 1, &disp_out, sizeof(disp_out));
    EXPECT_TRUE(looks_like_trampoline_x86_common(jmp_out, sizeof(jmp_out), addr, maps, r_start, r_end, true));
}

RISKENGINE_DEFINE_TEST_MAIN()
