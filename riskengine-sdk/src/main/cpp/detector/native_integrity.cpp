#include "native_integrity.h"
#include "../generated/detection_lists.h"
#include "../util/crypto_mini.h"
#include "../util/maps_parser.h"
#include "../util/obf_str.h"
#include "../util/safe_mem_read.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <jni.h>
#include <limits>
#include <link.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr size_t kPrologueBytes = 16;
constexpr size_t kShaWindowBytes = 64 * 1024;
constexpr size_t kShaSubChunkBytes = 4096;
constexpr size_t kMaxRecordedJni = 32;
constexpr size_t kMaxRecordedCoreFns = 8;

struct RecordedFnBaseline {
    uintptr_t masked_ptr = 0;
    uint8_t prologue_sha256[crypto_mini::kSha256DigestSize] = {};
    char tag[40] = {};
    bool has_prologue = false;
    bool valid = false;
};

std::atomic<uintptr_t> g_ptr_mask{0};
std::atomic<size_t> g_jni_count{0};
RecordedFnBaseline g_jni_baselines[kMaxRecordedJni] = {};

std::atomic<size_t> g_core_fn_count{0};
RecordedFnBaseline g_core_fn_baselines[kMaxRecordedCoreFns] = {};

uintptr_t get_or_init_ptr_mask() noexcept {
    uintptr_t cur = g_ptr_mask.load(std::memory_order_acquire);
    if (cur != 0) return cur;
    uintptr_t seed = reinterpret_cast<uintptr_t>(&g_ptr_mask)
            ^ static_cast<uintptr_t>(0xA55A5AA5C33C3CC3ULL)
            ^ (static_cast<uintptr_t>(my_gettid()) << 7);
    if (seed == 0) seed = static_cast<uintptr_t>(0x5A3C96F1ULL);
    uintptr_t expected = 0;
    if (g_ptr_mask.compare_exchange_strong(expected, seed,
                                           std::memory_order_acq_rel,
                                           std::memory_order_acquire)) {
        return seed;
    }
    return expected;
}

inline uintptr_t strip_code_thumb_bit(uintptr_t addr) noexcept {
#if defined(__arm__)
    return addr & ~static_cast<uintptr_t>(1u);
#else
    return addr;
#endif
}

bool compute_mem_prologue_sha256(safe_mem::PipeMemoryReader &mem,
                                 uintptr_t raw_addr,
                                 uint8_t out[crypto_mini::kSha256DigestSize]) noexcept {
    const uintptr_t code_addr = strip_code_thumb_bit(raw_addr);
    if (code_addr == 0) return false;
    uint8_t buf[kPrologueBytes] = {};
    if (!mem.read(code_addr, buf, sizeof(buf))) {
        return false;
    }
    crypto_mini::Sha256 sha;
    sha.update(buf, sizeof(buf));
    sha.final(out);
    return true;
}

void add_finding(std::vector<IntegrityFinding> &findings,
                 const std::string &token,
                 const std::string &code,
                 const std::string &location,
                 const std::string &value) {
    if (token.empty()) return;
    for (const auto &existing : findings) {
        if (existing.token == token) return;
    }
    findings.push_back({token, code, location, value});
}

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool path_is_named(const std::string &path, const std::string &so) {
    auto pos = path.rfind('/');
    std::string name = pos == std::string::npos ? path : path.substr(pos + 1);
    return name == so || name.find(so + ".") == 0;
}

const MapEntry *lowest_named_map(const std::vector<MapEntry> &maps, const std::string &so) {
    const MapEntry *best = nullptr;
    for (const auto &entry : maps) {
        if (path_is_named(entry.path, so)) {
            if (best == nullptr || entry.start < best->start) best = &entry;
        }
    }
    return best;
}

void rx_range_for(const std::vector<MapEntry> &maps, const std::string &so,
                  uintptr_t &start, uintptr_t &end) {
    start = 0;
    end = 0;
    for (const auto &entry : maps) {
        if (!is_rx(entry) || !path_is_named(entry.path, so)) continue;
        if (start == 0 || entry.start < start) start = entry.start;
        if (entry.end > end) end = entry.end;
    }
}

bool same_backing_file(const MapEntry &a, const MapEntry &b) {
    return a.inode != 0 && a.inode == b.inode && a.path == b.path;
}

/**
 * Guard against legitimate intra-image branches (such as Clang/LLVM extern_weak
 * tail-call forwarders in libdl.so on x86_64/ARM64): returns true if destination
 * stays inside an executable mapping belonging to the contiguous image of origin.
 */
bool branch_stays_in_image(const std::vector<MapEntry> &maps,
                           uintptr_t entry_addr,
                           uintptr_t destination) {
    for (size_t i = 0; i < maps.size(); ++i) {
        const MapEntry &origin = maps[i];
        if (entry_addr < origin.start || entry_addr >= origin.end) {
            continue;
        }
        if (origin.inode == 0 || origin.path.empty()) {
            return false;
        }
        size_t first = i;
        while (first > 0 && maps[first - 1].end == maps[first].start
                && same_backing_file(maps[first - 1], origin)) {
            --first;
        }
        size_t last = i;
        while (last + 1 < maps.size() && maps[last].end == maps[last + 1].start
                && same_backing_file(maps[last + 1], origin)) {
            ++last;
        }
        for (size_t idx = first; idx <= last; ++idx) {
            if (destination >= maps[idx].start && destination < maps[idx].end) {
                return is_rx(maps[idx]);
            }
        }
        return false;
    }
    return false;
}

#if defined(__aarch64__) || defined(RISKENGINE_HOST_TEST)
bool looks_like_trampoline_arm64(const uint8_t *p, size_t len, uintptr_t addr,
                                 const std::vector<MapEntry> &maps,
                                 uintptr_t range_start, uintptr_t range_end) {
    if (len < 12) return false;
    uint32_t w[4] = {};
    const size_t words = std::min<size_t>(len / 4, 4);
    for (size_t i = 0; i < words; ++i) {
        std::memcpy(&w[i], p + i * 4, sizeof(uint32_t));
    }
    const uint32_t insn = w[0];
    const uint32_t next = w[1];
    const uint32_t third = w[2];

    // Software breakpoint BRK #imm16
    if ((insn & 0xFFE0001Fu) == 0xD4200000u) return true;

    // LDR Xn, [PC, #imm] ; BR Xn (X16/X17 or arbitrary register)
    if ((insn & 0xFF000000u) == 0x58000000u && (next & 0xFFFFFC1Fu) == 0xD61F0000u) {
        const uint32_t rt = insn & 0x1Fu;
        const uint32_t rn = (next >> 5) & 0x1Fu;
        if (rt == rn) return true;
    }

    // ADRP X16/X17, #page ; ADD X16/X17, X16/X17, #off ; BR X16/X17
    if ((insn & 0x9F00001Eu) == 0x90000010u
        && (next & 0xFF8003DEu) == 0x91000210u
        && (third == 0xD61F0200u || third == 0xD61F0220u)) {
        return true;
    }

    // MOVZ/MOVK sequence + BR Xd (absolute address jump stub)
    if ((insn & 0x7F800000u) == 0x52800000u) {  // MOVZ
        const uint32_t rd = insn & 0x1Fu;
        for (size_t i = 1; i < words; ++i) {
            if ((w[i] & 0xFFFFFC1Fu) == 0xD61F0000u && (((w[i] >> 5) & 0x1Fu) == rd)) {
                return true;
            }
            if ((w[i] & 0x7F800000u) != 0x72800000u || (w[i] & 0x1Fu) != rd) {
                break;
            }
        }
    }

    // STP + LDR Xt, [PC, #imm] + BR Xt (register-preserving hook trampoline)
    if (words >= 4
        && ((insn & 0x7FC00000u) == 0x29000000u || (insn & 0x7FC00000u) == 0x29800000u)
        && (next & 0xFF000000u) == 0x58000000u
        && (third & 0xFFFFFC1Fu) == 0xD61F0000u) {
        const uint32_t rt = next & 0x1Fu;
        const uint32_t rn = (third >> 5) & 0x1Fu;
        if (rt == rn) return true;
    }

    // Direct B #imm26 — guarded by branch_stays_in_image to avoid LLVM forwarder FP.
    if ((insn & 0xFC000000u) == 0x14000000u) {
        uint32_t raw26 = insn & 0x03FFFFFFu;
        if ((raw26 & 0x02000000u) != 0) raw26 |= 0xFC000000u;
        const uintptr_t signed_disp = static_cast<uintptr_t>(
                static_cast<intptr_t>(static_cast<int32_t>(raw26))) << 2;
        const uintptr_t target = addr + signed_disp;
        if (branch_stays_in_image(maps, addr, target)) {
            return false;
        }
        if (range_start < range_end && (target < range_start || target >= range_end)) {
            return true;
        }
    }
    return false;
}
#endif

#if defined(__arm__) || defined(RISKENGINE_HOST_TEST)
bool looks_like_trampoline_arm32(const uint8_t *p, size_t len, uintptr_t raw_addr,
                                 const std::vector<MapEntry> &maps,
                                 uintptr_t range_start, uintptr_t range_end) {
    if (len < 4) return false;
    const bool is_thumb = (raw_addr & 1u) != 0;
    const uintptr_t addr = raw_addr & ~static_cast<uintptr_t>(1u);

    if (is_thumb) {
        uint16_t hw0 = 0;
        uint16_t hw1 = 0;
        std::memcpy(&hw0, p, sizeof(hw0));
        std::memcpy(&hw1, p + 2, sizeof(hw1));

        // 16-bit Thumb BKPT #imm8
        if ((hw0 & 0xFF00u) == 0xBE00u) return true;

        // 32-bit Thumb-2 LDR.W PC, [PC, #+/-imm12] (F8DF Fxxx or F85F Fxxx)
        if ((hw0 == 0xF8DFu || hw0 == 0xF85Fu) && (hw1 & 0xF000u) == 0xF000u) {
            return true;
        }

        // 32-bit Thumb-2 unconditional B.W #imm24 (encoding T4)
        if ((hw0 & 0xF800u) == 0xF000u && (hw1 & 0xD000u) == 0x9000u) {
            const uint32_t S = (hw0 >> 10) & 1u;
            const uint32_t J1 = (hw1 >> 13) & 1u;
            const uint32_t J2 = (hw1 >> 11) & 1u;
            const uint32_t I1 = ~(J1 ^ S) & 1u;
            const uint32_t I2 = ~(J2 ^ S) & 1u;
            const uint32_t imm10 = hw0 & 0x03FFu;
            const uint32_t imm11 = hw1 & 0x07FFu;
            uint32_t raw_off = (S << 24) | (I1 << 23) | (I2 << 22)
                    | (imm10 << 12) | (imm11 << 1);
            if (S != 0) raw_off |= 0xFE000000u;
            const int32_t signed_off = static_cast<int32_t>(raw_off);
            const uintptr_t target = addr + 4u + static_cast<uintptr_t>(signed_off);
            if (branch_stays_in_image(maps, addr, target)) {
                return false;
            }
            if (range_start < range_end && (target < range_start || target >= range_end)) {
                return true;
            }
        }

        // 16-bit BX r12 (0x4760)
        if (hw0 == 0x4760u) return true;
        return false;
    }

    // ARM32 (A32) state
    uint32_t insn = 0;
    std::memcpy(&insn, p, sizeof(insn));
    if ((insn & 0x0FF000F0u) == 0x01200070u) return true;               // BKPT
    if ((insn & 0x0F7FF000u) == 0x051FF000u) return true;               // LDR PC, [PC, #imm]
    if ((insn & 0x0FFFFFF0u) == 0x012FFF10u && (insn & 0xFu) != 14u) {  // BX rN (rN != LR)
        return true;
    }
    // ARM B #imm24 — guarded by branch_stays_in_image.
    if ((insn & 0x0F000000u) == 0x0A000000u) {
        uint32_t raw24 = insn & 0x00FFFFFFu;
        if ((raw24 & 0x00800000u) != 0) raw24 |= 0xFF000000u;
        const uintptr_t signed_disp = static_cast<uintptr_t>(
                static_cast<intptr_t>(static_cast<int32_t>(raw24))) << 2;
        const uintptr_t target = addr + 8u + signed_disp;
        if (branch_stays_in_image(maps, addr, target)) {
            return false;
        }
        if (range_start < range_end && (target < range_start || target >= range_end)) {
            return true;
        }
    }
    return false;
}
#endif

#if defined(__x86_64__) || defined(__i386__) || defined(RISKENGINE_HOST_TEST)
bool looks_like_trampoline_x86_common(const uint8_t *p, size_t len, uintptr_t addr,
                                      const std::vector<MapEntry> &maps,
                                      uintptr_t range_start, uintptr_t range_end,
                                      bool is_64bit) {
    if (len < 6) return false;
    if (p[0] == 0xCCu) return true;                                  // INT3
    if (p[0] == 0xFFu && p[1] == 0x25u) return true;                 // JMP [rip+disp32] / [imm32]
    if (p[0] == 0x68u && p[5] == 0xC3u) return true;                 // PUSH imm32 ; RET
    if (is_64bit) {
        if (len >= 12 && p[0] == 0x48u && p[1] == 0xB8u
            && p[10] == 0xFFu && p[11] == 0xE0u) {                   // MOVABS RAX, imm64; JMP RAX
            return true;
        }
    } else {
        if (len >= 7 && p[0] == 0xB8u && p[5] == 0xFFu && p[6] == 0xE0u) {  // MOV EAX, imm32; JMP EAX
            return true;
        }
    }
    // JMP rel32 — guarded by branch_stays_in_image for libdl extern_weak tail calls.
    if (p[0] == 0xE9u) {
        int32_t rel32 = 0;
        std::memcpy(&rel32, p + 1, sizeof(rel32));
        const uintptr_t target = addr + 5u
                + static_cast<uintptr_t>(static_cast<intptr_t>(rel32));
        if (branch_stays_in_image(maps, addr, target)) {
            return false;
        }
        if (range_start < range_end && (target < range_start || target >= range_end)) {
            return true;
        }
    }
    return false;
}
#endif

bool looks_like_trampoline(const uint8_t *p, size_t len, uintptr_t addr,
                           const std::vector<MapEntry> &maps,
                           uintptr_t range_start, uintptr_t range_end) {
#if defined(__aarch64__)
    return looks_like_trampoline_arm64(p, len, addr, maps, range_start, range_end);
#elif defined(__arm__)
    return looks_like_trampoline_arm32(p, len, addr, maps, range_start, range_end);
#elif defined(__x86_64__)
    return looks_like_trampoline_x86_common(p, len, addr, maps, range_start, range_end, true);
#elif defined(__i386__)
    return looks_like_trampoline_x86_common(p, len, addr, maps, range_start, range_end, false);
#else
    (void) p; (void) len; (void) addr; (void) maps; (void) range_start; (void) range_end;
    return false;
#endif
}

bool range_within_u64(uint64_t offset, uint64_t length, uint64_t total) {
    return offset <= total && length <= total - offset;
}

bool add_address(uintptr_t base, uintptr_t offset, uintptr_t &out) {
    if (offset > std::numeric_limits<uintptr_t>::max() - base) return false;
    out = base + offset;
    return true;
}

bool pread_exact(int fd, void *buf, size_t len, uint64_t offset) {
    auto *dst = reinterpret_cast<uint8_t *>(buf);
    size_t got = 0;
    while (got < len) {
        long n = my_pread64(fd, dst + got, len - got, offset + got);
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    return true;
}

#if defined(__LP64__)
using Ehdr = Elf64_Ehdr;
using Phdr = Elf64_Phdr;
using Shdr = Elf64_Shdr;
using Dyn = Elf64_Dyn;
using Sym = Elf64_Sym;
using Rela = Elf64_Rela;
using Rel = Elf64_Rel;
using ElfAddr = Elf64_Addr;
constexpr bool kElf64 = true;
#else
using Ehdr = Elf32_Ehdr;
using Phdr = Elf32_Phdr;
using Shdr = Elf32_Shdr;
using Dyn = Elf32_Dyn;
using Sym = Elf32_Sym;
using Rela = Elf32_Rela;
using Rel = Elf32_Rel;
using ElfAddr = Elf32_Addr;
constexpr bool kElf64 = false;
#endif

struct DiskElf {
    int fd = -1;
    uint64_t file_size = 0;
    uint64_t base_offset = 0;  // 0 for standalone .so, non-zero inside base.apk
    uint64_t inode = 0;
    uintptr_t load_bias = 0;
    Ehdr ehdr {};
    std::vector<Phdr> phdrs;
    std::vector<Shdr> shdrs;

    ~DiskElf() {
        if (fd >= 0) my_close(fd);
    }

    bool open(const std::string &path, uint64_t elf_base_offset, uintptr_t mem_base,
              uint64_t expected_inode = 0, bool explicit_bias = false) {
        struct stat st {};
        if (my_fstatat(AT_FDCWD, path.c_str(), &st, 0) != 0 || st.st_size <= 0) {
            return false;
        }
        if (expected_inode != 0 && static_cast<uint64_t>(st.st_ino) != expected_inode) {
            return false;
        }
        file_size = static_cast<uint64_t>(st.st_size);
        inode = static_cast<uint64_t>(st.st_ino);
        base_offset = elf_base_offset;
        if (!range_within_u64(base_offset, sizeof(Ehdr), file_size)) {
            return false;
        }
        fd = static_cast<int>(my_openat(AT_FDCWD, path.c_str(), O_RDONLY | O_CLOEXEC, 0));
        if (fd < 0) return false;

        if (!pread_exact(fd, &ehdr, sizeof(Ehdr), base_offset)) return false;
        if (ehdr.e_ident[EI_MAG0] != ELFMAG0 || ehdr.e_ident[EI_MAG1] != ELFMAG1
                || ehdr.e_ident[EI_MAG2] != ELFMAG2 || ehdr.e_ident[EI_MAG3] != ELFMAG3
                || ehdr.e_ident[EI_DATA] != ELFDATA2LSB
                || ehdr.e_ident[EI_VERSION] != EV_CURRENT
                || ehdr.e_ident[EI_CLASS] != (kElf64 ? ELFCLASS64 : ELFCLASS32)) {
            return false;
        }
        if (ehdr.e_phoff == 0 || ehdr.e_phentsize != sizeof(Phdr)
                || ehdr.e_phnum == 0 || ehdr.e_phnum > 128) {
            return false;
        }
        const uint64_t ph_bytes = static_cast<uint64_t>(ehdr.e_phnum) * sizeof(Phdr);
        if (!range_within_u64(base_offset, ehdr.e_phoff, file_size)
                || !range_within_u64(base_offset + ehdr.e_phoff, ph_bytes, file_size)) {
            return false;
        }
        phdrs.resize(ehdr.e_phnum);
        if (!pread_exact(fd, phdrs.data(), static_cast<size_t>(ph_bytes),
                         base_offset + ehdr.e_phoff)) {
            return false;
        }

        // Load optional section headers for exact SHF_EXECINSTR boundaries (works with 16KB pages).
        if (ehdr.e_shoff != 0 && ehdr.e_shentsize == sizeof(Shdr)
                && ehdr.e_shnum > 0 && ehdr.e_shnum <= 256) {
            const uint64_t sh_bytes = static_cast<uint64_t>(ehdr.e_shnum) * sizeof(Shdr);
            if (range_within_u64(base_offset, ehdr.e_shoff, file_size)
                    && range_within_u64(base_offset + ehdr.e_shoff, sh_bytes, file_size)) {
                std::vector<Shdr> loaded(ehdr.e_shnum);
                if (pread_exact(fd, loaded.data(), static_cast<size_t>(sh_bytes),
                                base_offset + ehdr.e_shoff)) {
                    shdrs = std::move(loaded);
                }
            }
        }

        if (explicit_bias) {
            load_bias = mem_base;
        } else {
            uintptr_t bias = mem_base;
            for (const auto &ph : phdrs) {
                if (ph.p_type == PT_LOAD && ph.p_offset == 0) {
                    if (ph.p_vaddr > mem_base) return false;
                    bias = mem_base - static_cast<uintptr_t>(ph.p_vaddr);
                    break;
                }
            }
            load_bias = bias;
        }
        return true;
    }

    bool vaddr_to_offset(uint64_t vaddr, uint64_t &file_off) const {
        for (const auto &ph : phdrs) {
            if (ph.p_type != PT_LOAD) continue;
            if (vaddr >= ph.p_vaddr && vaddr < ph.p_vaddr + ph.p_filesz) {
                const uint64_t rel = ph.p_offset + (vaddr - ph.p_vaddr);
                if (!range_within_u64(base_offset, rel, file_size)) return false;
                file_off = base_offset + rel;
                return file_off < file_size;
            }
        }
        return false;
    }

    bool read_dynamic(std::vector<Dyn> &out) const {
        for (const auto &ph : phdrs) {
            if (ph.p_type != PT_DYNAMIC) continue;
            if (ph.p_filesz == 0 || ph.p_filesz > 1024 * 1024) return false;
            if (!range_within_u64(base_offset, ph.p_offset, file_size)
                    || !range_within_u64(base_offset + ph.p_offset, ph.p_filesz, file_size)) {
                return false;
            }
            const size_t count = static_cast<size_t>(ph.p_filesz) / sizeof(Dyn);
            out.resize(count);
            return pread_exact(fd, out.data(), count * sizeof(Dyn), base_offset + ph.p_offset);
        }
        return false;
    }

    bool read_strtab_name(uint64_t strtab_off, uint64_t strtab_sz,
                          uint32_t name_idx, std::string &out) const {
        if (name_idx >= strtab_sz) return false;
        const size_t avail = static_cast<size_t>(
                std::min<uint64_t>(strtab_sz - name_idx, 256));
        if (avail == 0 || !range_within_u64(strtab_off + name_idx, avail, file_size)) {
            return false;
        }
        char buf[256] = {};
        if (!pread_exact(fd, buf, avail, strtab_off + name_idx)) return false;
        const void *nul = std::memchr(buf, '\0', avail);
        if (nul == nullptr) return false;
        out.assign(buf, static_cast<const char *>(nul) - buf);
        return true;
    }
};

uint32_t gnu_hash_str(const char *s) {
    uint32_t h = 5381u;
    for (const auto *p = reinterpret_cast<const unsigned char *>(s); *p != 0; ++p) {
        h = (h << 5) + h + *p;
    }
    return h;
}

uint32_t sysv_hash_str(const char *s) {
    uint32_t h = 0;
    for (const auto *p = reinterpret_cast<const unsigned char *>(s); *p != 0; ++p) {
        h = (h << 4) + *p;
        uint32_t g = h & 0xf0000000u;
        if (g != 0) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

bool lookup_symbol_gnu(const DiskElf &elf, uint64_t gnu_hash_off,
                       uint64_t symtab_off, uint64_t strtab_off, uint64_t strtab_sz,
                       const std::string &name, Sym &sym_out) {
    uint32_t header[4] = {};
    if (!range_within_u64(gnu_hash_off, sizeof(header), elf.file_size)) return false;
    if (!pread_exact(elf.fd, header, sizeof(header), gnu_hash_off)) return false;
    const uint32_t nbuckets = header[0];
    const uint32_t symoffset = header[1];
    const uint32_t bloom_size = header[2];
    if (nbuckets == 0 || nbuckets > 65536 || bloom_size > 65536) return false;

    const uint64_t buckets_off =
            gnu_hash_off + sizeof(header) + static_cast<uint64_t>(bloom_size) * sizeof(ElfAddr);
    const uint64_t chains_off = buckets_off + static_cast<uint64_t>(nbuckets) * sizeof(uint32_t);
    const uint32_t h = gnu_hash_str(name.c_str());

    uint32_t idx = 0;
    const uint64_t bucket_pos = buckets_off + static_cast<uint64_t>(h % nbuckets) * sizeof(uint32_t);
    if (!range_within_u64(bucket_pos, sizeof(uint32_t), elf.file_size)) return false;
    if (!pread_exact(elf.fd, &idx, sizeof(uint32_t), bucket_pos)) return false;
    if (idx < symoffset) return false;

    for (size_t step = 0; step < 256; ++step, ++idx) {
        const uint64_t chain_pos =
                chains_off + static_cast<uint64_t>(idx - symoffset) * sizeof(uint32_t);
        uint32_t chain_val = 0;
        if (!range_within_u64(chain_pos, sizeof(uint32_t), elf.file_size)) return false;
        if (!pread_exact(elf.fd, &chain_val, sizeof(uint32_t), chain_pos)) return false;
        if ((chain_val | 1u) == (h | 1u)) {
            Sym candidate {};
            const uint64_t sym_pos = symtab_off + static_cast<uint64_t>(idx) * sizeof(Sym);
            if (!range_within_u64(sym_pos, sizeof(Sym), elf.file_size)) return false;
            if (!pread_exact(elf.fd, &candidate, sizeof(Sym), sym_pos)) return false;
            std::string cand_name;
            if (elf.read_strtab_name(strtab_off, strtab_sz, candidate.st_name, cand_name)
                && cand_name == name) {
                sym_out = candidate;
                return true;
            }
        }
        if ((chain_val & 1u) != 0) break;
    }
    return false;
}

bool lookup_symbol_sysv(const DiskElf &elf, uint64_t hash_off,
                        uint64_t symtab_off, uint64_t strtab_off, uint64_t strtab_sz,
                        const std::string &name, Sym &sym_out) {
    uint32_t header[2] = {};
    if (!range_within_u64(hash_off, sizeof(header), elf.file_size)) return false;
    if (!pread_exact(elf.fd, header, sizeof(header), hash_off)) return false;
    const uint32_t nbucket = header[0];
    const uint32_t nchain = header[1];
    if (nbucket == 0 || nbucket > 65536 || nchain == 0 || nchain > 131072) return false;

    const uint64_t buckets_off = hash_off + sizeof(header);
    const uint64_t chains_off = buckets_off + static_cast<uint64_t>(nbucket) * sizeof(uint32_t);
    const uint32_t h = sysv_hash_str(name.c_str());

    uint32_t idx = 0;
    const uint64_t bucket_pos = buckets_off + static_cast<uint64_t>(h % nbucket) * sizeof(uint32_t);
    if (!range_within_u64(bucket_pos, sizeof(uint32_t), elf.file_size)) return false;
    if (!pread_exact(elf.fd, &idx, sizeof(uint32_t), bucket_pos)) return false;

    for (size_t step = 0; step < 256 && idx != 0 && idx < nchain; ++step) {
        Sym candidate {};
        const uint64_t sym_pos = symtab_off + static_cast<uint64_t>(idx) * sizeof(Sym);
        if (!range_within_u64(sym_pos, sizeof(Sym), elf.file_size)) return false;
        if (!pread_exact(elf.fd, &candidate, sizeof(Sym), sym_pos)) return false;
        std::string cand_name;
        if (elf.read_strtab_name(strtab_off, strtab_sz, candidate.st_name, cand_name)
            && cand_name == name) {
            sym_out = candidate;
            return true;
        }
        const uint64_t chain_pos = chains_off + static_cast<uint64_t>(idx) * sizeof(uint32_t);
        if (!range_within_u64(chain_pos, sizeof(uint32_t), elf.file_size)) return false;
        if (!pread_exact(elf.fd, &idx, sizeof(uint32_t), chain_pos)) return false;
    }
    return false;
}

struct ExecRange {
    uint64_t vaddr = 0;
    uint64_t file_off = 0;
    uint64_t size = 0;
};

/**
 * Collects executable code ranges using SHF_EXECINSTR section headers when
 * available (precise boundaries avoiding rodata/padding under 16KB pages),
 * falling back to PT_LOAD (PF_X) segments when section headers are stripped.
 * Always computes virtual addresses from sh_addr / p_vaddr (never sh_offset).
 */
std::vector<ExecRange> collect_exec_ranges(const DiskElf &elf) {
    std::vector<ExecRange> ranges;
    for (const auto &sh : elf.shdrs) {
        if ((sh.sh_flags & SHF_EXECINSTR) == 0 || sh.sh_type != SHT_PROGBITS
                || sh.sh_size == 0 || sh.sh_addr == 0) {
            continue;
        }
        uint64_t file_off = 0;
        if (!elf.vaddr_to_offset(sh.sh_addr, file_off)) continue;
        if (!range_within_u64(file_off, sh.sh_size, elf.file_size)) continue;
        ranges.push_back({sh.sh_addr, file_off, sh.sh_size});
    }
    if (!ranges.empty()) {
        return ranges;
    }
    for (const auto &ph : elf.phdrs) {
        if (ph.p_type != PT_LOAD || (ph.p_flags & PF_X) == 0 || ph.p_filesz == 0) {
            continue;
        }
        uint64_t file_off = 0;
        if (!elf.vaddr_to_offset(ph.p_vaddr, file_off)) continue;
        if (!range_within_u64(file_off, ph.p_filesz, elf.file_size)) continue;
        ranges.push_back({ph.p_vaddr, file_off, ph.p_filesz});
    }
    return ranges;
}

/**
 * Performs 64 KiB windowed SHA-256 disk-vs-memory comparison over all
 * executable sections/segments using COW-safe PipeMemoryReader.
 *
 * When cow_only == true (used for large system libraries like libc/libart),
 * only windows containing at least one pagemap-confirmed private anonymous
 * page are hashed and compared, preventing ACK 4.19/--no-rosegment noise and
 * keeping latency well under budget.
 */
void inspect_exec_sha256_windows(const DiskElf &elf,
                                 const std::string &label,
                                 const std::string &location,
                                 safe_mem::PipeMemoryReader &mem,
                                 const safe_mem::PagemapReader &pagemap,
                                 bool cow_only,
                                 std::vector<IntegrityFinding> &findings) {
    if (!mem.available()) return;
    if (cow_only && !pagemap.available()) return;
    const long raw_ps = sysconf(_SC_PAGESIZE);
    const size_t page_size = raw_ps >= 4096 ? static_cast<size_t>(raw_ps) : 4096u;
    const std::vector<ExecRange> ranges = collect_exec_ranges(elf);
    if (ranges.empty()) return;

    uint8_t disk_buf[kShaSubChunkBytes] = {};
    uint8_t mem_buf[kShaSubChunkBytes] = {};
    std::vector<safe_mem::PageResidency> range_residency;

    for (const auto &range : ranges) {
        uintptr_t range_base_addr = 0;
        if (!add_address(elf.load_bias, static_cast<uintptr_t>(range.vaddr), range_base_addr)) {
            continue;
        }
        uintptr_t range_aligned_start = 0;
        bool has_range_pagemap = false;
        if (cow_only) {
            uintptr_t range_end_addr = 0;
            if (!add_address(range_base_addr, static_cast<uintptr_t>(range.size), range_end_addr)) {
                continue;
            }
            range_aligned_start = range_base_addr & ~(static_cast<uintptr_t>(page_size) - 1u);
            const size_t total_pages = static_cast<size_t>(
                    (range_end_addr - range_aligned_start + page_size - 1u) / page_size);
            // Batch-read the whole range's pagemap entries (512 pages = 2 MiB per pread64 syscall)
            // instead of issuing one syscall + vector allocation per 64 KiB window.
            has_range_pagemap = pagemap.read_pages(
                    range_aligned_start, total_pages, page_size, range_residency);
            if (!has_range_pagemap) {
                continue;
            }
        }

        uint64_t offset = 0;
        while (offset < range.size) {
            const size_t win_len = static_cast<size_t>(
                    std::min<uint64_t>(kShaWindowBytes, range.size - offset));
            uintptr_t win_addr = 0;
            if (!add_address(elf.load_bias,
                             static_cast<uintptr_t>(range.vaddr + offset), win_addr)) {
                break;
            }

            if (cow_only) {
                const uintptr_t aligned_start = win_addr & ~(static_cast<uintptr_t>(page_size) - 1u);
                uintptr_t end_addr = 0;
                if (!add_address(win_addr, win_len, end_addr)) {
                    break;
                }
                const size_t first_idx = static_cast<size_t>(
                        (aligned_start - range_aligned_start) / page_size);
                const size_t pages = static_cast<size_t>(
                        (end_addr - aligned_start + page_size - 1u) / page_size);
                const size_t last_idx = std::min(first_idx + pages, range_residency.size());
                bool any_cow = false;
                for (size_t idx = first_idx; idx < last_idx; ++idx) {
                    const auto r = range_residency[idx];
                    if (r == safe_mem::PageResidency::ANONYMOUS_PAGE
                            || r == safe_mem::PageResidency::SWAPPED) {
                        any_cow = true;
                        break;
                    }
                }
                if (!any_cow) {
                    offset += win_len;
                    continue;
                }
            }

            // Fast path: read every 4 KiB chunk from disk and COW-safe pipe2 memory reader and
            // compare byte-for-byte. Only run full 64 KiB windowed SHA-256 confirmation when a
            // byte difference is observed (mathematically equivalent for clean images while
            // avoiding 1.3+ MB of software SHA-256 on every CRITICAL-tier scan).
            size_t checked = 0;
            bool readable = true;
            bool chunk_diff = false;

            while (checked < win_len) {
                const size_t step = std::min<size_t>(kShaSubChunkBytes, win_len - checked);
                if (!pread_exact(elf.fd, disk_buf, step, range.file_off + offset + checked)) {
                    readable = false;
                    break;
                }
                if (!mem.read(win_addr + checked, mem_buf, step)) {
                    // XOM or concurrently unmapped: visibility loss is NEVER a threat.
                    readable = false;
                    break;
                }
                if (std::memcmp(disk_buf, mem_buf, step) != 0) {
                    chunk_diff = true;
                    break;
                }
                checked += step;
            }

            if (readable && chunk_diff) {
                crypto_mini::Sha256 disk_sha;
                crypto_mini::Sha256 mem_sha;
                size_t hashed = 0;
                bool sha_readable = true;
                while (hashed < win_len) {
                    const size_t step = std::min<size_t>(kShaSubChunkBytes, win_len - hashed);
                    if (!pread_exact(elf.fd, disk_buf, step, range.file_off + offset + hashed)) {
                        sha_readable = false;
                        break;
                    }
                    if (!mem.read(win_addr + hashed, mem_buf, step)) {
                        sha_readable = false;
                        break;
                    }
                    disk_sha.update(disk_buf, step);
                    mem_sha.update(mem_buf, step);
                    hashed += step;
                }
                if (sha_readable) {
                    uint8_t disk_digest[crypto_mini::kSha256DigestSize] = {};
                    uint8_t mem_digest[crypto_mini::kSha256DigestSize] = {};
                    disk_sha.final(disk_digest);
                    mem_sha.final(mem_digest);
                    if (!crypto_mini::ct_memcmp(disk_digest, mem_digest,
                                                crypto_mini::kSha256DigestSize)) {
                        char detail[64] = {};
                        std::snprintf(detail, sizeof(detail), "sha256_window_off=0x%llx",
                                      static_cast<unsigned long long>(range.vaddr + offset));
                        add_finding(findings,
                                    OBF("text_mismatch:") + label,
                                    OBF("text_mismatch"),
                                    location,
                                    detail);
                        return;  // One confirmed mismatch per image is sufficient.
                    }
                }
            }
            offset += win_len;
        }
    }
}

void inspect_library_exports(const std::vector<MapEntry> &maps,
                             const std::string &so_name,
                             const std::vector<std::string> &wanted,
                             safe_mem::PipeMemoryReader &mem,
                             const safe_mem::PagemapReader &pagemap,
                             std::vector<IntegrityFinding> &findings) {
    const MapEntry *base_map = lowest_named_map(maps, so_name);
    if (base_map == nullptr || base_map->path.empty()) return;

    DiskElf elf;
    if (!elf.open(base_map->path, base_map->offset, base_map->start, base_map->inode)) return;

    // COW-safe full-segment scan on dirty anonymous pages of system library.
    inspect_exec_sha256_windows(elf, so_name, base_map->path, mem, pagemap, true, findings);

    std::vector<Dyn> dyn;
    if (!elf.read_dynamic(dyn)) return;

    uint64_t strtab_va = 0, strtab_sz = 0, symtab_va = 0;
    uint64_t gnu_hash_va = 0, sysv_hash_va = 0;
    size_t syment = sizeof(Sym);
    for (const auto &d : dyn) {
        if (d.d_tag == DT_NULL) break;
        if (d.d_tag == DT_STRTAB) strtab_va = d.d_un.d_ptr;
        else if (d.d_tag == DT_STRSZ) strtab_sz = d.d_un.d_val;
        else if (d.d_tag == DT_SYMTAB) symtab_va = d.d_un.d_ptr;
        else if (d.d_tag == DT_SYMENT) syment = static_cast<size_t>(d.d_un.d_val);
        else if (d.d_tag == DT_GNU_HASH) gnu_hash_va = d.d_un.d_ptr;
        else if (d.d_tag == DT_HASH) sysv_hash_va = d.d_un.d_ptr;
    }
    if (strtab_va == 0 || symtab_va == 0 || strtab_sz == 0 || syment != sizeof(Sym)) return;

    uint64_t strtab_off = 0, symtab_off = 0, gnu_hash_off = 0, sysv_hash_off = 0;
    if (!elf.vaddr_to_offset(strtab_va, strtab_off)
        || !elf.vaddr_to_offset(symtab_va, symtab_off)) {
        return;
    }
    const bool has_gnu = gnu_hash_va != 0 && elf.vaddr_to_offset(gnu_hash_va, gnu_hash_off);
    const bool has_sysv = sysv_hash_va != 0 && elf.vaddr_to_offset(sysv_hash_va, sysv_hash_off);
    if (!has_gnu && !has_sysv) return;

    uintptr_t rx_start = 0, rx_end = 0;
    rx_range_for(maps, so_name, rx_start, rx_end);

    for (const auto &name : wanted) {
        Sym sym {};
        bool found = false;
        if (has_gnu) {
            found = lookup_symbol_gnu(elf, gnu_hash_off, symtab_off, strtab_off, strtab_sz, name, sym);
        }
        if (!found && has_sysv) {
            found = lookup_symbol_sysv(elf, sysv_hash_off, symtab_off, strtab_off, strtab_sz, name, sym);
        }
        if (!found || sym.st_shndx == SHN_UNDEF || sym.st_value == 0) continue;

        const uint64_t sym_code_va = strip_code_thumb_bit(static_cast<uintptr_t>(sym.st_value));
        uint64_t func_file_off = 0;
        if (!elf.vaddr_to_offset(sym_code_va, func_file_off)) continue;

        constexpr size_t kMaxProbe = 32;
        size_t check_len = (sym.st_size > 0 && sym.st_size < kMaxProbe)
                ? static_cast<size_t>(sym.st_size) : kMaxProbe;
        if (check_len < 4) continue;
        // Ensure [sym_code_va, sym_code_va + check_len) stays contiguous within the same PT_LOAD.
        uint64_t end_file_off = 0;
        if (!elf.vaddr_to_offset(sym_code_va + check_len - 1u, end_file_off)
                || end_file_off != func_file_off + check_len - 1u) {
            continue;
        }
        if (!range_within_u64(func_file_off, check_len, elf.file_size)) continue;

        uintptr_t raw_mem_addr = 0;
        if (!add_address(elf.load_bias, static_cast<uintptr_t>(sym.st_value), raw_mem_addr)) {
            continue;
        }
        const uintptr_t mem_code_addr = strip_code_thumb_bit(raw_mem_addr);

        uint8_t mem_bytes[kMaxProbe] = {};
        if (!mem.read(mem_code_addr, mem_bytes, check_len)) continue;

        uint8_t disk_bytes[kMaxProbe] = {};
        if (!pread_exact(elf.fd, disk_bytes, check_len, func_file_off)) continue;

        if (std::memcmp(disk_bytes, mem_bytes, check_len) != 0) {
            add_finding(findings,
                        OBF("inline_hook:") + name,
                        OBF("inline_hook"),
                        so_name + ":" + name,
                        OBF("disk_memory_prologue_mismatch"));
        } else if (looks_like_trampoline(mem_bytes, check_len, raw_mem_addr,
                                         maps, rx_start, rx_end)) {
            add_finding(findings,
                        OBF("inline_hook:") + name,
                        OBF("inline_hook"),
                        so_name + ":" + name,
                        OBF("trampoline_pattern"));
        }
    }
}

bool is_trusted_got_target(const std::vector<MapEntry> &maps,
                           uintptr_t target,
                           const void *self_fbase,
                           uint64_t self_inode,
                           const std::string_view *trusted_libs,
                           size_t trusted_lib_count) {
    const uintptr_t code_target = strip_code_thumb_bit(target);
    const MapEntry *m = find_map_containing(maps, code_target);
    if (m == nullptr || !is_rx(*m)) return false;
    if (m->path.empty()) return false;

    const std::string lower = to_lower(m->path);
    for (size_t i = 0; i < trusted_lib_count; ++i) {
        if (lower.find(trusted_libs[i]) != std::string::npos) {
            return true;
        }
    }

    if (self_inode != 0 && m->inode == self_inode) {
        // Confirm intra-self mapping via dladdr only when target shares our backing file/APK
        // (avoids acquiring bionic linker mutex on libc/libdl/liblog/etc. GOT entries).
        Dl_info target_info {};
        if (self_fbase != nullptr
            && dladdr(reinterpret_cast<const void *>(code_target), &target_info) != 0
            && target_info.dli_fbase == self_fbase) {
            return true;
        }
        return false;
    }

    Dl_info target_info {};
    return self_fbase != nullptr
           && dladdr(reinterpret_cast<const void *>(code_target), &target_info) != 0
           && target_info.dli_fbase == self_fbase;
}

bool starts_with_sv(std::string_view s, std::string_view prefix) noexcept {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with_sv(std::string_view s, std::string_view suffix) noexcept {
    return s.size() >= suffix.size()
           && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

/**
 * Android ART interposes POSIX signal symbols (sigaction/sigprocmask/signal/etc.) via
 * libsigchain.so in every app process. Exempt ONLY known sigchain-interposed symbols AND
 * ONLY when resolved into a trusted system/APEX libsigchain.so executable mapping.
 */
bool is_trusted_sigchain_target(const std::vector<MapEntry> &maps,
                                uintptr_t target,
                                const std::string &sym_name) {
    if (sym_name.empty()) return false;
    const auto sym_sigaction = OBF("sigaction");
    const auto sym_sigaction64 = OBF("sigaction64");
    const auto sym_sigprocmask = OBF("sigprocmask");
    const auto sym_sigprocmask64 = OBF("sigprocmask64");
    const auto sym_signal = OBF("signal");
    const auto sym_bsd_signal = OBF("bsd_signal");
    const auto sym_sigset = OBF("sigset");
    const auto sym_sigwait = OBF("sigwait");
    const auto sym_sigwait64 = OBF("sigwait64");

    const bool is_sigchain_sym =
            sym_name == sym_sigaction.view()
            || sym_name == sym_sigaction64.view()
            || sym_name == sym_sigprocmask.view()
            || sym_name == sym_sigprocmask64.view()
            || sym_name == sym_signal.view()
            || sym_name == sym_bsd_signal.view()
            || sym_name == sym_sigset.view()
            || sym_name == sym_sigwait.view()
            || sym_name == sym_sigwait64.view();
    if (!is_sigchain_sym) return false;

    const uintptr_t code_target = strip_code_thumb_bit(target);
    const MapEntry *m = find_map_containing(maps, code_target);
    if (m == nullptr || !is_rx(*m) || m->path.empty()) return false;

    const std::string lower = to_lower(m->path);
    const auto sigchain_suffix = OBF("/libsigchain.so");
    if (!ends_with_sv(lower, sigchain_suffix.view())) return false;

    const auto p_apex_art = OBF("/apex/com.android.art/");
    const auto p_apex_rt = OBF("/apex/com.android.runtime/");
    const auto p_sys_lib = OBF("/system/lib/");
    const auto p_sys_lib64 = OBF("/system/lib64/");
    const auto p_sys_apex_art = OBF("/system/apex/com.android.art/");
    const auto p_sys_apex_rt = OBF("/system/apex/com.android.runtime/");
    return starts_with_sv(lower, p_apex_art.view())
           || starts_with_sv(lower, p_apex_rt.view())
           || starts_with_sv(lower, p_sys_lib.view())
           || starts_with_sv(lower, p_sys_lib64.view())
           || starts_with_sv(lower, p_sys_apex_art.view())
           || starts_with_sv(lower, p_sys_apex_rt.view());
}

struct SelfElfLocateCtx {
    uintptr_t anchor_addr = 0;
    uintptr_t load_bias = 0;
    uintptr_t first_load_vaddr = 0;
    bool found = false;
};

int find_self_phdr_cb(struct dl_phdr_info *info, size_t, void *data) {
    auto *ctx = static_cast<SelfElfLocateCtx *>(data);
    if (info == nullptr || info->dlpi_phdr == nullptr) return 0;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const auto &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD) continue;
        const uintptr_t seg_start = static_cast<uintptr_t>(info->dlpi_addr)
                + static_cast<uintptr_t>(ph.p_vaddr);
        const uintptr_t seg_end = seg_start + static_cast<uintptr_t>(ph.p_memsz);
        if (ctx->anchor_addr >= seg_start && ctx->anchor_addr < seg_end) {
            ctx->load_bias = static_cast<uintptr_t>(info->dlpi_addr);
            for (ElfW(Half) j = 0; j < info->dlpi_phnum; ++j) {
                if (info->dlpi_phdr[j].p_type == PT_LOAD && info->dlpi_phdr[j].p_offset == 0) {
                    ctx->first_load_vaddr = static_cast<uintptr_t>(info->dlpi_phdr[j].p_vaddr);
                    break;
                }
            }
            ctx->found = true;
            return 1;
        }
    }
    return 0;
}

bool resolve_self_elf(const std::vector<MapEntry> &maps,
                      std::string &path_out,
                      uint64_t &base_file_offset_out,
                      uint64_t &inode_out,
                      uintptr_t &load_bias_out,
                      const void *&fbase_out) {
    fbase_out = nullptr;
    inode_out = 0;

    // 1. Prefer dl_iterate_phdr: accurately resolves load_bias & base offset even
    //    under extractNativeLibs=false (APK-embedded .so) and 16KB page alignment.
    SelfElfLocateCtx phdr_ctx;
    phdr_ctx.anchor_addr = strip_code_thumb_bit(
            reinterpret_cast<uintptr_t>(&resolve_self_elf));
    dl_iterate_phdr(find_self_phdr_cb, &phdr_ctx);

    if (phdr_ctx.found) {
        const uintptr_t elf_hdr_addr = phdr_ctx.load_bias + phdr_ctx.first_load_vaddr;
        fbase_out = reinterpret_cast<const void *>(elf_hdr_addr);
        const MapEntry *entry = find_map_containing(maps, elf_hdr_addr);
        if (entry != nullptr && !entry->path.empty()) {
            path_out = entry->path;
            base_file_offset_out = entry->offset
                    + static_cast<uint64_t>(elf_hdr_addr - entry->start);
            inode_out = entry->inode;
            load_bias_out = phdr_ctx.load_bias;
            return true;
        }
    }

    // 2. Fallback to dladdr + maps.
    Dl_info owner {};
    if (dladdr(reinterpret_cast<const void *>(&resolve_self_elf), &owner) != 0
        && owner.dli_fbase != nullptr) {
        fbase_out = owner.dli_fbase;
        const uintptr_t elf_mem_base = reinterpret_cast<uintptr_t>(owner.dli_fbase);
        const MapEntry *entry = find_map_containing(maps, elf_mem_base);
        if (entry != nullptr && !entry->path.empty()) {
            path_out = entry->path;
            base_file_offset_out = entry->offset
                    + static_cast<uint64_t>(elf_mem_base - entry->start);
            inode_out = entry->inode;
            load_bias_out = elf_mem_base;
            return true;
        }
    }

    const MapEntry *named = lowest_named_map(maps, OBF("libriskengine.so"));
    if (named != nullptr) {
        path_out = named->path;
        base_file_offset_out = named->offset;
        inode_out = named->inode;
        load_bias_out = named->start;
        return true;
    }
    return false;
}

bool is_candidate_func_reloc_type(uint32_t r_type, bool is_plt_table) noexcept {
    if (is_plt_table) return true;
#if defined(__aarch64__)
    return r_type == R_AARCH64_JUMP_SLOT || r_type == R_AARCH64_GLOB_DAT
            || r_type == R_AARCH64_ABS64;
#elif defined(__arm__)
    return r_type == R_ARM_JUMP_SLOT || r_type == R_ARM_GLOB_DAT
            || r_type == R_ARM_ABS32;
#elif defined(__x86_64__)
    return r_type == R_X86_64_JUMP_SLOT || r_type == R_X86_64_GLOB_DAT
            || r_type == R_X86_64_64;
#elif defined(__i386__)
    return r_type == R_386_JMP_SLOT || r_type == R_386_GLOB_DAT
            || r_type == R_386_32;
#else
    (void) r_type;
    return true;
#endif
}

bool is_func_reloc_type(uint32_t r_type, uint8_t sym_type, bool is_plt_table) noexcept {
    if (is_plt_table) return true;
    if (sym_type != STT_FUNC) return false;
    return is_candidate_func_reloc_type(r_type, false);
}

void inspect_reloc_table(const DiskElf &elf,
                         const std::vector<MapEntry> &maps,
                         const void *self_fbase,
                         safe_mem::PipeMemoryReader &mem,
                         uint64_t strtab_off,
                         uint64_t strtab_sz,
                         uint64_t symtab_off,
                         uint64_t rel_va,
                         uint64_t rel_sz,
                         bool is_rela,
                         bool is_plt_table,
                         std::vector<IntegrityFinding> &findings) {
    if (rel_va == 0 || rel_sz == 0) return;
    uint64_t rel_off = 0;
    if (!elf.vaddr_to_offset(rel_va, rel_off)) return;

    const size_t ent_size = is_rela ? sizeof(Rela) : sizeof(Rel);
    const size_t count = std::min<size_t>(static_cast<size_t>(rel_sz) / ent_size, 4096);
    if (count == 0) return;

    // Decode trusted library substrings once outside the relocation loop.
    const auto lib_libc = OBF("libc.so");
    const auto lib_dl = OBF("libdl.so");
    const auto lib_log = OBF("liblog.so");
    const auto lib_m = OBF("libm.so");
    const auto lib_art = OBF("libart.so");
    const auto lib_cpp = OBF("libc++");
    const auto lib_linker = OBF("linker");
    const std::string_view trusted_libs[] = {
            lib_libc.view(), lib_dl.view(), lib_log.view(), lib_m.view(),
            lib_art.view(), lib_cpp.view(), lib_linker.view()
    };

    // Batch-read relocation entries in 4 KiB stack chunks instead of 1 pread64 per entry.
    constexpr size_t kRelChunkBytes = 4096;
    uint8_t rel_buf[kRelChunkBytes] = {};
    const size_t entries_per_chunk = kRelChunkBytes / ent_size;

    for (size_t base_i = 0; base_i < count; base_i += entries_per_chunk) {
        const size_t batch = std::min(entries_per_chunk, count - base_i);
        const uint64_t chunk_pos = rel_off + static_cast<uint64_t>(base_i) * ent_size;
        const size_t chunk_bytes = batch * ent_size;
        if (!range_within_u64(chunk_pos, chunk_bytes, elf.file_size)) break;
        if (!pread_exact(elf.fd, rel_buf, chunk_bytes, chunk_pos)) break;

        for (size_t j = 0; j < batch; ++j) {
            const uint8_t *raw_ent = rel_buf + j * ent_size;
            uint64_t r_offset = 0;
            size_t sym_index = 0;
            uint32_t r_type = 0;
            if constexpr (kElf64) {
                if (is_rela) {
                    Rela rela {};
                    std::memcpy(&rela, raw_ent, sizeof(rela));
                    r_offset = rela.r_offset;
                    sym_index = ELF64_R_SYM(rela.r_info);
                    r_type = static_cast<uint32_t>(ELF64_R_TYPE(rela.r_info));
                } else {
                    Rel rel {};
                    std::memcpy(&rel, raw_ent, sizeof(rel));
                    r_offset = rel.r_offset;
                    sym_index = ELF64_R_SYM(rel.r_info);
                    r_type = static_cast<uint32_t>(ELF64_R_TYPE(rel.r_info));
                }
            } else {
                if (is_rela) {
                    Rela rela {};
                    std::memcpy(&rela, raw_ent, sizeof(rela));
                    r_offset = rela.r_offset;
                    sym_index = ELF32_R_SYM(rela.r_info);
                    r_type = static_cast<uint32_t>(ELF32_R_TYPE(rela.r_info));
                } else {
                    Rel rel {};
                    std::memcpy(&rel, raw_ent, sizeof(rel));
                    r_offset = rel.r_offset;
                    sym_index = ELF32_R_SYM(rel.r_info);
                    r_type = static_cast<uint32_t>(ELF32_R_TYPE(rel.r_info));
                }
            }

            if (sym_index == 0) continue;
            if (!is_candidate_func_reloc_type(r_type, is_plt_table)) continue;

            const uint64_t sym_pos = symtab_off + static_cast<uint64_t>(sym_index) * sizeof(Sym);
            if (!range_within_u64(sym_pos, sizeof(Sym), elf.file_size)) continue;
            Sym sym {};
            if (!pread_exact(elf.fd, &sym, sizeof(sym), sym_pos)) continue;

            const uint8_t sym_type = kElf64
                    ? ELF64_ST_TYPE(sym.st_info) : ELF32_ST_TYPE(sym.st_info);
            if (!is_func_reloc_type(r_type, sym_type, is_plt_table)) continue;

            uintptr_t got_addr = 0;
            if (!add_address(elf.load_bias, static_cast<uintptr_t>(r_offset), got_addr)) continue;

            uintptr_t target = 0;
            if (!mem.read(got_addr, &target, sizeof(target))) continue;

            if (target != 0 && !is_trusted_got_target(
                    maps, target, self_fbase, elf.inode, trusted_libs, 7)) {
                // Only read strtab symbol name when a suspicious GOT target is actually found.
                std::string name;
                if (!elf.read_strtab_name(strtab_off, strtab_sz, sym.st_name, name)) continue;
                if (name.empty()) continue;
                if (is_trusted_sigchain_target(maps, target, name)) continue;
                add_finding(findings,
                            OBF("got_hook:") + name,
                            OBF("got_hook"),
                            name,
                            is_plt_table ? OBF("plt_slot_redirected") : OBF("rela_got_redirected"));
            }
        }
    }
}

/**
 * Inspects libriskengine.so's own executable sections (64 KiB windowed SHA-256),
 * plus both PLT (DT_JMPREL) and GOT (DT_RELA / DT_REL) slots via PipeMemoryReader.
 */
void inspect_self_image(const std::vector<MapEntry> &maps,
                        safe_mem::PipeMemoryReader &mem,
                        const safe_mem::PagemapReader &pagemap,
                        std::vector<IntegrityFinding> &findings,
                        const void *&self_fbase_out) {
    std::string self_path;
    uint64_t base_off = 0;
    uint64_t inode = 0;
    uintptr_t load_bias = 0;
    self_fbase_out = nullptr;
    if (!resolve_self_elf(maps, self_path, base_off, inode, load_bias, self_fbase_out)
        || self_path.empty()) {
        return;
    }

    DiskElf elf;
    if (!elf.open(self_path, base_off, load_bias, inode, true)) return;

    // Full executable section 64 KiB windowed SHA-256 check on self (~125-188 KB).
    inspect_exec_sha256_windows(elf, OBF("self"), self_path, mem, pagemap, false, findings);

    std::vector<Dyn> dyn;
    if (!elf.read_dynamic(dyn)) return;

    uint64_t strtab_va = 0, strtab_sz = 0, symtab_va = 0;
    uint64_t pltrel_va = 0, pltrel_sz = 0;
    uint64_t rela_va = 0, rela_sz = 0;
    uint64_t rel_va = 0, rel_sz = 0;
    long pltrel_type = kElf64 ? DT_RELA : DT_REL;
    size_t syment = sizeof(Sym);

    for (const auto &d : dyn) {
        if (d.d_tag == DT_NULL) break;
        if (d.d_tag == DT_STRTAB) strtab_va = d.d_un.d_ptr;
        else if (d.d_tag == DT_STRSZ) strtab_sz = d.d_un.d_val;
        else if (d.d_tag == DT_SYMTAB) symtab_va = d.d_un.d_ptr;
        else if (d.d_tag == DT_SYMENT) syment = static_cast<size_t>(d.d_un.d_val);
        else if (d.d_tag == DT_JMPREL) pltrel_va = d.d_un.d_ptr;
        else if (d.d_tag == DT_PLTRELSZ) pltrel_sz = d.d_un.d_val;
        else if (d.d_tag == DT_PLTREL) pltrel_type = static_cast<long>(d.d_un.d_val);
        else if (d.d_tag == DT_RELA) rela_va = d.d_un.d_ptr;
        else if (d.d_tag == DT_RELASZ) rela_sz = d.d_un.d_val;
        else if (d.d_tag == DT_REL) rel_va = d.d_un.d_ptr;
        else if (d.d_tag == DT_RELSZ) rel_sz = d.d_un.d_val;
    }
    if (strtab_va == 0 || symtab_va == 0 || strtab_sz == 0 || syment != sizeof(Sym)) {
        return;
    }

    uint64_t strtab_off = 0, symtab_off = 0;
    if (!elf.vaddr_to_offset(strtab_va, strtab_off)
        || !elf.vaddr_to_offset(symtab_va, symtab_off)) {
        return;
    }

    // 1. PLT relocations (DT_JMPREL)
    inspect_reloc_table(elf, maps, self_fbase_out, mem,
                        strtab_off, strtab_sz, symtab_off,
                        pltrel_va, pltrel_sz, pltrel_type == DT_RELA, true, findings);

    // 2. GOT / GLOB_DAT relocations (DT_RELA / DT_REL)
    if (rela_va != 0 && rela_sz != 0) {
        inspect_reloc_table(elf, maps, self_fbase_out, mem,
                            strtab_off, strtab_sz, symtab_off,
                            rela_va, rela_sz, true, false, findings);
    }
    if (rel_va != 0 && rel_sz != 0) {
        inspect_reloc_table(elf, maps, self_fbase_out, mem,
                            strtab_off, strtab_sz, symtab_off,
                            rel_va, rel_sz, false, false, findings);
    }
}

void inspect_recorded_baselines(const std::vector<MapEntry> &maps,
                                const void *self_fbase,
                                safe_mem::PipeMemoryReader &mem,
                                std::vector<IntegrityFinding> &findings) {
    if (!mem.available()) return;
    const uintptr_t mask = g_ptr_mask.load(std::memory_order_acquire);
    if (mask == 0) return;

    auto verify_entry = [&](const RecordedFnBaseline &entry,
                            const std::string &token_prefix,
                            const std::string &code) {
        if (!entry.valid) return;
        const uintptr_t raw_addr = entry.masked_ptr ^ mask;
        const uintptr_t code_addr = strip_code_thumb_bit(raw_addr);
        if (code_addr == 0) return;

        // 1. Ensure address still resides in self executable image.
        const MapEntry *m = find_map_containing(maps, code_addr);
        bool in_self = (m != nullptr && is_rx(*m));
        if (in_self && self_fbase != nullptr) {
            Dl_info info {};
            if (dladdr(reinterpret_cast<const void *>(code_addr), &info) != 0
                && info.dli_fbase != nullptr && info.dli_fbase != self_fbase) {
                in_self = false;
            }
        }
        if (!in_self) {
            add_finding(findings,
                        token_prefix + entry.tag,
                        code,
                        entry.tag,
                        OBF("ptr_outside_self_image"));
            return;
        }

        // 2. Compare 16-byte entry prologue SHA-256 against JNI_OnLoad baseline.
        if (entry.has_prologue) {
            uint8_t current_sha[crypto_mini::kSha256DigestSize] = {};
            if (compute_mem_prologue_sha256(mem, raw_addr, current_sha)
                && !crypto_mini::ct_memcmp(current_sha, entry.prologue_sha256,
                                           crypto_mini::kSha256DigestSize)) {
                add_finding(findings,
                            token_prefix + entry.tag,
                            code,
                            entry.tag,
                            OBF("prologue_sha256_mismatch"));
            }
        }
    };

    const size_t jni_n = std::min(g_jni_count.load(std::memory_order_acquire), kMaxRecordedJni);
    for (size_t i = 0; i < jni_n; ++i) {
        verify_entry(g_jni_baselines[i], OBF("jni_self_hook:"), OBF("jni_self_hook"));
    }

    const size_t core_n = std::min(
            g_core_fn_count.load(std::memory_order_acquire), kMaxRecordedCoreFns);
    for (size_t i = 0; i < core_n; ++i) {
        verify_entry(g_core_fn_baselines[i], OBF("fn_prologue_hook:"), OBF("fn_prologue_hook"));
    }
}

void inspect_jni_env_table(JNIEnv *env, const std::vector<MapEntry> &maps,
                           safe_mem::PipeMemoryReader &mem,
                           std::vector<IntegrityFinding> &findings) {
    if (env == nullptr || !mem.available()) return;

    const JNINativeInterface *fn_table = nullptr;
    if (!mem.read(reinterpret_cast<uintptr_t>(env), &fn_table, sizeof(fn_table))
        || fn_table == nullptr) {
        return;
    }

    JNINativeInterface copied {};
    if (!mem.read(reinterpret_cast<uintptr_t>(fn_table), &copied, sizeof(copied))) {
        return;
    }

    const uintptr_t find_class = strip_code_thumb_bit(
            reinterpret_cast<uintptr_t>(reinterpret_cast<void *>(copied.FindClass)));
    const uintptr_t get_version = strip_code_thumb_bit(
            reinterpret_cast<uintptr_t>(reinterpret_cast<void *>(copied.GetVersion)));

    uintptr_t art_start = 0, art_end = 0;
    rx_range_for(maps, OBF("libart.so"), art_start, art_end);
    if (art_start == 0) return;

    auto outside = [&](uintptr_t addr) {
        return addr != 0 && (addr < art_start || addr >= art_end);
    };
    if (outside(find_class)) {
        add_finding(findings,
                    OBF("jni_table_hook:FindClass"),
                    OBF("jni_table_hook"),
                    OBF("JNIEnv::FindClass"),
                    OBF("outside_libart"));
    }
    if (outside(get_version)) {
        add_finding(findings,
                    OBF("jni_table_hook:GetVersion"),
                    OBF("jni_table_hook"),
                    OBF("JNIEnv::GetVersion"),
                    OBF("outside_libart"));
    }
}

}  // namespace

void native_integrity_record_jni_table(const JNINativeMethod *methods, int count) {
    if (methods == nullptr || count <= 0) return;
    const uintptr_t mask = get_or_init_ptr_mask();
    safe_mem::PipeMemoryReader mem;

    const size_t limit = std::min(static_cast<size_t>(count), kMaxRecordedJni);
    for (size_t i = 0; i < limit; ++i) {
        RecordedFnBaseline &slot = g_jni_baselines[i];
        slot = RecordedFnBaseline{};
        const uintptr_t fn_addr = reinterpret_cast<uintptr_t>(methods[i].fnPtr);
        slot.masked_ptr = fn_addr ^ mask;
        std::snprintf(slot.tag, sizeof(slot.tag), "slot_%zu", i);
        slot.has_prologue = mem.available()
                && compute_mem_prologue_sha256(mem, fn_addr, slot.prologue_sha256);
        slot.valid = fn_addr != 0;
    }
    g_jni_count.store(limit, std::memory_order_release);
}

void native_integrity_record_core_fn(const char *tag, const void *fn_ptr) {
    if (tag == nullptr || fn_ptr == nullptr) return;
    const size_t idx = g_core_fn_count.load(std::memory_order_relaxed);
    if (idx >= kMaxRecordedCoreFns) return;

    const uintptr_t mask = get_or_init_ptr_mask();
    safe_mem::PipeMemoryReader mem;

    RecordedFnBaseline &slot = g_core_fn_baselines[idx];
    slot = RecordedFnBaseline{};
    const uintptr_t fn_addr = reinterpret_cast<uintptr_t>(fn_ptr);
    slot.masked_ptr = fn_addr ^ mask;
    std::snprintf(slot.tag, sizeof(slot.tag), "%s", tag);
    slot.has_prologue = mem.available()
            && compute_mem_prologue_sha256(mem, fn_addr, slot.prologue_sha256);
    slot.valid = fn_addr != 0;
    g_core_fn_count.store(idx + 1, std::memory_order_release);
}

std::vector<IntegrityFinding> native_collect_integrity_findings(
        JNIEnv *env, const std::vector<MapEntry> &maps) {
    std::vector<IntegrityFinding> findings;
    safe_mem::PipeMemoryReader mem;
    safe_mem::PagemapReader pagemap;
    if (!mem.available()) {
        return findings;
    }

    const void *self_fbase = nullptr;
    inspect_self_image(maps, mem, pagemap, findings, self_fbase);
    inspect_recorded_baselines(maps, self_fbase, mem, findings);

    const std::vector<std::string> wanted = list_monitored_libc_symbols();
    inspect_library_exports(maps, OBF("libc.so"), wanted, mem, pagemap, findings);
    inspect_library_exports(maps, OBF("libdl.so"), wanted, mem, pagemap, findings);

    // Also run COW-only executable page check on libart.so (catches ART runtime patching).
    const MapEntry *art_map = lowest_named_map(maps, OBF("libart.so"));
    if (art_map != nullptr && !art_map->path.empty()) {
        DiskElf art_elf;
        if (art_elf.open(art_map->path, art_map->offset, art_map->start, art_map->inode)) {
            inspect_exec_sha256_windows(art_elf, OBF("libart.so"), art_map->path,
                                        mem, pagemap, true, findings);
        }
    }

    inspect_jni_env_table(env, maps, mem, findings);
    return findings;
}

std::string native_get_integrity_evidence(JNIEnv *env, const std::vector<MapEntry> &maps) {
    const auto findings = native_collect_integrity_findings(env, maps);
    std::string joined;
    for (size_t i = 0; i < findings.size(); ++i) {
        if (i) joined.push_back(',');
        joined.append(findings[i].token);
    }
    return joined;
}

std::string native_get_integrity_evidence(JNIEnv *env) {
    auto maps = read_self_maps();
    return native_get_integrity_evidence(env, maps);
}
