#include "detector/tee_binder_probe.h"

#include "util/maps_parser.h"
#include "util/obf_str.h"
#include "util/payload_codec.h"
#include "util/safe_mem_read.h"
#include "util/syscall_wrapper.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <linux/android/binder.h>
#include <new>
#include <string>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace {

#if !defined(__LP64__)
#error "RiskEngine tee_binder_probe requires a 64-bit ABI (arm64-v8a or x86_64)"
#endif
using ElfEhdr = Elf64_Ehdr;
using ElfPhdr = Elf64_Phdr;
using ElfDyn = Elf64_Dyn;
using ElfSym = Elf64_Sym;
using ElfRela = Elf64_Rela;
using ElfRel = Elf64_Rel;
#define TEE_ELF_R_SYM(i) ELF64_R_SYM(i)
#define TEE_ELF_R_TYPE(i) ELF64_R_TYPE(i)

#if defined(__aarch64__)
constexpr unsigned long kJumpSlotRelocType = R_AARCH64_JUMP_SLOT;
#elif defined(__x86_64__)
constexpr unsigned long kJumpSlotRelocType = R_X86_64_JUMP_SLOT;
#else
constexpr unsigned long kJumpSlotRelocType = 0;
#endif

constexpr int kRepeatedRounds = 3;
constexpr int kHoneypotSamplesPerRound = 16;
constexpr uint64_t kHoneypotBaseGapThresholdNs = 15000ULL;
constexpr uint64_t kHoneypotNoiseMultiplier = 4ULL;
constexpr uint64_t kHoneypotRatioThresholdPct = 160ULL;
constexpr int kMaxDerDepth = 40;
constexpr size_t kMaxDerBytes = 256 * 1024;

std::string to_hex_ptr(uintptr_t v) {
    char buf[24] = {};
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    return std::string(buf);
}

std::string to_lower_ascii(const std::string &in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        if (c >= 'A' && c <= 'Z') {
            out.push_back(static_cast<char>(c - 'A' + 'a'));
        } else {
            out.push_back(c);
        }
    }
    return out;
}

// Strip /data/app/~~<token>==/ segments so random install tokens never false-positive.
std::string sanitize_install_path(const std::string &path) {
    std::string out = path;
    size_t pos = 0;
    while ((pos = out.find("~~", pos)) != std::string::npos) {
        size_t end = out.find('/', pos);
        if (end == std::string::npos) {
            out.erase(pos);
            break;
        }
        out.erase(pos, end - pos);
    }
    return out;
}

bool read_exact_pread(int fd, void *buf, size_t size, uint64_t offset) {
    auto *dst = static_cast<uint8_t *>(buf);
    size_t done = 0;
    while (done < size) {
        long n = my_pread64(fd, dst + done, size - done, offset + done);
        if (n <= 0) {
            return false;
        }
        done += static_cast<size_t>(n);
    }
    return true;
}

struct LibMapInfo {
    bool found = false;
    uintptr_t lowest_base = 0;
    std::string path;
};

LibMapInfo find_library_in_maps(const std::string &so_suffix) {
    LibMapInfo info{};
    for_each_self_map([&](const MapEntry &entry) -> bool {
        if (entry.path.empty()) {
            return true;
        }
        size_t pos = entry.path.find(so_suffix);
        if (pos == std::string::npos) {
            return true;
        }
        // Require boundary before name ('/' or start) and after name (end or space/deleted)
        bool left_ok = (pos == 0 || entry.path[pos - 1] == '/');
        size_t after = pos + so_suffix.size();
        bool right_ok = (after == entry.path.size() || entry.path[after] == ' ');
        if (!left_ok || !right_ok) {
            return true;
        }
        if (!info.found || entry.start < info.lowest_base) {
            info.found = true;
            info.lowest_base = entry.start;
            info.path = entry.path;
            // Strip " (deleted)" suffix if present for disk path opening
            size_t sp = info.path.find(" (deleted)");
            if (sp != std::string::npos) {
                info.path.resize(sp);
            }
        }
        return true;
    });
    return info;
}

// ==================== Vector 1: /proc/self/maps Scan ====================

void run_maps_vector(payload_codec::PayloadBuilder &pb, int &hits_out) {
    const std::array<std::string, 5> needles = {
        OBF("trickystore"),
        OBF("tricky_store"),
        OBF("keystore_interceptor"),
        OBF("libtricky"),
        OBF("teesimulator"),
    };

    std::vector<std::string> seen;
    for_each_self_map([&](const MapEntry &entry) -> bool {
        if (entry.path.empty()) {
            return true;
        }
        std::string clean = to_lower_ascii(sanitize_install_path(entry.path));
        for (const auto &needle : needles) {
            if (!needle.empty() && clean.find(needle) != std::string::npos) {
                std::string key = needle + "|" + entry.path;
                if (std::find(seen.begin(), seen.end(), key) == seen.end()) {
                    seen.push_back(key);
                    payload_codec::RecordBuilder rec;
                    rec.add("kind", "maps_artifact")
                       .add("token", needle)
                       .add("path", entry.path);
                    pb.add_record(rec);
                    hits_out++;
                }
                break;
            }
        }
        return true;
    });
}

// ==================== Vector 2: libbinder.so ioctl GOT ====================

void run_got_ioctl_vector(safe_mem::PipeMemoryReader &mem,
                          payload_codec::PayloadBuilder &pb,
                          int &checked_out,
                          int &hits_out) {
    if (!mem.available() || kJumpSlotRelocType == 0) {
        return;
    }

    const auto ioctl_sym = OBF("ioctl");
    void *real_ioctl = dlsym(RTLD_DEFAULT, ioctl_sym.c_str());
    if (real_ioctl == nullptr) {
        return;
    }

    const auto libbinder_name = OBF("libbinder.so");
    LibMapInfo binder = find_library_in_maps(libbinder_name);
    if (!binder.found || binder.path.empty()) {
        return;
    }

    safe_mem::ScopedFd fd(static_cast<int>(
            my_openat(AT_FDCWD, binder.path.c_str(), O_RDONLY | O_CLOEXEC, 0)));
    if (!fd.valid()) {
        return;
    }

    ElfEhdr ehdr{};
    if (!read_exact_pread(fd.get(), &ehdr, sizeof(ehdr), 0)
            || std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0
            || ehdr.e_phnum == 0 || ehdr.e_phnum > 128
            || ehdr.e_phentsize != sizeof(ElfPhdr)) {
        return;
    }

    std::vector<ElfPhdr> phdrs;
    phdrs.resize(ehdr.e_phnum);
    if (!read_exact_pread(fd.get(), phdrs.data(), sizeof(ElfPhdr) * ehdr.e_phnum, ehdr.e_phoff)) {
        return;
    }

    uintptr_t min_load_vaddr = UINTPTR_MAX;
    uintptr_t dyn_vaddr = 0;
    size_t dyn_memsz = 0;
    for (const auto &ph : phdrs) {
        if (ph.p_type == PT_LOAD && ph.p_vaddr < min_load_vaddr) {
            min_load_vaddr = static_cast<uintptr_t>(ph.p_vaddr);
        }
        if (ph.p_type == PT_DYNAMIC) {
            dyn_vaddr = static_cast<uintptr_t>(ph.p_vaddr);
            dyn_memsz = static_cast<size_t>(ph.p_memsz);
        }
    }
    if (min_load_vaddr == UINTPTR_MAX || dyn_vaddr == 0 || dyn_memsz < sizeof(ElfDyn)) {
        return;
    }

    // Load bias accounts for ELF files whose first PT_LOAD has non-zero p_vaddr.
    const long sys_pg = sysconf(_SC_PAGESIZE);
    const uintptr_t page_size = (sys_pg > 0 && (sys_pg & (sys_pg - 1)) == 0)
            ? static_cast<uintptr_t>(sys_pg) : static_cast<uintptr_t>(4096U);
    const uintptr_t page_mask = ~(page_size - 1U);
    const uintptr_t load_bias = binder.lowest_base - (min_load_vaddr & page_mask);
    const uintptr_t dyn_addr = load_bias + dyn_vaddr;

    const size_t max_dyn = std::min<size_t>(dyn_memsz / sizeof(ElfDyn), 512);
    uintptr_t jmprel = 0;
    size_t pltrelsz = 0;
    uintptr_t pltrel_type = 0;
    uintptr_t symtab_addr = 0;
    uintptr_t strtab_addr = 0;
    size_t strsz = 0;

    for (size_t i = 0; i < max_dyn; ++i) {
        ElfDyn dyn{};
        if (!mem.read(dyn_addr + i * sizeof(ElfDyn), &dyn, sizeof(dyn))) {
            return;
        }
        if (dyn.d_tag == DT_NULL) {
            break;
        }
        switch (dyn.d_tag) {
            case DT_JMPREL:
                jmprel = static_cast<uintptr_t>(dyn.d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                pltrelsz = static_cast<size_t>(dyn.d_un.d_val);
                break;
            case DT_PLTREL:
                pltrel_type = static_cast<uintptr_t>(dyn.d_un.d_val);
                break;
            case DT_SYMTAB:
                symtab_addr = static_cast<uintptr_t>(dyn.d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab_addr = static_cast<uintptr_t>(dyn.d_un.d_ptr);
                break;
            case DT_STRSZ:
                strsz = static_cast<size_t>(dyn.d_un.d_val);
                break;
            default:
                break;
        }
    }

    auto rebase_if_needed = [load_bias, base = binder.lowest_base](uintptr_t ptr) -> uintptr_t {
        if (ptr == 0) return 0;
        return ptr < base ? (load_bias + ptr) : ptr;
    };
    jmprel = rebase_if_needed(jmprel);
    symtab_addr = rebase_if_needed(symtab_addr);
    strtab_addr = rebase_if_needed(strtab_addr);

    if (jmprel == 0 || pltrelsz == 0 || symtab_addr == 0 || strtab_addr == 0) {
        return;
    }

    const bool use_rela = (pltrel_type == DT_RELA)
            || (pltrel_type == 0 && sizeof(void *) == 8);
    const size_t entry_size = use_rela ? sizeof(ElfRela) : sizeof(ElfRel);
    const size_t rel_count = std::min<size_t>(pltrelsz / entry_size, 4096);

    const auto libc_suffix = OBF("libc.so");

    for (size_t i = 0; i < rel_count; ++i) {
        uintptr_t r_offset = 0;
        unsigned long r_info = 0;
        if (use_rela) {
            ElfRela rela{};
            if (!mem.read(jmprel + i * sizeof(ElfRela), &rela, sizeof(rela))) {
                break;
            }
            r_offset = static_cast<uintptr_t>(rela.r_offset);
            r_info = static_cast<unsigned long>(rela.r_info);
        } else {
            ElfRel rel{};
            if (!mem.read(jmprel + i * sizeof(ElfRel), &rel, sizeof(rel))) {
                break;
            }
            r_offset = static_cast<uintptr_t>(rel.r_offset);
            r_info = static_cast<unsigned long>(rel.r_info);
        }

        if (TEE_ELF_R_TYPE(r_info) != kJumpSlotRelocType) {
            continue;
        }
        const unsigned long sym_idx = TEE_ELF_R_SYM(r_info);
        ElfSym sym{};
        if (!mem.read(symtab_addr + sym_idx * sizeof(ElfSym), &sym, sizeof(sym))) {
            continue;
        }
        const size_t need_len = ioctl_sym.size() + 1;
        if (strsz > 0 && (sym.st_name >= strsz || strsz - sym.st_name < need_len)) {
            continue;
        }
        char name_buf[16] = {};
        if (need_len > sizeof(name_buf)
                || !mem.read(strtab_addr + sym.st_name, name_buf, need_len)) {
            continue;
        }
        if (std::memcmp(name_buf, ioctl_sym.c_str(), need_len) != 0) {
            continue;
        }

        checked_out++;
        uintptr_t got_value = 0;
        if (!mem.read(load_bias + r_offset, &got_value, sizeof(got_value))) {
            return;
        }

        const uintptr_t real_addr = reinterpret_cast<uintptr_t>(real_ioctl);
        if (got_value != real_addr) {
            Dl_info dl_info{};
            std::string hook_lib = "unknown";
            bool in_libc = false;
            if (dladdr(reinterpret_cast<void *>(got_value), &dl_info)
                    && dl_info.dli_fname != nullptr) {
                hook_lib = dl_info.dli_fname;
                if (hook_lib.find(libc_suffix) != std::string::npos) {
                    in_libc = true;
                }
            }
            if (!in_libc) {
                payload_codec::RecordBuilder rec;
                rec.add("kind", "got_ioctl_hook")
                   .add("got", to_hex_ptr(got_value))
                   .add("real", to_hex_ptr(real_addr))
                   .add("hook_lib", hook_lib);
                pb.add_record(rec);
                hits_out++;
            }
        }
        return;
    }
}

// ==================== Vector 3: ioctl 16B Inline Hook ====================

void run_inline_ioctl_vector(safe_mem::PipeMemoryReader &mem,
                             payload_codec::PayloadBuilder &pb,
                             int &checked_out,
                             int &hits_out) {
    if (!mem.available()) {
        return;
    }

    const auto ioctl_sym = OBF("ioctl");
    void *ioctl_addr = dlsym(RTLD_DEFAULT, ioctl_sym.c_str());
    if (ioctl_addr == nullptr) {
        return;
    }

    Dl_info ioctl_info{};
    if (!dladdr(ioctl_addr, &ioctl_info) || ioctl_info.dli_fname == nullptr) {
        return;
    }

    const uintptr_t code_addr = reinterpret_cast<uintptr_t>(ioctl_addr);

    uint8_t mem_prologue[16] = {};
    if (!mem.read(code_addr, mem_prologue, sizeof(mem_prologue))) {
        return;
    }

    checked_out++;
    bool detected = false;
    (void) detected;

    safe_mem::ScopedFd fd(static_cast<int>(
            my_openat(AT_FDCWD, ioctl_info.dli_fname, O_RDONLY | O_CLOEXEC, 0)));
    if (fd.valid()) {
        ElfEhdr ehdr{};
        if (read_exact_pread(fd.get(), &ehdr, sizeof(ehdr), 0)
                && std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) == 0
                && ehdr.e_phnum > 0 && ehdr.e_phnum <= 128
                && ehdr.e_phentsize == sizeof(ElfPhdr)) {
            std::vector<ElfPhdr> phdrs;
            phdrs.resize(ehdr.e_phnum);
            if (read_exact_pread(fd.get(), phdrs.data(), sizeof(ElfPhdr) * ehdr.e_phnum, ehdr.e_phoff)) {
                uintptr_t min_load_vaddr = UINTPTR_MAX;
                for (const auto &ph : phdrs) {
                    if (ph.p_type == PT_LOAD && ph.p_vaddr < min_load_vaddr) {
                        min_load_vaddr = static_cast<uintptr_t>(ph.p_vaddr);
                    }
                }
                if (min_load_vaddr != UINTPTR_MAX && ioctl_info.dli_fbase != nullptr) {
                    const uintptr_t base = reinterpret_cast<uintptr_t>(ioctl_info.dli_fbase);
                    const long sys_pg = sysconf(_SC_PAGESIZE);
                    const uintptr_t page_size = (sys_pg > 0 && (sys_pg & (sys_pg - 1)) == 0)
                            ? static_cast<uintptr_t>(sys_pg) : static_cast<uintptr_t>(4096U);
                    const uintptr_t page_mask = ~(page_size - 1U);
                    const uintptr_t load_bias = base - (min_load_vaddr & page_mask);
                    if (code_addr >= load_bias) {
                        const uintptr_t ioctl_va = code_addr - load_bias;
                        for (const auto &ph : phdrs) {
                            if (ph.p_type != PT_LOAD) continue;
                            if (ioctl_va >= ph.p_vaddr
                                    && ioctl_va + sizeof(mem_prologue) <= ph.p_vaddr + ph.p_filesz) {
                                const uint64_t file_off = ph.p_offset + (ioctl_va - ph.p_vaddr);
                                uint8_t disk_prologue[16] = {};
                                if (read_exact_pread(fd.get(), disk_prologue, sizeof(disk_prologue), file_off)) {
                                    if (std::memcmp(mem_prologue, disk_prologue, sizeof(mem_prologue)) != 0) {
                                        detected = true;
                                        payload_codec::RecordBuilder rec;
                                        rec.add("kind", "inline_ioctl_hook")
                                           .add("reason", "disk_mem_16b_mismatch")
                                           .add("lib", ioctl_info.dli_fname);
                                        pb.add_record(rec);
                                        hits_out++;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

#if defined(__aarch64__)
    if (!detected) {
        uint32_t insns[4] = {};
        std::memcpy(insns, mem_prologue, sizeof(insns));
        // Check first instruction for cross-library unconditional B trampoline
        if ((insns[0] & 0xFC000000U) == 0x14000000U) {
            int32_t imm26 = static_cast<int32_t>(insns[0] << 6) >> 6;
            uintptr_t target = code_addr + static_cast<uintptr_t>(static_cast<intptr_t>(imm26) * 4);
            Dl_info tgt_info{};
            if (dladdr(reinterpret_cast<void *>(target), &tgt_info)
                    && tgt_info.dli_fname != nullptr
                    && std::strcmp(tgt_info.dli_fname, ioctl_info.dli_fname) != 0) {
                detected = true;
                payload_codec::RecordBuilder rec;
                rec.add("kind", "inline_ioctl_hook")
                   .add("reason", "arm64_external_branch")
                   .add("hook_lib", tgt_info.dli_fname);
                pb.add_record(rec);
                hits_out++;
            }
        }
        // Check first two instructions for BR Xn trampoline
        if (!detected) {
            for (int i = 0; i < 2; ++i) {
                if ((insns[i] & 0xFFFFFC1FU) == 0xD61F0000U) {
                    payload_codec::RecordBuilder rec;
                    rec.add("kind", "inline_ioctl_hook")
                       .add("reason", "arm64_br_trampoline");
                    pb.add_record(rec);
                    hits_out++;
                    break;
                }
            }
        }
    }
#endif
}

// ==================== 3-Way Ioctl Backends (Libc / Syscall / Asm) ====================

enum class IoctlBackend : uint8_t {
    LIBC = 0,
    SYSCALL = 1,
    ASM = 2,
};

struct IoctlOutcome {
    long ret = -1;
    int err = 0;
};

long inline_asm_ioctl(int fd, unsigned long req, void *arg) noexcept {
#if defined(__aarch64__)
    register long x8 __asm__("x8") = __NR_ioctl;
    register long x0 __asm__("x0") = static_cast<long>(fd);
    register long x1 __asm__("x1") = static_cast<long>(req);
    register long x2 __asm__("x2") = reinterpret_cast<long>(arg);
    __asm__ __volatile__(
            "svc #0"
            : "+r"(x0)
            : "r"(x1), "r"(x2), "r"(x8)
            : "memory", "cc");
    return x0;
#elif defined(__x86_64__)
    long ret = 0;
    __asm__ __volatile__(
            "syscall"
            : "=a"(ret)
            : "a"(static_cast<long>(__NR_ioctl)),
              "D"(static_cast<long>(fd)),
              "S"(static_cast<long>(req)),
              "d"(reinterpret_cast<long>(arg))
            : "rcx", "r11", "memory", "cc");
    return ret;
#else
    return my_ioctl(fd, req, reinterpret_cast<unsigned long>(arg));
#endif
}

IoctlOutcome invoke_ioctl(IoctlBackend backend, int fd, unsigned long req, void *arg) {
    constexpr int kMaxEintrRetries = 4;
    IoctlOutcome out{};
    for (int attempt = 0; attempt <= kMaxEintrRetries; ++attempt) {
        if (backend == IoctlBackend::LIBC) {
            errno = 0;
            int rc = ::ioctl(fd, req, arg);
            out.ret = rc;
            out.err = (rc < 0) ? errno : 0;
        } else if (backend == IoctlBackend::SYSCALL) {
            errno = 0;
            long rc = ::syscall(__NR_ioctl, fd, req, arg);
            out.ret = rc;
            out.err = (rc < 0) ? errno : 0;
        } else {
            long raw = inline_asm_ioctl(fd, req, arg);
            if (raw < 0 && raw >= -4095) {
                out.ret = -1;
                out.err = static_cast<int>(-raw);
            } else {
                out.ret = raw;
                out.err = 0;
            }
        }
        if (!(out.ret < 0 && out.err == EINTR)) {
            break;
        }
    }
    return out;
}

int open_binder_dev() {
    const auto dev_binder = OBF("/dev/binder");
    int fd = static_cast<int>(my_openat(AT_FDCWD, dev_binder.c_str(), O_RDWR | O_CLOEXEC, 0));
    if (fd >= 0) {
        return fd;
    }
    const auto dev_hwbinder = OBF("/dev/hwbinder");
    return static_cast<int>(my_openat(AT_FDCWD, dev_hwbinder.c_str(), O_RDWR | O_CLOEXEC, 0));
}

// ==================== Vector 4: BINDER_VERSION 3-Way Parity ====================

void run_binder_version_parity_vector(payload_codec::PayloadBuilder &pb,
                                      int &checked_out,
                                      int &hits_out) {
    int mismatch_rounds = 0;
    std::string first_detail;

    for (int round = 0; round < kRepeatedRounds; ++round) {
        safe_mem::ScopedFd fd(open_binder_dev());
        if (!fd.valid()) {
            return;
        }
        checked_out++;

        struct binder_version v_libc{};
        struct binder_version v_sys{};
        struct binder_version v_asm{};

        IoctlOutcome o_libc = invoke_ioctl(IoctlBackend::LIBC, fd.get(), BINDER_VERSION, &v_libc);
        IoctlOutcome o_sys = invoke_ioctl(IoctlBackend::SYSCALL, fd.get(), BINDER_VERSION, &v_sys);
        IoctlOutcome o_asm = invoke_ioctl(IoctlBackend::ASM, fd.get(), BINDER_VERSION, &v_asm);

        bool libc_vs_sys = (o_libc.ret == o_sys.ret && o_libc.err == o_sys.err
                && v_libc.protocol_version == v_sys.protocol_version);
        bool libc_vs_asm = (o_libc.ret == o_asm.ret && o_libc.err == o_asm.err
                && v_libc.protocol_version == v_asm.protocol_version);
        bool sys_vs_asm = (o_sys.ret == o_asm.ret && o_sys.err == o_asm.err
                && v_sys.protocol_version == v_asm.protocol_version);

        if (!libc_vs_sys || !libc_vs_asm || !sys_vs_asm) {
            mismatch_rounds++;
            if (first_detail.empty()) {
                char buf[160] = {};
                std::snprintf(buf, sizeof(buf),
                        "libc=%ld/%d/%d;sys=%ld/%d/%d;asm=%ld/%d/%d",
                        o_libc.ret, o_libc.err, static_cast<int>(v_libc.protocol_version),
                        o_sys.ret, o_sys.err, static_cast<int>(v_sys.protocol_version),
                        o_asm.ret, o_asm.err, static_cast<int>(v_asm.protocol_version));
                first_detail = buf;
            }
        }
    }

    if (mismatch_rounds >= 2) {
        payload_codec::RecordBuilder rec;
        rec.add("kind", "binder_version_mismatch")
           .add_int("mismatch_rounds", mismatch_rounds)
           .add("detail", first_detail);
        pb.add_record(rec);
        hits_out++;
    }
}

// ==================== Vector 5: Rotating-Order Binder Honeypot ====================

uint64_t monotonic_now_ns() noexcept {
    struct timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
}

struct TimingSummary {
    bool valid = false;
    uint64_t median_ns = 0;
    uint64_t mad_ns = 0;
};

TimingSummary compute_median_mad(std::vector<uint64_t> values) {
    TimingSummary s{};
    if (values.empty()) {
        return s;
    }
    std::sort(values.begin(), values.end());
    size_t mid = values.size() / 2;
    s.median_ns = (values.size() % 2 == 1)
            ? values[mid]
            : (values[mid - 1] + values[mid]) / 2ULL;

    std::vector<uint64_t> devs;
    devs.reserve(values.size());
    for (uint64_t v : values) {
        devs.push_back(v >= s.median_ns ? (v - s.median_ns) : (s.median_ns - v));
    }
    std::sort(devs.begin(), devs.end());
    s.mad_ns = (devs.size() % 2 == 1)
            ? devs[mid]
            : (devs[mid - 1] + devs[mid]) / 2ULL;
    s.valid = true;
    return s;
}

void run_honeypot_timing_vector(payload_codec::PayloadBuilder &pb,
                                int &checked_out,
                                int &hits_out) {
    const auto ks_desc = OBF("android.security.keystore2");
    int suspicious_rounds = 0;
    std::vector<uint64_t> round_gaps;
    std::vector<uint64_t> round_floors;
    std::vector<uint64_t> round_ratios;

    for (int round = 0; round < kRepeatedRounds; ++round) {
        safe_mem::ScopedFd fd(open_binder_dev());
        if (!fd.valid()) {
            return;
        }
        void *mapped = reinterpret_cast<void *>(
                my_mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, fd.get(), 0));
        if (mapped == MAP_FAILED) {
            return;
        }

        checked_out++;
        // Rotate execution order across rounds to cancel cold-start/cache bias
        IoctlBackend order[3] = {
            static_cast<IoctlBackend>(round % 3),
            static_cast<IoctlBackend>((round + 1) % 3),
            static_cast<IoctlBackend>((round + 2) % 3),
        };

        TimingSummary summaries[3] = {};
        uint8_t write_buf[256] = {};
        uint8_t fake_data[64] = {};
        size_t desc_len = std::min<size_t>(ks_desc.size(), sizeof(fake_data) - 1);
        std::memcpy(fake_data, ks_desc.data(), desc_len);

        const uint32_t cmd = BC_TRANSACTION;
        std::memcpy(write_buf, &cmd, sizeof(cmd));

        struct binder_transaction_data txn{};
        txn.target.handle = 0;
        txn.code = 1;
        txn.data_size = sizeof(fake_data);
        txn.offsets_size = 0;
        txn.data.ptr.buffer = static_cast<binder_uintptr_t>(reinterpret_cast<uintptr_t>(fake_data));
        txn.data.ptr.offsets = 0;
        std::memcpy(write_buf + sizeof(cmd), &txn, sizeof(txn));

        for (IoctlBackend b : order) {
            std::vector<uint64_t> samples;
            samples.reserve(kHoneypotSamplesPerRound);
            for (int i = 0; i < kHoneypotSamplesPerRound; ++i) {
                struct binder_write_read bwr{};
                bwr.write_buffer = static_cast<binder_uintptr_t>(reinterpret_cast<uintptr_t>(write_buf));
                bwr.write_size = sizeof(cmd) + sizeof(txn);
                bwr.write_consumed = 0;

                uint64_t t0 = monotonic_now_ns();
                (void) invoke_ioctl(b, fd.get(), BINDER_WRITE_READ, &bwr);
                uint64_t t1 = monotonic_now_ns();
                samples.push_back(t1 >= t0 ? (t1 - t0) : 0ULL);
            }
            summaries[static_cast<int>(b)] = compute_median_mad(std::move(samples));
        }

        my_munmap(mapped, 4096);

        const TimingSummary &s_libc = summaries[static_cast<int>(IoctlBackend::LIBC)];
        const TimingSummary &s_sys = summaries[static_cast<int>(IoctlBackend::SYSCALL)];
        const TimingSummary &s_asm = summaries[static_cast<int>(IoctlBackend::ASM)];
        if (!s_libc.valid || !s_sys.valid || !s_asm.valid) {
            continue;
        }

        uint64_t lower_fast = std::min(s_sys.median_ns, s_asm.median_ns);
        uint64_t lower_slow = std::max(s_sys.median_ns, s_asm.median_ns);
        bool lower_stable = (lower_slow <= lower_fast + 25000ULL)
                && (lower_slow * 2ULL <= std::max<uint64_t>(1ULL, lower_fast) * 3ULL);

        if (s_libc.median_ns > lower_fast) {
            uint64_t gap = s_libc.median_ns - lower_fast;
            uint64_t lower_mad = (s_sys.median_ns <= s_asm.median_ns) ? s_sys.mad_ns : s_asm.mad_ns;
            uint64_t noise_floor = std::max({
                kHoneypotBaseGapThresholdNs,
                s_libc.mad_ns * kHoneypotNoiseMultiplier,
                lower_mad * kHoneypotNoiseMultiplier,
            });
            uint64_t ratio_pct = (s_libc.median_ns * 100ULL) / std::max<uint64_t>(1ULL, lower_fast);
            round_gaps.push_back(gap);
            round_floors.push_back(noise_floor);
            round_ratios.push_back(ratio_pct);

            if (lower_stable && gap > noise_floor && ratio_pct >= kHoneypotRatioThresholdPct) {
                suspicious_rounds++;
            }
        }
    }

    if (suspicious_rounds >= 2) {
        TimingSummary gap_sum = compute_median_mad(round_gaps);
        TimingSummary floor_sum = compute_median_mad(round_floors);
        TimingSummary ratio_sum = compute_median_mad(round_ratios);

        payload_codec::RecordBuilder rec;
        rec.add("kind", "honeypot_timing_anomaly")
           .add_int("hits", suspicious_rounds)
           .add_uint("median_gap_ns", gap_sum.median_ns)
           .add_uint("gap_mad_ns", gap_sum.mad_ns)
           .add_uint("noise_floor_ns", floor_sum.median_ns)
           .add_uint("ratio_pct", ratio_sum.median_ns);
        pb.add_record(rec);
        hits_out++;
    }
}

// ==================== Native Leaf DER Inspector ====================

struct DerTlv {
    bool ok = false;
    uint8_t tag_class = 0;
    bool constructed = false;
    uint32_t tag_number = 0;
    size_t value_offset = 0;
    size_t value_length = 0;
    size_t next_offset = 0;
    bool non_minimal_length = false;
};

DerTlv parse_der_tlv(const uint8_t *bytes, size_t end, size_t offset) {
    DerTlv tlv{};
    if (bytes == nullptr || offset >= end) {
        return tlv;
    }

    size_t cur = offset;
    uint8_t first_tag = bytes[cur++];
    tlv.tag_class = (first_tag >> 6) & 0x03U;
    tlv.constructed = (first_tag & 0x20U) != 0U;
    uint32_t tag_num = first_tag & 0x1FU;

    if (tag_num == 0x1FU) {
        tag_num = 0;
        int tag_bytes = 0;
        while (true) {
            if (cur >= end) return tlv;
            uint8_t b = bytes[cur++];
            if (tag_bytes == 0 && (b & 0x7FU) == 0U) {
                tlv.non_minimal_length = true;
            }
            if (++tag_bytes > 5 || tag_num > (static_cast<uint32_t>(INT32_MAX) >> 7)) {
                return tlv;
            }
            tag_num = (tag_num << 7) | (b & 0x7FU);
            if ((b & 0x80U) == 0U) {
                break;
            }
        }
        if (tag_num < 31U) {
            tlv.non_minimal_length = true;
        }
    }
    tlv.tag_number = tag_num;

    if (cur >= end) {
        return tlv;
    }

    uint8_t len_byte = bytes[cur++];
    size_t val_len = 0;
    if ((len_byte & 0x80U) == 0U) {
        val_len = len_byte;
    } else {
        size_t len_octets = len_byte & 0x7FU;
        if (len_octets == 0 || len_octets > 4 || end - cur < len_octets) {
            return tlv;
        }
        uint8_t first_len_octet = bytes[cur];
        for (size_t i = 0; i < len_octets; ++i) {
            val_len = (val_len << 8) | bytes[cur++];
        }
        if (first_len_octet == 0x00 || val_len <= 0x7FU) {
            tlv.non_minimal_length = true;
        }
    }

    if (val_len > end - cur) {
        return tlv;
    }

    tlv.ok = true;
    tlv.value_offset = cur;
    tlv.value_length = val_len;
    tlv.next_offset = cur + val_len;
    return tlv;
}

bool is_ascii_hex_char(uint8_t c) {
    return (c >= '0' && c <= '9')
            || (c >= 'a' && c <= 'f')
            || (c >= 'A' && c <= 'F');
}

bool is_hex_template_tag(const DerTlv &tlv) {
    if (tlv.tag_class != 0 || tlv.constructed) {
        return false;
    }
    return tlv.tag_number == 0x04 || tlv.tag_number == 0x0C
            || tlv.tag_number == 0x13 || tlv.tag_number == 0x14
            || tlv.tag_number == 0x16 || tlv.tag_number == 0x1A;
}

struct DerScanFlags {
    bool hex_template_32 = false;
    bool non_minimal_length = false;
    bool structure_invalid = false;
};

struct ByteRange {
    bool valid = false;
    size_t start = 0;
    size_t end = 0;
};

// Locate X.509 TBSCertificate.issuer byte range so genuine Google KeyMint/StrongBox Batch CA
// Issuer serialNumber=<32-hex> RDNs do not trigger HEX_TEMPLATE_32 false positives.
ByteRange find_x509_issuer_range(const uint8_t *bytes, size_t len) {
    ByteRange none{};
    DerTlv cert = parse_der_tlv(bytes, len, 0);
    if (!cert.ok || cert.tag_class != 0 || !cert.constructed
            || cert.tag_number != 0x10 || cert.next_offset != len) {
        return none;
    }
    size_t cur = cert.value_offset;
    size_t end = cert.next_offset;
    DerTlv tbs = parse_der_tlv(bytes, end, cur);
    if (!tbs.ok || tbs.tag_class != 0 || !tbs.constructed || tbs.tag_number != 0x10) {
        return none;
    }
    cur = tbs.next_offset;
    if (cur >= end) {
        return none;
    }
    DerTlv sig_alg = parse_der_tlv(bytes, end, cur);
    if (!sig_alg.ok || sig_alg.tag_class != 0 || !sig_alg.constructed || sig_alg.tag_number != 0x10) {
        return none;
    }
    cur = sig_alg.next_offset;
    if (cur >= end) {
        return none;
    }
    DerTlv sig_val = parse_der_tlv(bytes, end, cur);
    if (!sig_val.ok || sig_val.tag_class != 0 || sig_val.constructed
            || sig_val.tag_number != 0x03 || sig_val.next_offset != end) {
        return none;
    }

    // Inside TBSCertificate (RFC 5280 §4.1.2):
    //   version [0] EXPLICIT Version (INTEGER) OPTIONAL,
    //   serialNumber INTEGER, signature SEQUENCE, issuer SEQUENCE,
    //   validity SEQUENCE, subject SEQUENCE, subjectPublicKeyInfo SEQUENCE, ...
    size_t tbs_cur = tbs.value_offset;
    size_t tbs_end = tbs.next_offset;
    if (tbs_cur >= tbs_end) {
        return none;
    }
    DerTlv field = parse_der_tlv(bytes, tbs_end, tbs_cur);
    if (!field.ok || field.next_offset <= tbs_cur || field.next_offset > tbs_end) {
        return none;
    }
    if (field.tag_class == 2 && field.constructed && field.tag_number == 0) {
        if (field.value_length == 0) {
            return none;
        }
        DerTlv ver_int = parse_der_tlv(bytes, field.next_offset, field.value_offset);
        if (!ver_int.ok || ver_int.tag_class != 0 || ver_int.constructed
                || ver_int.tag_number != 0x02 || ver_int.next_offset != field.next_offset) {
            return none;
        }
        tbs_cur = field.next_offset;
        if (tbs_cur >= tbs_end) {
            return none;
        }
        field = parse_der_tlv(bytes, tbs_end, tbs_cur);
        if (!field.ok || field.next_offset <= tbs_cur || field.next_offset > tbs_end) {
            return none;
        }
    }
    // serialNumber: primitive INTEGER
    if (field.tag_class != 0 || field.constructed || field.tag_number != 0x02) {
        return none;
    }
    tbs_cur = field.next_offset;
    if (tbs_cur >= tbs_end) {
        return none;
    }
    // signature: constructed SEQUENCE
    DerTlv tbs_sig = parse_der_tlv(bytes, tbs_end, tbs_cur);
    if (!tbs_sig.ok || tbs_sig.tag_class != 0 || !tbs_sig.constructed
            || tbs_sig.tag_number != 0x10 || tbs_sig.next_offset <= tbs_cur
            || tbs_sig.next_offset > tbs_end) {
        return none;
    }
    tbs_cur = tbs_sig.next_offset;
    if (tbs_cur >= tbs_end) {
        return none;
    }
    // issuer: constructed SEQUENCE
    DerTlv issuer = parse_der_tlv(bytes, tbs_end, tbs_cur);
    if (!issuer.ok || issuer.tag_class != 0 || !issuer.constructed
            || issuer.tag_number != 0x10 || issuer.next_offset <= tbs_cur
            || issuer.next_offset > tbs_end) {
        return none;
    }
    const size_t issuer_start = tbs_cur;
    const size_t issuer_end = issuer.next_offset;
    tbs_cur = issuer_end;
    if (tbs_cur >= tbs_end) {
        return none;
    }
    // validity: constructed SEQUENCE
    DerTlv validity = parse_der_tlv(bytes, tbs_end, tbs_cur);
    if (!validity.ok || validity.tag_class != 0 || !validity.constructed
            || validity.tag_number != 0x10 || validity.next_offset <= tbs_cur
            || validity.next_offset > tbs_end) {
        return none;
    }
    tbs_cur = validity.next_offset;
    if (tbs_cur >= tbs_end) {
        return none;
    }
    // subject: constructed SEQUENCE
    DerTlv subject = parse_der_tlv(bytes, tbs_end, tbs_cur);
    if (!subject.ok || subject.tag_class != 0 || !subject.constructed
            || subject.tag_number != 0x10 || subject.next_offset <= tbs_cur
            || subject.next_offset > tbs_end) {
        return none;
    }
    tbs_cur = subject.next_offset;
    if (tbs_cur >= tbs_end) {
        return none;
    }
    // subjectPublicKeyInfo: constructed SEQUENCE
    DerTlv spki = parse_der_tlv(bytes, tbs_end, tbs_cur);
    if (!spki.ok || spki.tag_class != 0 || !spki.constructed
            || spki.tag_number != 0x10 || spki.next_offset <= tbs_cur
            || spki.next_offset > tbs_end) {
        return none;
    }

    ByteRange range{};
    range.valid = true;
    range.start = issuer_start;
    range.end = issuer_end;
    return range;
}

bool walk_der_tree(const uint8_t *bytes,
                   size_t start,
                   size_t end,
                   int depth,
                   DerScanFlags &flags,
                   const ByteRange &issuer_range) {
    if (depth > kMaxDerDepth || start > end) {
        return false;
    }
    size_t cur = start;
    while (cur < end) {
        DerTlv tlv = parse_der_tlv(bytes, end, cur);
        if (tlv.non_minimal_length) {
            flags.non_minimal_length = true;
        }
        if (!tlv.ok || tlv.next_offset > end || tlv.next_offset <= cur) {
            return false;
        }
        const bool in_issuer = issuer_range.valid
                && cur >= issuer_range.start
                && tlv.next_offset <= issuer_range.end;
        if (!in_issuer && is_hex_template_tag(tlv) && tlv.value_length == 32) {
            bool all_hex = true;
            for (size_t i = 0; i < 32; ++i) {
                if (!is_ascii_hex_char(bytes[tlv.value_offset + i])) {
                    all_hex = false;
                    break;
                }
            }
            if (all_hex) {
                flags.hex_template_32 = true;
            }
        }
        if (tlv.constructed && tlv.value_length > 0) {
            if (!walk_der_tree(bytes, tlv.value_offset, tlv.next_offset,
                               depth + 1, flags, issuer_range)) {
                return false;
            }
        }
        cur = tlv.next_offset;
    }
    return cur == end;
}

bool fallback_scan_hex_template_32(const uint8_t *bytes,
                                   size_t len,
                                   const ByteRange &issuer_range) {
    size_t run = 0;
    bool all_hex = true;
    for (size_t i = 0; i < len; ++i) {
        if (issuer_range.valid && i >= issuer_range.start && i < issuer_range.end) {
            if (run == 32 && all_hex) {
                return true;
            }
            run = 0;
            all_hex = true;
            continue;
        }
        uint8_t c = bytes[i];
        if (c >= 0x21 && c <= 0x7E) {
            run++;
            if (!is_ascii_hex_char(c)) {
                all_hex = false;
            }
        } else {
            if (run == 32 && all_hex) {
                return true;
            }
            run = 0;
            all_hex = true;
        }
    }
    return run == 32 && all_hex;
}

}  // namespace

std::string native_get_tee_binder_probe(bool include_honeypot_timing) {
    payload_codec::PayloadBuilder pb(payload_codec::Status::OK, 0);
    safe_mem::PipeMemoryReader mem;

    int maps_hits = 0;
    int got_checked = 0;
    int got_hits = 0;
    int inline_checked = 0;
    int inline_hits = 0;
    int version_checked = 0;
    int version_hits = 0;
    int honeypot_checked = 0;
    int honeypot_hits = 0;

    run_maps_vector(pb, maps_hits);
    run_got_ioctl_vector(mem, pb, got_checked, got_hits);
    run_inline_ioctl_vector(mem, pb, inline_checked, inline_hits);
    run_binder_version_parity_vector(pb, version_checked, version_hits);
    if (include_honeypot_timing) {
        run_honeypot_timing_vector(pb, honeypot_checked, honeypot_hits);
    }

    pb.add_header_int("maps_hits", maps_hits)
      .add_header_int("got_checked", got_checked)
      .add_header_int("got_hits", got_hits)
      .add_header_int("inline_checked", inline_checked)
      .add_header_int("inline_hits", inline_hits)
      .add_header_int("version_checked", version_checked)
      .add_header_int("version_hits", version_hits)
      .add_header_int("honeypot_checked", honeypot_checked)
      .add_header_int("honeypot_hits", honeypot_hits);
    return pb.build();
}

std::string native_inspect_leaf_der(const uint8_t *bytes, size_t len) {
    if (bytes == nullptr || len < 8 || len > kMaxDerBytes) {
        payload_codec::PayloadBuilder pb(payload_codec::Status::ERROR, 0);
        pb.add_header("reason", "invalid_der_size");
        return pb.build();
    }

    DerScanFlags flags{};
    const ByteRange issuer_range = find_x509_issuer_range(bytes, len);
    DerTlv top = parse_der_tlv(bytes, len, 0);
    if (top.non_minimal_length) {
        flags.non_minimal_length = true;
    }
    if (!top.ok || top.tag_class != 0 || !top.constructed || top.tag_number != 0x10
            || top.next_offset != len) {
        flags.structure_invalid = true;
    } else {
        if (!walk_der_tree(bytes, top.value_offset, top.next_offset, 1, flags, issuer_range)) {
            flags.structure_invalid = true;
        }
    }
    if (!flags.hex_template_32 && fallback_scan_hex_template_32(bytes, len, issuer_range)) {
        flags.hex_template_32 = true;
    }

    payload_codec::PayloadBuilder pb(payload_codec::Status::OK, 0);
    pb.add_header_int("hex_template_32", flags.hex_template_32 ? 1 : 0)
      .add_header_int("non_minimal_length", flags.non_minimal_length ? 1 : 0)
      .add_header_int("structure_invalid", flags.structure_invalid ? 1 : 0);

    if (flags.hex_template_32) {
        payload_codec::RecordBuilder rec;
        rec.add("kind", "der_finding").add("code", "HEX_TEMPLATE_32");
        pb.add_record(rec);
    }
    if (flags.non_minimal_length) {
        payload_codec::RecordBuilder rec;
        rec.add("kind", "der_finding").add("code", "NON_MINIMAL_LENGTH");
        pb.add_record(rec);
    }
    if (flags.structure_invalid) {
        payload_codec::RecordBuilder rec;
        rec.add("kind", "der_finding").add("code", "DER_STRUCTURE_INVALID");
        pb.add_record(rec);
    }
    return pb.build();
}
