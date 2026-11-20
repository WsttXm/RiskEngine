#include "native_integrity.h"
#include "../generated/detection_lists.h"
#include "../util/maps_parser.h"
#include "../util/obf_str.h"
#include "../util/raw_dir.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <jni.h>
#include <limits>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

void add_token(std::vector<std::string> &tokens, const std::string &token) {
    if (!token.empty()
        && std::find(tokens.begin(), tokens.end(), token) == tokens.end()) {
        tokens.push_back(token);
    }
}

std::string join_tokens(const std::vector<std::string> &tokens) {
    std::string joined;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i) joined += ",";
        joined += tokens[i];
    }
    return joined;
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

#if defined(__aarch64__)
bool looks_like_trampoline(const uint8_t *p, uintptr_t addr,
                           uintptr_t range_start, uintptr_t range_end) {
    uint32_t insn = 0, next = 0, third = 0;
    std::memcpy(&insn, p, sizeof(insn));
    std::memcpy(&next, p + 4, sizeof(next));
    std::memcpy(&third, p + 8, sizeof(third));
    // LDR X16/X17, [PC, #imm] ; BR X16/X17
    if ((insn & 0xFF00001Fu) == 0x58000010u && next == 0xD61F0200u) return true;
    if ((insn & 0xFF00001Fu) == 0x58000011u && next == 0xD61F0220u) return true;
    // ADRP X16/X17, #page ; ADD X16/X17, X16/X17, #off ; BR X16/X17
    if ((insn & 0x9F00001Eu) == 0x90000010u
        && (next & 0xFF8003DEu) == 0x91000210u
        && (third == 0xD61F0200u || third == 0xD61F0220u)) {
        return true;
    }
    // Software breakpoint BRK #imm16
    if ((insn & 0xFFE0001Fu) == 0xD4200000u) return true;
    // Direct out-of-range B #imm26
    if ((insn & 0xFC000000u) == 0x14000000u && range_start < range_end) {
        int32_t imm26 = static_cast<int32_t>(insn & 0x03FFFFFFu);
        if (imm26 & 0x02000000) imm26 |= static_cast<int32_t>(0xFC000000);
        uintptr_t target = addr + (static_cast<intptr_t>(imm26) << 2);
        if (target < range_start || target >= range_end) return true;
    }
    return false;
}
#elif defined(__arm__)
bool looks_like_trampoline(const uint8_t *p, uintptr_t, uintptr_t, uintptr_t) {
    uint32_t insn = 0;
    std::memcpy(&insn, p, sizeof(insn));
    return (insn & 0x0FFFFFF0u) == 0x012FFF10u       // bx/blx register
           || (insn & 0x0F7FF000u) == 0x051FF000u;   // ldr pc, [..]
}
#elif defined(__x86_64__)
bool looks_like_trampoline(const uint8_t *p, uintptr_t, uintptr_t, uintptr_t) {
    if (p[0] == 0xCCu) return true;                              // INT3 breakpoint
    if (p[0] == 0xE9u) return true;                              // JMP rel32
    if (p[0] == 0xFFu && p[1] == 0x25u) return true;             // JMP [rip + disp32]
    if (p[0] == 0x48u && p[1] == 0xB8u                           // MOVABS RAX, imm64
        && p[10] == 0xFFu && p[11] == 0xE0u) return true;        // JMP RAX
    return false;
}
#else
bool looks_like_trampoline(const uint8_t *, uintptr_t, uintptr_t, uintptr_t) {
    return false;
}
#endif

const uint8_t *safe_read(const std::vector<MapEntry> &maps, uintptr_t addr, size_t n) {
    const MapEntry *entry = find_map_containing(maps, addr);
    if (entry == nullptr || addr >= entry->end
            || n > static_cast<size_t>(entry->end - addr)) return nullptr;
    if (entry->perms.empty() || entry->perms[0] != 'r') return nullptr;
    return reinterpret_cast<const uint8_t *>(addr);
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
    uint8_t *dst = reinterpret_cast<uint8_t *>(buf);
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
using Dyn = Elf64_Dyn;
using Sym = Elf64_Sym;
using Rela = Elf64_Rela;
using Rel = Elf64_Rel;
using ElfAddr = Elf64_Addr;
constexpr bool kElf64 = true;
#else
using Ehdr = Elf32_Ehdr;
using Phdr = Elf32_Phdr;
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
    uintptr_t load_bias = 0;
    Ehdr ehdr {};
    std::vector<Phdr> phdrs;

    ~DiskElf() {
        if (fd >= 0) my_close(fd);
    }

    bool open(const std::string &path, uint64_t elf_base_offset, uintptr_t mem_base) {
        struct stat st {};
        if (my_fstatat(AT_FDCWD, path.c_str(), &st, 0) != 0 || st.st_size <= 0) {
            return false;
        }
        file_size = static_cast<uint64_t>(st.st_size);
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
        if (!range_within_u64(base_offset + ehdr.e_phoff, ph_bytes, file_size)) {
            return false;
        }
        phdrs.resize(ehdr.e_phnum);
        if (!pread_exact(fd, phdrs.data(), static_cast<size_t>(ph_bytes),
                         base_offset + ehdr.e_phoff)) {
            return false;
        }

        uintptr_t bias = mem_base;
        for (const auto &ph : phdrs) {
            if (ph.p_type == PT_LOAD && ph.p_offset == 0) {
                if (ph.p_vaddr > mem_base) return false;
                bias = mem_base - static_cast<uintptr_t>(ph.p_vaddr);
                break;
            }
        }
        load_bias = bias;
        return true;
    }

    bool vaddr_to_offset(uint64_t vaddr, uint64_t &file_off) const {
        for (const auto &ph : phdrs) {
            if (ph.p_type != PT_LOAD) continue;
            if (vaddr >= ph.p_vaddr && vaddr < ph.p_vaddr + ph.p_filesz) {
                uint64_t rel = ph.p_offset + (vaddr - ph.p_vaddr);
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
            if (!range_within_u64(base_offset + ph.p_offset, ph.p_filesz, file_size)) {
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
        char buf[256] = {0};
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
    uint32_t header[4] = {0};
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
    uint32_t header[2] = {0};
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

/**
 * Compares the first bytes of exported libc / libdl symbols in memory against
 * their clean on-disk ELF image. Architecture-independent: catches ARM64,
 * ARM32, x86 and x86_64 inline hooks and software breakpoints alike.
 */
void inspect_library_exports(const std::vector<MapEntry> &maps,
                             const std::string &so_name,
                             const std::vector<std::string> &wanted,
                             std::vector<std::string> &tokens) {
    const MapEntry *base_map = lowest_named_map(maps, so_name);
    if (base_map == nullptr || base_map->path.empty()) return;

    DiskElf elf;
    if (!elf.open(base_map->path, base_map->offset, base_map->start)) return;

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

        uint64_t func_file_off = 0;
        if (!elf.vaddr_to_offset(sym.st_value, func_file_off)) continue;

        constexpr size_t kMaxProbe = 32;
        size_t check_len = (sym.st_size > 0 && sym.st_size < kMaxProbe)
                ? static_cast<size_t>(sym.st_size) : kMaxProbe;
        if (check_len < 4) continue;
        if (!range_within_u64(func_file_off, check_len, elf.file_size)) continue;

        uintptr_t mem_addr = 0;
        if (!add_address(elf.load_bias, static_cast<uintptr_t>(sym.st_value), mem_addr)) continue;
        const uint8_t *mem_bytes = safe_read(maps, mem_addr, check_len);
        if (mem_bytes == nullptr) continue;

        uint8_t disk_bytes[kMaxProbe] = {0};
        if (!pread_exact(elf.fd, disk_bytes, check_len, func_file_off)) continue;

        if (std::memcmp(disk_bytes, mem_bytes, check_len) != 0) {
            add_token(tokens, OBF("inline_hook:") + name);
        } else if (check_len >= 12
                   && looks_like_trampoline(mem_bytes, mem_addr, rx_start, rx_end)) {
            add_token(tokens, OBF("inline_hook:") + name);
        }
    }
}

bool is_trusted_got_target(const std::vector<MapEntry> &maps, uintptr_t target,
                           const void *self_fbase) {
    const MapEntry *m = find_map_containing(maps, target);
    if (m == nullptr || !is_rx(*m)) return false;
    if (m->path.empty()) return false;

    Dl_info target_info {};
    if (self_fbase != nullptr
        && dladdr(reinterpret_cast<const void *>(target), &target_info) != 0
        && target_info.dli_fbase == self_fbase) {
        return true;
    }

    const std::string lower = to_lower(m->path);
    return lower.find(OBF("libc.so")) != std::string::npos
           || lower.find(OBF("libdl.so")) != std::string::npos
           || lower.find(OBF("liblog.so")) != std::string::npos
           || lower.find(OBF("libm.so")) != std::string::npos
           || lower.find(OBF("libart.so")) != std::string::npos
           || lower.find(OBF("linker")) != std::string::npos;
}

bool resolve_self_elf(const std::vector<MapEntry> &maps,
                      std::string &path_out,
                      uint64_t &base_file_offset_out,
                      uintptr_t &mem_base_out,
                      const void *&fbase_out) {
    Dl_info owner {};
    fbase_out = nullptr;
    if (dladdr(reinterpret_cast<const void *>(&resolve_self_elf), &owner) != 0
        && owner.dli_fbase != nullptr) {
        fbase_out = owner.dli_fbase;
        const uintptr_t elf_mem_base = reinterpret_cast<uintptr_t>(owner.dli_fbase);
        const MapEntry *entry = find_map_containing(maps, elf_mem_base);
        if (entry != nullptr) {
            path_out = entry->path;
            base_file_offset_out = entry->offset + static_cast<uint64_t>(elf_mem_base - entry->start);
            mem_base_out = elf_mem_base;
            return true;
        }
    }
    const MapEntry *named = lowest_named_map(maps, OBF("libriskengine.so"));
    if (named != nullptr) {
        path_out = named->path;
        base_file_offset_out = named->offset;
        mem_base_out = named->start;
        return true;
    }
    return false;
}

/**
 * Inspects libriskengine.so's own PLT/GOT entries (DT_JMPREL) to catch
 * xHook / ByteHook / ShadowHook redirecting imports like __system_property_get.
 */
void inspect_self_got_hooks(const std::vector<MapEntry> &maps,
                            std::vector<std::string> &tokens) {
    std::string self_path;
    uint64_t base_off = 0;
    uintptr_t mem_base = 0;
    const void *self_fbase = nullptr;
    if (!resolve_self_elf(maps, self_path, base_off, mem_base, self_fbase)
        || self_path.empty()) {
        return;
    }

    DiskElf elf;
    if (!elf.open(self_path, base_off, mem_base)) return;

    std::vector<Dyn> dyn;
    if (!elf.read_dynamic(dyn)) return;

    uint64_t strtab_va = 0, strtab_sz = 0, symtab_va = 0;
    uint64_t pltrel_va = 0, pltrel_sz = 0;
    long pltrel_type = DT_RELA;
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
    }
    if (strtab_va == 0 || symtab_va == 0 || strtab_sz == 0
        || pltrel_va == 0 || pltrel_sz == 0 || syment != sizeof(Sym)) {
        return;
    }

    uint64_t strtab_off = 0, symtab_off = 0, pltrel_off = 0;
    if (!elf.vaddr_to_offset(strtab_va, strtab_off)
        || !elf.vaddr_to_offset(symtab_va, symtab_off)
        || !elf.vaddr_to_offset(pltrel_va, pltrel_off)) {
        return;
    }

    const size_t ent_size = (pltrel_type == DT_RELA && kElf64) ? sizeof(Rela) : sizeof(Rel);
    const size_t count = std::min<size_t>(static_cast<size_t>(pltrel_sz) / ent_size, 4096);

    for (size_t i = 0; i < count; ++i) {
        const uint64_t rel_pos = pltrel_off + static_cast<uint64_t>(i) * ent_size;
        if (!range_within_u64(rel_pos, ent_size, elf.file_size)) break;

        uint64_t r_offset = 0;
        size_t sym_index = 0;
        if constexpr (kElf64) {
            if (pltrel_type == DT_RELA) {
                Rela rela {};
                if (!pread_exact(elf.fd, &rela, sizeof(rela), rel_pos)) continue;
                r_offset = rela.r_offset;
                sym_index = ELF64_R_SYM(rela.r_info);
            } else {
                Rel rel {};
                if (!pread_exact(elf.fd, &rel, sizeof(rel), rel_pos)) continue;
                r_offset = rel.r_offset;
                sym_index = ELF64_R_SYM(rel.r_info);
            }
        } else {
            Rel rel {};
            if (!pread_exact(elf.fd, &rel, sizeof(rel), rel_pos)) continue;
            r_offset = rel.r_offset;
            sym_index = ELF32_R_SYM(rel.r_info);
        }

        const uint64_t sym_pos = symtab_off + static_cast<uint64_t>(sym_index) * sizeof(Sym);
        if (!range_within_u64(sym_pos, sizeof(Sym), elf.file_size)) continue;
        Sym sym {};
        if (!pread_exact(elf.fd, &sym, sizeof(sym), sym_pos)) continue;

        std::string name;
        if (!elf.read_strtab_name(strtab_off, strtab_sz, sym.st_name, name)) continue;
        if (name.empty()) continue;

        uintptr_t got_addr = 0;
        if (!add_address(elf.load_bias, static_cast<uintptr_t>(r_offset), got_addr)) continue;
        const uint8_t *slot = safe_read(maps, got_addr, sizeof(uintptr_t));
        if (slot == nullptr) continue;

        uintptr_t target = 0;
        std::memcpy(&target, slot, sizeof(target));
        if (target != 0 && !is_trusted_got_target(maps, target, self_fbase)) {
            add_token(tokens, OBF("got_hook:") + name);
        }
    }
}

void inspect_jni_table(JNIEnv *env, const std::vector<MapEntry> &maps,
                       std::vector<std::string> &tokens) {
    if (env == nullptr) return;
    uintptr_t find_class = reinterpret_cast<uintptr_t>(
            reinterpret_cast<void *>(env->functions->FindClass));
    uintptr_t get_version = reinterpret_cast<uintptr_t>(
            reinterpret_cast<void *>(env->functions->GetVersion));
    uintptr_t art_start = 0, art_end = 0;
    rx_range_for(maps, OBF("libart.so"), art_start, art_end);
    if (art_start == 0) return;
    auto outside = [&](uintptr_t addr) {
        return addr != 0 && (addr < art_start || addr >= art_end);
    };
    if (outside(find_class)) add_token(tokens, OBF("jni_table_hook:FindClass"));
    if (outside(get_version)) add_token(tokens, OBF("jni_table_hook:GetVersion"));
}

uint64_t hash_bytes(const uint8_t *data, size_t len, uint64_t seed) {
    uint64_t hash = 0xCBF29CE484222325ull ^ seed;
    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= 0x100000001B3ull;
    }
    return hash;
}

bool numeric_name(const std::string &name) {
    if (name.empty()) return false;
    for (char c : name) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

bool contains_token(const std::string &haystack, const std::string &token) {
    auto pos = haystack.find(token);
    while (pos != std::string::npos) {
        bool left = pos == 0 || !(isalnum(static_cast<unsigned char>(haystack[pos - 1]))
                                  || haystack[pos - 1] == '_');
        size_t end = pos + token.size();
        bool right = end == haystack.size()
                     || !(isalnum(static_cast<unsigned char>(haystack[end]))
                          || haystack[end] == '_');
        if (left && right) return true;
        pos = haystack.find(token, pos + 1);
    }
    return false;
}

}  // namespace

uint64_t native_hash_fn_prologue(const void *fn_ptr) {
    if (fn_ptr == nullptr) return 0;
    const auto *bytes = reinterpret_cast<const uint8_t *>(fn_ptr);
    return hash_bytes(bytes, 16, static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fn_ptr)));
}

std::string native_get_integrity_evidence(JNIEnv *env, const std::vector<MapEntry> &maps) {
    std::vector<std::string> tokens;
    const std::vector<std::string> wanted = list_monitored_libc_symbols();
    inspect_library_exports(maps, OBF("libc.so"), wanted, tokens);
    inspect_library_exports(maps, OBF("libdl.so"), wanted, tokens);
    inspect_self_got_hooks(maps, tokens);
    inspect_jni_table(env, maps, tokens);
    return join_tokens(tokens);
}

std::string native_get_integrity_evidence(JNIEnv *env) {
    auto maps = read_self_maps();
    return native_get_integrity_evidence(env, maps);
}

std::string native_get_so_integrity_evidence(const std::vector<MapEntry> &maps) {
    std::vector<std::string> tokens;

    std::string self_path;
    uint64_t base_file_offset = 0;
    uintptr_t mem_base = 0;
    const void *self_fbase = nullptr;
    if (!resolve_self_elf(maps, self_path, base_file_offset, mem_base, self_fbase)) {
        add_token(tokens, OBF("text_mismatch:missing_map"));
        return join_tokens(tokens);
    }
    if (self_path.empty()
        || self_path.find(OBF("memfd:")) != std::string::npos
        || self_path.find(OBF("/memfd:")) != std::string::npos
        || self_path.find(OBF("ashmem")) != std::string::npos) {
        add_token(tokens, OBF("text_mismatch:anonymous_map"));
        return join_tokens(tokens);
    }

    DiskElf elf;
    if (!elf.open(self_path, base_file_offset, mem_base)) {
        // Distinguish file access error vs malformed ELF header.
        struct stat st {};
        if (my_fstatat(AT_FDCWD, self_path.c_str(), &st, 0) != 0 || st.st_size <= 0) {
            add_token(tokens, OBF("text_mismatch:file_unreadable"));
        } else {
            add_token(tokens, OBF("text_mismatch:bad_elf"));
        }
        return join_tokens(tokens);
    }

    bool compared_any = false;
    size_t segments_checked = 0;
    constexpr size_t kWindow = 64 * 1024;
    std::vector<uint8_t> disk_window(kWindow);

    for (size_t i = 0; i < elf.phdrs.size(); ++i) {
        const auto &ph = elf.phdrs[i];
        if (ph.p_type != PT_LOAD) continue;
        if ((ph.p_flags & PF_X) == 0) continue;
        const uint64_t seg_file_off = base_file_offset + ph.p_offset;
        const uint64_t seg_file_sz = ph.p_filesz;
        if (seg_file_sz == 0 || !range_within_u64(seg_file_off, seg_file_sz, elf.file_size)) {
            continue;
        }
        uintptr_t mem_addr = 0;
        if (!add_address(elf.load_bias, static_cast<uintptr_t>(ph.p_vaddr), mem_addr)) {
            continue;
        }

        uint64_t offset = 0;
        bool segment_mismatch = false;
        while (offset < seg_file_sz) {
            const size_t chunk = static_cast<size_t>(
                    std::min<uint64_t>(kWindow, seg_file_sz - offset));
            uintptr_t win_addr = 0;
            if (!add_address(mem_addr, static_cast<uintptr_t>(offset), win_addr)) {
                offset += chunk;
                continue;
            }
            const uint8_t *mem = safe_read(maps, win_addr, chunk);
            if (mem == nullptr) {
                offset += chunk;
                continue;
            }
            if (!pread_exact(elf.fd, disk_window.data(), chunk, seg_file_off + offset)) {
                offset += chunk;
                continue;
            }
            compared_any = true;
            const uint64_t seed = static_cast<uint64_t>(ph.p_vaddr) + offset;
            if (hash_bytes(disk_window.data(), chunk, seed) != hash_bytes(mem, chunk, seed)) {
                segment_mismatch = true;
                break;
            }
            offset += chunk;
        }
        ++segments_checked;
        if (segment_mismatch) {
            add_token(tokens, OBF("text_mismatch"));
            add_token(tokens, OBF("text_mismatch_seg:") + std::to_string(i));
            break;
        }
    }

    if (!compared_any && segments_checked > 0) {
        add_token(tokens, OBF("text_mismatch:unreadable_segments"));
    }
    return join_tokens(tokens);
}

std::string native_get_so_integrity_evidence() {
    auto maps = read_self_maps();
    return native_get_so_integrity_evidence(maps);
}

std::string native_get_jni_self_table_evidence(JNIEnv *env,
                                               const void *const *registered,
                                               const uint64_t *expected_prologues,
                                               size_t count,
                                               const std::vector<MapEntry> &maps) {
    std::vector<std::string> tokens;
    (void) env;
    if (registered == nullptr || count == 0) {
        return join_tokens(tokens);
    }
    Dl_info owner {};
    if (dladdr(reinterpret_cast<const void *>(&resolve_self_elf),
               &owner) == 0 || owner.dli_fbase == nullptr) {
        add_token(tokens, OBF("jni_self:no_range"));
        return join_tokens(tokens);
    }

    uintptr_t self_rx_start = 0, self_rx_end = 0;
    const MapEntry *self_map = find_map_containing(
            maps, reinterpret_cast<uintptr_t>(&resolve_self_elf));
    if (self_map != nullptr && is_rx(*self_map)) {
        self_rx_start = self_map->start;
        self_rx_end = self_map->end;
    }

    for (size_t i = 0; i < count; ++i) {
        auto addr = reinterpret_cast<uintptr_t>(registered[i]);
        if (addr == 0) continue;
        Dl_info target {};
        if (dladdr(registered[i], &target) == 0
                || target.dli_fbase != owner.dli_fbase) {
            add_token(tokens, OBF("jni_self_hook:") + std::to_string(i));
            continue;
        }
        const uint8_t *prologue = safe_read(maps, addr, 16);
        if (prologue != nullptr) {
            if (expected_prologues != nullptr && expected_prologues[i] != 0) {
                if (hash_bytes(prologue, 16, static_cast<uint64_t>(addr))
                        != expected_prologues[i]) {
                    add_token(tokens, OBF("jni_self_hook:") + std::to_string(i));
                    continue;
                }
            }
            if (looks_like_trampoline(prologue, addr, self_rx_start, self_rx_end)) {
                add_token(tokens, OBF("jni_self_hook:") + std::to_string(i));
            }
        }
    }
    return join_tokens(tokens);
}

std::string native_get_jni_self_table_evidence(JNIEnv *env,
                                               const void *const *registered,
                                               size_t count) {
    auto maps = read_self_maps();
    return native_get_jni_self_table_evidence(env, registered, nullptr, count, maps);
}

std::string native_scan_process_tokens() {
    std::vector<std::string> tokens;
    const std::string proc_root = OBF("/proc");
    RawDirResult proc = raw_list_dir(proc_root.c_str());
    if (!proc.ok()) return "";
    const std::string proc_slash = OBF("/proc/");
    const std::string comm_suffix = OBF("/comm");
    const std::string cmd_suffix = OBF("/cmdline");
    auto wanted = list_process_tokens();

    for (const auto &name : proc.names) {
        if (!numeric_name(name)) continue;
        std::string comm_path = proc_slash + name + comm_suffix;
        std::string cmd_path = proc_slash + name + cmd_suffix;
        char comm[128] = {0};
        char cmdline[256] = {0};
        int comm_len = read_file_content(comm_path.c_str(), comm, sizeof(comm));
        int cmd_len = read_file_content(cmd_path.c_str(), cmdline, sizeof(cmdline));

        std::string comm_str;
        if (comm_len > 0) {
            comm_str.assign(comm, std::min(static_cast<size_t>(comm_len), sizeof(comm) - 1));
        }
        std::string cmd_str;
        if (cmd_len > 0) {
            cmd_str.assign(cmdline, std::min(static_cast<size_t>(cmd_len), sizeof(cmdline) - 1));
            for (char &ch : cmd_str) {
                if (ch == '\0') ch = ' ';
            }
        }

        std::string haystack = to_lower(comm_str + " " + cmd_str);
        for (const auto &token : wanted) {
            if (contains_token(haystack, token)) {
                add_token(tokens, token);
            }
        }
    }
    return join_tokens(tokens);
}
