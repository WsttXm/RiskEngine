#include "native_integrity.h"
#include "../generated/detection_lists.h"
#include "../util/maps_parser.h"
#include "../util/obf_str.h"
#include "../util/raw_dir.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <jni.h>
#include <string>
#include <sys/mman.h>
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
bool looks_like_arm64_trampoline(const uint8_t *p, uintptr_t addr,
                                 uintptr_t range_start, uintptr_t range_end) {
    uint32_t insn;
    memcpy(&insn, p, sizeof(insn));
    uint32_t next;
    memcpy(&next, p + 4, sizeof(next));
    if ((insn & 0xFF00001Fu) == 0x58000010u && next == 0xD61F0200u) return true;
    if ((insn & 0xFF00001Fu) == 0x58000011u && next == 0xD61F0220u) return true;
    if ((insn & 0xFC000000u) == 0x14000000u) {
        int32_t imm26 = static_cast<int32_t>(insn & 0x03FFFFFFu);
        if (imm26 & 0x02000000) imm26 |= static_cast<int32_t>(0xFC000000);
        uintptr_t target = addr + (static_cast<intptr_t>(imm26) << 2);
        if (target < range_start || target >= range_end) return true;
    }
    return false;
}
#endif

#if defined(__arm__)
bool looks_like_arm32_trampoline(const uint8_t *p) {
    // ldr pc, [pc, #imm] / classic 4-byte hook jump
    uint32_t insn;
    memcpy(&insn, p, sizeof(insn));
    return (insn & 0x0FFFFFF0u) == 0x012FFF10u  // bx/blx register
           || (insn & 0x0F7FF000u) == 0x051FF000u;  // ldr pc, [..]
}
#endif

const uint8_t *safe_read(const std::vector<MapEntry> &maps, uintptr_t addr, size_t n) {
    const MapEntry *entry = find_map_containing(maps, addr);
    if (entry == nullptr || addr + n > entry->end) return nullptr;
    if (entry->perms.empty() || entry->perms[0] != 'r') return nullptr;
    return reinterpret_cast<const uint8_t *>(addr);
}

#if defined(__LP64__)
using Ehdr = Elf64_Ehdr;
using Phdr = Elf64_Phdr;
using Dyn = Elf64_Dyn;
using Sym = Elf64_Sym;
using Rela = Elf64_Rela;
using Rel = Elf64_Rel;
constexpr bool kElf64 = true;
#else
using Ehdr = Elf32_Ehdr;
using Phdr = Elf32_Phdr;
using Dyn = Elf32_Dyn;
using Sym = Elf32_Sym;
using Rela = Elf32_Rela;
using Rel = Elf32_Rel;
constexpr bool kElf64 = false;
#endif

struct ElfView {
    const uint8_t *base = nullptr;
    size_t size = 0;
    uintptr_t load_bias = 0;
};

bool parse_elf(const uint8_t *base, size_t size, uintptr_t map_start, ElfView &view) {
    if (base == nullptr || size < sizeof(Ehdr)) return false;
    auto *ehdr = reinterpret_cast<const Ehdr *>(base);
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1) {
        return false;
    }
    if (ehdr->e_phoff == 0 || ehdr->e_phentsize != sizeof(Phdr)) return false;
    if (ehdr->e_phoff + static_cast<size_t>(ehdr->e_phnum) * sizeof(Phdr) > size) {
        return false;
    }
    auto *phdrs = reinterpret_cast<const Phdr *>(base + ehdr->e_phoff);
    uintptr_t bias = map_start;
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_offset == 0) {
            bias = map_start - static_cast<uintptr_t>(phdrs[i].p_vaddr);
            break;
        }
    }
    view.base = base;
    view.size = size;
    view.load_bias = bias;
    return true;
}

const Dyn *dynamic_table(const ElfView &view, size_t &count) {
    auto *ehdr = reinterpret_cast<const Ehdr *>(view.base);
    auto *phdrs = reinterpret_cast<const Phdr *>(view.base + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdrs[i].p_type != PT_DYNAMIC) continue;
        if (phdrs[i].p_offset + phdrs[i].p_filesz > view.size) return nullptr;
        count = static_cast<size_t>(phdrs[i].p_filesz / sizeof(Dyn));
        return reinterpret_cast<const Dyn *>(view.base + phdrs[i].p_offset);
    }
    return nullptr;
}

void inspect_libc_hooks(const std::vector<MapEntry> &maps, std::vector<std::string> &tokens) {
    const MapEntry *base_map = lowest_named_map(maps, OBF("libc.so"));
    if (base_map == nullptr || base_map->path.empty()) return;

    struct stat st {};
    if (my_fstatat(AT_FDCWD, base_map->path.c_str(), &st, 0) != 0 || st.st_size <= 0) {
        return;
    }
    int fd = static_cast<int>(my_openat(AT_FDCWD, base_map->path.c_str(),
                                        O_RDONLY | O_CLOEXEC, 0));
    if (fd < 0) return;
    auto mapped = reinterpret_cast<uint8_t *>(
            my_mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0));
    my_close(fd);
    if (mapped == nullptr || mapped == reinterpret_cast<uint8_t *>(-1)) return;

    ElfView view;
    if (!parse_elf(mapped, static_cast<size_t>(st.st_size), base_map->start, view)) {
        my_munmap(mapped, static_cast<size_t>(st.st_size));
        return;
    }

    size_t dyn_count = 0;
    const Dyn *dyn = dynamic_table(view, dyn_count);
    if (dyn == nullptr) {
        my_munmap(mapped, static_cast<size_t>(st.st_size));
        return;
    }

    const char *strtab = nullptr;
    const Sym *symtab = nullptr;
    size_t syment = sizeof(Sym);
    const void *pltrel = nullptr;
    size_t pltrel_size = 0;
    long pltrel_type = DT_RELA;

    for (size_t i = 0; i < dyn_count && dyn[i].d_tag != DT_NULL; ++i) {
        auto tag = dyn[i].d_tag;
        auto val = dyn[i].d_un.d_ptr;
        if (tag == DT_STRTAB) strtab = reinterpret_cast<const char *>(view.load_bias + val);
        if (tag == DT_SYMTAB) symtab = reinterpret_cast<const Sym *>(view.load_bias + val);
        if (tag == DT_SYMENT) syment = static_cast<size_t>(dyn[i].d_un.d_val);
        if (tag == DT_JMPREL) pltrel = reinterpret_cast<const void *>(view.load_bias + val);
        if (tag == DT_PLTRELSZ) pltrel_size = static_cast<size_t>(dyn[i].d_un.d_val);
        if (tag == DT_PLTREL) pltrel_type = static_cast<long>(dyn[i].d_un.d_val);
    }
    if (strtab == nullptr || symtab == nullptr) {
        my_munmap(mapped, static_cast<size_t>(st.st_size));
        return;
    }

    uintptr_t rx_start = 0, rx_end = 0;
    rx_range_for(maps, OBF("libc.so"), rx_start, rx_end);

    const std::vector<std::string> wanted = list_monitored_libc_symbols();

    auto check_symbol = [&](const char *name, uintptr_t file_addr, uintptr_t got_addr) {
        if (name == nullptr) return;
        bool match = false;
        for (const auto &item : wanted) {
            if (item == name) {
                match = true;
                break;
            }
        }
        if (!match) return;
        if (file_addr != 0) {
            const uint8_t *bytes = safe_read(maps, file_addr, 16);
            if (bytes != nullptr) {
#if defined(__aarch64__)
                if (looks_like_arm64_trampoline(bytes, file_addr, rx_start, rx_end)) {
                    add_token(tokens, OBF("inline_hook:") + name);
                }
#elif defined(__arm__)
                if (looks_like_arm32_trampoline(bytes)) {
                    add_token(tokens, OBF("inline_hook:") + name);
                }
#else
                (void) bytes;
#endif
            }
        }
        if (got_addr != 0) {
            const uint8_t *slot = safe_read(maps, got_addr, sizeof(uintptr_t));
            if (slot != nullptr) {
                uintptr_t target = 0;
                memcpy(&target, slot, sizeof(target));
                if (target != 0 && (target < rx_start || target >= rx_end)) {
                    add_token(tokens, OBF("got_hook:") + name);
                }
            }
        }
    };

    auto resolve_sym = [&](size_t index) -> const Sym * {
        return reinterpret_cast<const Sym *>(
                reinterpret_cast<const uint8_t *>(symtab) + index * syment);
    };

    if (pltrel != nullptr && pltrel_size > 0) {
        if (pltrel_type == DT_RELA && kElf64) {
            size_t count = pltrel_size / sizeof(Rela);
            auto *relas = reinterpret_cast<const Rela *>(pltrel);
            for (size_t i = 0; i < count; ++i) {
                size_t sym_index = kElf64 ? ELF64_R_SYM(relas[i].r_info)
                                          : ELF32_R_SYM(relas[i].r_info);
                const Sym *sym = resolve_sym(sym_index);
                const char *name = strtab + sym->st_name;
                uintptr_t func = sym->st_value ? view.load_bias + sym->st_value : 0;
                uintptr_t got = view.load_bias + relas[i].r_offset;
                check_symbol(name, func, got);
            }
        } else {
            size_t count = pltrel_size / sizeof(Rel);
            auto *rels = reinterpret_cast<const Rel *>(pltrel);
            for (size_t i = 0; i < count; ++i) {
                size_t sym_index = kElf64 ? ELF64_R_SYM(rels[i].r_info)
                                          : ELF32_R_SYM(rels[i].r_info);
                const Sym *sym = resolve_sym(sym_index);
                const char *name = strtab + sym->st_name;
                uintptr_t func = sym->st_value ? view.load_bias + sym->st_value : 0;
                uintptr_t got = view.load_bias + rels[i].r_offset;
                check_symbol(name, func, got);
            }
        }
    }

    my_munmap(mapped, static_cast<size_t>(st.st_size));
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

/**
 * 64-bit FNV-1a. Replaces the previous CRC32: CRC is linear, so an attacker
 * who patches code can compensate with a few bytes elsewhere in the same
 * window. FNV-1a has no such trivial algebraic fixup.
 */
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

std::string native_get_integrity_evidence(JNIEnv *env) {
    std::vector<std::string> tokens;
    auto maps = read_self_maps();
    inspect_libc_hooks(maps, tokens);
    inspect_jni_table(env, maps, tokens);
    return join_tokens(tokens);
}

std::string native_get_so_integrity_evidence() {
    std::vector<std::string> tokens;
    auto maps = read_self_maps();
    const MapEntry *self = lowest_named_map(maps, OBF("libriskengine.so"));
    if (self == nullptr) {
        add_token(tokens, OBF("text_mismatch:missing_map"));
        return join_tokens(tokens);
    }
    if (self->path.empty()
        || self->path.find(OBF("memfd:")) != std::string::npos
        || self->path.find(OBF("/memfd:")) != std::string::npos
        || self->path.find(OBF("ashmem")) != std::string::npos) {
        add_token(tokens, OBF("text_mismatch:anonymous_map"));
        return join_tokens(tokens);
    }

    struct stat st {};
    if (my_fstatat(AT_FDCWD, self->path.c_str(), &st, 0) != 0 || st.st_size <= 0) {
        add_token(tokens, OBF("text_mismatch:file_unreadable"));
        return join_tokens(tokens);
    }
    int fd = static_cast<int>(my_openat(AT_FDCWD, self->path.c_str(),
                                        O_RDONLY | O_CLOEXEC, 0));
    if (fd < 0) {
        add_token(tokens, OBF("text_mismatch:file_unreadable"));
        return join_tokens(tokens);
    }
    auto mapped = reinterpret_cast<uint8_t *>(
            my_mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0));
    my_close(fd);
    if (mapped == nullptr || mapped == reinterpret_cast<uint8_t *>(-1)) {
        add_token(tokens, OBF("text_mismatch:file_unreadable"));
        return join_tokens(tokens);
    }

    ElfView view;
    if (!parse_elf(mapped, static_cast<size_t>(st.st_size), self->start, view)) {
        my_munmap(mapped, static_cast<size_t>(st.st_size));
        add_token(tokens, OBF("text_mismatch:bad_elf"));
        return join_tokens(tokens);
    }
    auto *ehdr = reinterpret_cast<const Ehdr *>(view.base);
    auto *phdrs = reinterpret_cast<const Phdr *>(view.base + ehdr->e_phoff);

    // Walk every executable PT_LOAD in full. The previous implementation
    // hashed only the first 4096 bytes of the first such segment, so any hook
    // placed past that offset was invisible.
    bool compared_any = false;
    size_t segments_checked = 0;
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        if ((phdrs[i].p_flags & PF_X) == 0) continue;
        size_t file_off = static_cast<size_t>(phdrs[i].p_offset);
        size_t file_sz = static_cast<size_t>(phdrs[i].p_filesz);
        if (file_sz == 0 || file_off + file_sz > static_cast<size_t>(st.st_size)) {
            continue;
        }
        uintptr_t mem_addr = view.load_bias + static_cast<uintptr_t>(phdrs[i].p_vaddr);

        // Compare in windows so one unreadable page does not void the segment.
        constexpr size_t kWindow = 64 * 1024;
        size_t offset = 0;
        bool segment_mismatch = false;
        while (offset < file_sz) {
            size_t chunk = std::min(kWindow, file_sz - offset);
            const uint8_t *mem = safe_read(maps, mem_addr + offset, chunk);
            if (mem == nullptr) {
                offset += chunk;
                continue;
            }
            compared_any = true;
            const uint64_t seed = static_cast<uint64_t>(phdrs[i].p_vaddr) + offset;
            if (hash_bytes(view.base + file_off + offset, chunk, seed)
                != hash_bytes(mem, chunk, seed)) {
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
    my_munmap(mapped, static_cast<size_t>(st.st_size));
    return join_tokens(tokens);
}

std::string native_get_jni_self_table_evidence(JNIEnv *env,
                                               const void *const *registered,
                                               size_t count) {
    std::vector<std::string> tokens;
    (void) env;
    if (registered == nullptr || count == 0) {
        return join_tokens(tokens);
    }
    auto maps = read_self_maps();
    uintptr_t self_start = 0, self_end = 0;
    rx_range_for(maps, OBF("libriskengine.so"), self_start, self_end);
    if (self_start == 0) {
        add_token(tokens, OBF("jni_self:no_range"));
        return join_tokens(tokens);
    }
    // Every JNI entry point this library registered must still live inside this
    // library's executable range. A Java-level or PLT-level redirect of our own
    // bridge moves the pointer out of range.
    for (size_t i = 0; i < count; ++i) {
        auto addr = reinterpret_cast<uintptr_t>(registered[i]);
        if (addr == 0) continue;
        if (addr < self_start || addr >= self_end) {
            add_token(tokens, OBF("jni_self_hook:") + std::to_string(i));
        }
    }
    return join_tokens(tokens);
}

std::string native_scan_process_tokens() {
    std::vector<std::string> tokens;
    RawDirResult proc = raw_list_dir("/proc");
    if (!proc.ok()) return "";
    auto wanted = list_process_tokens();
    for (const auto &name : proc.names) {
        if (!numeric_name(name)) continue;
        std::string comm_path = "/proc/" + name + "/comm";
        std::string cmd_path = "/proc/" + name + "/cmdline";
        char comm[128] = {0};
        char cmdline[256] = {0};
        read_file_content(comm_path.c_str(), comm, sizeof(comm));
        read_file_content(cmd_path.c_str(), cmdline, sizeof(cmdline));
        for (size_t i = 0; i < sizeof(cmdline); ++i) {
            if (cmdline[i] == '\0') cmdline[i] = ' ';
        }
        std::string haystack = to_lower(std::string(comm) + " " + cmdline);
        for (const auto &token : wanted) {
            if (contains_token(haystack, token)) {
                add_token(tokens, token);
            }
        }
    }
    return join_tokens(tokens);
}
