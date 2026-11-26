#include "detector/custom_rom_probe.h"

#include "util/maps_parser.h"
#include "util/mylibc.h"
#include "util/obf_str.h"
#include "util/payload_codec.h"
#include "util/syscall_wrapper.h"

#include <cstdint>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <set>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <vector>

namespace {

#if !defined(__LP64__)
#error "RiskEngine custom_rom_probe requires a 64-bit ABI (arm64-v8a or x86_64)"
#endif
using ElfHeader = Elf64_Ehdr;
using ElfSection = Elf64_Shdr;
using ElfSymbol = Elf64_Sym;

constexpr uint64_t kMaxStagefrightMapBytes = 64ULL * 1024ULL * 1024ULL;

bool ends_with(std::string_view value, std::string_view suffix) noexcept {
    return value.size() >= suffix.size()
            && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool starts_with(std::string_view value, std::string_view prefix) noexcept {
    return value.size() >= prefix.size()
            && value.compare(0, prefix.size(), prefix) == 0;
}

std::string strip_deleted_suffix(std::string path) {
    constexpr std::string_view kDeleted = " (deleted)";
    if (ends_with(path, kDeleted)) {
        path.erase(path.size() - kDeleted.size());
    }
    return path;
}

bool extract_maps_dev_column(std::string_view raw_line, std::string *dev_out) {
    if (dev_out == nullptr || raw_line.empty()) {
        return false;
    }
    // Columns: 0=addr 1=perms 2=offset 3=dev 4=inode [5=path]
    std::size_t pos = 0;
    const std::size_t n = raw_line.size();
    for (int col = 0; col < 4; ++col) {
        while (pos < n && my_is_space(static_cast<unsigned char>(raw_line[pos]))) {
            pos++;
        }
        std::size_t start = pos;
        while (pos < n && !my_is_space(static_cast<unsigned char>(raw_line[pos]))) {
            pos++;
        }
        if (start == pos) {
            return false;
        }
        if (col == 3) {
            std::string_view dev = raw_line.substr(start, pos - start);
            if (dev.find(':') == std::string_view::npos) {
                return false;
            }
            dev_out->assign(dev.data(), dev.size());
            return true;
        }
    }
    return false;
}

bool is_zero_device(std::string_view dev) noexcept {
    for (char c : dev) {
        if (c != '0' && c != ':') {
            return false;
        }
    }
    return true;
}

bool contains_symbol_on_disk(const std::string &path, const char *symbol_name) {
    if (path.empty() || symbol_name == nullptr || symbol_name[0] == '\0') {
        return false;
    }
    const long fd_ret = my_openat(AT_FDCWD, path.c_str(), O_RDONLY | O_CLOEXEC, 0);
    if (fd_ret < 0) {
        return false;
    }
    const int fd = static_cast<int>(fd_ret);

    struct stat st = {};
    if (my_fstatat(fd, "", &st, AT_EMPTY_PATH) < 0
            || !S_ISREG(st.st_mode)
            || st.st_size <= 0
            || static_cast<uint64_t>(st.st_size) < sizeof(ElfHeader)
            || static_cast<uint64_t>(st.st_size) > kMaxStagefrightMapBytes) {
        my_close(fd);
        return false;
    }

    const size_t file_size = static_cast<size_t>(st.st_size);
    const long map_ret = my_mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    my_close(fd);
    if (map_ret < 0) {
        return false;
    }
    void *mapping = reinterpret_cast<void *>(static_cast<uintptr_t>(map_ret));
    if (mapping == MAP_FAILED || mapping == nullptr) {
        return false;
    }

    bool found = false;
    const auto *base = static_cast<const uint8_t *>(mapping);
    const auto *ehdr = reinterpret_cast<const ElfHeader *>(base);

    const uint64_t sh_table_bytes =
            static_cast<uint64_t>(ehdr->e_shentsize) * static_cast<uint64_t>(ehdr->e_shnum);
    const bool valid_elf =
            my_memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0
            && ehdr->e_shoff != 0
            && ehdr->e_shentsize == sizeof(ElfSection)
            && ehdr->e_shnum > 0
            && static_cast<uint64_t>(ehdr->e_shoff) <= file_size
            && sh_table_bytes <= static_cast<uint64_t>(file_size) - static_cast<uint64_t>(ehdr->e_shoff);

    if (valid_elf) {
        const auto *sections = reinterpret_cast<const ElfSection *>(base + ehdr->e_shoff);
        const size_t target_len = my_strlen(symbol_name);

        for (uint16_t i = 0; i < ehdr->e_shnum && !found; ++i) {
            const ElfSection &sec = sections[i];
            if (sec.sh_type != SHT_DYNSYM && sec.sh_type != SHT_SYMTAB) {
                continue;
            }
            if (sec.sh_entsize != sizeof(ElfSymbol) || sec.sh_link >= ehdr->e_shnum) {
                continue;
            }
            const ElfSection &strtab = sections[sec.sh_link];
            if (sec.sh_offset > file_size || sec.sh_size > file_size - sec.sh_offset) {
                continue;
            }
            if (strtab.sh_offset > file_size || strtab.sh_size > file_size - strtab.sh_offset) {
                continue;
            }

            const auto *syms = reinterpret_cast<const ElfSymbol *>(base + sec.sh_offset);
            const size_t sym_count = sec.sh_size / sizeof(ElfSymbol);
            for (size_t s = 0; s < sym_count; ++s) {
                const ElfSymbol &sym = syms[s];
                if (sym.st_shndx == SHN_UNDEF || sym.st_value == 0 || sym.st_name >= strtab.sh_size) {
                    continue;
                }
                const size_t remaining = strtab.sh_size - sym.st_name;
                if (remaining <= target_len) {
                    continue;
                }
                const char *name = reinterpret_cast<const char *>(base + strtab.sh_offset + sym.st_name);
                if (my_memcmp(name, symbol_name, target_len) == 0 && name[target_len] == '\0') {
                    found = true;
                    break;
                }
            }
        }
    }

    my_munmap(mapping, file_size);
    return found;
}

bool contains_symbol_in_memory(const std::string &path, const char *symbol_name) {
    if (path.empty() || symbol_name == nullptr) {
        return false;
    }
    void *handle = dlopen(path.c_str(), RTLD_NOW | RTLD_NOLOAD);
    if (handle == nullptr) {
        return false;
    }
    void *sym = dlsym(handle, symbol_name);
    dlclose(handle);
    return sym != nullptr;
}

}  // namespace

std::string native_get_custom_rom_probe() {
    const auto stagefright_name = OBF("/libstagefright.so");
    const auto target_symbol = OBF("_ZN7android15ANetworkSession10threadLoopEv");
    const auto fw_res_suffix = OBF("/framework-res.apk");
    const auto sys_prefix = OBF("/system/");
    const auto apex_prefix = OBF("/apex/");

    std::set<std::string> stagefright_paths;
    std::set<std::string> fw_res_devs;

    const bool maps_ok = for_each_self_map([&](const MapEntry &entry) -> bool {
        if (entry.path.empty()) {
            return true;
        }
        std::string clean_path = strip_deleted_suffix(entry.path);
        if (ends_with(clean_path, stagefright_name.c_str())
                && (starts_with(clean_path, sys_prefix.c_str())
                    || starts_with(clean_path, apex_prefix.c_str()))) {
            struct stat st = {};
            if (my_fstatat(AT_FDCWD, clean_path.c_str(), &st, 0) == 0) {
                stagefright_paths.insert(clean_path);
            }
        } else if (ends_with(clean_path, fw_res_suffix.c_str())) {
            std::string dev;
            if (extract_maps_dev_column(entry.raw, &dev) && !is_zero_device(dev)) {
                fw_res_devs.insert(dev);
            }
        }
        return true;
    });

    // Fallback to standard system path matching pointer width if libstagefright.so is not yet mapped.
    if (stagefright_paths.empty()) {
#if defined(__LP64__)
        const auto fallback_path = OBF("/system/lib64/libstagefright.so");
#else
        const auto fallback_path = OBF("/system/lib/libstagefright.so");
#endif
        struct stat st = {};
        if (my_fstatat(AT_FDCWD, fallback_path.c_str(), &st, 0) == 0) {
            stagefright_paths.insert(fallback_path.c_str());
        }
    }

    if (!maps_ok && stagefright_paths.empty()) {
        payload_codec::PayloadBuilder err(payload_codec::Status::RESTRICTED, raw_last_error());
        err.add_header("reason", "maps_and_stagefright_unavailable");
        return err.build();
    }

    payload_codec::PayloadBuilder payload(payload_codec::Status::OK, 0);
    int stagefright_hits = 0;

    for (const std::string &path : stagefright_paths) {
        const bool disk_hit = contains_symbol_on_disk(path, target_symbol.c_str());
        const bool mem_hit = contains_symbol_in_memory(path, target_symbol.c_str());
        if (disk_hit || mem_hit) {
            stagefright_hits++;
            payload_codec::RecordBuilder rec;
            rec.add("kind", "stagefright_symbol")
               .add("path", path)
               .add("source", (disk_hit && mem_hit) ? "both" : (disk_hit ? "disk" : "memory"));
            payload.add_record(rec);
        }
    }

    if (fw_res_devs.size() > 1) {
        std::string devs_joined;
        for (const std::string &dev : fw_res_devs) {
            if (!devs_joined.empty()) {
                devs_joined.push_back(',');
            }
            devs_joined.append(dev);
        }
        payload_codec::RecordBuilder rec;
        rec.add("kind", "framework_res_multi_dev")
           .add_int("dev_count", static_cast<int64_t>(fw_res_devs.size()))
           .add("devs", devs_joined);
        payload.add_record(rec);
    }

    payload.add_header_int("stagefright_checked", static_cast<int64_t>(stagefright_paths.size()));
    payload.add_header_int("stagefright_hits", stagefright_hits);
    payload.add_header_int("framework_res_devs", static_cast<int64_t>(fw_res_devs.size()));
    return payload.build();
}
