#include "detector/zygisk_atexit_probe.h"

#include "util/mylibc.h"
#include "util/obf_str.h"
#include "util/payload_codec.h"
#include "util/safe_mem_read.h"
#include "util/syscall_wrapper.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <limits>
#include <new>
#include <pthread.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <vector>

#if defined(__ANDROID__)
#include <android/api-level.h>
#endif

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

namespace zygisk_atexit {

namespace {

#if UINTPTR_MAX == UINT64_MAX
using ElfHeader = Elf64_Ehdr;
using ElfSection = Elf64_Shdr;
using ElfSymbol = Elf64_Sym;
constexpr uint8_t kElfClass = ELFCLASS64;
#else
using ElfHeader = Elf32_Ehdr;
using ElfSection = Elf32_Shdr;
using ElfSymbol = Elf32_Sym;
constexpr uint8_t kElfClass = ELFCLASS32;
#endif

#if defined(__aarch64__)
constexpr uint16_t kElfMachine = EM_AARCH64;
#elif defined(__arm__)
constexpr uint16_t kElfMachine = EM_ARM;
#elif defined(__x86_64__)
constexpr uint16_t kElfMachine = EM_X86_64;
#elif defined(__i386__)
constexpr uint16_t kElfMachine = EM_386;
#else
constexpr uint16_t kElfMachine = EM_NONE;
#endif

constexpr size_t kMaxAtexitEntries = 65536;
constexpr size_t kMaxLibcImageBytes = 32 * 1024 * 1024;
constexpr size_t kMaxReportedHits = 8;

bool in_bounds(uint64_t offset, uint64_t count, size_t total) noexcept {
    return offset <= total && count <= total - offset;
}

template<typename T>
bool read_struct(const uint8_t *image, size_t image_size, uint64_t offset, T &out) noexcept {
    if (!in_bounds(offset, sizeof(T), image_size)) {
        return false;
    }
    my_memcpy(&out, image + offset, sizeof(T));
    return true;
}

bool resolve_symbol_addr(const ElfSymbol &sym,
                         const ElfSection &sec,
                         uintptr_t bias,
                         uintptr_t &out) noexcept {
    if ((sec.sh_flags & (SHF_ALLOC | SHF_WRITE)) != (SHF_ALLOC | SHF_WRITE)) {
        return false;
    }
    if (sym.st_value < sec.sh_addr || sym.st_size == 0) {
        return false;
    }
    if (!in_bounds(sym.st_value - sec.sh_addr, sym.st_size, sec.sh_size)) {
        return false;
    }
    if (sym.st_value > std::numeric_limits<uintptr_t>::max() - bias) {
        return false;
    }
    if (sym.st_size > std::numeric_limits<uintptr_t>::max() - bias - sym.st_value) {
        return false;
    }
    out = bias + static_cast<uintptr_t>(sym.st_value);
    return true;
}

std::string_view basename_sv(std::string_view path) noexcept {
    size_t slash = path.rfind('/');
    return (slash == std::string_view::npos) ? path : path.substr(slash + 1);
}

bool sv_eq(std::string_view a, std::string_view b) noexcept {
    return a.size() == b.size() && (a.empty() || my_memcmp(a.data(), b.data(), a.size()) == 0);
}

bool sv_starts_with(std::string_view s, std::string_view prefix) noexcept {
    return s.size() >= prefix.size() && my_memcmp(s.data(), prefix.data(), prefix.size()) == 0;
}

bool is_map_readable(const MapEntry &m) noexcept {
    return m.perms.size() >= 1 && m.perms[0] == 'r';
}

bool is_map_writable(const MapEntry &m) noexcept {
    return m.perms.size() >= 2 && m.perms[1] == 'w';
}

bool is_map_executable(const MapEntry &m) noexcept {
    return m.perms.size() >= 3 && m.perms[2] == 'x';
}

bool is_range_covered(const std::vector<MapEntry> &maps,
                      uintptr_t start,
                      size_t bytes,
                      bool require_writable) noexcept {
    if (bytes == 0) return true;
    if (bytes > std::numeric_limits<uintptr_t>::max() - start) return false;
    const uintptr_t end = start + bytes;
    for (const auto &m : maps) {
        if (m.end <= start) continue;
        if (m.start > start || !is_map_readable(m) || (require_writable && !is_map_writable(m))) {
            return false;
        }
        if (m.end >= end) return true;
        start = m.end;
    }
    return false;
}

std::vector<MapEntry> intersect_unchanged_maps(const std::vector<MapEntry> &before,
                                               const std::vector<MapEntry> &after) {
    std::vector<MapEntry> stable;
    stable.reserve(std::min(before.size(), after.size()));
    for (const auto &m : before) {
        for (const auto &o : after) {
            if (m.start == o.start && m.end == o.end && m.perms == o.perms
                && m.offset == o.offset && m.inode == o.inode && m.path == o.path) {
                stable.push_back(m);
                break;
            }
        }
    }
    return stable;
}

bool read_file_bytes_raw(int fd, uint8_t *dst, size_t total) noexcept {
    size_t done = 0;
    while (done < total) {
        const size_t chunk = std::min<size_t>(total - done, 65536);
        const long n = my_pread64(fd, dst + done, chunk, static_cast<uint64_t>(done));
        if (n <= 0) {
            return false;
        }
        done += static_cast<size_t>(n);
    }
    return true;
}

int get_android_api_level() noexcept {
#if defined(__ANDROID__)
    return android_get_device_api_level();
#else
    return 34;
#endif
}

std::string build_unavailable_payload(payload_codec::Status status,
                                      int err_no,
                                      const char *state_label) {
    payload_codec::PayloadBuilder pb(status, err_no);
    pb.add_header("state", state_label);
    pb.add_header_int("entries", 0);
    pb.add_header_int("null_entries", 0);
    pb.add_header_int("anchored_gaps", 0);
    pb.add_header_int("anon_callbacks", 0);
    return pb.build();
}

}  // namespace

LibcObjects locate_libc_objects(const uint8_t *image, size_t image_size, uintptr_t bias) noexcept {
    LibcObjects out;
    if (image == nullptr || image_size < sizeof(ElfHeader)) {
        out.state = ObjectState::kMalformed;
        return out;
    }
    ElfHeader hdr {};
    if (!read_struct(image, image_size, 0, hdr)
        || hdr.e_ident[0] != 0x7f || hdr.e_ident[1] != 'E'
        || hdr.e_ident[2] != 'L' || hdr.e_ident[3] != 'F'
        || hdr.e_ident[EI_CLASS] != kElfClass
        || hdr.e_ident[EI_DATA] != ELFDATA2LSB
        || hdr.e_ident[EI_VERSION] != EV_CURRENT
        || hdr.e_type != ET_DYN
        || (kElfMachine != EM_NONE && hdr.e_machine != kElfMachine)
        || hdr.e_version != EV_CURRENT
        || hdr.e_ehsize != sizeof(ElfHeader)) {
        out.state = ObjectState::kMalformed;
        return out;
    }
    if (hdr.e_shnum == 0) {
        return out;
    }
    if (hdr.e_shentsize != sizeof(ElfSection)
        || !in_bounds(hdr.e_shoff, static_cast<uint64_t>(hdr.e_shnum) * sizeof(ElfSection), image_size)) {
        out.state = ObjectState::kMalformed;
        return out;
    }

    const auto sym_whole = OBF("_ZL7g_array");
    const auto sym_split_prefix = OBF("_ZL7g_array.");
    const auto sym_lock = OBF("_ZL13g_atexit_lock");

    std::array<uintptr_t, 5> split {};
    uintptr_t whole = 0;
    bool conflict = false;
    auto assign = [&](uintptr_t &slot, uintptr_t value) noexcept {
        if (slot != 0 && slot != value) {
            conflict = true;
        }
        slot = value;
    };

    for (size_t si = 0; si < hdr.e_shnum; ++si) {
        ElfSection table {};
        if (!read_struct(image, image_size, hdr.e_shoff + si * sizeof(ElfSection), table)) {
            out.state = ObjectState::kMalformed;
            return out;
        }
        if (table.sh_type != SHT_SYMTAB) {
            continue;
        }
        ElfSection strings {};
        if (table.sh_link >= hdr.e_shnum
            || table.sh_entsize != sizeof(ElfSymbol)
            || (table.sh_size % sizeof(ElfSymbol)) != 0
            || !in_bounds(table.sh_offset, table.sh_size, image_size)
            || !read_struct(image, image_size,
                            hdr.e_shoff + static_cast<uint64_t>(table.sh_link) * sizeof(ElfSection),
                            strings)
            || strings.sh_type != SHT_STRTAB
            || !in_bounds(strings.sh_offset, strings.sh_size, image_size)) {
            out.state = ObjectState::kMalformed;
            return out;
        }

        for (size_t pos = 0; pos < table.sh_size; pos += sizeof(ElfSymbol)) {
            ElfSymbol sym {};
            read_struct(image, image_size, table.sh_offset + pos, sym);
            if (ELF32_ST_TYPE(sym.st_info) != STT_OBJECT
                || sym.st_shndx == SHN_UNDEF
                || sym.st_shndx >= hdr.e_shnum) {
                continue;
            }
            if (sym.st_name >= strings.sh_size) {
                out.state = ObjectState::kMalformed;
                return out;
            }
            const char *name_ptr =
                    reinterpret_cast<const char *>(image + strings.sh_offset + sym.st_name);
            const size_t max_name_len = static_cast<size_t>(strings.sh_size - sym.st_name);
            size_t name_len = 0;
            while (name_len < max_name_len && name_ptr[name_len] != '\0') {
                ++name_len;
            }
            if (name_len == max_name_len) {
                out.state = ObjectState::kMalformed;
                return out;
            }
            const std::string_view name(name_ptr, name_len);
            const bool is_whole = sv_eq(name, sym_whole.view());
            const bool is_lock = sv_eq(name, sym_lock.view());
            const bool is_split = name.size() == sym_split_prefix.size() + 1
                    && sv_starts_with(name, sym_split_prefix.view())
                    && name.back() >= '0' && name.back() <= '4';
            if (!is_whole && !is_lock && !is_split) {
                continue;
            }

            ElfSection sec {};
            uintptr_t addr = 0;
            read_struct(image, image_size,
                        hdr.e_shoff + static_cast<uint64_t>(sym.st_shndx) * sizeof(ElfSection), sec);
            if (!resolve_symbol_addr(sym, sec, bias, addr)) {
                out.state = ObjectState::kMalformed;
                return out;
            }
            if (is_whole && sym.st_size == 4 * sizeof(uintptr_t) + sizeof(uint64_t)) {
                assign(whole, addr);
            }
            if (is_lock) {
                assign(out.mutex, addr);
                out.mutex_size = static_cast<size_t>(sym.st_size);
            }
            if (is_split) {
                const size_t field = static_cast<size_t>(name.back() - '0');
                const size_t expected_size = (field == 4) ? sizeof(uint64_t) : sizeof(uintptr_t);
                if (sym.st_size == expected_size) {
                    assign(split[field], addr);
                }
            }
        }
    }

    for (size_t i = 0; i < split.size(); ++i) {
        const uintptr_t expected = (whole == 0) ? 0 : (whole + i * sizeof(uintptr_t));
        if (split[i] != 0 && expected != 0 && split[i] != expected) {
            conflict = true;
        }
        out.fields[i] = (split[i] != 0) ? split[i] : expected;
    }

    if (conflict) {
        out.state = ObjectState::kMalformed;
        return out;
    }
    bool all_fields_found = (out.mutex != 0);
    for (uintptr_t f : out.fields) {
        if (f == 0) {
            all_fields_found = false;
            break;
        }
    }
    if (!all_fields_found) {
        out.state = ObjectState::kUnsupported;
        return out;
    }

    bool distinct = true;
    for (size_t i = 0; i < out.fields.size(); ++i) {
        const size_t bytes = (i == 4) ? sizeof(uint64_t) : sizeof(uintptr_t);
        const size_t alignment = (i == 4) ? alignof(uint64_t) : alignof(uintptr_t);
        const uintptr_t start = out.fields[i];
        const uintptr_t end = start + bytes;
        if ((start % alignment) != 0 || end < start) {
            distinct = false;
            break;
        }
        if (start < out.mutex + out.mutex_size && out.mutex < end) {
            distinct = false;
            break;
        }
        for (size_t j = 0; j < i; ++j) {
            const size_t other_bytes = (j == 4) ? sizeof(uint64_t) : sizeof(uintptr_t);
            if (start < out.fields[j] + other_bytes && out.fields[j] < end) {
                distinct = false;
                break;
            }
        }
        if (!distinct) break;
    }
    out.state = distinct ? ObjectState::kFound : ObjectState::kMalformed;
    return out;
}

TableAnalysis interpret_atexit_table(const std::vector<AtexitEntry> &entries,
                                     const std::vector<MapEntry> &stable_maps) {
    TableAnalysis out;
    const auto p_data_app = OBF("/data/app/");
    const auto p_data_user = OBF("/data/user/");
    const auto p_data_data = OBF("/data/data/");
    const auto p_mnt_expand = OBF("/mnt/expand/");
    const auto lib_art = OBF("libart.so");
    const auto lib_perfetto = OBF("libperfetto_hprof.so");
    const auto lib_adbconn = OBF("libadbconnection.so");
    const auto lib_wilhelm = OBF("libwilhelm.so");
    const auto p_memfd_slash = OBF("/memfd:");
    const auto p_memfd = OBF("memfd:");
    const auto p_anon_empty = OBF("[anon:]");
    const auto p_dev_zero_del = OBF("/dev/zero (deleted)");

    auto dso_path_of = [&](const AtexitEntry &e) noexcept -> std::string_view {
        const MapEntry *owner = find_map_containing(stable_maps, e.dso);
        return owner == nullptr ? std::string_view() : std::string_view(owner->path);
    };
    auto is_app_image = [&](std::string_view path) noexcept -> bool {
        return sv_starts_with(path, p_data_app.view())
                || sv_starts_with(path, p_data_user.view())
                || sv_starts_with(path, p_data_data.view())
                || sv_starts_with(path, p_mnt_expand.view());
    };
    auto is_perfetto = [&](const AtexitEntry &e) noexcept -> bool {
        const MapEntry *fn_map = find_map_containing(stable_maps, e.fn);
        return fn_map != nullptr && is_map_executable(*fn_map)
                && sv_eq(basename_sv(fn_map->path), lib_art.view())
                && sv_eq(basename_sv(dso_path_of(e)), lib_perfetto.view());
    };
    auto is_anon_exec_owner = [&](const MapEntry &m) noexcept -> bool {
        const std::string_view p(m.path);
        return p.empty()
                || sv_starts_with(p, p_memfd_slash.view())
                || sv_starts_with(p, p_memfd.view())
                || sv_eq(p, p_anon_empty.view())
                || sv_eq(p, p_dev_zero_del.view());
    };

    size_t boundary = entries.size();
    for (size_t i = 0; i < entries.size(); ++i) {
        if (entries[i].empty()) {
            ++out.null_entries;
            continue;
        }
        if (is_app_image(dso_path_of(entries[i]))) {
            boundary = std::min(boundary, i);
        }
    }
    for (size_t i = 0; i + 1 < boundary; ++i) {
        if (is_perfetto(entries[i]) && is_perfetto(entries[i + 1])) {
            boundary = i + 1;
            break;
        }
    }

    out.bounded = boundary < entries.size();
    out.dense_clearing = !entries.empty() && out.null_entries * 5 >= entries.size() * 3;
    if (!out.bounded || out.dense_clearing) {
        return out;
    }

    // 1. Detect atexit callbacks resolving into anonymous executable pages.
    for (size_t i = 0; i < boundary; ++i) {
        const auto &e = entries[i];
        if (e.empty()) continue;
        const MapEntry *owner = find_map_containing(stable_maps, e.fn);
        if (owner == nullptr || !is_map_executable(*owner)) {
            ++out.unresolved_callbacks;
            continue;
        }
        if (is_anon_exec_owner(*owner)) {
            if (out.anon_callbacks.size() < kMaxReportedHits) {
                std::string label = owner->path.empty() ? OBF("[anon_exec]").str() : owner->path;
                out.anon_callbacks.push_back({i, std::move(label)});
            }
        }
    }

    // 2. Detect >= 3 contiguous unloaded-module holes adjacent to known Zygote runtime anchors.
    for (size_t start = 0; start < boundary;) {
        if (!entries[start].empty()) {
            ++start;
            continue;
        }
        size_t end = start;
        while (end < entries.size() && entries[end].empty()) {
            ++end;
        }
        const size_t count = end - start;
        bool anchored = false;
        if (count >= 3 && start > 0 && end <= boundary && end < entries.size()) {
            const std::string_view prev_base = basename_sv(dso_path_of(entries[start - 1]));
            anchored = sv_eq(prev_base, lib_adbconn.view()) || sv_eq(prev_base, lib_wilhelm.view());
            if (!anchored && sv_eq(prev_base, lib_art.view()) && start >= 16) {
                anchored = true;
                for (size_t k = start - 16; k < start; ++k) {
                    if (entries[k].empty() || !sv_eq(basename_sv(dso_path_of(entries[k])), lib_art.view())) {
                        anchored = false;
                        break;
                    }
                }
            }
            if (!anchored && end + 1 < entries.size()) {
                anchored = is_perfetto(entries[end]) && is_perfetto(entries[end + 1]);
            }
        }
        if (anchored && out.anchored_holes.size() < kMaxReportedHits) {
            out.anchored_holes.push_back({start, end - 1, count});
        }
        start = end;
    }
    return out;
}

}  // namespace zygisk_atexit

std::string native_get_zygisk_atexit_probe() {
    using namespace zygisk_atexit;

    const int api = get_android_api_level();
    if (api < 30 || api > 37) {
        return build_unavailable_payload(payload_codec::Status::UNSUPPORTED, 0, "UNSUPPORTED");
    }

    const std::vector<MapEntry> maps_before = read_self_maps();
    if (maps_before.empty()) {
        return build_unavailable_payload(payload_codec::Status::RESTRICTED, EACCES, "UNAVAILABLE");
    }

    const auto sym_cxa_atexit = OBF("__cxa_atexit");
    const auto sym_cxa_finalize = OBF("__cxa_finalize");
    const auto libc_name = OBF("libc.so");

    void *cxa_atexit = dlsym(RTLD_DEFAULT, sym_cxa_atexit.c_str());
    void *cxa_finalize = dlsym(RTLD_DEFAULT, sym_cxa_finalize.c_str());

    const MapEntry *atexit_owner = find_map_containing(
            maps_before, reinterpret_cast<uintptr_t>(cxa_atexit));
    const MapEntry *finalize_owner = find_map_containing(
            maps_before, reinterpret_cast<uintptr_t>(cxa_finalize));

    const bool atexit_drift = atexit_owner != nullptr
            && !sv_eq(basename_sv(atexit_owner->path), libc_name.view());
    const bool finalize_drift = finalize_owner != nullptr
            && !sv_eq(basename_sv(finalize_owner->path), libc_name.view());

    payload_codec::PayloadBuilder pb(payload_codec::Status::OK, 0);
    if (atexit_drift || finalize_drift) {
        payload_codec::RecordBuilder rec;
        rec.add("kind", OBF("atexit_runtime_drift").c_str())
           .add("atexit_owner", atexit_owner ? atexit_owner->path : "")
           .add("finalize_owner", finalize_owner ? finalize_owner->path : "");
        pb.add_record(rec);
    }

    Dl_info info {};
    if (cxa_atexit == nullptr || dladdr(cxa_atexit, &info) == 0
        || info.dli_fname == nullptr || info.dli_fbase == nullptr
        || !sv_eq(basename_sv(info.dli_fname), libc_name.view())) {
        if (!atexit_drift && !finalize_drift) {
            return build_unavailable_payload(payload_codec::Status::UNSUPPORTED, 0, "UNAVAILABLE");
        }
        pb.add_header("state", "PARTIAL");
        pb.add_header_int("entries", 0);
        pb.add_header_int("null_entries", 0);
        pb.add_header_int("anchored_gaps", 0);
        pb.add_header_int("anon_callbacks", 0);
        return pb.build();
    }

    const long fd_ret = my_openat(AT_FDCWD, info.dli_fname, O_RDONLY | O_CLOEXEC, 0);
    if (fd_ret < 0) {
        const int err = raw_last_error();
        if (!atexit_drift && !finalize_drift) {
            return build_unavailable_payload(
                    (err == EACCES || err == EPERM)
                            ? payload_codec::Status::RESTRICTED
                            : payload_codec::Status::UNSUPPORTED,
                    err, "UNAVAILABLE");
        }
        pb.add_header("state", "PARTIAL");
        return pb.build();
    }
    safe_mem::ScopedFd libc_fd(static_cast<int>(fd_ret));

    struct stat st {};
    if (my_fstatat(libc_fd.get(), "", &st, AT_EMPTY_PATH) != 0) {
        return build_unavailable_payload(payload_codec::Status::UNSUPPORTED, raw_last_error(), "UNAVAILABLE");
    }
    if (atexit_owner == nullptr || atexit_owner->inode == 0
        || atexit_owner->inode != static_cast<uint64_t>(st.st_ino)) {
        return build_unavailable_payload(payload_codec::Status::UNSUPPORTED, 0, "UNAVAILABLE");
    }
    if (st.st_size <= 0 || static_cast<uint64_t>(st.st_size) > kMaxLibcImageBytes) {
        return build_unavailable_payload(payload_codec::Status::UNSUPPORTED, 0, "UNSUPPORTED");
    }

    const size_t img_size = static_cast<size_t>(st.st_size);
    uint8_t *raw_img = new (std::nothrow) uint8_t[img_size];
    if (raw_img == nullptr) {
        return build_unavailable_payload(payload_codec::Status::ERROR, ENOMEM, "UNAVAILABLE");
    }
    struct RawDeleter {
        uint8_t *p;
        ~RawDeleter() { delete[] p; }
    } img_guard {raw_img};

    if (!read_file_bytes_raw(libc_fd.get(), raw_img, img_size)) {
        return build_unavailable_payload(payload_codec::Status::UNSUPPORTED, raw_last_error(), "UNAVAILABLE");
    }

    const LibcObjects objects = locate_libc_objects(
            raw_img, img_size, reinterpret_cast<uintptr_t>(info.dli_fbase));
    if (objects.state != ObjectState::kFound) {
        return build_unavailable_payload(payload_codec::Status::UNSUPPORTED, 0, "UNSUPPORTED");
    }

    if (objects.mutex_size != sizeof(pthread_mutex_t)
        || (objects.mutex % alignof(pthread_mutex_t)) != 0
        || !is_range_covered(maps_before, objects.mutex, sizeof(pthread_mutex_t), true)) {
        return build_unavailable_payload(payload_codec::Status::UNSUPPORTED, 0, "UNSUPPORTED");
    }
    for (size_t i = 0; i < objects.fields.size(); ++i) {
        const size_t sz = (i == 4) ? sizeof(uint64_t) : sizeof(uintptr_t);
        if (!is_range_covered(maps_before, objects.fields[i], sz, false)) {
            return build_unavailable_payload(payload_codec::Status::UNSUPPORTED, 0, "UNAVAILABLE");
        }
    }

    safe_mem::PipeMemoryReader pipe_mem;
    if (!pipe_mem.available()) {
        return build_unavailable_payload(payload_codec::Status::ERROR, EIO, "UNAVAILABLE");
    }

    // Allocate entry buffer BEFORE acquiring libc's atexit lock.
    AtexitEntry *entry_buf = new (std::nothrow) AtexitEntry[kMaxAtexitEntries];
    if (entry_buf == nullptr) {
        return build_unavailable_payload(payload_codec::Status::ERROR, ENOMEM, "UNAVAILABLE");
    }
    struct EntryDeleter {
        AtexitEntry *p;
        ~EntryDeleter() { delete[] p; }
    } entry_guard {entry_buf};

    // Red line: NEVER call blocking pthread_mutex_lock; use pthread_mutex_trylock ONLY.
    auto *mutex = reinterpret_cast<pthread_mutex_t *>(objects.mutex);
    const int lock_rc = pthread_mutex_trylock(mutex);
    if (lock_rc != 0) {
        return build_unavailable_payload(
                payload_codec::Status::UNSUPPORTED, lock_rc,
                lock_rc == EBUSY ? "BUSY" : "UNAVAILABLE");
    }

    // Zero heap allocations, zero logging, zero direct pointer dereference under lock.
    std::array<uintptr_t, 4> meta {};
    uint64_t total_appends = 0;
    bool readable = true;
    for (size_t i = 0; i < meta.size(); ++i) {
        readable = readable && pipe_mem.read(objects.fields[i], &meta[i], sizeof(uintptr_t));
    }
    readable = readable && pipe_mem.read(objects.fields[4], &total_appends, sizeof(total_appends));

    const uintptr_t array_ptr = meta[0];
    const size_t entry_size = static_cast<size_t>(meta[1]);
    const size_t extracted_count = static_cast<size_t>(meta[2]);
    const size_t capacity = static_cast<size_t>(meta[3]);

    const bool bounded = entry_size <= kMaxAtexitEntries && capacity <= kMaxAtexitEntries;
    const bool valid = readable
            && entry_size <= capacity
            && extracted_count <= entry_size
            && total_appends >= entry_size
            && (entry_size == 0
                || (array_ptr != 0 && (array_ptr % alignof(AtexitEntry)) == 0));

    bool table_read = false;
    if (valid && bounded) {
        if (entry_size == 0) {
            table_read = true;
        } else if (is_range_covered(maps_before, array_ptr, entry_size * sizeof(AtexitEntry), false)) {
            table_read = pipe_mem.read(array_ptr, entry_buf, entry_size * sizeof(AtexitEntry));
        }
    }

    const int unlock_rc = pthread_mutex_unlock(mutex);
    if (unlock_rc != 0 || !readable || !valid || !bounded || !table_read) {
        return build_unavailable_payload(payload_codec::Status::UNSUPPORTED, 0, "UNAVAILABLE");
    }

    std::vector<AtexitEntry> entries(entry_buf, entry_buf + entry_size);
    size_t observed_nulls = 0;
    for (const auto &e : entries) {
        if (e.empty()) ++observed_nulls;
    }
    if (observed_nulls != extracted_count) {
        return build_unavailable_payload(payload_codec::Status::UNSUPPORTED, 0, "INVALID");
    }

    const std::vector<MapEntry> maps_after = read_self_maps();
    const std::vector<MapEntry> stable_maps = intersect_unchanged_maps(maps_before, maps_after);
    const TableAnalysis analysis = interpret_atexit_table(entries, stable_maps);

    const bool is_partial = !analysis.bounded || analysis.dense_clearing
            || analysis.unresolved_callbacks > 0;
    pb.add_header("state", is_partial ? "PARTIAL" : "COLLECTED");
    pb.add_header_int("entries", static_cast<int64_t>(entries.size()));
    pb.add_header_int("null_entries", static_cast<int64_t>(analysis.null_entries));
    pb.add_header_int("anchored_gaps", static_cast<int64_t>(analysis.anchored_holes.size()));
    pb.add_header_int("anon_callbacks", static_cast<int64_t>(analysis.anon_callbacks.size()));

    for (const auto &hit : analysis.anon_callbacks) {
        payload_codec::RecordBuilder rec;
        rec.add("kind", OBF("atexit_anon_callback").c_str())
           .add_uint("index", hit.index)
           .add("owner", hit.owner);
        pb.add_record(rec);
    }
    for (const auto &hole : analysis.anchored_holes) {
        payload_codec::RecordBuilder rec;
        rec.add("kind", OBF("atexit_hole_run").c_str())
           .add_uint("start", hole.start)
           .add_uint("end", hole.end)
           .add_uint("count", hole.count);
        pb.add_record(rec);
    }

    return pb.build();
}
