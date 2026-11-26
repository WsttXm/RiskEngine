#include "native_hook_detector.h"
#include "art_hook_detector.h"
#include "native_integrity.h"
#include "../util/maps_parser.h"
#include "../util/mylibc.h"
#include "../util/obf_str.h"
#include "../util/payload_codec.h"
#include "../util/raw_dir.h"
#include "../util/safe_mem_read.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif

namespace {

struct HookFinding {
    std::string token;
    std::string code;
    std::string location;
    std::string value;
    std::string family;
};

void add_finding(std::vector<HookFinding> &findings,
                 const std::string &token,
                 const std::string &code,
                 const std::string &location,
                 const std::string &value,
                 const std::string &family) {
    if (token.empty()) return;
    for (const auto &existing : findings) {
        if (existing.token == token) return;
    }
    findings.push_back({token, code, location, value, family});
}

void add_string_unique(std::vector<std::string> &evidence, const std::string &value) {
    if (!value.empty()
        && std::find(evidence.begin(), evidence.end(), value) == evidence.end()) {
        evidence.push_back(value);
    }
}

inline char ascii_lower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

std::string to_lower(std::string value) {
    for (char &c : value) {
        c = ascii_lower(c);
    }
    return value;
}

void to_lower_inplace(char *buf, size_t len) noexcept {
    for (size_t i = 0; i < len; ++i) {
        buf[i] = ascii_lower(buf[i]);
    }
}

bool contains_any_sv(std::string_view haystack,
                     const std::string_view *needles,
                     size_t count) noexcept {
    for (size_t i = 0; i < count; ++i) {
        if (haystack.find(needles[i]) != std::string_view::npos) return true;
    }
    return false;
}

bool is_all_digits_str(const std::string &s) noexcept {
    if (s.empty()) return false;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

std::string format_hex_u64(uint64_t val) {
    char buf[24] = {};
    static const char kDigits[] = "0123456789abcdef";
    buf[0] = '0';
    buf[1] = 'x';
    int pos = 2;
    bool started = false;
    for (int shift = 60; shift >= 0; shift -= 4) {
        unsigned nib = static_cast<unsigned>((val >> shift) & 0xFU);
        if (nib != 0 || started || shift == 0) {
            started = true;
            buf[pos++] = kDigits[nib];
        }
    }
    buf[pos] = '\0';
    return std::string(buf, static_cast<size_t>(pos));
}

std::string extract_basename(const std::string &path) {
    if (path.empty()) return {};
    size_t slash = path.rfind('/');
    std::string base = (slash == std::string::npos) ? path : path.substr(slash + 1);
    const auto del_suf = OBF(" (deleted)");
    size_t del = base.find(del_suf.view());
    if (del != std::string::npos) {
        base.erase(del);
    }
    return base;
}

bool is_suspicious_executable_region(const MapEntry &entry) noexcept {
    if (!entry.path.empty()) return false;
    if (entry.end <= entry.start || entry.perms.size() < 3) return false;
    return entry.perms[0] == 'r' && entry.perms[2] == 'x';
}

void scan_unix_sockets(std::vector<HookFinding> &findings) {
    std::string content = read_file_string(OBF("/proc/net/unix").c_str(), 512 * 1024);
    if (content.empty()) return;
    std::string lower = to_lower(content);
    if (lower.find(OBF("re.frida")) != std::string::npos
        || lower.find(OBF("frida:")) != std::string::npos
        || lower.find(OBF("frida-zymbiote")) != std::string::npos
        || lower.find(OBF("linjector")) != std::string::npos) {
        add_finding(findings, OBF("unix_socket:frida"), OBF("unix_socket_frida"),
                    OBF("/proc/net/unix"), OBF("frida"), OBF("frida"));
    }
    if (lower.find(OBF("gum-js")) != std::string::npos) {
        add_finding(findings, OBF("unix_socket:gum"), OBF("unix_socket_gum"),
                    OBF("/proc/net/unix"), OBF("gum-js"), OBF("frida"));
    }
}

std::string sanitize_memfd_label(const std::string &path) {
    const std::string prefix = OBF("/memfd:");
    std::string label = path.rfind(prefix, 0) == 0 ? path.substr(prefix.size()) : path;
    const std::string deleted_suffix = OBF(" (deleted)");
    auto del_pos = label.find(deleted_suffix);
    if (del_pos != std::string::npos) {
        label.erase(del_pos);
    }
    std::string clean;
    clean.reserve(std::min<size_t>(label.size(), 32));
    for (char c : label) {
        if (clean.size() >= 32) break;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
            clean.push_back(c);
        }
    }
    return clean.empty() ? OBF("unknown") : clean;
}

bool read_elf_magic_safe(safe_mem::PipeMemoryReader &mem, uintptr_t addr) {
    if (!mem.available() || addr == 0) return false;
    unsigned char magic[4] = {};
    return mem.read(addr, magic, sizeof(magic))
           && magic[0] == 0x7f && magic[1] == 'E'
           && magic[2] == 'L' && magic[3] == 'F';
}

bool read_validated_elf_header_safe(safe_mem::PipeMemoryReader &mem, uintptr_t addr) {
    if (!mem.available() || addr == 0) return false;
    unsigned char hdr[16] = {};
    if (!mem.read(addr, hdr, sizeof(hdr))) {
        return false;
    }
    // Verify ELF magic + valid ELFCLASS (32/64) + little-endian + EV_CURRENT
    // to prevent accidental 4-byte collisions in random JIT code pages.
    return hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F'
           && (hdr[4] == 1 || hdr[4] == 2)
           && hdr[5] == 1
           && hdr[6] == 1;
}

/**
 * Full /proc/self/fd symlink scan using raw getdents64 (raw_list_dir) + raw readlinkat
 * and mylibc helpers to detect linjector pipes, Frida FIFOs, memfd Frida artifacts, and sockets.
 */
void scan_self_fds(std::vector<HookFinding> &findings, bool &has_frida_family) {
    const auto fd_dir = OBF("/proc/self/fd");
    RawDirResult fds = raw_list_dir(fd_dir.c_str());
    if (!fds.ok()) {
        return;
    }

    const auto fd_prefix = OBF("/proc/self/fd/");
    const auto kw_linjector = OBF("linjector");
    const auto kw_frida = OBF("frida");
    const auto kw_frida_gadget = OBF("frida-gadget");
    const auto kw_libgadget = OBF("libgadget");
    const auto kw_gum_js = OBF("gum-js");
    const auto kw_re_frida = OBF("re.frida");
    const auto fam_frida = OBF("frida");

    char link_buf[384] = {};
    char lower_buf[384] = {};
    for (const auto &entry_name : fds.names) {
        if (!is_all_digits_str(entry_name)) {
            continue;
        }
        std::string fd_path = std::string(fd_prefix.c_str()) + entry_name;
        const long n = my_readlinkat(AT_FDCWD, fd_path.c_str(), link_buf, sizeof(link_buf) - 1);
        if (n <= 0) {
            continue;
        }
        const size_t len = static_cast<size_t>(n);
        link_buf[len] = '\0';
        my_memcpy(lower_buf, link_buf, len + 1);
        to_lower_inplace(lower_buf, len);

        if (my_strstr(lower_buf, kw_linjector.c_str()) != nullptr) {
            has_frida_family = true;
            add_finding(findings,
                        OBF("fd:linjector").str(),
                        OBF("fd_linjector").str(),
                        std::string(link_buf, len),
                        entry_name,
                        fam_frida.str());
        } else if (my_strstr(lower_buf, kw_frida.c_str()) != nullptr
                   || my_strstr(lower_buf, kw_re_frida.c_str()) != nullptr
                   || my_strstr(lower_buf, kw_frida_gadget.c_str()) != nullptr
                   || my_strstr(lower_buf, kw_libgadget.c_str()) != nullptr
                   || my_strstr(lower_buf, kw_gum_js.c_str()) != nullptr) {
            has_frida_family = true;
            std::string target(link_buf, len);
            std::string label = extract_basename(target);
            if (label.empty()) label = entry_name;
            add_finding(findings,
                        OBF("fd:frida:").str() + label,
                        OBF("fd_frida").str(),
                        target,
                        entry_name,
                        fam_frida.str());
        }
    }
}

void extract_status_name(const char *status_buf, size_t len,
                         const char *name_key, size_t key_len,
                         char *out, size_t out_cap) noexcept {
    if (!status_buf || !name_key || key_len == 0 || !out || out_cap == 0) return;
    out[0] = '\0';
    const char *p = status_buf;
    const char *end = status_buf + len;
    while (p < end) {
        if (static_cast<size_t>(end - p) >= key_len
                && my_memcmp(p, name_key, key_len) == 0) {
            const char *val = p + key_len;
            while (val < end && (*val == ' ' || *val == '\t')) ++val;
            size_t out_len = 0;
            while (val < end && *val != '\n' && *val != '\r' && out_len + 1 < out_cap) {
                out[out_len++] = *val++;
            }
            out[out_len] = '\0';
            return;
        }
        while (p < end && *p != '\n') ++p;
        if (p < end && *p == '\n') ++p;
    }
}

/**
 * Probes unnamed anonymous private executable (r-xp) mappings for ELF headers
 * exclusively via PipeMemoryReader (zero direct dereference).
 */
void scan_anon_exec_elfs(const std::vector<MapEntry> &maps,
                         std::vector<HookFinding> &findings) {
    safe_mem::PipeMemoryReader mem;
    if (!mem.available()) {
        return;
    }
    const auto tok_prefix = OBF("anon_elf_exec:");
    const auto code_name = OBF("anon_elf_exec");
    const auto fam = OBF("hook_integrity");

    int probed = 0;
    constexpr int kMaxAnonExecProbes = 64;
    for (const auto &entry : maps) {
        if (!entry.path.empty()) continue;
        if (entry.end <= entry.start || (entry.end - entry.start) < 4096) continue;
        if (entry.perms.size() < 4) continue;
        if (entry.perms[0] != 'r' || entry.perms[2] != 'x' || entry.perms[3] != 'p') continue;
        if (++probed > kMaxAnonExecProbes) break;

        if (read_validated_elf_header_safe(mem, entry.start)) {
            std::string addr_hex = format_hex_u64(static_cast<uint64_t>(entry.start));
            add_finding(findings,
                        tok_prefix.str() + addr_hex,
                        code_name.str(),
                        addr_hex,
                        entry.perms,
                        fam.str());
        }
    }
}

struct PhdrExecSegment {
    uintptr_t start;
    uintptr_t end;
    std::string name;
};

struct PhdrCollectContext {
    std::vector<PhdrExecSegment> exec_segments;
    std::vector<std::pair<uintptr_t, uintptr_t>> all_load_ranges;
};

int collect_phdr_cb(struct dl_phdr_info *info, size_t, void *data) {
    if (info == nullptr || data == nullptr || info->dlpi_phdr == nullptr) {
        return 0;
    }
    auto *ctx = static_cast<PhdrCollectContext *>(data);
    const char *raw_name = info->dlpi_name != nullptr ? info->dlpi_name : "";
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const auto &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD || ph.p_memsz == 0) {
            continue;
        }
        uintptr_t seg_start = static_cast<uintptr_t>(info->dlpi_addr + ph.p_vaddr);
        uintptr_t seg_end = seg_start + static_cast<uintptr_t>(ph.p_memsz);
        if (seg_end <= seg_start) {
            continue;
        }
        ctx->all_load_ranges.emplace_back(seg_start, seg_end);
        if ((ph.p_flags & PF_X) != 0) {
            ctx->exec_segments.push_back({seg_start, seg_end, raw_name});
        }
    }
    return 0;
}

bool overlaps_any_range(uintptr_t seg_start, uintptr_t seg_end,
                        const std::vector<std::pair<uintptr_t, uintptr_t>> &ranges) noexcept {
    for (const auto &r : ranges) {
        if (seg_start < r.second && seg_end > r.first) {
            return true;
        }
    }
    return false;
}

/**
 * Bidirectional visibility diff between linker dl_iterate_phdr PT_LOAD segments
 * and /proc/self/maps, filtering dalvik/jit/vdso/system non-dlopen mappings.
 */
void scan_dl_iterate_phdr_diff(const std::vector<MapEntry> &maps,
                               std::vector<HookFinding> &findings) {
    if (maps.empty()) {
        return;
    }
    PhdrCollectContext ctx;
    ctx.exec_segments.reserve(256);
    ctx.all_load_ranges.reserve(512);
    dl_iterate_phdr(collect_phdr_cb, &ctx);
    if (ctx.exec_segments.empty()) {
        return;
    }

    const auto kw_so = OBF(".so");
    const auto kw_vdso = OBF("vdso");
    const auto kw_linux_gate = OBF("linux-gate");
    const auto fam = OBF("hook_integrity");

    // Direction 1: linker knows an executable .so PT_LOAD segment, yet /proc/self/maps hides it.
    for (const auto &seg : ctx.exec_segments) {
        if (seg.name.empty()) continue;
        std::string lower_name = to_lower(seg.name);
        if (lower_name.find(kw_so.view()) == std::string::npos) continue;
        if (lower_name.find(kw_vdso.view()) != std::string::npos
            || lower_name.find(kw_linux_gate.view()) != std::string::npos) {
            continue;
        }
        if (find_map_containing(maps, seg.start) == nullptr) {
            // Re-verify live /proc/self/maps once to rule out concurrent dlopen() TOCTOU.
            MapEntry live {};
            if (find_self_map_containing(seg.start, live)) {
                continue;
            }
            std::string base = extract_basename(seg.name);
            add_finding(findings,
                        OBF("stealth_so_hidden_in_maps:").str() + base,
                        OBF("stealth_so_hidden_in_maps").str(),
                        seg.name,
                        format_hex_u64(static_cast<uint64_t>(seg.start)),
                        fam.str());
        }
    }

    // Direction 2: executable .so mapping in /proc/self/maps from untrusted/deleted locations
    // that does not overlap any linker dl_iterate_phdr PT_LOAD range (unlinked solist).
    // All OBF needles and lowercase buffer are hoisted outside the maps loop (D26).
    const auto kw_deleted = OBF("(deleted)");
    const auto kw_data_local_tmp = OBF("/data/local/tmp/");
    const auto kw_dev_prefix = OBF("/dev/");
    const auto kw_anon = OBF("[anon:");
    const auto kw_vdso_b = OBF("[vdso]");
    const auto kw_vsys = OBF("[vsyscall]");
    const auto kw_dalvik = OBF("dalvik");
    const auto kw_jit = OBF("jit");
    const auto kw_linker = OBF("linker");

    std::string lower;
    lower.reserve(256);
    for (const auto &entry : maps) {
        if (entry.path.empty() || entry.perms.size() < 3 || entry.perms[2] != 'x') continue;
        lower.resize(entry.path.size());
        for (size_t i = 0; i < entry.path.size(); ++i) {
            lower[i] = ascii_lower(entry.path[i]);
        }
        const std::string_view lower_sv(lower);
        if (lower_sv.find(kw_so.view()) == std::string_view::npos) continue;

        const bool suspicious_origin =
                lower_sv.find(kw_deleted.view()) != std::string_view::npos
                || lower_sv.rfind(kw_data_local_tmp.view(), 0) == 0
                || lower_sv.rfind(kw_dev_prefix.view(), 0) == 0;
        if (!suspicious_origin) {
            continue;
        }
        if (lower_sv.find(kw_anon.view()) != std::string_view::npos
            || lower_sv.find(kw_vdso_b.view()) != std::string_view::npos
            || lower_sv.find(kw_vsys.view()) != std::string_view::npos
            || lower_sv.find(kw_dalvik.view()) != std::string_view::npos
            || lower_sv.find(kw_jit.view()) != std::string_view::npos
            || lower_sv.find(kw_linker.view()) != std::string_view::npos) {
            continue;
        }
        // Use interval overlap rather than point containment to handle 4KB/16KB page-aligned
        // /proc/self/maps VMA boundaries vs non-page-aligned ELF PT_LOAD p_vaddr ranges.
        if (!overlaps_any_range(entry.start, entry.end, ctx.all_load_ranges)) {
            std::string base = extract_basename(entry.path);
            add_finding(findings,
                        OBF("stealth_so_unlinked:").str() + base,
                        OBF("stealth_so_unlinked").str(),
                        entry.path,
                        format_hex_u64(static_cast<uint64_t>(entry.start)),
                        fam.str());
        }
    }
}

/**
 * Read-only sigaction handler integrity check for SIGSEGV, SIGTRAP, and SIGILL.
 * Explicitly allows mapped libraries (such as ART's libsigchain.so) and only flags
 * handlers pointing into unmapped memory or unnamed anonymous executable pages.
 */
void scan_sigaction_handlers(const std::vector<MapEntry> &maps,
                             std::vector<HookFinding> &findings) {
    if (maps.empty()) {
        return;
    }
    struct SigCheck {
        int sig;
        const char *name;
    };
    const auto s_segv = OBF("SIGSEGV");
    const auto s_trap = OBF("SIGTRAP");
    const auto s_ill = OBF("SIGILL");
    const SigCheck checks[] = {
            {SIGSEGV, s_segv.c_str()},
            {SIGTRAP, s_trap.c_str()},
            {SIGILL, s_ill.c_str()},
    };

    const auto kw_sigchain = OBF("libsigchain");
    const auto kw_anon = OBF("[anon:");
    const auto fam = OBF("hook_integrity");

    for (const auto &chk : checks) {
        struct sigaction sa {};
        if (sigaction(chk.sig, nullptr, &sa) != 0) {
            continue;
        }
        uintptr_t handler_addr = 0;
        if ((sa.sa_flags & SA_SIGINFO) != 0) {
            handler_addr = reinterpret_cast<uintptr_t>(sa.sa_sigaction);
            if (handler_addr == reinterpret_cast<uintptr_t>(SIG_DFL)
                || handler_addr == reinterpret_cast<uintptr_t>(SIG_IGN)) {
                continue;
            }
        } else {
            if (sa.sa_handler == SIG_DFL || sa.sa_handler == SIG_IGN) {
                continue;
            }
            handler_addr = reinterpret_cast<uintptr_t>(sa.sa_handler);
        }
        if (handler_addr == 0) {
            continue;
        }

        const MapEntry *mapping = find_map_containing(maps, handler_addr);
        MapEntry live_mapping {};
        if (mapping == nullptr && find_self_map_containing(handler_addr, live_mapping)) {
            mapping = &live_mapping;
        }
        if (mapping == nullptr) {
            add_finding(findings,
                        OBF("sigaction_anon_handler:").str() + chk.name,
                        OBF("sigaction_anon_handler").str(),
                        chk.name,
                        OBF("unmapped:").str() + format_hex_u64(static_cast<uint64_t>(handler_addr)),
                        fam.str());
            continue;
        }
        if (!mapping->path.empty()) {
            std::string lower = to_lower(mapping->path);
            if (lower.find(kw_sigchain.view()) != std::string::npos) {
                continue;
            }
            if (lower.rfind(kw_anon.view(), 0) != 0) {
                // Mapped to a named library/file (e.g., libart.so, crash reporter .so) -> benign.
                continue;
            }
        }
        // Handler points into an unnamed or [anon:*] region.
        add_finding(findings,
                    OBF("sigaction_anon_handler:").str() + chk.name,
                    OBF("sigaction_anon_handler").str(),
                    chk.name,
                    format_hex_u64(static_cast<uint64_t>(handler_addr)),
                    fam.str());
    }
}

void scan_self_wx_segments(const std::vector<MapEntry> &maps,
                           std::vector<HookFinding> &findings) {
    Dl_info self_info {};
    uintptr_t self_base = 0;
    if (dladdr(reinterpret_cast<const void *>(&scan_self_wx_segments), &self_info) != 0
        && self_info.dli_fbase != nullptr) {
        self_base = reinterpret_cast<uintptr_t>(self_info.dli_fbase);
    }
    const MapEntry *self_code = find_map_containing(
            maps, reinterpret_cast<uintptr_t>(&scan_self_wx_segments));

    const auto obf_self_so = OBF("libriskengine.so");
    const auto obf_art_so = OBF("libart.so");
    const auto obf_libc_so = OBF("libc.so");

    for (const auto &entry : maps) {
        if (entry.perms.size() < 3) continue;
        const bool writable = entry.perms[1] == 'w';
        const bool executable = entry.perms[2] == 'x';
        if (!writable || !executable) continue;

        if ((self_code != nullptr && entry.start == self_code->start)
            || (self_base != 0 && self_base >= entry.start && self_base < entry.end)) {
            add_finding(findings, OBF("wx_segment:self"), OBF("wx_segment_self"),
                        entry.path.empty() ? std::string(obf_self_so.view()) : entry.path,
                        entry.perms, OBF("hook_integrity"));
            continue;
        }
        std::string lower = to_lower(entry.path);
        if (lower.find(obf_self_so.view()) != std::string::npos) {
            add_finding(findings, OBF("wx_segment:self"), OBF("wx_segment_self"),
                        entry.path, entry.perms, OBF("hook_integrity"));
        } else if (lower.find(obf_art_so.view()) != std::string::npos
                   || lower.find(obf_libc_so.view()) != std::string::npos) {
            add_finding(findings, OBF("wx_segment:") + lower, OBF("wx_segment"),
                        entry.path, entry.perms, OBF("hook_integrity"));
        }
    }
}

void append_art_csv_tokens(const std::string &csv, std::vector<HookFinding> &findings) {
    if (csv.empty()) return;
    size_t start = 0;
    while (start <= csv.size()) {
        size_t comma = csv.find(',', start);
        if (comma == std::string::npos) comma = csv.size();
        std::string tok = csv.substr(start, comma - start);
        if (!tok.empty()) {
            std::string code = tok;
            std::string location;
            auto colon = tok.find(':');
            if (colon != std::string::npos) {
                code = tok.substr(0, colon);
                location = tok.substr(colon + 1);
            }
            // Leave family empty for context/non-integrity ART tokens (such as
            // loader_depth:<N>, which appears on every clean device) so Java's
            // SelfIntegrityProbe/EvidenceFamily classifies only true threats.
            std::string family;
            if (tok.rfind(OBF("jni_slot_hook:"), 0) == 0
                || tok.rfind(OBF("art_native_cleared:"), 0) == 0
                || (tok.rfind(OBF("art_native_flag:"), 0) == 0
                    && tok != OBF("art_native_flag:invoke"))) {
                family = OBF("hook_integrity");
            }
            add_finding(findings, tok, code, location, tok, family);
        }
        if (comma == csv.size()) break;
        start = comma + 1;
    }
}

void classify_thread_name(const char *lower_name,
                          const std::string &loc,
                          std::vector<HookFinding> &findings,
                          bool &has_frida_family,
                          bool &saw_gmain,
                          const char *kw_gum_loop,
                          const char *kw_pool_frida,
                          const char *kw_pool_spawner,
                          const char *kw_frida_helper,
                          const char *kw_gdbus,
                          const char *kw_frida,
                          const char *kw_gmain) {
    if (lower_name == nullptr || lower_name[0] == '\0') return;
    if (my_strstr(lower_name, kw_gum_loop) != nullptr) {
        has_frida_family = true;
        add_finding(findings, OBF("thread:gum-js-loop"), OBF("frida_thread"),
                    loc, OBF("gum-js-loop"), OBF("frida"));
    } else if (my_strstr(lower_name, kw_pool_frida) != nullptr) {
        has_frida_family = true;
        add_finding(findings, OBF("thread:pool-frida"), OBF("frida_thread"),
                    loc, OBF("pool-frida"), OBF("frida"));
    } else if (my_strstr(lower_name, kw_pool_spawner) != nullptr) {
        has_frida_family = true;
        add_finding(findings, OBF("thread:pool-spawner"), OBF("frida_thread"),
                    loc, OBF("pool-spawner"), OBF("frida"));
    } else if (my_strstr(lower_name, kw_frida_helper) != nullptr) {
        has_frida_family = true;
        add_finding(findings, OBF("thread:frida-helper"), OBF("frida_thread"),
                    loc, OBF("frida-helper"), OBF("frida"));
    } else if (my_strstr(lower_name, kw_gdbus) != nullptr) {
        has_frida_family = true;
        add_finding(findings, OBF("thread:gdbus"), OBF("frida_thread"),
                    loc, OBF("gdbus"), OBF("frida"));
    } else if (my_strstr(lower_name, kw_frida) != nullptr) {
        has_frida_family = true;
        add_finding(findings, OBF("thread:frida"), OBF("frida_thread"),
                    loc, OBF("frida"), OBF("frida"));
    } else if (my_strstr(lower_name, kw_gmain) != nullptr) {
        saw_gmain = true;
    }
}

void collect_hook_findings(JNIEnv *env, const std::vector<MapEntry> &maps,
                           std::vector<HookFinding> &findings) {
    bool has_frida_family = false;

    // Decode all loop needles once outside the /proc/self/maps hot loop
    // (avoids ~27k per-scan OBF decodes & heap vector allocations on 2,500+ map lines).
    const auto kw_frida = OBF("frida");
    const auto kw_libfrida = OBF("libfrida");
    const auto kw_frida_gadget = OBF("frida-gadget");
    const auto kw_libgadget = OBF("libgadget.so");
    const auto kw_xposed = OBF("xposed");
    const auto kw_lsposed = OBF("lsposed");
    const auto kw_liblsposed = OBF("liblsposed");
    const auto kw_lspd = OBF("lspd");
    const auto kw_substrate = OBF("substrate");

    const std::string_view frida_needles[] = {
            kw_frida.view(), kw_libfrida.view(),
            kw_frida_gadget.view(), kw_libgadget.view()
    };

    std::string lower;
    lower.reserve(256);
    for (const auto &entry : maps) {
        const std::string &raw_path = entry.path;
        if (raw_path.empty()) {
            // Unnamed anonymous mapping: cannot contain path keywords; check anon r-x only.
            if (is_suspicious_executable_region(entry)) {
                add_finding(findings, OBF("anon_exec:") + entry.perms,
                            OBF("anon_exec"), OBF("/proc/self/maps"), entry.perms, "");
            }
            continue;
        }
        lower.resize(raw_path.size());
        for (size_t i = 0; i < raw_path.size(); ++i) {
            lower[i] = ascii_lower(raw_path[i]);
        }
        const std::string_view lower_sv(lower);

        if (contains_any_sv(lower_sv, frida_needles, 4)) {
            has_frida_family = true;
            if (lower_sv.find(kw_frida.view()) != std::string_view::npos
                || lower_sv.find(kw_libfrida.view()) != std::string_view::npos) {
                add_finding(findings,
                            OBF("maps:frida:") + raw_path,
                            OBF("frida_maps"), raw_path, entry.perms, OBF("frida"));
            }
            if (lower_sv.find(kw_frida_gadget.view()) != std::string_view::npos
                || lower_sv.find(kw_libgadget.view()) != std::string_view::npos) {
                add_finding(findings,
                            OBF("maps:gadget:") + raw_path,
                            OBF("frida_gadget_maps"), raw_path, entry.perms, OBF("frida"));
            }
        }
        if (lower_sv.find(kw_xposed.view()) != std::string_view::npos) {
            add_finding(findings,
                        OBF("maps:xposed:") + raw_path,
                        OBF("xposed_maps"), raw_path, entry.perms, OBF("xposed"));
        }
        if (lower_sv.find(kw_lsposed.view()) != std::string_view::npos
            || lower_sv.find(kw_liblsposed.view()) != std::string_view::npos
            || lower_sv.find(kw_lspd.view()) != std::string_view::npos) {
            add_finding(findings,
                        OBF("maps:lsposed:") + raw_path,
                        OBF("lsposed_maps"), raw_path, entry.perms, OBF("xposed"));
        }
        if (lower_sv.find(kw_substrate.view()) != std::string_view::npos) {
            add_finding(findings,
                        OBF("maps:substrate:") + raw_path,
                        OBF("substrate_maps"), raw_path, entry.perms, OBF("xposed"));
        }
    }

    // Full /proc/self/fd symlink scan (linjector, Frida FIFOs/sockets).
    scan_self_fds(findings, has_frida_family);

    // Extended thread scan: both /proc/self/task/*/comm AND /proc/self/task/*/status Name:.
    bool saw_gmain = false;
    RawDirResult tasks = raw_list_dir(OBF("/proc/self/task").c_str());
    if (tasks.ok()) {
        const auto task_prefix = OBF("/proc/self/task/");
        const auto comm_suffix = OBF("/comm");
        const auto status_suffix = OBF("/status");
        const auto kw_gum_loop = OBF("gum-js-loop");
        const auto kw_pool_frida = OBF("pool-frida");
        const auto kw_pool_spawner = OBF("pool-spawner");
        const auto kw_frida_helper = OBF("frida-helper");
        const auto kw_gdbus = OBF("gdbus");
        const auto kw_gmain = OBF("gmain");
        const auto kw_name_key = OBF("Name:");

        char comm_buf[64] = {};
        char status_buf[256] = {};
        char status_name[64] = {};
        for (const auto &tid : tasks.names) {
            if (!is_all_digits_str(tid)) continue;
            std::string base = std::string(task_prefix.c_str()) + tid;
            std::string comm_path = base + comm_suffix.c_str();
            int n_comm = read_file_content(comm_path.c_str(), comm_buf, sizeof(comm_buf));
            if (n_comm > 0) {
                to_lower_inplace(comm_buf, static_cast<size_t>(n_comm));
                classify_thread_name(
                        comm_buf, comm_path, findings, has_frida_family, saw_gmain,
                        kw_gum_loop.c_str(), kw_pool_frida.c_str(), kw_pool_spawner.c_str(),
                        kw_frida_helper.c_str(), kw_gdbus.c_str(),
                        kw_frida.c_str(), kw_gmain.c_str());
            }

            std::string status_path = base + status_suffix.c_str();
            int n_status = read_file_content(status_path.c_str(), status_buf, sizeof(status_buf));
            if (n_status > 0) {
                extract_status_name(status_buf, static_cast<size_t>(n_status),
                                    kw_name_key.c_str(), kw_name_key.size(),
                                    status_name, sizeof(status_name));
                size_t sname_len = my_strlen(status_name);
                if (sname_len > 0) {
                    to_lower_inplace(status_name, sname_len);
                    classify_thread_name(
                            status_name, status_path, findings, has_frida_family, saw_gmain,
                            kw_gum_loop.c_str(), kw_pool_frida.c_str(), kw_pool_spawner.c_str(),
                            kw_frida_helper.c_str(), kw_gdbus.c_str(),
                            kw_frida.c_str(), kw_gmain.c_str());
                }
            }
        }
    }
    if (saw_gmain && has_frida_family) {
        add_finding(findings, OBF("thread:gmain"), OBF("thread_gmain"),
                    OBF("/proc/self/task"), OBF("gmain"), "");
    }

    scan_unix_sockets(findings);
    scan_self_wx_segments(maps, findings);
    for (const auto &token : native_scan_memfd_private_elfs(maps)) {
        std::string label;
        auto colon = token.find(':');
        if (colon != std::string::npos) label = token.substr(colon + 1);
        add_finding(findings, token, OBF("memfd_private_elf"), label, token, OBF("hook_integrity"));
    }
    scan_anon_exec_elfs(maps, findings);
    scan_dl_iterate_phdr_diff(maps, findings);
    scan_sigaction_handlers(maps, findings);

    append_art_csv_tokens(native_get_art_hook_evidence(env, maps), findings);
    for (const auto &item : native_collect_integrity_findings(env, maps)) {
        add_finding(findings, item.token, item.code, item.location, item.value,
                    OBF("hook_integrity"));
    }
}

}  // namespace

std::vector<std::string> native_scan_memfd_private_elfs(const std::vector<MapEntry> &maps) {
    struct MemfdGroup {
        std::string label;
        bool has_priv_exec = false;
        bool has_priv_data = false;
        uintptr_t base_addr = 0;
    };

    const std::string memfd_prefix = OBF("/memfd:");
    std::map<uint64_t, MemfdGroup> groups;
    uint64_t synthetic_key = 1ull << 63;

    for (const auto &entry : maps) {
        if (entry.path.rfind(memfd_prefix, 0) != 0) continue;
        if (entry.perms.size() < 4) continue;
        if (entry.perms[3] != 'p') continue;

        uint64_t key = entry.inode != 0 ? entry.inode : (++synthetic_key);
        auto &group = groups[key];
        if (group.label.empty()) {
            group.label = sanitize_memfd_label(entry.path);
        }
        if (entry.perms[2] == 'x') {
            group.has_priv_exec = true;
        } else if (entry.perms[0] == 'r') {
            group.has_priv_data = true;
        }
        if (entry.offset == 0 && entry.perms[0] == 'r' && group.base_addr == 0) {
            group.base_addr = entry.start;
        }
    }

    std::vector<std::string> results;
    safe_mem::PipeMemoryReader mem;

    for (const auto &kv : groups) {
        const auto &group = kv.second;
        if (!group.has_priv_exec) continue;

        bool is_elf = group.base_addr != 0 && read_elf_magic_safe(mem, group.base_addr);
        if (is_elf || group.has_priv_data) {
            add_string_unique(results, OBF("memfd_private_elf:") + group.label);
        }
    }
    return results;
}

std::string native_get_hook_evidence(JNIEnv *env, const std::vector<MapEntry> &maps) {
    std::vector<HookFinding> findings;
    collect_hook_findings(env, maps, findings);

    payload_codec::PayloadBuilder payload(payload_codec::Status::OK, 0);
    payload.add_header("v", "2");
    for (const auto &f : findings) {
        payload_codec::RecordBuilder rec;
        rec.add("token", f.token);
        rec.add("code", f.code);
        rec.add("location", f.location);
        rec.add("value", f.value);
        if (!f.family.empty()) {
            rec.add("family", f.family);
        }
        payload.add_record(rec);
    }
    return payload.build();
}

std::string native_get_hook_evidence(JNIEnv *env) {
    auto maps = read_self_maps();
    return native_get_hook_evidence(env, maps);
}
