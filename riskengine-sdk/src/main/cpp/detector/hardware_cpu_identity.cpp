#include "detector/hardware_cpu_identity.h"

#include "util/disposable_child.h"
#include "util/mylibc.h"
#include "util/obf_str.h"
#include "util/payload_codec.h"
#include "util/syscall_wrapper.h"

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <new>
#include <sched.h>
#include <string>
#include <string_view>
#include <sys/utsname.h>
#include <vector>

#if defined(__aarch64__) && defined(__linux__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#ifndef HWCAP_CPUID
#define HWCAP_CPUID (1UL << 11)
#endif
#endif

#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

namespace riskengine {
namespace cpu_identity {

namespace {

std::string_view trim_view(std::string_view sv) noexcept {
    std::size_t start = 0;
    while (start < sv.size() && my_is_space(static_cast<unsigned char>(sv[start]))) {
        start++;
    }
    std::size_t end = sv.size();
    while (end > start && my_is_space(static_cast<unsigned char>(sv[end - 1]))) {
        end--;
    }
    return sv.substr(start, end - start);
}

bool parse_u32_auto(std::string_view raw, uint32_t *out) noexcept {
    if (out == nullptr) {
        return false;
    }
    std::string_view trimmed = trim_view(raw);
    if (trimmed.empty() || trimmed.size() > 32) {
        return false;
    }
    char buf[40] = {};
    my_memcpy(buf, trimmed.data(), trimmed.size());
    buf[trimmed.size()] = '\0';

    if (trimmed.size() >= 2 && buf[0] == '0' && (buf[1] == 'x' || buf[1] == 'X')) {
        uint64_t val = 0;
        if (!my_hex_parse(buf, &val) || val > UINT32_MAX) {
            return false;
        }
        *out = static_cast<uint32_t>(val);
        return true;
    }

    uint64_t acc = 0;
    for (std::size_t i = 0; i < trimmed.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(buf[i]);
        if (!my_is_digit(c)) {
            return false;
        }
        acc = acc * 10ULL + static_cast<uint64_t>(c - '0');
        if (acc > UINT32_MAX) {
            return false;
        }
    }
    *out = static_cast<uint32_t>(acc);
    return true;
}

std::string format_hex32(uint32_t value) {
    char buf[16] = {};
    std::snprintf(buf, sizeof(buf), "0x%08x", value);
    return std::string(buf);
}

struct ProcCpuBlock {
    int cpu = -1;
    bool has_impl = false;
    bool has_var = false;
    bool has_part = false;
    bool has_rev = false;
    uint32_t impl = 0;
    uint32_t var = 0;
    uint32_t part = 0;
    uint32_t rev = 0;

    bool to_midr(uint32_t *out) const noexcept {
        if (!has_impl || !has_var || !has_part || !has_rev || out == nullptr) {
            return false;
        }
        if (impl > 0xffU || var > 0xfU || part > 0xfffU || rev > 0xfU) {
            return false;
        }
        *out = (impl << 24U) | (var << 20U) | (part << 4U) | rev;
        return true;
    }
};

#if defined(__aarch64__) && defined(__linux__)

struct ChildCpuProbeInput {
    int count = 0;
    int cpus[kMaxProbeCpus] = {};
};

struct ChildCpuProbeEntry {
    int cpu = -1;
    uint32_t mrs_midr = 0;
    uint8_t mrs_state = static_cast<uint8_t>(MrsReadState::kNotAttempted);
    uint8_t reserved[3] = {};
    uint32_t off_cpu_retries = 0;
};

struct ChildCpuProbeOutput {
    int count = 0;
    ChildCpuProbeEntry entries[kMaxProbeCpus] = {};
};

inline bool is_running_on_cpu(int cpu) noexcept {
    unsigned current = 0;
    return my_getcpu(&current, nullptr) == 0 && current == static_cast<unsigned>(cpu);
}

int child_read_midr_body(const void *ctx, int report_fd) {
    const auto *input = static_cast<const ChildCpuProbeInput *>(ctx);
    if (input == nullptr || input->count <= 0 || input->count > kMaxProbeCpus) {
        return 1;
    }

    ChildCpuProbeOutput out = {};
    out.count = input->count;

    for (int i = 0; i < input->count; ++i) {
        int cpu = input->cpus[i];
        ChildCpuProbeEntry &entry = out.entries[i];
        entry.cpu = cpu;
        entry.mrs_state = static_cast<uint8_t>(MrsReadState::kNotAttempted);

        if (cpu < 0 || cpu >= CPU_SETSIZE) {
            entry.mrs_state = static_cast<uint8_t>(MrsReadState::kUnattributed);
            continue;
        }

        cpu_set_t target = {};
        CPU_ZERO(&target);
        CPU_SET(cpu, &target);
        if (sched_setaffinity(0, sizeof(target), &target) != 0) {
            entry.mrs_state = static_cast<uint8_t>(MrsReadState::kUnattributed);
            continue;
        }

        uint32_t agreed_midr = 0;
        int agreeing_reads = 0;
        bool unstable = false;

        for (int attempt = 0;
             attempt < kMaxReadsPerCpu && agreeing_reads < kAgreeingReadsRequired;
             ++attempt) {
            const bool started_on = is_running_on_cpu(cpu);
            uint64_t raw_val = 0;
            __asm__ volatile("mrs %0, MIDR_EL1" : "=r"(raw_val));
            const bool ended_on = is_running_on_cpu(cpu);

            if (!started_on || !ended_on) {
                entry.off_cpu_retries++;
                if (sched_setaffinity(0, sizeof(target), &target) != 0) {
                    break;
                }
                continue;
            }

            const uint32_t midr32 = static_cast<uint32_t>(raw_val & 0xffffffffULL);
            if (agreeing_reads > 0 && agreed_midr != midr32) {
                unstable = true;
                break;
            }
            agreed_midr = midr32;
            agreeing_reads++;
        }

        if (unstable) {
            entry.mrs_state = static_cast<uint8_t>(MrsReadState::kUnstable);
        } else if (agreeing_reads == kAgreeingReadsRequired) {
            entry.mrs_midr = agreed_midr;
            entry.mrs_state = static_cast<uint8_t>(MrsReadState::kVerified);
        } else {
            entry.mrs_state = static_cast<uint8_t>(MrsReadState::kUnattributed);
        }
    }

    if (!riskengine::util::write_child_report(report_fd, &out, sizeof(out))) {
        return 2;
    }
    return 0;
}

#endif  // defined(__aarch64__) && defined(__linux__)

}  // namespace

bool parse_sysfs_midr(std::string_view raw, uint32_t *out) noexcept {
    if (out == nullptr) {
        return false;
    }
    std::string_view trimmed = trim_view(raw);
    if (trimmed.empty() || trimmed.size() > 32) {
        return false;
    }
    char buf[40] = {};
    my_memcpy(buf, trimmed.data(), trimmed.size());
    buf[trimmed.size()] = '\0';

    uint64_t parsed = 0;
    if (!my_hex_parse(buf, &parsed) || parsed > UINT32_MAX) {
        return false;
    }
    *out = static_cast<uint32_t>(parsed);
    return true;
}

bool parse_proc_cpuinfo_midr(std::string_view cpuinfo, int target_cpu, uint32_t *out) noexcept {
    if (target_cpu < 0 || out == nullptr || cpuinfo.empty()) {
        return false;
    }

    ProcCpuBlock block = {};
    std::size_t pos = 0;
    while (pos <= cpuinfo.size()) {
        std::size_t nl = cpuinfo.find('\n', pos);
        std::string_view line = (nl == std::string_view::npos)
                ? cpuinfo.substr(pos)
                : cpuinfo.substr(pos, nl - pos);
        std::string_view trimmed = trim_view(line);

        if (trimmed.empty()) {
            if (block.cpu == target_cpu && block.to_midr(out)) {
                return true;
            }
            block = ProcCpuBlock{};
        } else {
            std::size_t colon = trimmed.find(':');
            if (colon != std::string_view::npos) {
                std::string_view key = trim_view(trimmed.substr(0, colon));
                std::string_view val = trim_view(trimmed.substr(colon + 1));
                uint32_t parsed = 0;
                if (key == "processor") {
                    if (block.cpu == target_cpu && block.to_midr(out)) {
                        return true;
                    }
                    block = ProcCpuBlock{};
                    if (parse_u32_auto(val, &parsed)) {
                        block.cpu = static_cast<int>(parsed);
                    }
                } else if (block.cpu == target_cpu) {
                    if (key == "CPU implementer" && parse_u32_auto(val, &parsed)) {
                        block.has_impl = true;
                        block.impl = parsed;
                    } else if (key == "CPU variant" && parse_u32_auto(val, &parsed)) {
                        block.has_var = true;
                        block.var = parsed;
                    } else if (key == "CPU part" && parse_u32_auto(val, &parsed)) {
                        block.has_part = true;
                        block.part = parsed;
                    } else if (key == "CPU revision" && parse_u32_auto(val, &parsed)) {
                        block.has_rev = true;
                        block.rev = parsed;
                    }
                }
            }
        }

        if (nl == std::string_view::npos) {
            break;
        }
        pos = nl + 1;
    }

    return block.cpu == target_cpu && block.to_midr(out);
}

std::string encode_cpu_identity_observations(const std::vector<CpuMidrObservation> &observations,
                                             bool cpuid_emulation_available) {
    payload_codec::PayloadBuilder payload(payload_codec::Status::OK, 0);
    int verified_cores = 0;
    int cached_cores = 0;

    for (const CpuMidrObservation &obs : observations) {
        if (obs.has_sysfs || obs.has_cpuinfo) {
            cached_cores++;
        }
        const bool mrs_ok = obs.has_mrs && obs.mrs_state == MrsReadState::kVerified;
        if (mrs_ok) {
            verified_cores++;
        }

        if (mrs_ok && obs.has_sysfs && !midr_matches_masked(obs.mrs_midr, obs.sysfs_midr)) {
            payload_codec::RecordBuilder rec;
            rec.add("kind", "midr_sysfs_mismatch")
               .add_int("cpu", obs.cpu)
               .add("mrs", format_hex32(obs.mrs_midr))
               .add("sysfs", format_hex32(obs.sysfs_midr));
            payload.add_record(rec);
        }
        if (mrs_ok && obs.has_cpuinfo && !midr_matches_masked(obs.mrs_midr, obs.cpuinfo_midr)) {
            payload_codec::RecordBuilder rec;
            rec.add("kind", "midr_cpuinfo_mismatch")
               .add_int("cpu", obs.cpu)
               .add("mrs", format_hex32(obs.mrs_midr))
               .add("cpuinfo", format_hex32(obs.cpuinfo_midr));
            payload.add_record(rec);
        }
        if (obs.has_sysfs && obs.has_cpuinfo
                && !midr_matches_masked(obs.sysfs_midr, obs.cpuinfo_midr)) {
            payload_codec::RecordBuilder rec;
            rec.add("kind", "sysfs_cpuinfo_mismatch")
               .add_int("cpu", obs.cpu)
               .add("sysfs", format_hex32(obs.sysfs_midr))
               .add("cpuinfo", format_hex32(obs.cpuinfo_midr));
            payload.add_record(rec);
        }
    }

    payload.add_header_int("cores_checked", static_cast<int64_t>(observations.size()));
    payload.add_header_int("verified_cores", verified_cores);
    payload.add_header_int("cached_cores", cached_cores);
    payload.add_header("cpuid_emulation", cpuid_emulation_available ? "1" : "0");
    return payload.build();
}

}  // namespace cpu_identity
}  // namespace riskengine

std::string native_get_hardware_cpu_identity() {
#if defined(__aarch64__) && defined(__linux__)
    using namespace riskengine::cpu_identity;

    cpu_set_t affinity = {};
    CPU_ZERO(&affinity);
    if (sched_getaffinity(0, sizeof(affinity), &affinity) != 0) {
        payload_codec::PayloadBuilder err(payload_codec::Status::RESTRICTED, errno);
        err.add_header("reason", "affinity_unavailable");
        return err.build();
    }

    const bool cpuid_available = (getauxval(AT_HWCAP) & HWCAP_CPUID) != 0;

    ChildCpuProbeInput child_input = {};
    for (int cpu = 0; cpu < CPU_SETSIZE && child_input.count < kMaxProbeCpus; ++cpu) {
        if (CPU_ISSET(cpu, &affinity)) {
            child_input.cpus[child_input.count++] = cpu;
        }
    }

    if (child_input.count == 0) {
        payload_codec::PayloadBuilder err(payload_codec::Status::RESTRICTED, 0);
        err.add_header("reason", "no_online_cpus");
        return err.build();
    }

    const auto cpuinfo_path = OBF("/proc/cpuinfo");
    const std::string cpuinfo = read_file_string(cpuinfo_path.c_str(), 256 * 1024);
    const auto sysfs_prefix = OBF("/sys/devices/system/cpu/cpu");
    const auto sysfs_suffix = OBF("/regs/identification/midr_el1");

    std::vector<CpuMidrObservation> observations;
    observations.reserve(static_cast<std::size_t>(child_input.count));
    for (int i = 0; i < child_input.count; ++i) {
        CpuMidrObservation obs = {};
        obs.cpu = child_input.cpus[i];

        std::string sysfs_path = std::string(sysfs_prefix.c_str())
                + std::to_string(obs.cpu) + sysfs_suffix.c_str();
        std::string sysfs_raw = read_file_string(sysfs_path.c_str(), 128);
        if (!sysfs_raw.empty()) {
            uint32_t midr = 0;
            if (parse_sysfs_midr(sysfs_raw, &midr)) {
                obs.has_sysfs = true;
                obs.sysfs_midr = midr;
            }
        }
        if (!cpuinfo.empty()) {
            uint32_t midr = 0;
            if (parse_proc_cpuinfo_midr(cpuinfo, obs.cpu, &midr)) {
                obs.has_cpuinfo = true;
                obs.cpuinfo_midr = midr;
            }
        }
        observations.push_back(obs);
    }

    if (cpuid_available) {
        ChildCpuProbeOutput child_out = {};
        riskengine::util::ChildDeadlines deadlines;
        deadlines.run = std::chrono::milliseconds(1000);
        deadlines.reap = std::chrono::milliseconds(250);

        riskengine::util::ChildOutcome outcome = riskengine::util::run_disposable_child(
                reinterpret_cast<uint8_t *>(&child_out),
                sizeof(child_out),
                deadlines,
                &child_read_midr_body,
                &child_input);

        if (outcome.end == riskengine::util::ChildEnd::kSignaled && outcome.signal == SIGILL) {
            // Kernel advertised HWCAP_CPUID yet trapped MRS MIDR_EL1 with SIGILL;
            // report cleanly without crashing parent and still preserve sysfs/cpuinfo checks.
            for (auto &obs : observations) {
                obs.mrs_state = MrsReadState::kFaulted;
            }
        } else if (outcome.end == riskengine::util::ChildEnd::kExited
                && outcome.exit_status == 0
                && outcome.report_length == sizeof(child_out)
                && child_out.count == child_input.count) {
            for (int i = 0; i < child_out.count; ++i) {
                const ChildCpuProbeEntry &ce = child_out.entries[i];
                if (ce.cpu == observations[static_cast<std::size_t>(i)].cpu) {
                    observations[static_cast<std::size_t>(i)].mrs_state =
                            static_cast<MrsReadState>(ce.mrs_state);
                    observations[static_cast<std::size_t>(i)].off_cpu_retries = ce.off_cpu_retries;
                    if (observations[static_cast<std::size_t>(i)].mrs_state
                            == MrsReadState::kVerified) {
                        observations[static_cast<std::size_t>(i)].has_mrs = true;
                        observations[static_cast<std::size_t>(i)].mrs_midr = ce.mrs_midr;
                    }
                }
            }
        }
    }

    return encode_cpu_identity_observations(observations, cpuid_available);
#else
    payload_codec::PayloadBuilder unsup(payload_codec::Status::UNSUPPORTED, 0);
    unsup.add_header("reason", "non_arm64");
    return unsup.build();
#endif
}

std::string native_get_kernel_consistency() {
    auto trim_str = [](const std::string &s) -> std::string {
        std::size_t start = 0;
        while (start < s.size() && my_is_space(static_cast<unsigned char>(s[start]))) {
            start++;
        }
        std::size_t end = s.size();
        while (end > start && my_is_space(static_cast<unsigned char>(s[end - 1]))) {
            end--;
        }
        return s.substr(start, end - start);
    };

    struct utsname uts = {};
    const bool has_uname = (my_uname(&uts) == 0);
    const std::string uname_release = has_uname ? trim_str(std::string(uts.release)) : "";
    const std::string uname_version = has_uname ? trim_str(std::string(uts.version)) : "";

    const auto p_osrelease = OBF("/proc/sys/kernel/osrelease");
    const auto p_kversion = OBF("/proc/sys/kernel/version");
    const auto p_version = OBF("/proc/version");

    const std::string proc_osrelease = trim_str(read_file_string(p_osrelease.c_str(), 1024));
    const std::string proc_kversion = trim_str(read_file_string(p_kversion.c_str(), 1024));
    const std::string proc_version = trim_str(read_file_string(p_version.c_str(), 2048));

    if (uname_release.empty() && proc_osrelease.empty()
            && proc_kversion.empty() && proc_version.empty()) {
        payload_codec::PayloadBuilder err(payload_codec::Status::RESTRICTED, raw_last_error());
        err.add_header("reason", "kernel_sources_unavailable");
        return err.build();
    }

    payload_codec::PayloadBuilder payload(payload_codec::Status::OK, 0);
    if (!uname_release.empty()) {
        payload.add_header("uname_release", uname_release);
    }
    if (!uname_version.empty()) {
        payload.add_header("uname_version", uname_version);
    }
    if (!proc_osrelease.empty()) {
        payload.add_header("proc_osrelease", proc_osrelease);
    }
    if (!proc_kversion.empty()) {
        payload.add_header("proc_kversion", proc_kversion);
    }
    if (!proc_version.empty()) {
        payload.add_header("proc_version", proc_version);
    }
    return payload.build();
}

std::string native_get_pif_properties() {
#if defined(__ANDROID__)
    struct PifPropHit {
        std::string key;
        std::string value;
    };
    struct CollectCtx {
        std::vector<PifPropHit> hits;
        int scanned = 0;
        std::string p1;
        std::string p2;
        std::string p3;
    };

    CollectCtx ctx;
    const auto pref1 = OBF("persist.sys.pihooks");
    const auto pref2 = OBF("persist.sys.pixelprops");
    const auto pref3 = OBF("persist.sys.spoof.gms");
    ctx.p1 = pref1.c_str();
    ctx.p2 = pref2.c_str();
    ctx.p3 = pref3.c_str();

    auto matches_pif_prefix = [](const char *name, const CollectCtx &c) -> bool {
        if (name == nullptr) {
            return false;
        }
        return my_strncmp(name, c.p1.c_str(), c.p1.size()) == 0
                || my_strncmp(name, c.p2.c_str(), c.p2.size()) == 0
                || my_strncmp(name, c.p3.c_str(), c.p3.size()) == 0;
    };

    auto add_hit = [](CollectCtx *c, const char *name, const char *val) {
        if (c == nullptr || name == nullptr || val == nullptr || val[0] == '\0') {
            return;
        }
        if (c->hits.size() >= 64) {
            return;
        }
        for (const auto &existing : c->hits) {
            if (existing.key == name) {
                return;
            }
        }
        c->hits.push_back({std::string(name), std::string(val)});
    };

    __system_property_foreach(
            [](const prop_info *pi, void *cookie) {
                if (pi == nullptr || cookie == nullptr) {
                    return;
                }
                __system_property_read_callback(
                        pi,
                        [](void *cb_cookie, const char *name, const char *value, uint32_t) {
                            auto *c = static_cast<CollectCtx *>(cb_cookie);
                            if (c == nullptr || name == nullptr) {
                                return;
                            }
                            c->scanned++;
                            if (my_strncmp(name, c->p1.c_str(), c->p1.size()) == 0
                                    || my_strncmp(name, c->p2.c_str(), c->p2.size()) == 0
                                    || my_strncmp(name, c->p3.c_str(), c->p3.size()) == 0) {
                                if (value != nullptr && value[0] != '\0' && c->hits.size() < 64) {
                                    bool dup = false;
                                    for (const auto &existing : c->hits) {
                                        if (existing.key == name) {
                                            dup = true;
                                            break;
                                        }
                                    }
                                    if (!dup) {
                                        c->hits.push_back({std::string(name), std::string(value)});
                                    }
                                }
                            }
                        },
                        cookie);
            },
            &ctx);

    // Explicit direct lookups for canonical PIF/PixelProps keys in case foreach skipped an area.
    const auto k1 = OBF("persist.sys.pihooks.enable");
    const auto k2 = OBF("persist.sys.pihooks.disable.gms_props");
    const auto k3 = OBF("persist.sys.pihooks.disable.gms_key_attestation_block");
    const auto k4 = OBF("persist.sys.pixelprops.gms");
    const auto k5 = OBF("persist.sys.pixelprops.pi");
    const auto k6 = OBF("persist.sys.spoof.gms");
    const char *canonical_keys[] = {
            k1.c_str(), k2.c_str(), k3.c_str(), k4.c_str(), k5.c_str(), k6.c_str()
    };
    for (const char *key : canonical_keys) {
        if (!matches_pif_prefix(key, ctx)) {
            continue;
        }
        char val[PROP_VALUE_MAX] = {};
        if (__system_property_get(key, val) > 0) {
            add_hit(&ctx, key, val);
        }
    }

    payload_codec::PayloadBuilder payload(payload_codec::Status::OK, 0);
    payload.add_header_int("props_scanned", ctx.scanned);
    payload.add_header_int("hits", static_cast<int64_t>(ctx.hits.size()));
    for (const auto &hit : ctx.hits) {
        payload_codec::RecordBuilder rec;
        rec.add("kind", "pif_prop")
           .add("key", hit.key)
           .add("value", hit.value);
        payload.add_record(rec);
    }
    return payload.build();
#else
    payload_codec::PayloadBuilder unsup(payload_codec::Status::UNSUPPORTED, 0);
    unsup.add_header("reason", "non_android");
    return unsup.build();
#endif
}
