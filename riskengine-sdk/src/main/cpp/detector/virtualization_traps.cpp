#include "detector/virtualization_traps.h"

#include "collector/system_property_collector.h"
#include "util/disposable_child.h"
#include "util/maps_parser.h"
#include "util/mylibc.h"
#include "util/obf_str.h"
#include "util/payload_codec.h"
#include "util/syscall_wrapper.h"

#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <sched.h>
#include <string>
#include <string_view>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <vector>

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef STATX_BASIC_STATS
#define STATX_BASIC_STATS 0x000007ffU
#endif

namespace virtualization_traps {

namespace {

constexpr double kYieldCvCeiling = 0.03;
constexpr int64_t kYieldMeanCeilingNs = 250000LL;
constexpr size_t kYieldBucketCeiling = 2;
constexpr uint64_t kClockFreqMask = 0xffffffffULL;
constexpr int kSyscallAttempts = 3;

inline char ascii_lower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

int64_t monotonic_ns() noexcept {
    struct timespec ts {};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return static_cast<int64_t>(ts.tv_sec) * 1000000000LL + static_cast<int64_t>(ts.tv_nsec);
}

#if defined(__aarch64__)
inline uint64_t read_arm64_cntfrq() noexcept {
    uint64_t val = 0;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(val));
    return val;
}

inline uint64_t read_arm64_cntvct() noexcept {
    uint64_t val = 0;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(val) : : "memory");
    return val;
}
#endif

struct OpenHowCompat {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

struct StatxCompat {
    uint8_t raw[256];
};

bool is_unsupported_errno(int err) noexcept {
    return err == ENOSYS || err == EINVAL || err == EPERM;
}

struct SyscallCompareResult {
    uint8_t supported = 0;
    uint8_t mismatch_count = 0;
    int32_t last_libc_errno = 0;
    int32_t last_raw_errno = 0;
};

struct CoreSyscallPackReport {
    SyscallCompareResult statx_res {};
    SyscallCompareResult memfd_res {};
    SyscallCompareResult renameat2_res {};
};

struct ModernSyscallPackReport {
    SyscallCompareResult openat2_res {};
    SyscallCompareResult pidfd_res {};
};

struct SyscallPackContext {
    char statx_path[64];
    char rename_old[64];
    char rename_new[64];
    char openat2_path[64];
    char memfd_name[32];
};

// Async-signal-safe helper inside disposable_child: compares libc syscall() vs raw inline asm.
struct SingleCallOutcome {
    bool ok = false;
    int err = 0;
};

void record_pair(SyscallCompareResult &acc,
                 const SingleCallOutcome &libc_out,
                 const SingleCallOutcome &raw_out,
                 int &supported_attempts) noexcept {
    if (!libc_out.ok && !raw_out.ok
        && libc_out.err == raw_out.err
        && is_unsupported_errno(libc_out.err)) {
        return;
    }
    supported_attempts++;
    if (libc_out.ok != raw_out.ok || (!libc_out.ok && libc_out.err != raw_out.err)) {
        acc.mismatch_count++;
        acc.last_libc_errno = libc_out.ok ? 0 : libc_out.err;
        acc.last_raw_errno = raw_out.ok ? 0 : raw_out.err;
    }
}

int run_core_syscall_pack_child(const void *raw_ctx, int report_fd) {
    const auto *ctx = static_cast<const SyscallPackContext *>(raw_ctx);
    CoreSyscallPackReport report {};

    // 1. statx
#if defined(__NR_statx)
    {
        int sup = 0;
        for (int i = 0; i < kSyscallAttempts; ++i) {
            StatxCompat stx_a {};
            errno = 0;
            long lr = ::syscall(__NR_statx, AT_FDCWD, ctx->statx_path, 0, STATX_BASIC_STATS, &stx_a);
            SingleCallOutcome lo {lr >= 0, lr >= 0 ? 0 : errno};

            StatxCompat stx_b {};
            long rr = my_statx(AT_FDCWD, ctx->statx_path, 0, STATX_BASIC_STATS, &stx_b);
            SingleCallOutcome ro {rr >= 0, rr >= 0 ? 0 : raw_last_error()};
            record_pair(report.statx_res, lo, ro, sup);
        }
        report.statx_res.supported = sup > 0 ? 1 : 0;
    }
#endif

    // 2. memfd_create
#if defined(__NR_memfd_create)
    {
        int sup = 0;
        for (int i = 0; i < kSyscallAttempts; ++i) {
            errno = 0;
            long lr = ::syscall(__NR_memfd_create, ctx->memfd_name, MFD_CLOEXEC);
            int lerr = (lr >= 0) ? 0 : errno;
            if (lr >= 0) my_close(static_cast<int>(lr));
            SingleCallOutcome lo {lr >= 0, lerr};

            long rr = my_memfd_create(ctx->memfd_name, MFD_CLOEXEC);
            int rerr = (rr >= 0) ? 0 : raw_last_error();
            if (rr >= 0) my_close(static_cast<int>(rr));
            SingleCallOutcome ro {rr >= 0, rerr};
            record_pair(report.memfd_res, lo, ro, sup);
        }
        report.memfd_res.supported = sup > 0 ? 1 : 0;
    }
#endif

    // 3. renameat2
#if defined(__NR_renameat2)
    {
        int sup = 0;
        for (int i = 0; i < kSyscallAttempts; ++i) {
            errno = 0;
            long lr = ::syscall(__NR_renameat2, AT_FDCWD, ctx->rename_old,
                                AT_FDCWD, ctx->rename_new, 0);
            SingleCallOutcome lo {lr >= 0, lr >= 0 ? 0 : errno};

            long rr = my_renameat2(AT_FDCWD, ctx->rename_old, AT_FDCWD, ctx->rename_new, 0);
            SingleCallOutcome ro {rr >= 0, rr >= 0 ? 0 : raw_last_error()};
            record_pair(report.renameat2_res, lo, ro, sup);
        }
        report.renameat2_res.supported = sup > 0 ? 1 : 0;
    }
#endif

    return riskengine::util::write_child_report(report_fd, &report, sizeof(report)) ? 0 : 1;
}

int run_modern_syscall_pack_child(const void *raw_ctx, int report_fd) {
    const auto *ctx = static_cast<const SyscallPackContext *>(raw_ctx);
    ModernSyscallPackReport report {};

    // 4. openat2 (may trigger SIGSYS on Android 11 seccomp; isolated in its own disposable child)
#if defined(__NR_openat2)
    {
        int sup = 0;
        for (int i = 0; i < kSyscallAttempts; ++i) {
            OpenHowCompat how {};
            how.flags = static_cast<uint64_t>(O_RDONLY | O_CLOEXEC);
            errno = 0;
            long lr = ::syscall(__NR_openat2, AT_FDCWD, ctx->openat2_path, &how, sizeof(how));
            int lerr = (lr >= 0) ? 0 : errno;
            if (lr >= 0) my_close(static_cast<int>(lr));
            SingleCallOutcome lo {lr >= 0, lerr};

            long rr = my_openat2(AT_FDCWD, ctx->openat2_path, &how, sizeof(how));
            int rerr = (rr >= 0) ? 0 : raw_last_error();
            if (rr >= 0) my_close(static_cast<int>(rr));
            SingleCallOutcome ro {rr >= 0, rerr};
            record_pair(report.openat2_res, lo, ro, sup);
        }
        report.openat2_res.supported = sup > 0 ? 1 : 0;
    }
#endif

    // 5. pidfd_open
#if defined(__NR_pidfd_open)
    {
        int sup = 0;
        const pid_t self_pid = getpid();
        for (int i = 0; i < kSyscallAttempts; ++i) {
            errno = 0;
            long lr = ::syscall(__NR_pidfd_open, self_pid, 0);
            int lerr = (lr >= 0) ? 0 : errno;
            if (lr >= 0) my_close(static_cast<int>(lr));
            SingleCallOutcome lo {lr >= 0, lerr};

            long rr = my_pidfd_open(self_pid, 0);
            int rerr = (rr >= 0) ? 0 : raw_last_error();
            if (rr >= 0) my_close(static_cast<int>(rr));
            SingleCallOutcome ro {rr >= 0, rerr};
            record_pair(report.pidfd_res, lo, ro, sup);
        }
        report.pidfd_res.supported = sup > 0 ? 1 : 0;
    }
#endif

    return riskengine::util::write_child_report(report_fd, &report, sizeof(report)) ? 0 : 1;
}

struct TimingAndClockReport {
    int32_t yield_completed = 0;
    int32_t yield_suspicious = 0;
    double last_yield_cv = 0.0;
    int64_t last_yield_mean_ns = 0;
    int32_t clock_supported = 0;
    int32_t clock_completed = 0;
    int32_t clock_suspicious = 0;
    uint64_t last_freq = 0;
    uint64_t last_counter_ns = 0;
    int64_t last_wall_ns = 0;
};

int run_timing_and_clock_child(const void *, int report_fd) {
    TimingAndClockReport report {};

    // 1. sched_yield latency CV across 3 attempts x 32 samples (zero heap allocation).
    int64_t samples[32] = {};
    for (int attempt = 0; attempt < 3; ++attempt) {
        for (int i = 0; i < 32; ++i) {
            const int64_t t0 = monotonic_ns();
            sched_yield();
            const int64_t t1 = monotonic_ns();
            samples[i] = (t1 >= t0) ? (t1 - t0) : 0;
        }
        const YieldStats stats = evaluate_yield_samples(samples, 32);
        if (!stats.valid) {
            continue;
        }
        report.yield_completed++;
        report.last_yield_cv = stats.cv;
        report.last_yield_mean_ns = stats.mean_ns;
        if (stats.suspicious) {
            report.yield_suspicious++;
        }
    }

    // 2. ARM64 cntfrq_el0 / cntvct_el0 vs CLOCK_MONOTONIC overflow-safe clock drift.
#if defined(__aarch64__)
    report.clock_supported = 1;
    for (int attempt = 0; attempt < 3; ++attempt) {
        const uint64_t raw_freq = read_arm64_cntfrq();
        const uint64_t freq = raw_freq & kClockFreqMask;
        const int64_t wall_start = monotonic_ns();
        const uint64_t cnt_start = read_arm64_cntvct();
        for (int i = 0; i < 256; ++i) {
            (void) my_gettid();
        }
        const uint64_t cnt_end = read_arm64_cntvct();
        const int64_t wall_end = monotonic_ns();

        if (freq == 0ULL) {
            continue;
        }
        const uint64_t cnt_delta = (cnt_end > cnt_start) ? (cnt_end - cnt_start) : 0ULL;
        const int64_t wall_delta = (wall_end > wall_start) ? (wall_end - wall_start) : 0LL;
        uint64_t cnt_ns = 0;
        const bool drift = is_clock_drift_suspicious(cnt_delta, raw_freq, wall_delta, &cnt_ns);
        report.clock_completed++;
        report.last_freq = freq;
        report.last_counter_ns = cnt_ns;
        report.last_wall_ns = wall_delta;
        if (drift) {
            report.clock_suspicious++;
        }
    }
#endif

    return riskengine::util::write_child_report(report_fd, &report, sizeof(report)) ? 0 : 1;
}

void emit_syscall_mismatch(payload_codec::PayloadBuilder &pb,
                           const char *name,
                           const SyscallCompareResult &res) {
    if (res.supported != 0 && res.mismatch_count >= 2) {
        payload_codec::RecordBuilder rec;
        rec.add("kind", OBF("sacrificial_syscall_mismatch").c_str())
           .add("syscall", name)
           .add_int("mismatches", res.mismatch_count)
           .add_int("libc_errno", res.last_libc_errno)
           .add_int("raw_errno", res.last_raw_errno);
        pb.add_record(rec);
    }
}

void scan_native_bridge_fast(payload_codec::PayloadBuilder &pb, int &bridge_hits) {
    // 1. ro.dalvik.vm.native.bridge property
    const std::string nb_prop = get_system_property(OBF("ro.dalvik.vm.native.bridge").c_str());
    if (!nb_prop.empty() && nb_prop != "0") {
        bridge_hits++;
        payload_codec::RecordBuilder rec;
        rec.add("kind", OBF("native_bridge_prop").c_str())
           .add("value", nb_prop);
        pb.add_record(rec);
    }

    // 2. /proc/self/maps scan for binary translation libraries
    const auto kw_libhoudini = OBF("libhoudini.so");
    const auto kw_libnb = OBF("libnb.so");
    const auto kw_libndk_trans = OBF("libndk_translation.so");
    const auto kw_houdini_bin = OBF("/houdini");
    std::string matched_map;
    std::string lower;
    lower.reserve(256);
    for_each_self_map([&](const MapEntry &entry) -> bool {
        if (entry.path.empty()) return true;
        lower.resize(entry.path.size());
        for (size_t i = 0; i < entry.path.size(); ++i) {
            lower[i] = ascii_lower(entry.path[i]);
        }
        const std::string_view sv(lower);
        if (sv.find(kw_libhoudini.view()) != std::string_view::npos
            || sv.find(kw_libnb.view()) != std::string_view::npos
            || sv.find(kw_libndk_trans.view()) != std::string_view::npos
            || sv.find(kw_houdini_bin.view()) != std::string_view::npos) {
            matched_map = entry.path;
            return false;
        }
        return true;
    });
    if (!matched_map.empty()) {
        bridge_hits++;
        payload_codec::RecordBuilder rec;
        rec.add("kind", OBF("native_bridge_maps").c_str())
           .add("path", matched_map);
        pb.add_record(rec);
    }

    // 3. /proc/self/cmdline scan for -Xnative-bridge
    std::string cmdline = read_file_string(OBF("/proc/self/cmdline").c_str(), 16384);
    if (!cmdline.empty()) {
        for (char &c : cmdline) {
            if (c == '\0') c = ' ';
        }
        const auto kw_xnb = OBF("-Xnative-bridge");
        if (cmdline.find(kw_xnb.view()) != std::string::npos) {
            bridge_hits++;
            payload_codec::RecordBuilder rec;
            rec.add("kind", OBF("native_bridge_cmdline").c_str())
               .add("marker", kw_xnb.c_str());
            pb.add_record(rec);
        }
    }

    // 4. Raw faccessat checks for Native Bridge binaries & libraries (all OBF-protected).
    auto check_nb_file = [&](const auto &obf_path) {
        if (my_faccessat(AT_FDCWD, obf_path.c_str(), F_OK, 0) == 0) {
            bridge_hits++;
            payload_codec::RecordBuilder rec;
            rec.add("kind", OBF("native_bridge_file").c_str())
               .add("path", obf_path.c_str());
            pb.add_record(rec);
        }
    };
    check_nb_file(OBF("/system/bin/houdini"));
    check_nb_file(OBF("/system/bin/houdini64"));
    check_nb_file(OBF("/system/lib/libhoudini.so"));
    check_nb_file(OBF("/system/lib64/libhoudini.so"));
    check_nb_file(OBF("/system/lib/libnb.so"));
    check_nb_file(OBF("/system/lib64/libnb.so"));
    check_nb_file(OBF("/system/lib/libndk_translation.so"));
    check_nb_file(OBF("/system/lib64/libndk_translation.so"));
}

}  // namespace

YieldStats evaluate_yield_samples(const int64_t *samples, size_t count) noexcept {
    YieldStats out;
    if (samples == nullptr || count == 0) {
        return out;
    }
    double sum = 0.0;
    for (size_t i = 0; i < count; ++i) {
        if (samples[i] > 0) {
            sum += static_cast<double>(samples[i]);
        }
    }
    const double mean = sum / static_cast<double>(count);
    if (mean <= 0.0) {
        return out;
    }
    double var = 0.0;
    int64_t unique_buckets[64] = {};
    size_t bucket_count = 0;
    for (size_t i = 0; i < count; ++i) {
        const double val = samples[i] > 0 ? static_cast<double>(samples[i]) : 0.0;
        const double diff = val - mean;
        var += diff * diff;

        const int64_t us_bucket = (samples[i] > 0 ? samples[i] : 0) / 1000LL;
        bool seen = false;
        for (size_t b = 0; b < bucket_count; ++b) {
            if (unique_buckets[b] == us_bucket) {
                seen = true;
                break;
            }
        }
        if (!seen && bucket_count < 64) {
            unique_buckets[bucket_count++] = us_bucket;
        }
    }
    var /= static_cast<double>(count);
    out.valid = true;
    out.mean_ns = static_cast<int64_t>(mean);
    out.cv = std::sqrt(var) / mean;
    out.unique_us_buckets = bucket_count;
    out.suspicious = (bucket_count <= kYieldBucketCeiling)
            && (out.cv < kYieldCvCeiling)
            && (out.mean_ns < kYieldMeanCeilingNs);
    return out;
}

uint64_t compute_counter_ns_safe(uint64_t counter_delta, uint64_t raw_freq) noexcept {
    const uint64_t freq = raw_freq & kClockFreqMask;
    if (freq == 0ULL) {
        return 0ULL;
    }
    // Split into whole seconds + remainder so counter_delta * 1e9 never overflows uint64_t.
    const uint64_t delta_sec = counter_delta / freq;
    const uint64_t delta_rem = counter_delta % freq;
    constexpr uint64_t kNsPerSec = 1000000000ULL;
    if (delta_sec > (UINT64_MAX / kNsPerSec) - 1ULL) {
        return UINT64_MAX;
    }
    return delta_sec * kNsPerSec + (delta_rem * kNsPerSec) / freq;
}

bool is_clock_drift_suspicious(uint64_t counter_delta,
                               uint64_t raw_freq,
                               int64_t wall_delta_ns,
                               uint64_t *out_counter_ns) noexcept {
    const uint64_t freq = raw_freq & kClockFreqMask;
    if (freq == 0ULL) {
        if (out_counter_ns != nullptr) *out_counter_ns = 0ULL;
        return false;
    }
    const uint64_t cnt_ns = compute_counter_ns_safe(counter_delta, freq);
    if (out_counter_ns != nullptr) {
        *out_counter_ns = cnt_ns;
    }
    if (counter_delta == 0ULL) {
        return true;
    }
    if (wall_delta_ns <= 0LL) {
        return false;
    }
    const uint64_t wall_u = static_cast<uint64_t>(wall_delta_ns);
    const uint64_t diff = (cnt_ns >= wall_u) ? (cnt_ns - wall_u) : (wall_u - cnt_ns);
    // Gross mismatch threshold: > 75% divergence between firmware CNTFRQ scaling and CLOCK_MONOTONIC.
    return diff > ((wall_u / 4ULL) * 3ULL + ((wall_u % 4ULL) * 3ULL) / 4ULL);
}

}  // namespace virtualization_traps

std::string native_get_virtualization_traps(bool include_postponed_traps) {
    using namespace virtualization_traps;

    payload_codec::PayloadBuilder pb(payload_codec::Status::OK, 0);
    int bridge_hits = 0;
    scan_native_bridge_fast(pb, bridge_hits);

    int syscall_pack_ran = 0;
    int seccomp_trapped = 0;
    int timing_ran = 0;
    int clock_ran = 0;

    if (include_postponed_traps) {
        SyscallPackContext ctx {};
        my_strlcpy(ctx.statx_path, OBF("/proc/self/re_virt_statx_missing").c_str(), sizeof(ctx.statx_path));
        my_strlcpy(ctx.rename_old, OBF("/proc/self/re_virt_rename_old").c_str(), sizeof(ctx.rename_old));
        my_strlcpy(ctx.rename_new, OBF("/proc/self/re_virt_rename_new").c_str(), sizeof(ctx.rename_new));
        my_strlcpy(ctx.openat2_path, OBF("/proc/self/re_virt_openat2_missing").c_str(), sizeof(ctx.openat2_path));
        my_strlcpy(ctx.memfd_name, OBF("re_virt_mfd").c_str(), sizeof(ctx.memfd_name));

        riskengine::util::ChildDeadlines deadlines;
        deadlines.run = std::chrono::milliseconds(1000);
        deadlines.reap = std::chrono::milliseconds(250);

        // Child 1A: Core sacrificial syscall pack (statx, memfd_create, renameat2).
        CoreSyscallPackReport core_rep {};
        const auto core_out = riskengine::util::run_disposable_child(
                reinterpret_cast<uint8_t *>(&core_rep), sizeof(core_rep), deadlines,
                &run_core_syscall_pack_child, &ctx);
        if (core_out.end == riskengine::util::ChildEnd::kExited
            && core_out.exit_status == 0
            && core_out.report_length == sizeof(core_rep)) {
            syscall_pack_ran = 1;
            emit_syscall_mismatch(pb, OBF("statx").c_str(), core_rep.statx_res);
            emit_syscall_mismatch(pb, OBF("memfd_create").c_str(), core_rep.memfd_res);
            emit_syscall_mismatch(pb, OBF("renameat2").c_str(), core_rep.renameat2_res);
        } else if (core_out.end == riskengine::util::ChildEnd::kSeccompTrapped) {
            seccomp_trapped = 1;
        }

        // Child 1B: Modern syscalls (openat2, pidfd_open); isolated so Android 11 seccomp
        // SIGSYS never disrupts Child 1A or the host process.
        ModernSyscallPackReport mod_rep {};
        const auto mod_out = riskengine::util::run_disposable_child(
                reinterpret_cast<uint8_t *>(&mod_rep), sizeof(mod_rep), deadlines,
                &run_modern_syscall_pack_child, &ctx);
        if (mod_out.end == riskengine::util::ChildEnd::kExited
            && mod_out.exit_status == 0
            && mod_out.report_length == sizeof(mod_rep)) {
            syscall_pack_ran = 1;
            emit_syscall_mismatch(pb, OBF("openat2").c_str(), mod_rep.openat2_res);
            emit_syscall_mismatch(pb, OBF("pidfd_open").c_str(), mod_rep.pidfd_res);
        } else if (mod_out.end == riskengine::util::ChildEnd::kSeccompTrapped) {
            seccomp_trapped = 1;
        }

        // Child 2: sched_yield CV + ARM64 cntfrq_el0/cntvct_el0 vs CLOCK_MONOTONIC drift.
        TimingAndClockReport tc_rep {};
        const auto tc_out = riskengine::util::run_disposable_child(
                reinterpret_cast<uint8_t *>(&tc_rep), sizeof(tc_rep), deadlines,
                &run_timing_and_clock_child, nullptr);
        if (tc_out.end == riskengine::util::ChildEnd::kExited
            && tc_out.exit_status == 0
            && tc_out.report_length == sizeof(tc_rep)) {
            if (tc_rep.yield_completed >= 2) {
                timing_ran = 1;
                if (tc_rep.yield_suspicious >= 2) {
                    char cv_buf[32] = {};
                    std::snprintf(cv_buf, sizeof(cv_buf), "%.4f", tc_rep.last_yield_cv);
                    payload_codec::RecordBuilder rec;
                    rec.add("kind", OBF("sched_yield_low_cv").c_str())
                       .add("cv", cv_buf)
                       .add_int("mean_ns", tc_rep.last_yield_mean_ns)
                       .add_int("suspicious", tc_rep.yield_suspicious)
                       .add("severity", "INFO");
                    pb.add_record(rec);
                }
            }
            if (tc_rep.clock_supported != 0 && tc_rep.clock_completed >= 2) {
                clock_ran = 1;
                if (tc_rep.clock_suspicious >= 2) {
                    payload_codec::RecordBuilder rec;
                    rec.add("kind", OBF("arm64_clock_drift").c_str())
                       .add_uint("freq", tc_rep.last_freq)
                       .add_uint("counter_ns", tc_rep.last_counter_ns)
                       .add_int("wall_ns", tc_rep.last_wall_ns)
                       .add_int("suspicious", tc_rep.clock_suspicious);
                    pb.add_record(rec);
                }
            }
        }
    }

    pb.add_header_int("postponed", include_postponed_traps ? 1 : 0);
    pb.add_header_int("native_bridge_hits", bridge_hits);
    pb.add_header_int("syscall_pack_ran", syscall_pack_ran);
    pb.add_header_int("seccomp_trapped", seccomp_trapped);
    pb.add_header_int("timing_ran", timing_ran);
    pb.add_header_int("clock_ran", clock_ran);
    return pb.build();
}
