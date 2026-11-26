#include "detector/kernel_sidechannel.h"

#include "util/disposable_child.h"
#include "util/mylibc.h"
#include "util/obf_str.h"
#include "util/payload_codec.h"
#include "util/raw_dir.h"
#include "util/syscall_wrapper.h"

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <sched.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>

namespace riskengine {
namespace kernel_sidechannel {

namespace {

constexpr unsigned int kKsuMagic1 = 0xDEADBEEFU;
constexpr unsigned int kKsuMagic2 = 0xCAFEBABEU;
constexpr unsigned long kKsuIoctlGetInfo = _IOC(_IOC_READ, 'K', 2, 0);
constexpr unsigned long kKsuIoctlCheckSafemode = _IOC(_IOC_READ, 'K', 5, 0);

struct KsuGetInfoCmd {
    uint32_t version = 0;
    uint32_t flags = 0;
    uint32_t features = 0;
};

struct KsuCheckSafemodeCmd {
    uint8_t in_safe_mode = 0;
};

struct KsuRebootChildPacket {
    uint32_t version = 0;
    uint32_t flags = 0;
    uint32_t features = 0;
    uint8_t safemode_supported = 0;
    uint8_t in_safe_mode = 0;
    uint8_t hit = 0;
    uint8_t reserved = 0;
};

#if defined(__aarch64__) && defined(__linux__)

constexpr int kKpAttempts = 4;
// Modern KernelPatch (0.11+ / APatch) validates low 32 bits of arg1 against
// [SUPERCALL_HELLO (0x1000), SUPERCALL_MAX] before touching arg0. Setting bit 63
// keeps the signed 64-bit off_t negative so stock do_sys_truncate() still rejects
// immediately with -EINVAL without dereferencing arg0 (0 FP on stock kernels).
constexpr off_t kKpLegacyNegLen = static_cast<off_t>(-1);
constexpr off_t kKpModernNegHelloLen = static_cast<off_t>(static_cast<int64_t>(0x8000000000001000ULL));
constexpr long kKpHelloMagic = 0x11581158L;

struct KpResidencyPacket {
    uint8_t checked = 0;
    uint8_t hit = 0;
    uint8_t modern_hit = 0;
    uint8_t hello_magic_hit = 0;
    uint8_t pre_resident = 0;
    uint8_t control_resident = 0;
    uint8_t control_failed = 0;
    uint8_t map_failed = 0;
    uint8_t mincore_failed = 0;
    uint8_t reserved[3] = {};
};

struct KpChildInput {
    std::size_t page_size = 4096;
};

int kp_truncate_child_body(const void *ctx, int report_fd) {
    const auto *input = static_cast<const KpChildInput *>(ctx);
    const std::size_t page_size = (input != nullptr && input->page_size >= 4096)
            ? input->page_size
            : 4096U;

    KpResidencyPacket pkt = {};

    const long ctrl_ret = my_mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ctrl_ret == -1) {
        pkt.control_failed = 1;
        riskengine::util::write_child_report(report_fd, &pkt, sizeof(pkt));
        return 0;
    }
    void *control_page = reinterpret_cast<void *>(static_cast<uintptr_t>(ctrl_ret));

    for (int i = 0; i < kKpAttempts; ++i) {
        const long page_ret = my_mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page_ret == -1) {
            pkt.map_failed++;
            continue;
        }
        void *page = reinterpret_cast<void *>(static_cast<uintptr_t>(page_ret));

        unsigned char vec_before = 0;
        if (my_mincore(page, page_size, &vec_before) != 0) {
            pkt.mincore_failed++;
            my_munmap(page, page_size);
            continue;
        }
        if ((vec_before & 0x1U) != 0) {
            pkt.pre_resident++;
            my_munmap(page, page_size);
            continue;
        }

        // 1. Modern KernelPatch 0.11+ / APatch probe: negative signed off_t with low32 = SUPERCALL_HELLO (0x1000).
        //    Stock kernels reject length < 0 immediately with -EINVAL without reading arg0.
        const long modern_ret = my_truncate(
                reinterpret_cast<const char *>(page), kKpModernNegHelloLen);
        if (modern_ret == kKpHelloMagic) {
            pkt.hello_magic_hit = 1;
        }

        unsigned char vec_after = 0;
        if (my_mincore(page, page_size, &vec_after) != 0) {
            pkt.mincore_failed++;
        } else if ((vec_after & 0x1U) != 0) {
            pkt.checked++;
            pkt.modern_hit++;
            pkt.hit++;
        } else {
            // 2. Legacy KernelPatch <= 0.10.x probe: arg1 == -1 before command range check.
            (void) my_truncate(reinterpret_cast<const char *>(page), kKpLegacyNegLen);
            unsigned char vec_legacy = 0;
            if (my_mincore(page, page_size, &vec_legacy) != 0) {
                pkt.mincore_failed++;
            } else {
                pkt.checked++;
                if ((vec_legacy & 0x1U) != 0) {
                    pkt.hit++;
                }
            }
        }
        my_munmap(page, page_size);
    }

    unsigned char ctrl_vec = 0;
    if (my_mincore(control_page, page_size, &ctrl_vec) != 0) {
        pkt.control_failed = 1;
        pkt.mincore_failed++;
    } else if ((ctrl_vec & 0x1U) != 0) {
        pkt.control_resident = 1;
    }
    my_munmap(control_page, page_size);

    if (!riskengine::util::write_child_report(report_fd, &pkt, sizeof(pkt))) {
        return 2;
    }
    return 0;
}

inline uint64_t read_cntvct_el0() noexcept {
    uint64_t val = 0;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0\n\tisb" : "=r"(val) : : "memory");
    return val;
}

inline bool is_on_cpu(int cpu) noexcept {
    unsigned cur = 0;
    return my_getcpu(&cur, nullptr) == 0 && cur == static_cast<unsigned>(cpu);
}

#endif  // defined(__aarch64__) && defined(__linux__)

int ksu_reboot_child_body(const void *, int report_fd) {
    KsuRebootChildPacket pkt = {};
    int driver_fd = -1;
    (void) my_reboot(kKsuMagic1, kKsuMagic2, 0, &driver_fd);
    if (driver_fd >= 0) {
        KsuGetInfoCmd info = {};
        if (my_ioctl(driver_fd, kKsuIoctlGetInfo,
                     reinterpret_cast<unsigned long>(&info)) == 0
                && info.version != 0) {
            pkt.version = info.version;
            pkt.flags = info.flags;
            pkt.features = info.features;
            pkt.hit = 1;

            KsuCheckSafemodeCmd safe_cmd = {};
            if (my_ioctl(driver_fd, kKsuIoctlCheckSafemode,
                         reinterpret_cast<unsigned long>(&safe_cmd)) == 0) {
                pkt.safemode_supported = 1;
                pkt.in_safe_mode = safe_cmd.in_safe_mode;
            }
        }
        my_close(driver_fd);
    }

    if (!riskengine::util::write_child_report(report_fd, &pkt, sizeof(pkt))) {
        return 2;
    }
    return 0;
}

struct SusfsChildInput {
    uid_t target_uid = 0;
};

int susfs_setresuid_child_body(const void *ctx, int) {
    const auto *input = static_cast<const SusfsChildInput *>(ctx);
    if (input == nullptr) {
        return 1;
    }
    const uid_t u = input->target_uid;
    const long ret = my_setresuid(u, u, u);
    return (ret == 0) ? 100 : 0;
}

double compute_median(std::vector<uint64_t> &sorted) {
    if (sorted.empty()) {
        return 0.0;
    }
    const std::size_t n = sorted.size();
    if ((n & 1U) == 1U) {
        return static_cast<double>(sorted[n / 2]);
    }
    return 0.5 * (static_cast<double>(sorted[n / 2 - 1]) + static_cast<double>(sorted[n / 2]));
}

double compute_mad(const std::vector<uint64_t> &sorted, double median) {
    if (sorted.empty()) {
        return 0.0;
    }
    std::vector<double> deviations;
    deviations.reserve(sorted.size());
    for (uint64_t v : sorted) {
        deviations.push_back(std::fabs(static_cast<double>(v) - median));
    }
    std::sort(deviations.begin(), deviations.end());
    const std::size_t n = deviations.size();
    if ((n & 1U) == 1U) {
        return deviations[n / 2];
    }
    return 0.5 * (deviations[n / 2 - 1] + deviations[n / 2]);
}

void scan_ksu_driver_fds(payload_codec::PayloadBuilder &payload, int &hits_out) {
    const auto fd_dir = OBF("/proc/self/fd");
    const auto needle = OBF("ksu_driver");
    RawDirResult dir = raw_list_dir(fd_dir.c_str());
    if (!dir.ok()) {
        return;
    }
    for (const std::string &name : dir.names) {
        if (name.empty() || !my_is_digit(static_cast<unsigned char>(name[0]))) {
            continue;
        }
        std::string link_path = std::string(fd_dir.c_str()) + "/" + name;
        char target[256] = {};
        const long len = my_readlinkat(AT_FDCWD, link_path.c_str(), target, sizeof(target) - 1);
        if (len <= 0) {
            continue;
        }
        target[len] = '\0';
        if (my_strstr(target, needle.c_str()) != nullptr) {
            hits_out++;
            payload_codec::RecordBuilder rec;
            rec.add("kind", "ksu_driver_fd")
               .add("fd", name)
               .add("target", target);
            payload.add_record(rec);
        }
    }
}

bool check_pty_xattr(const char *path,
                     const char *selinux_attr,
                     const char *ksu_needle,
                     payload_codec::PayloadBuilder &payload,
                     int &checked_out,
                     int &hits_out) {
    struct stat st = {};
    if (my_fstatat(AT_FDCWD, path, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return false;
    }
    checked_out++;
    char attr_buf[256] = {};
    const long attr_len = my_lgetxattr(path, selinux_attr, attr_buf, sizeof(attr_buf) - 1);
    if (attr_len <= 0) {
        return false;
    }
    attr_buf[attr_len] = '\0';
    if (my_strstr(attr_buf, ksu_needle) != nullptr) {
        hits_out++;
        payload_codec::RecordBuilder rec;
        rec.add("kind", "devpts_ksu_xattr")
           .add("path", path)
           .add("context", attr_buf);
        payload.add_record(rec);
        return true;
    }
    return false;
}

void scan_devpts_xattr(payload_codec::PayloadBuilder &payload, int &checked_out, int &hits_out) {
    const auto pts_prefix = OBF("/dev/pts/");
    const auto selinux_attr = OBF("security.selinux");
    const auto ksu_needle = OBF("ksu_file");

    char path_buf[48] = {};
    for (int i = 0; i <= 100; ++i) {
        std::snprintf(path_buf, sizeof(path_buf), "%s%d", pts_prefix.c_str(), i);
        check_pty_xattr(path_buf, selinux_attr.c_str(), ksu_needle.c_str(),
                        payload, checked_out, hits_out);
    }

    // Also inspect a freshly allocated PTY in case a KSU devpts hook stamps new nodes.
    const int master_fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (master_fd >= 0) {
        if (grantpt(master_fd) == 0 && unlockpt(master_fd) == 0) {
            char pts_name[64] = {};
            if (ptsname_r(master_fd, pts_name, sizeof(pts_name)) == 0 && pts_name[0] != '\0') {
                check_pty_xattr(pts_name, selinux_attr.c_str(), ksu_needle.c_str(),
                                payload, checked_out, hits_out);
            }
        }
        my_close(master_fd);
    }
}

#if defined(__aarch64__) && defined(__linux__)

void run_arm64_prctl_timing_sidechannel(payload_codec::PayloadBuilder &payload,
                                        bool &timing_ran_out,
                                        int &consecutive_hits_out) {
    constexpr int kRequiredConsecutiveHits = 3;
    constexpr int kMaxRounds = 6;
    constexpr int kSamplesPerVector = 24;  // 3 target vectors * 24 = 72, 3 control vectors * 24 = 72
    constexpr int kTargetOptions[3] = {
            static_cast<int>(0xDEADBEEFU),
            static_cast<int>(0xDEADBEEFU),
            static_cast<int>(0xDEADBEEFU)
    };
    constexpr unsigned long kTargetCmds[3] = {0UL, 2UL, 10UL};
    constexpr int kControlOptions[3] = {
            static_cast<int>(0xDEADBEF0U),
            static_cast<int>(0xBAD0BEEFU),
            static_cast<int>(0x7F001234U)
    };
    constexpr unsigned long kControlCmds[3] = {0UL, 2UL, 10UL};

    cpu_set_t original_affinity = {};
    CPU_ZERO(&original_affinity);
    if (sched_getaffinity(0, sizeof(original_affinity), &original_affinity) != 0) {
        return;
    }

    unsigned current_cpu = 0;
    if (my_getcpu(&current_cpu, nullptr) != 0 || current_cpu >= CPU_SETSIZE) {
        return;
    }
    const int pinned_cpu = static_cast<int>(current_cpu);
    cpu_set_t pin_mask = {};
    CPU_ZERO(&pin_mask);
    CPU_SET(pinned_cpu, &pin_mask);
    if (sched_setaffinity(0, sizeof(pin_mask), &pin_mask) != 0) {
        return;
    }

    timing_ran_out = true;
    int consecutive_hits = 0;
    TimingRoundStats last_hit_stats = {};
    std::vector<uint64_t> target_samples;
    std::vector<uint64_t> control_samples;
    target_samples.reserve(3 * kSamplesPerVector);
    control_samples.reserve(3 * kSamplesPerVector);

    for (int round = 0; round < kMaxRounds && consecutive_hits < kRequiredConsecutiveHits; ++round) {
        target_samples.clear();
        control_samples.clear();
        bool migrated = false;

        for (int iter = 0; iter < kSamplesPerVector && !migrated; ++iter) {
            // Interleave 6 vectors and alternate target-first vs control-first order.
            const bool target_first = ((iter + round) & 1) == 0;
            for (int v = 0; v < 3; ++v) {
                if (!is_on_cpu(pinned_cpu)) {
                    migrated = true;
                    break;
                }
                if (target_first) {
                    const uint64_t t0 = read_cntvct_el0();
                    (void) my_prctl(kTargetOptions[v], kTargetCmds[v], 0, 0, 0);
                    const uint64_t t1 = read_cntvct_el0();
                    const uint64_t c0 = read_cntvct_el0();
                    (void) my_prctl(kControlOptions[v], kControlCmds[v], 0, 0, 0);
                    const uint64_t c1 = read_cntvct_el0();
                    if (!is_on_cpu(pinned_cpu)) {
                        migrated = true;
                        break;
                    }
                    if (t1 >= t0 && c1 >= c0) {
                        target_samples.push_back(t1 - t0);
                        control_samples.push_back(c1 - c0);
                    }
                } else {
                    const uint64_t c0 = read_cntvct_el0();
                    (void) my_prctl(kControlOptions[v], kControlCmds[v], 0, 0, 0);
                    const uint64_t c1 = read_cntvct_el0();
                    const uint64_t t0 = read_cntvct_el0();
                    (void) my_prctl(kTargetOptions[v], kTargetCmds[v], 0, 0, 0);
                    const uint64_t t1 = read_cntvct_el0();
                    if (!is_on_cpu(pinned_cpu)) {
                        migrated = true;
                        break;
                    }
                    if (t1 >= t0 && c1 >= c0) {
                        target_samples.push_back(t1 - t0);
                        control_samples.push_back(c1 - c0);
                    }
                }
            }
        }

        if (migrated || target_samples.size() < 24 || control_samples.size() < 24) {
            consecutive_hits = 0;
            continue;
        }

        TimingRoundStats stats = evaluate_prctl_timing_round(
                target_samples.data(), target_samples.size(),
                control_samples.data(), control_samples.size());
        if (stats.anomalous) {
            consecutive_hits++;
            last_hit_stats = stats;
        } else {
            consecutive_hits = 0;
        }
    }

    sched_setaffinity(0, sizeof(original_affinity), &original_affinity);
    consecutive_hits_out = consecutive_hits;

    if (consecutive_hits >= kRequiredConsecutiveHits) {
        char metrics[128] = {};
        std::snprintf(metrics, sizeof(metrics),
                      "cpu=%d,t_med=%.1f,c_med=%.1f,z=%.2f,cos=%.3f",
                      pinned_cpu,
                      last_hit_stats.target_median,
                      last_hit_stats.control_median,
                      last_hit_stats.robust_z,
                      last_hit_stats.cosine_similarity);
        payload_codec::RecordBuilder rec;
        rec.add("kind", "ksu_prctl_timing_anomaly")
           .add_int("cpu", pinned_cpu)
           .add_int("consecutive_hits", consecutive_hits)
           .add("metrics", metrics);
        payload.add_record(rec);
    }
}

#endif  // defined(__aarch64__) && defined(__linux__)

}  // namespace

TimingRoundStats evaluate_prctl_timing_round(const uint64_t *target_samples,
                                             std::size_t target_count,
                                             const uint64_t *control_samples,
                                             std::size_t control_count) {
    TimingRoundStats stats = {};
    if (target_samples == nullptr || control_samples == nullptr
            || target_count < 12 || control_count < 12) {
        return stats;
    }

    std::vector<uint64_t> t_sorted(target_samples, target_samples + target_count);
    std::vector<uint64_t> c_sorted(control_samples, control_samples + control_count);
    std::sort(t_sorted.begin(), t_sorted.end());
    std::sort(c_sorted.begin(), c_sorted.end());

    // Trim top 10% IRQ outliers before histogramming.
    const std::size_t t_trim = std::max<std::size_t>(1, t_sorted.size() * 9 / 10);
    const std::size_t c_trim = std::max<std::size_t>(1, c_sorted.size() * 9 / 10);
    t_sorted.resize(t_trim);
    c_sorted.resize(c_trim);

    stats.target_median = compute_median(t_sorted);
    stats.control_median = compute_median(c_sorted);
    stats.control_mad = compute_mad(c_sorted, stats.control_median);

    const double robust_sigma = std::max(1.0, 1.4826 * stats.control_mad);
    stats.robust_z = (stats.target_median - stats.control_median) / robust_sigma;

    // Build 16-bin histogram spanning [min_val, max_val] across both trimmed distributions.
    constexpr std::size_t kBins = 16;
    const uint64_t min_v = std::min(t_sorted.front(), c_sorted.front());
    const uint64_t max_v = std::max(t_sorted.back(), c_sorted.back());
    double hist_t[kBins] = {};
    double hist_c[kBins] = {};

    if (max_v > min_v) {
        const double span = static_cast<double>(max_v - min_v) + 1.0;
        for (uint64_t v : t_sorted) {
            std::size_t bin = static_cast<std::size_t>(
                    (static_cast<double>(v - min_v) / span) * static_cast<double>(kBins));
            if (bin >= kBins) bin = kBins - 1;
            hist_t[bin] += 1.0;
        }
        for (uint64_t v : c_sorted) {
            std::size_t bin = static_cast<std::size_t>(
                    (static_cast<double>(v - min_v) / span) * static_cast<double>(kBins));
            if (bin >= kBins) bin = kBins - 1;
            hist_c[bin] += 1.0;
        }
        double dot = 0.0;
        double norm_t = 0.0;
        double norm_c = 0.0;
        for (std::size_t i = 0; i < kBins; ++i) {
            dot += hist_t[i] * hist_c[i];
            norm_t += hist_t[i] * hist_t[i];
            norm_c += hist_c[i] * hist_c[i];
        }
        const double denom = std::sqrt(norm_t) * std::sqrt(norm_c);
        stats.cosine_similarity = (denom > 0.0) ? (dot / denom) : 1.0;
    } else {
        stats.cosine_similarity = 1.0;
    }

    const double min_rel_delta = std::max(2.0, stats.control_median * 0.15);
    const bool median_separated = (stats.target_median - stats.control_median) >= min_rel_delta;
    stats.anomalous = median_separated
            && stats.robust_z >= 3.0
            && stats.cosine_similarity < 0.90;
    return stats;
}

bool is_kernelpatch_negative_trusted_release(const char *release) noexcept {
    if (release == nullptr || release[0] == '\0') {
        return false;
    }
    int major = -1;
    int minor = -1;
    if (std::sscanf(release, "%d.%d", &major, &minor) < 2 || major < 0 || minor < 0) {
        return false;
    }
    return major < 6 || (major == 6 && minor <= 6);
}

}  // namespace kernel_sidechannel
}  // namespace riskengine

std::string native_get_kernel_sidechannel(bool include_postponed_timing) {
    using namespace riskengine::kernel_sidechannel;

    payload_codec::PayloadBuilder payload(payload_codec::Status::OK, 0);
    riskengine::util::ChildDeadlines deadlines;
    deadlines.run = std::chrono::milliseconds(1000);
    deadlines.reap = std::chrono::milliseconds(250);

    int probes_run = 0;

    // 1. KernelPatch sys_truncate + mincore residency side-channel (ARM64 disposable child).
    bool kp_negative_trusted = false;
#if defined(__aarch64__) && defined(__linux__)
    {
        struct utsname uts = {};
        const bool have_uname = (my_uname(&uts) == 0);
        const bool kernel_scope_ok = have_uname
                && is_kernelpatch_negative_trusted_release(uts.release);

        KpChildInput kp_in = {};
        const long ps = sysconf(_SC_PAGESIZE);
        kp_in.page_size = (ps >= 4096) ? static_cast<std::size_t>(ps) : 4096U;

        KpResidencyPacket kp_pkt = {};
        riskengine::util::ChildOutcome kp_out = riskengine::util::run_disposable_child(
                reinterpret_cast<uint8_t *>(&kp_pkt),
                sizeof(kp_pkt),
                deadlines,
                &kp_truncate_child_body,
                &kp_in);

        if (kp_out.end == riskengine::util::ChildEnd::kExited
                && kp_out.exit_status == 0
                && kp_out.report_length == sizeof(kp_pkt)) {
            probes_run++;
            const bool measurement_valid =
                    kp_pkt.control_failed == 0
                    && kp_pkt.control_resident == 0
                    && kp_pkt.map_failed == 0
                    && kp_pkt.mincore_failed == 0
                    && kp_pkt.pre_resident == 0
                    && kp_pkt.checked == kKpAttempts;
            kp_negative_trusted = measurement_valid && kernel_scope_ok;

            // Direct SUPERCALL_HELLO_MAGIC reply on negative-length truncate is conclusive on any kernel.
            if (kp_pkt.hello_magic_hit != 0) {
                payload_codec::RecordBuilder rec;
                rec.add("kind", "kernelpatch_supercall_hello")
                   .add("magic", "0x11581158")
                   .add("kernel", have_uname ? uts.release : "");
                payload.add_record(rec);
            }

            // Positive residency hit is conclusive on any kernel version once control page is verified clean.
            if (kp_pkt.hit > 0 && kp_pkt.control_failed == 0
                    && kp_pkt.control_resident == 0 && kp_pkt.pre_resident == 0) {
                payload_codec::RecordBuilder rec;
                rec.add("kind", "kernelpatch_truncate_hit")
                   .add_int("hits", kp_pkt.hit)
                   .add_int("modern_hits", kp_pkt.modern_hit)
                   .add_int("checked", kp_pkt.checked)
                   .add("kernel", have_uname ? uts.release : "");
                payload.add_record(rec);
            }
        }
    }
#endif
    payload.add_header("kp_negative_trusted", kp_negative_trusted ? "1" : "0");

    // 2. KernelSU reboot(0xDEADBEEF, 0xCAFEBABE) + KSU_IOCTL_GET_INFO (disposable child).
    {
        KsuRebootChildPacket ksu_pkt = {};
        riskengine::util::ChildOutcome ksu_out = riskengine::util::run_disposable_child(
                reinterpret_cast<uint8_t *>(&ksu_pkt),
                sizeof(ksu_pkt),
                deadlines,
                &ksu_reboot_child_body,
                nullptr);

        if (ksu_out.end == riskengine::util::ChildEnd::kExited
                && ksu_out.exit_status == 0
                && ksu_out.report_length == sizeof(ksu_pkt)) {
            probes_run++;
            if (ksu_pkt.hit != 0 && ksu_pkt.version != 0) {
                payload_codec::RecordBuilder rec;
                rec.add("kind", "ksu_reboot_ioctl")
                   .add_uint("version", ksu_pkt.version)
                   .add_uint("flags", ksu_pkt.flags)
                   .add_uint("features", ksu_pkt.features)
                   .add_bool("safe_mode", ksu_pkt.safemode_supported != 0 && ksu_pkt.in_safe_mode != 0);
                payload.add_record(rec);
            }
        }
    }

    // 3. SUSFS setresuid SIGKILL trap (disposable child).
    {
        const uid_t current_uid = getuid();
        if (current_uid > 0) {
            SusfsChildInput susfs_in = {};
            susfs_in.target_uid = (current_uid > 10000) ? 10000U : (current_uid - 1U);

            riskengine::util::ChildOutcome susfs_out = riskengine::util::run_disposable_child(
                    nullptr,
                    0,
                    deadlines,
                    &susfs_setresuid_child_body,
                    &susfs_in);

            if (susfs_out.end == riskengine::util::ChildEnd::kSignaled
                    && susfs_out.signal == SIGKILL) {
                probes_run++;
                payload_codec::RecordBuilder rec;
                rec.add("kind", "susfs_setresuid_sigkill")
                   .add_uint("uid", current_uid)
                   .add_uint("target_uid", susfs_in.target_uid);
                payload.add_record(rec);
            } else if (susfs_out.end == riskengine::util::ChildEnd::kExited
                    && susfs_out.exit_status == 100) {
                probes_run++;
                payload_codec::RecordBuilder rec;
                rec.add("kind", "setresuid_unexpected_success")
                   .add_uint("uid", current_uid)
                   .add_uint("target_uid", susfs_in.target_uid);
                payload.add_record(rec);
            } else if (susfs_out.end == riskengine::util::ChildEnd::kExited
                    && susfs_out.exit_status == 0) {
                probes_run++;
            }
        }
    }

    // 4. /proc/self/fd [ksu_driver] & devpts security.selinux ksu_file xattr.
    int ksu_fd_hits = 0;
    scan_ksu_driver_fds(payload, ksu_fd_hits);
    int devpts_checked = 0;
    int devpts_hits = 0;
    scan_devpts_xattr(payload, devpts_checked, devpts_hits);
    if (devpts_checked > 0 || ksu_fd_hits > 0) {
        probes_run++;
    }

    // 5. Optional ARM64 prctl(0xDEADBEEF) microarchitectural timing side-channel (POSTPONED only).
    bool timing_ran = false;
    int timing_hits = 0;
#if defined(__aarch64__) && defined(__linux__)
    if (include_postponed_timing) {
        run_arm64_prctl_timing_sidechannel(payload, timing_ran, timing_hits);
        if (timing_ran) {
            probes_run++;
        }
    }
#else
    (void) include_postponed_timing;
#endif

    if (probes_run == 0) {
        payload.set_status(payload_codec::Status::RESTRICTED, raw_last_error());
    }
    payload.add_header_int("probes_run", probes_run);
    payload.add_header_int("devpts_checked", devpts_checked);
    payload.add_header("timing_ran", timing_ran ? "1" : "0");
    payload.add_header_int("timing_consecutive_hits", timing_hits);
    return payload.build();
}
