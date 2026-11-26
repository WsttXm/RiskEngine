#ifndef RISKENGINE_KERNEL_SIDECHANNEL_H
#define RISKENGINE_KERNEL_SIDECHANNEL_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace riskengine {
namespace kernel_sidechannel {

struct TimingRoundStats {
    double target_median = 0.0;
    double control_median = 0.0;
    double control_mad = 0.0;
    double cosine_similarity = 1.0;
    double robust_z = 0.0;
    bool anomalous = false;
};

/**
 * Pure statistical evaluator for one round of 6-vector interleaved prctl timing samples.
 * Computes median, MAD (Median Absolute Deviation), and normalized histogram cosine
 * similarity to detect statistically significant kernel branch divergence without
 * false positives under normal scheduling jitter.
 */
TimingRoundStats evaluate_prctl_timing_round(const uint64_t *target_samples,
                                             std::size_t target_count,
                                             const uint64_t *control_samples,
                                             std::size_t control_count);

/**
 * Parses a Linux uname release string (e.g. "6.6.30-android15") and returns true
 * iff major/minor were parsed and kernel <= 6.6 (conservative faulting uaccess scope
 * for trusting a negative KernelPatch sys_truncate+mincore outcome).
 */
bool is_kernelpatch_negative_trusted_release(const char *release) noexcept;

}  // namespace kernel_sidechannel
}  // namespace riskengine

/**
 * Executes kernel root side-channel probes (KernelPatch sys_truncate+mincore,
 * KernelSU reboot/ioctl + /proc/self/fd [ksu_driver] + devpts ksu_file xattr,
 * SUSFS setresuid SIGKILL trap, and optionally ARM64 prctl timing side-channel
 * when include_postponed_timing is true).
 *
 * All hazardous syscalls (truncate, reboot, setresuid) execute strictly inside
 * disposable_child. Returns a NativePayloadCodec frame.
 */
std::string native_get_kernel_sidechannel(bool include_postponed_timing);

#endif  // RISKENGINE_KERNEL_SIDECHANNEL_H
