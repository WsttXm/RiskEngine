#ifndef RISKENGINE_VIRTUALIZATION_TRAPS_H
#define RISKENGINE_VIRTUALIZATION_TRAPS_H

#include <cstddef>
#include <cstdint>
#include <string>

/**
 * Native virtualization and binary translation trap suite returning a payload_codec frame.
 *
 * Fast path (always executed):
 *  - Native Bridge detection: ro.dalvik.vm.native.bridge, /proc/self/maps,
 *    /proc/self/cmdline (-Xnative-bridge), and /system/{bin,lib,lib64} houdini/nb/ndk_translation.
 *
 * Postponed path (only when include_postponed_traps == true, strictly inside disposable_child):
 *  - sacrificial_syscall_pack: compares libc syscall() vs raw inline asm for
 *    statx, memfd_create, renameat2, openat2, and pidfd_open.
 *  - sched_yield latency coefficient of variation (CV < 0.03 -> WEAK/INFO only).
 *  - ARM64 cntfrq_el0/cntvct_el0 vs CLOCK_MONOTONIC overflow-safe sec/rem clock drift.
 */
std::string native_get_virtualization_traps(bool include_postponed_traps);

namespace virtualization_traps {

struct YieldStats {
    bool valid = false;
    int64_t mean_ns = 0;
    double cv = 0.0;
    size_t unique_us_buckets = 0;
    bool suspicious = false;
};

/** Pure sched_yield CV & microsecond bucket analyzer exposed for host C++ testing. */
YieldStats evaluate_yield_samples(const int64_t *samples, size_t count) noexcept;

/**
 * Overflow-safe sec/rem conversion of ARM64 counter ticks to nanoseconds.
 * Masks freq to bits [31:0] (ClockFreq); returns 0 when masked freq == 0.
 */
uint64_t compute_counter_ns_safe(uint64_t counter_delta, uint64_t raw_freq) noexcept;

/** Evaluates whether ARM64 counter delta grossly diverges from CLOCK_MONOTONIC wall delta. */
bool is_clock_drift_suspicious(uint64_t counter_delta,
                               uint64_t raw_freq,
                               int64_t wall_delta_ns,
                               uint64_t *out_counter_ns = nullptr) noexcept;

}  // namespace virtualization_traps

#endif  // RISKENGINE_VIRTUALIZATION_TRAPS_H
