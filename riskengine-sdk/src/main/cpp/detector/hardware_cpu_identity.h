#ifndef RISKENGINE_HARDWARE_CPU_IDENTITY_H
#define RISKENGINE_HARDWARE_CPU_IDENTITY_H

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace riskengine {
namespace cpu_identity {

constexpr uint32_t kMidrComparisonMask = 0xfff0ffffU;
constexpr int kAgreeingReadsRequired = 3;
constexpr int kMaxReadsPerCpu = 8;
constexpr int kMaxProbeCpus = 64;

enum class MrsReadState : uint8_t {
    kNotAttempted = 0,
    kVerified = 1,
    kUnattributed = 2,
    kUnstable = 3,
    kFaulted = 4,
};

struct CpuMidrObservation {
    int cpu = -1;
    bool has_sysfs = false;
    uint32_t sysfs_midr = 0;
    bool has_cpuinfo = false;
    uint32_t cpuinfo_midr = 0;
    bool has_mrs = false;
    uint32_t mrs_midr = 0;
    MrsReadState mrs_state = MrsReadState::kNotAttempted;
    uint32_t off_cpu_retries = 0;
};

/**
 * Compares two 32-bit MIDR_EL1 values using mask 0xfff0ffff (ignoring the
 * Architecture bits [19:16] that /proc/cpuinfo omits).
 */
inline bool midr_matches_masked(uint32_t a, uint32_t b) noexcept {
    return (a & kMidrComparisonMask) == (b & kMidrComparisonMask);
}

/**
 * Parses a sysfs midr_el1 string (e.g. "0x00000000411fd050\n") into uint32_t.
 */
bool parse_sysfs_midr(std::string_view raw, uint32_t *out) noexcept;

/**
 * Extracts and assembles the 32-bit MIDR for target_cpu from /proc/cpuinfo text
 * (implementer[31:24] | variant[23:20] | part[15:4] | revision[3:0]).
 */
bool parse_proc_cpuinfo_midr(std::string_view cpuinfo, int target_cpu, uint32_t *out) noexcept;

/**
 * Encodes collected CPU MIDR observations into a NativePayloadCodec frame.
 */
std::string encode_cpu_identity_observations(const std::vector<CpuMidrObservation> &observations,
                                             bool cpuid_emulation_available);

}  // namespace cpu_identity
}  // namespace riskengine

/**
 * Probes ARM64 EL0 MIDR_EL1 inside a SIGILL-safe disposable child (bracketed by
 * raw __NR_getcpu requiring 3 agreeing same-core reads) and compares against
 * sysfs midr_el1 and /proc/cpuinfo using mask 0xfff0ffff.
 * Returns a NativePayloadCodec frame.
 */
std::string native_get_hardware_cpu_identity();

/**
 * Reads kernel identity via raw __NR_uname plus raw procfs reads of
 * /proc/sys/kernel/{osrelease,version} and /proc/version.
 * Returns a NativePayloadCodec frame for 3-source comparison with Java os.version.
 */
std::string native_get_kernel_consistency();

/**
 * Scans Bionic system properties for PlayIntegrityFix / PixelProps spoofing keys
 * (persist.sys.pihooks*, persist.sys.pixelprops*, persist.sys.spoof.gms).
 * Returns a NativePayloadCodec frame.
 */
std::string native_get_pif_properties();

#endif  // RISKENGINE_HARDWARE_CPU_IDENTITY_H
