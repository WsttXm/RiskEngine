#ifndef RISKENGINE_KERNEL_SU_PROBE_H
#define RISKENGINE_KERNEL_SU_PROBE_H

#include <string>

/**
 * Probes for kernel-resident root managers via their prctl side channel.
 *
 * KernelSU hooks prctl and answers a private option number. On a stock kernel
 * that option is unknown and prctl fails with EINVAL, leaving the output
 * buffer untouched. When the KSU kernel module is present it writes a known
 * magic value and/or returns success. This finds KernelSU even when every
 * userspace file it installs has been renamed or hidden, which path probing
 * cannot do.
 *
 * Only reads are performed. No attempt is made to request root, escalate, or
 * invoke any manager behaviour.
 */
std::string native_get_kernel_root_evidence();

#endif
