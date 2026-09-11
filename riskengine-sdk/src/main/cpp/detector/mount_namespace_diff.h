#ifndef RISKENGINE_MOUNT_NAMESPACE_DIFF_H
#define RISKENGINE_MOUNT_NAMESPACE_DIFF_H

#include <string>

/**
 * Compares this process's mount view against init's (pid 1).
 *
 * Zygisk DenyList / Shamiko style hiding works by unmounting the root
 * framework's bind mounts inside the target process's mount namespace. The
 * mounts stay visible to init. A mount present for init but missing here, or
 * a namespace id difference with a suspiciously smaller mount table, is
 * evidence of targeted hiding that path probes cannot see.
 *
 * Returns a comma separated token list; empty when nothing was observed or
 * when /proc/1 is not readable (an unprivileged app usually cannot read it,
 * which is itself reported as a coverage token rather than a silent pass).
 */
std::string native_get_mount_namespace_evidence();

#endif
