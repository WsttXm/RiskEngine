#include "seccomp_arch_checker.h"
#include <string>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stddef.h>

#ifndef AUDIT_ARCH_X86_64
#define AUDIT_ARCH_X86_64 (EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#endif
#ifndef AUDIT_ARCH_I386
#define AUDIT_ARCH_I386 (EM_386|__AUDIT_ARCH_LE)
#endif
#ifndef AUDIT_ARCH_ARM
#define AUDIT_ARCH_ARM (EM_ARM|__AUDIT_ARCH_LE)
#endif
#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 (EM_AARCH64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#endif

static const uint32_t DetectX86Flag = 0xDEADBEEF;
static bool seccomp_installed = false;

static void install_check_arch_seccomp() {
    if (seccomp_installed) return;

    struct sock_filter filter[] = {
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (uint32_t) offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP + BPF_JEQ, __NR_getpid, 0, 12),
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (uint32_t) offsetof(struct seccomp_data, args[0])),
            BPF_JUMP(BPF_JMP + BPF_JEQ, DetectX86Flag, 0, 10),
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (uint32_t) offsetof(struct seccomp_data, arch)),
            BPF_JUMP(BPF_JMP + BPF_JEQ, AUDIT_ARCH_X86_64, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (864 & SECCOMP_RET_DATA)),
            BPF_JUMP(BPF_JMP + BPF_JEQ, AUDIT_ARCH_I386, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (386 & SECCOMP_RET_DATA)),
            BPF_JUMP(BPF_JMP + BPF_JEQ, AUDIT_ARCH_ARM, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (0xA32 & SECCOMP_RET_DATA)),
            BPF_JUMP(BPF_JMP + BPF_JEQ, AUDIT_ARCH_AARCH64, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (0xA64 & SECCOMP_RET_DATA)),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (6 & SECCOMP_RET_DATA)),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
    };

    struct sock_fprog program = {
            .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
            .filter = filter
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0) {
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0) {
            seccomp_installed = true;
        }
    }
}

std::string check_arch_by_seccomp() {
    install_check_arch_seccomp();
    if (!seccomp_installed) return "";

    errno = 0;
    syscall(__NR_getpid, DetectX86Flag);

    if (errno == 386) {
        return "I386";
    } else if (errno == 864) {
        return "X86_64";
    } else if (errno == 0xA32 || errno == 0xA64) {
        return ""; // ARM, normal
    } else if (errno == 0) {
        return ""; // seccomp not active
    }
    return "unknown_arch:" + std::to_string(errno);
}
