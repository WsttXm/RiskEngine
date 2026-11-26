#include "hma_uid_probe.h"

#include "../util/disposable_child.h"
#include "../util/obf_str.h"
#include "../util/payload_codec.h"
#include "../util/syscall_wrapper.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES 3
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

namespace {

constexpr int kMaxUidSpan = 10000;
constexpr uint32_t kActiveReportVersion = 1;
constexpr uint32_t kSeccompReportVersion = 1;
constexpr int kQueryTrapExitStatus = 126;

#if defined(__aarch64__)
constexpr uint32_t kAuditArch = AUDIT_ARCH_AARCH64;
#elif defined(__x86_64__)
constexpr uint32_t kAuditArch = AUDIT_ARCH_X86_64;
#else
constexpr uint32_t kAuditArch = 0;
#endif

using RawSigactionFn = int (*)(int, const struct sigaction *, struct sigaction *);

RawSigactionFn resolve_raw_sigaction() {
#if defined(__ANDROID__)
    static const RawSigactionFn fn = []() -> RawSigactionFn {
        auto libc_name = OBF("libc.so");
        void *libc = dlopen(libc_name.c_str(), RTLD_NOW | RTLD_NOLOAD);
        if (libc == nullptr) {
            return nullptr;
        }
        auto sym = OBF("sigaction");
        auto resolved = reinterpret_cast<RawSigactionFn>(dlsym(libc, sym.c_str()));
        dlclose(libc);
        return resolved;
    }();
    return fn;
#else
    return &::sigaction;
#endif
}

[[noreturn]] void child_exit_now(int code) {
#if defined(__NR_exit_group)
    syscall(__NR_exit_group, code);
#endif
    void (*volatile exit_fn)(int) = &::_exit;
    exit_fn(code);
    for (;;) {
    }
}

int64_t monotonic_ms() {
    timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return -1;
    }
    return static_cast<int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

long syscall_eintr_retry_2(long nr, long a1, long a2) {
    long ret = -1;
    do {
        errno = 0;
        ret = syscall(nr, a1, a2);
    } while (ret < 0 && errno == EINTR);
    return ret;
}

long syscall_eintr_retry_3(long nr, long a1, long a2, long a3) {
    long ret = -1;
    do {
        errno = 0;
        ret = syscall(nr, a1, a2, a3);
    } while (ret < 0 && errno == EINTR);
    return ret;
}

// =========================================================================
// 1. Active App UID scanner via getpriority(PRIO_USER, uid)
// =========================================================================

enum ActiveScanStatus : int32_t {
    kScanComplete = 0,
    kScanPartial = 1,
    kScanRestricted = 2,
    kScanUnsupported = 3,
    kScanError = 4,
};

struct ActiveUidReport {
    uint32_t version;
    int32_t status;
    int32_t err_no;
    int32_t checked;
    int32_t active_count;
    uint8_t bitmap[(kMaxUidSpan + 7) / 8];
};

struct ActiveUidContext {
    int first_uid;
    int last_uid;
};

int active_uid_child_body(const void *raw_ctx, int report_fd) {
    const auto *ctx = static_cast<const ActiveUidContext *>(raw_ctx);
    ActiveUidReport report{};
    report.version = kActiveReportVersion;
    report.status = kScanComplete;

    const int64_t start_ms = monotonic_ms();
    const int span = ctx->last_uid - ctx->first_uid + 1;
    for (int offset = 0; offset < span; ++offset) {
        if ((offset & 0xFF) == 0 && offset > 0) {
            const int64_t now = monotonic_ms();
            if (start_ms >= 0 && now >= 0 && (now - start_ms) >= 1200) {
                report.status = kScanPartial;
                report.err_no = ETIMEDOUT;
                break;
            }
        }
        const int uid = ctx->first_uid + offset;
        const long ret = syscall_eintr_retry_2(__NR_getpriority, PRIO_USER, uid);
        if (ret >= 0) {
            report.bitmap[offset / 8] |= static_cast<uint8_t>(1u << (offset % 8));
            report.active_count++;
            report.checked++;
        } else {
            const int err = errno;
            if (err == ESRCH) {
                report.checked++;
            } else if (err == EPERM || err == EACCES) {
                report.status = kScanRestricted;
                report.err_no = err;
                break;
            } else if (err == ENOSYS || err == EINVAL) {
                report.status = kScanUnsupported;
                report.err_no = err;
                break;
            } else {
                report.status = kScanError;
                report.err_no = err;
                break;
            }
        }
    }

    return riskengine::util::write_child_report(report_fd, &report, sizeof(report)) ? 0 : 1;
}

// =========================================================================
// 2. SECCOMP_FILTER_FLAG_NEW_LISTENER integrity probe for getpriority
// =========================================================================

enum SeccompInstallStatus : int32_t {
    kSeccompInstalled = 0,
    kSeccompForeignListener = 1,
    kSeccompUnsupported = 2,
    kSeccompRestricted = 3,
    kSeccompFailure = 4,
    kSeccompInstallTrapped = 5,
};

enum SeccompQueryOutcome : int32_t {
    kQueryComplete = 0,
    kQueryTrapped = 1,
    kQuerySignaled = 2,
    kQueryTimeout = 3,
    kQueryFailure = 4,
    kQueryNotRun = 5,
};

struct SeccompProbeReport {
    uint32_t version;
    int32_t install_status;
    int32_t install_error;
    int32_t kernel_major;
    int32_t kernel_minor;
    int32_t queried;
    int32_t notified;
    int32_t first_suppressed;
    int32_t last_suppressed;
    int32_t query_outcome;
    int32_t query_error;
    int32_t self_notified;
};

struct SeccompProbeContext {
    int first_uid;
    int last_uid;
    RawSigactionFn raw_sigaction;
};

void read_kernel_version_into(SeccompProbeReport &report) {
    struct utsname uts{};
    if (my_uname(&uts) < 0) {
        return;
    }
    const char *p = uts.release;
    int major = 0;
    int minor = 0;
    while (*p >= '0' && *p <= '9') {
        if (major > 100000) break;
        major = major * 10 + (*p - '0');
        ++p;
    }
    if (*p == '.') {
        ++p;
        while (*p >= '0' && *p <= '9') {
            if (minor > 100000) break;
            minor = minor * 10 + (*p - '0');
            ++p;
        }
    }
    if (major > 0) {
        report.kernel_major = major;
        report.kernel_minor = minor;
    }
}

int32_t classify_seccomp_install_error(int err) {
    switch (err) {
        case EBUSY:
            return kSeccompForeignListener;
        case EINVAL:
        case ENOSYS:
            return kSeccompUnsupported;
        case EPERM:
        case EACCES:
            return kSeccompRestricted;
        default:
            return kSeccompFailure;
    }
}

void query_sigsys_handler(int, siginfo_t *info, void *) {
    const bool attributed = info != nullptr
            && info->si_code == SYS_SECCOMP
            && info->si_syscall == __NR_getpriority
            && static_cast<uint32_t>(info->si_arch) == kAuditArch;
    child_exit_now(attributed
            ? kQueryTrapExitStatus
            : riskengine::util::kChildSeccompTrappedExitStatus);
}

int query_grandchild_body(int listener_fd,
                          pid_t coordinator_pid,
                          int first_uid,
                          int last_uid,
                          RawSigactionFn raw_sigaction) {
    if (my_prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0 || my_getppid() != coordinator_pid) {
        return 1;
    }
    if (raw_sigaction == nullptr) {
        return 1;
    }
    struct sigaction sa{};
    sa.sa_sigaction = query_sigsys_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (raw_sigaction(SIGSYS, &sa, nullptr) != 0) {
        return 1;
    }
    struct sigaction alrm_sa{};
    alrm_sa.sa_handler = SIG_DFL;
    sigemptyset(&alrm_sa.sa_mask);
    if (raw_sigaction(SIGALRM, &alrm_sa, nullptr) != 0) {
        return 1;
    }
    struct itimerval timer{};
    timer.it_value.tv_sec = 3;
    if (syscall_eintr_retry_3(
                __NR_setitimer, ITIMER_REAL,
                reinterpret_cast<long>(&timer), 0) < 0) {
        return 1;
    }
    my_close(listener_fd);

    for (int64_t uid = first_uid; uid <= last_uid; ++uid) {
        (void) syscall_eintr_retry_2(__NR_getpriority, PRIO_USER, static_cast<int>(uid));
    }
    return 0;
}

void stop_and_reap_grandchild(pid_t child) {
    if (child <= 0) {
        return;
    }
    (void) kill(child, SIGKILL);
    const int64_t start = monotonic_ms();
    int status = 0;
    for (int attempt = 0; attempt < 250; ++attempt) {
        const pid_t reaped = waitpid(child, &status, WNOHANG);
        if (reaped == child || (reaped < 0 && errno != EINTR)) {
            return;
        }
        const int64_t now = monotonic_ms();
        if (start >= 0 && now >= 0 && (now - start) >= 250) {
            return;
        }
        const timespec interval{0, 1000000};
        nanosleep(&interval, nullptr);
    }
}

void service_seccomp_queries(int listener_fd,
                             int report_fd,
                             int first_uid,
                             int last_uid,
                             RawSigactionFn raw_sigaction,
                             SeccompProbeReport &report) {
    if (raw_sigaction == nullptr) {
        report.query_outcome = kQueryFailure;
        report.query_error = ENOSYS;
        return;
    }
    const pid_t coordinator = getpid();
    const uid_t self_uid = getuid();

    struct sigaction chld_sa{};
    chld_sa.sa_handler = SIG_DFL;
    sigemptyset(&chld_sa.sa_mask);
    if (raw_sigaction(SIGCHLD, &chld_sa, nullptr) != 0) {
        report.query_outcome = kQueryFailure;
        report.query_error = errno;
        return;
    }

    const pid_t child = fork();
    if (child < 0) {
        report.query_outcome = kQueryFailure;
        report.query_error = errno;
        return;
    }
    if (child == 0) {
        my_close(report_fd);
        child_exit_now(query_grandchild_body(
                listener_fd, coordinator, first_uid, last_uid, raw_sigaction));
    }

    std::array<uint8_t, (kMaxUidSpan + 7) / 8> seen{};
    const int64_t start_ms = monotonic_ms();
    bool exited = false;
    int wait_status = 0;
    report.query_outcome = kQueryFailure;

    for (;;) {
        const int64_t now = monotonic_ms();
        if (start_ms < 0 || now < 0) {
            report.query_error = EIO;
            break;
        }
        if ((now - start_ms) >= 1800) {
            report.query_outcome = kQueryTimeout;
            report.query_error = ETIMEDOUT;
            break;
        }

        const pid_t reaped = waitpid(child, &wait_status, WNOHANG);
        if (reaped == child) {
            exited = true;
            break;
        }
        if (reaped < 0) {
            if (errno == EINTR) {
                continue;
            }
            report.query_error = errno;
            if (errno == ECHILD) {
                return;
            }
            break;
        }

        struct pollfd pfd{};
        pfd.fd = listener_fd;
        pfd.events = POLLIN;
        int ready = 0;
        do {
            errno = 0;
            ready = poll(&pfd, 1, 20);
        } while (ready < 0 && errno == EINTR);
        if (ready < 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            report.query_error = ready < 0 ? errno : EIO;
            break;
        }
        if (ready == 0 || (pfd.revents & POLLIN) == 0) {
            continue;
        }

        struct seccomp_notif notif{};
        long received = -1;
        do {
            errno = 0;
            received = ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &notif);
        } while (received < 0 && errno == EINTR);
        if (received < 0 && errno == ENOENT) {
            continue;
        }
        if (received < 0) {
            report.query_error = errno;
            break;
        }

        const int uid = static_cast<int>(notif.data.args[1]);
        if (notif.pid != static_cast<uint32_t>(child)
                || notif.data.arch != kAuditArch
                || notif.data.nr != __NR_getpriority
                || static_cast<int>(notif.data.args[0]) != PRIO_USER
                || uid < first_uid
                || uid > last_uid) {
            report.query_error = EPROTO;
            break;
        }

        struct seccomp_notif_resp resp{};
        resp.id = notif.id;
        long sent = -1;
        do {
            errno = 0;
            sent = ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
        } while (sent < 0 && errno == EINTR && (monotonic_ms() - start_ms) < 1800);
        if (sent < 0 && errno == ENOENT) {
            continue;
        }
        if (sent < 0) {
            report.query_error = errno;
            break;
        }

        const size_t idx = static_cast<size_t>(uid - first_uid);
        const uint8_t bit = static_cast<uint8_t>(1u << (idx % 8));
        if ((seen[idx / 8] & bit) == 0) {
            seen[idx / 8] |= bit;
            report.notified++;
        }
        if (uid == static_cast<int>(self_uid)) {
            report.self_notified = 1;
        }
    }

    if (!exited) {
        stop_and_reap_grandchild(child);
        return;
    }

    if (WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0) {
        report.query_outcome = kQueryComplete;
        report.queried = last_uid - first_uid + 1;
        for (int i = 0; i < report.queried; ++i) {
            if ((seen[i / 8] & static_cast<uint8_t>(1u << (i % 8))) == 0) {
                if (report.first_suppressed < 0) {
                    report.first_suppressed = first_uid + i;
                }
                report.last_suppressed = first_uid + i;
            }
        }
    } else if (WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == kQueryTrapExitStatus) {
        report.query_outcome = kQueryTrapped;
        report.query_error = SIGSYS;
    } else if (WIFSIGNALED(wait_status)) {
        const int sig = WTERMSIG(wait_status);
        report.query_outcome = (sig == SIGALRM) ? kQueryTimeout : kQuerySignaled;
        report.query_error = sig;
    } else {
        report.query_error = (WIFEXITED(wait_status)
                && WEXITSTATUS(wait_status) == riskengine::util::kChildSeccompTrappedExitStatus)
                ? SIGSYS
                : EPROTO;
    }
}

int install_getpriority_listener(int *out_error) {
    struct sock_filter code[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<uint32_t>(offsetof(seccomp_data, arch))),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kAuditArch, 0, 5),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<uint32_t>(offsetof(seccomp_data, nr))),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(__NR_getpriority), 0, 3),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<uint32_t>(offsetof(seccomp_data, args))),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(PRIO_USER), 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog{};
    prog.len = static_cast<unsigned short>(sizeof(code) / sizeof(code[0]));
    prog.filter = code;

    const long fd = syscall_eintr_retry_3(
            __NR_seccomp,
            SECCOMP_SET_MODE_FILTER,
            static_cast<long>(SECCOMP_FILTER_FLAG_NEW_LISTENER),
            reinterpret_cast<long>(&prog));
    if (fd < 0) {
        *out_error = errno;
        return -1;
    }
    *out_error = 0;
    return static_cast<int>(fd);
}

int seccomp_probe_child_body(const void *raw_ctx, int report_fd) {
    const auto *ctx = static_cast<const SeccompProbeContext *>(raw_ctx);
    SeccompProbeReport report{};
    report.version = kSeccompReportVersion;
    report.first_suppressed = -1;
    report.last_suppressed = -1;
    report.query_outcome = kQueryNotRun;

    read_kernel_version_into(report);
    if (report.kernel_major > 0 && report.kernel_major < 5) {
        report.install_status = kSeccompUnsupported;
        report.install_error = ENOSYS;
        return riskengine::util::write_child_report(report_fd, &report, sizeof(report)) ? 0 : 1;
    }

    struct seccomp_notif_sizes sizes{};
    if (kAuditArch == 0
            || syscall_eintr_retry_3(
                    __NR_seccomp,
                    SECCOMP_GET_NOTIF_SIZES,
                    0,
                    reinterpret_cast<long>(&sizes)) < 0) {
        report.install_error = (kAuditArch == 0) ? ENOTSUP : errno;
        report.install_status = classify_seccomp_install_error(report.install_error);
        if (report.install_status == kSeccompForeignListener) {
            report.install_status = kSeccompFailure;
        }
        if (kAuditArch == 0) {
            report.install_status = kSeccompUnsupported;
        }
    } else if (sizes.seccomp_notif != sizeof(struct seccomp_notif)
            || sizes.seccomp_notif_resp != sizeof(struct seccomp_notif_resp)
            || sizes.seccomp_data != sizeof(struct seccomp_data)) {
        report.install_status = kSeccompUnsupported;
        report.install_error = EPROTONOSUPPORT;
    } else if (my_prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1
            && my_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        const int err = raw_last_error();
        report.install_error = err;
        report.install_status = (err == EPERM || err == EACCES)
                ? kSeccompRestricted
                : kSeccompFailure;
    } else {
        int install_err = 0;
        const int listener_fd = install_getpriority_listener(&install_err);
        if (listener_fd < 0) {
            report.install_status = classify_seccomp_install_error(install_err);
            report.install_error = install_err;
        } else {
            report.install_status = kSeccompInstalled;
            service_seccomp_queries(
                    listener_fd, report_fd,
                    ctx->first_uid, ctx->last_uid,
                    ctx->raw_sigaction, report);
            my_close(listener_fd);
        }
    }

    return riskengine::util::write_child_report(report_fd, &report, sizeof(report)) ? 0 : 1;
}

bool valid_seccomp_report(const SeccompProbeReport &r, int first_uid, int last_uid) {
    const int span = last_uid - first_uid + 1;
    if (r.version != kSeccompReportVersion
            || r.install_status < kSeccompInstalled
            || r.install_status > kSeccompInstallTrapped
            || r.kernel_major < 0 || r.kernel_minor < 0
            || r.queried < 0 || r.queried > span
            || r.notified < 0 || r.notified > span
            || r.query_outcome < kQueryComplete || r.query_outcome > kQueryNotRun
            || (r.self_notified != 0 && r.self_notified != 1)) {
        return false;
    }
    if (r.install_status == kSeccompForeignListener && r.install_error != EBUSY) return false;
    if (r.install_status == kSeccompInstallTrapped && r.install_error != SIGSYS) return false;
    if (r.query_outcome == kQueryTrapped && r.query_error != SIGSYS) return false;
    if (r.install_status != kSeccompInstalled) {
        return r.queried == 0 && r.notified == 0
                && r.first_suppressed == -1 && r.last_suppressed == -1
                && r.query_outcome == kQueryNotRun && r.self_notified == 0;
    }
    if (r.install_error != 0) return false;
    if (r.query_outcome != kQueryComplete) {
        return r.query_outcome != kQueryNotRun
                && r.queried == 0
                && r.first_suppressed == -1 && r.last_suppressed == -1;
    }
    if (r.query_error != 0 || r.queried != span || r.notified > r.queried) return false;
    if (r.notified == r.queried) {
        const int self_uid = static_cast<int>(getuid());
        const bool self_expected = (self_uid >= first_uid && self_uid <= last_uid);
        return r.first_suppressed == -1 && r.last_suppressed == -1
                && (!self_expected || r.self_notified == 1);
    }
    const int missing = r.queried - r.notified;
    if (r.first_suppressed < first_uid || r.last_suppressed > last_uid
            || r.last_suppressed < r.first_suppressed
            || missing > (r.last_suppressed - r.first_suppressed + 1)
            || (missing == 1 && r.first_suppressed != r.last_suppressed)) {
        return false;
    }
    return true;
}

const char *install_status_name(int32_t s) {
    switch (s) {
        case kSeccompInstalled:       return "installed";
        case kSeccompForeignListener: return "foreign_listener";
        case kSeccompUnsupported:     return "unsupported";
        case kSeccompRestricted:      return "restricted";
        case kSeccompInstallTrapped:  return "install_trapped";
        default:                      return "failure";
    }
}

const char *query_outcome_name(int32_t o) {
    switch (o) {
        case kQueryComplete: return "complete";
        case kQueryTrapped:  return "trapped";
        case kQuerySignaled: return "signaled";
        case kQueryTimeout:  return "timeout";
        case kQueryNotRun:   return "not_run";
        default:             return "failure";
    }
}

}  // namespace

std::string native_scan_active_app_uids(int first_uid, int last_uid) {
    if (first_uid < 0 || last_uid < first_uid
            || static_cast<int64_t>(last_uid) - first_uid >= kMaxUidSpan) {
        return payload_codec::PayloadBuilder(payload_codec::Status::ERROR, EINVAL)
                .add_header("reason", "invalid_uid_range")
                .build();
    }

    const ActiveUidContext ctx{first_uid, last_uid};
    std::array<uint8_t, sizeof(ActiveUidReport)> buf{};
    const auto outcome = riskengine::util::run_disposable_child(
            buf.data(),
            buf.size(),
            riskengine::util::ChildDeadlines{
                    std::chrono::milliseconds{1500},
                    std::chrono::milliseconds{250}
            },
            &active_uid_child_body,
            &ctx);

    using riskengine::util::ChildEnd;
    if (outcome.end != ChildEnd::kExited
            || outcome.exit_status != 0
            || outcome.report_length != sizeof(ActiveUidReport)) {
        const int err = (outcome.end == ChildEnd::kTimedOut || outcome.end == ChildEnd::kNotReaped)
                ? ETIMEDOUT
                : (outcome.signal != 0 ? outcome.signal : (outcome.error != 0 ? outcome.error : EIO));
        const payload_codec::Status status = (outcome.end == ChildEnd::kSeccompTrapped)
                ? payload_codec::Status::RESTRICTED
                : payload_codec::Status::ERROR;
        return payload_codec::PayloadBuilder(status, err)
                .add_header("reason", outcome.end == ChildEnd::kSeccompTrapped
                        ? "seccomp_trapped" : "child_failed")
                .build();
    }

    ActiveUidReport report{};
    std::memcpy(&report, buf.data(), sizeof(report));
    const int span = last_uid - first_uid + 1;
    if (report.version != kActiveReportVersion
            || report.status < kScanComplete || report.status > kScanError
            || report.checked < 0 || report.checked > span
            || report.active_count < 0 || report.active_count > report.checked) {
        return payload_codec::PayloadBuilder(payload_codec::Status::ERROR, EPROTO)
                .add_header("reason", "invalid_report")
                .build();
    }

    payload_codec::Status frame_status = payload_codec::Status::OK;
    if (report.status == kScanRestricted) {
        frame_status = payload_codec::Status::RESTRICTED;
    } else if (report.status == kScanUnsupported) {
        frame_status = payload_codec::Status::UNSUPPORTED;
    } else if (report.status == kScanError) {
        frame_status = payload_codec::Status::ERROR;
    }

    payload_codec::PayloadBuilder builder(frame_status, report.err_no);
    builder.add_header_int("first_uid", first_uid)
            .add_header_int("last_uid", last_uid)
            .add_header_int("checked", report.checked)
            .add_header_int("active_count", report.active_count)
            .add_header("complete", report.status == kScanComplete ? "1" : "0");

    if (frame_status == payload_codec::Status::OK) {
        for (int i = 0; i < span; ++i) {
            if ((report.bitmap[i / 8] & static_cast<uint8_t>(1u << (i % 8))) != 0) {
                payload_codec::RecordBuilder rec;
                rec.add("kind", "active_uid").add_int("uid", first_uid + i);
                builder.add_record(rec);
            }
        }
    }
    return builder.build();
}

std::string native_probe_seccomp_uid_filter(int first_uid, int last_uid) {
    if (first_uid < 0 || last_uid < first_uid
            || static_cast<int64_t>(last_uid) - first_uid >= kMaxUidSpan) {
        return payload_codec::PayloadBuilder(payload_codec::Status::ERROR, EINVAL)
                .add_header("reason", "invalid_uid_range")
                .build();
    }

    const SeccompProbeContext ctx{first_uid, last_uid, resolve_raw_sigaction()};
    std::array<uint8_t, sizeof(SeccompProbeReport)> buf{};
    const auto outcome = riskengine::util::run_disposable_child(
            buf.data(),
            buf.size(),
            riskengine::util::ChildDeadlines{
                    std::chrono::milliseconds{2500},
                    std::chrono::milliseconds{250}
            },
            &seccomp_probe_child_body,
            &ctx);

    SeccompProbeReport report{};
    report.version = kSeccompReportVersion;
    report.first_suppressed = -1;
    report.last_suppressed = -1;
    report.query_outcome = kQueryNotRun;

    using riskengine::util::ChildEnd;
    if (outcome.end == ChildEnd::kExited
            && outcome.exit_status == 0
            && outcome.report_length == sizeof(SeccompProbeReport)) {
        std::memcpy(&report, buf.data(), sizeof(report));
        if (!valid_seccomp_report(report, first_uid, last_uid)) {
            report = SeccompProbeReport{};
            report.version = kSeccompReportVersion;
            report.first_suppressed = -1;
            report.last_suppressed = -1;
            report.query_outcome = kQueryNotRun;
            report.install_status = kSeccompFailure;
            report.install_error = EPROTO;
        }
    } else if (outcome.end == ChildEnd::kSeccompTrapped) {
        report.install_status = kSeccompInstallTrapped;
        report.install_error = SIGSYS;
    } else {
        report.install_status = kSeccompFailure;
        if (outcome.end == ChildEnd::kTimedOut || outcome.end == ChildEnd::kNotReaped) {
            report.install_error = ETIMEDOUT;
        } else if (outcome.signal != 0) {
            report.install_error = outcome.signal;
        } else {
            report.install_error = outcome.error != 0 ? outcome.error : EIO;
        }
    }

    payload_codec::Status frame_status = payload_codec::Status::OK;
    int frame_errno = 0;
    if (report.install_status == kSeccompUnsupported) {
        frame_status = payload_codec::Status::UNSUPPORTED;
        frame_errno = report.install_error;
    } else if (report.install_status == kSeccompRestricted) {
        frame_status = payload_codec::Status::RESTRICTED;
        frame_errno = report.install_error;
    } else if (report.install_status == kSeccompFailure) {
        frame_status = payload_codec::Status::ERROR;
        frame_errno = report.install_error;
    }

    payload_codec::RecordBuilder rec;
    rec.add("kind", "seccomp_uid")
            .add("install_status", install_status_name(report.install_status))
            .add_int("install_error", report.install_error)
            .add_int("kernel_major", report.kernel_major)
            .add_int("kernel_minor", report.kernel_minor)
            .add_int("queried", report.queried)
            .add_int("notified", report.notified)
            .add_int("first_suppressed", report.first_suppressed)
            .add_int("last_suppressed", report.last_suppressed)
            .add("query_outcome", query_outcome_name(report.query_outcome))
            .add_int("query_error", report.query_error)
            .add_int("self_notified", report.self_notified);

    return payload_codec::PayloadBuilder(frame_status, frame_errno)
            .add_record(rec)
            .build();
}
