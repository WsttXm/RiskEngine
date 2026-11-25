#include "disposable_child.h"

#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__ANDROID__)
#include "obf_str.h"
#include "raw_syscall.h"
#endif

namespace riskengine {
namespace util {

namespace {

using Clock = std::chrono::steady_clock;
using SigactionFn = int (*)(int, const struct sigaction *, struct sigaction *);
using SigprocmaskFn = int (*)(int, const sigset_t *, sigset_t *);

struct RawSignalFns {
    SigactionFn sigaction_fn = nullptr;
    SigprocmaskFn sigprocmask_fn = nullptr;
};

constexpr timespec kReapPollInterval{0, 1000000};  // 1 ms
constexpr std::chrono::milliseconds kMinDeadline{1};
constexpr std::chrono::milliseconds kMaxDeadline{60000};  // 60 s upper bound against chrono overflow

std::chrono::milliseconds clamp_deadline(std::chrono::milliseconds value) {
    if (value < kMinDeadline) {
        return kMinDeadline;
    }
    if (value > kMaxDeadline) {
        return kMaxDeadline;
    }
    return value;
}

pthread_mutex_t g_fork_mutex = PTHREAD_MUTEX_INITIALIZER;

class ScopedPthreadLock {
public:
    explicit ScopedPthreadLock(pthread_mutex_t *mutex) : mutex_(mutex) {
        pthread_mutex_lock(mutex_);
    }
    ~ScopedPthreadLock() {
        pthread_mutex_unlock(mutex_);
    }
    ScopedPthreadLock(const ScopedPthreadLock &) = delete;
    ScopedPthreadLock &operator=(const ScopedPthreadLock &) = delete;

private:
    pthread_mutex_t *mutex_;
};

// Resolve raw Bionic sigaction & sigprocmask BEFORE fork() to bypass ART's libsigchain interposer.
// Calling libsigchain wrappers in a forked child can unwind/allocate and deadlock.
RawSignalFns resolve_raw_signal_fns() {
#if defined(__ANDROID__)
    static const RawSignalFns resolved = []() -> RawSignalFns {
        RawSignalFns fns{};
        auto libc_name = OBF("libc.so");
        void *libc = dlopen(libc_name.c_str(), RTLD_NOW | RTLD_NOLOAD);
        if (libc == nullptr) {
            return fns;
        }
        auto sigaction_sym = OBF("sigaction");
        auto sigprocmask_sym = OBF("sigprocmask");
        fns.sigaction_fn = reinterpret_cast<SigactionFn>(dlsym(libc, sigaction_sym.c_str()));
        fns.sigprocmask_fn = reinterpret_cast<SigprocmaskFn>(dlsym(libc, sigprocmask_sym.c_str()));
        dlclose(libc);
        return fns;
    }();
    return resolved;
#else
    return RawSignalFns{&::sigaction, &::sigprocmask};
#endif
}

[[noreturn]] void terminate_child_now(int status) {
#if defined(__ANDROID__) && defined(__NR_exit_group)
    raw_syscall1(__NR_exit_group, status);
#endif
    void (*const immediate_terminate)(int) = &::_exit;
    immediate_terminate(status);
    __builtin_unreachable();
}

void sigsys_trap_handler(int /*signo*/) {
    terminate_child_now(kChildSeccompTrappedExitStatus);
}

bool setup_child_signals(const RawSignalFns &fns) {
    if (fns.sigaction_fn == nullptr || fns.sigprocmask_fn == nullptr) {
        return false;
    }

    sigset_t unblock{};
    sigemptyset(&unblock);
    sigaddset(&unblock, SIGSEGV);
    sigaddset(&unblock, SIGBUS);
    sigaddset(&unblock, SIGABRT);
    sigaddset(&unblock, SIGILL);
    sigaddset(&unblock, SIGSYS);
    fns.sigprocmask_fn(SIG_UNBLOCK, &unblock, nullptr);

    const int default_signals[] = {SIGSEGV, SIGBUS, SIGABRT, SIGILL};
    for (int signo : default_signals) {
        struct sigaction action{};
        action.sa_handler = SIG_DFL;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
        fns.sigaction_fn(signo, &action, nullptr);
    }

    struct sigaction sys_action{};
    sys_action.sa_handler = &sigsys_trap_handler;
    sigemptyset(&sys_action.sa_mask);
    sys_action.sa_flags = 0;
    return fns.sigaction_fn(SIGSYS, &sys_action, nullptr) == 0;
}

[[noreturn]] void run_child_process(int report_fd,
                                    const RawSignalFns &fns,
                                    ChildBody body,
                                    const void *context) {
    if (!setup_child_signals(fns)) {
        terminate_child_now(kChildSetupFailedExitStatus);
    }
    int status = body(context, report_fd);
    if (status < 0) {
        status = 1;
    } else if (status >= kChildSetupFailedExitStatus) {
        status = kChildSetupFailedExitStatus - 1;
    }
    terminate_child_now(status);
}

int open_nonblocking_cloexec_pipe(int pipe_fds[2]) {
#if defined(__linux__) || defined(__ANDROID__)
    return pipe2(pipe_fds, O_CLOEXEC | O_NONBLOCK);
#else
    if (pipe(pipe_fds) != 0) {
        return -1;
    }
    for (int i = 0; i < 2; ++i) {
        int fd_flags = fcntl(pipe_fds[i], F_GETFD);
        if (fd_flags < 0 || fcntl(pipe_fds[i], F_SETFD, fd_flags | FD_CLOEXEC) != 0) {
            int saved = errno;
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            errno = saved;
            return -1;
        }
        int status_flags = fcntl(pipe_fds[i], F_GETFL);
        if (status_flags < 0 || fcntl(pipe_fds[i], F_SETFL, status_flags | O_NONBLOCK) != 0) {
            int saved = errno;
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            errno = saved;
            return -1;
        }
    }
    return 0;
#endif
}

void drain_report_pipe(int read_fd,
                       uint8_t *report_buf,
                       std::size_t report_capacity,
                       std::size_t &length,
                       Clock::time_point deadline) {
    uint8_t overflow[512]{};
    while (true) {
        const auto now = Clock::now();
        if (now >= deadline) {
            return;
        }
        const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        int timeout_ms = 1;
        if (remaining.count() > 0) {
            timeout_ms = (remaining.count() > INT_MAX)
                                 ? INT_MAX
                                 : static_cast<int>(remaining.count());
        }

        struct pollfd pfd{};
        pfd.fd = read_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        const int ready = poll(&pfd, 1, timeout_ms);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (ready == 0) {
            continue;
        }

        if ((pfd.revents & (POLLIN | POLLHUP)) != 0) {
            while (true) {
                if (Clock::now() >= deadline) {
                    return;
                }
                const bool full = (report_buf == nullptr || length >= report_capacity);
                const ssize_t count = full
                                              ? read(read_fd, overflow, sizeof(overflow))
                                              : read(read_fd, report_buf + length,
                                                     report_capacity - length);
                if (count > 0) {
                    if (!full) {
                        length += static_cast<std::size_t>(count);
                    }
                    continue;
                }
                if (count == 0) {
                    return;  // EOF: child closed write end
                }
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                return;
            }
        }

        if ((pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
            return;
        }
    }
}

enum class ReapResult {
    kReaped,
    kRunning,
    kFailed,
};

ReapResult reap_until(pid_t pid,
                      int &status,
                      int &err_out,
                      Clock::time_point deadline) {
    while (true) {
        const pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            return ReapResult::kReaped;
        }
        if (waited < 0) {
            if (errno == EINTR) {
                continue;
            }
            err_out = errno;
            return ReapResult::kFailed;
        }
        if (Clock::now() >= deadline) {
            return ReapResult::kRunning;
        }
        nanosleep(&kReapPollInterval, nullptr);
    }
}

ChildOutcome classify_status(int status, ChildOutcome outcome) {
    if (WIFSIGNALED(status)) {
        outcome.end = ChildEnd::kSignaled;
        outcome.signal = WTERMSIG(status);
        return outcome;
    }
    if (WIFEXITED(status)) {
        const int code = WEXITSTATUS(status);
        if (code == kChildSeccompTrappedExitStatus) {
            outcome.end = ChildEnd::kSeccompTrapped;
        } else if (code == kChildSetupFailedExitStatus) {
            outcome.end = ChildEnd::kSetupFailed;
        } else {
            outcome.end = ChildEnd::kExited;
            outcome.exit_status = code;
        }
        return outcome;
    }
    outcome.end = ChildEnd::kWaitFailed;
    return outcome;
}

}  // namespace

bool write_child_report(int report_fd, const void *data, std::size_t length) {
    if (report_fd < 0 || (data == nullptr && length > 0)) {
        return false;
    }
    const auto *bytes = static_cast<const uint8_t *>(data);
    std::size_t written = 0;
    int eagain_retries = 0;
    while (written < length) {
        const ssize_t n = write(report_fd, bytes + written, length - written);
        if (n > 0) {
            written += static_cast<std::size_t>(n);
            eagain_retries = 0;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (++eagain_retries > 200) {
                return false;
            }
            struct pollfd pfd{};
            pfd.fd = report_fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            poll(&pfd, 1, 5);
            continue;
        }
        return false;
    }
    return true;
}

ChildOutcome run_disposable_child(uint8_t *report_buf,
                                  std::size_t report_capacity,
                                  ChildDeadlines deadlines,
                                  ChildBody body,
                                  const void *context) {
    ChildOutcome outcome{};
    if (body == nullptr) {
        outcome.error = EINVAL;
        return outcome;
    }

    // Concurrency = 1 across the entire process.
    ScopedPthreadLock guard(&g_fork_mutex);

    // Resolve raw Bionic sigaction & sigprocmask BEFORE fork().
    const RawSignalFns signal_fns = resolve_raw_signal_fns();
    if (signal_fns.sigaction_fn == nullptr || signal_fns.sigprocmask_fn == nullptr) {
        outcome.end = ChildEnd::kSetupFailed;
        outcome.error = ENOSYS;
        return outcome;
    }

    int pipe_fds[2] = {-1, -1};
    if (open_nonblocking_cloexec_pipe(pipe_fds) != 0) {
        outcome.error = errno;
        return outcome;
    }

    const pid_t pid = fork();
    if (pid < 0) {
        outcome.error = errno;
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return outcome;
    }

    if (pid == 0) {
        close(pipe_fds[0]);
        run_child_process(pipe_fds[1], signal_fns, body, context);
    }

    close(pipe_fds[1]);

    const auto run_budget = clamp_deadline(deadlines.run);
    const auto reap_budget = clamp_deadline(deadlines.reap);

    const Clock::time_point run_deadline = Clock::now() + run_budget;
    drain_report_pipe(pipe_fds[0], report_buf, report_capacity,
                      outcome.report_length, run_deadline);

    int status = 0;
    ReapResult reap = reap_until(pid, status, outcome.error, run_deadline);
    const bool timed_out = (reap == ReapResult::kRunning);
    if (timed_out) {
        kill(pid, SIGKILL);
        reap = reap_until(pid, status, outcome.error, Clock::now() + reap_budget);
    }
    close(pipe_fds[0]);

    switch (reap) {
        case ReapResult::kFailed:
            outcome.end = ChildEnd::kWaitFailed;
            return outcome;
        case ReapResult::kRunning:
            outcome.end = ChildEnd::kNotReaped;
            return outcome;
        case ReapResult::kReaped:
            break;
    }

    if (timed_out) {
        outcome.end = ChildEnd::kTimedOut;
        return outcome;
    }
    return classify_status(status, outcome);
}

}  // namespace util
}  // namespace riskengine
