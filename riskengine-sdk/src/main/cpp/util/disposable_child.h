#ifndef RISKENGINE_DISPOSABLE_CHILD_H
#define RISKENGINE_DISPOSABLE_CHILD_H

#include <chrono>
#include <cstddef>
#include <cstdint>

namespace riskengine {
namespace util {

constexpr int kChildSetupFailedExitStatus = 124;
constexpr int kChildSeccompTrappedExitStatus = 125;

enum class ChildEnd {
    kNotStarted,      // pipe2 or fork failed; error holds errno
    kSetupFailed,     // child failed to install SIGSYS trap handler
    kExited,          // child returned normally; exit_status holds body return code (< 124)
    kSignaled,        // child died by signal; signal holds WTERMSIG
    kSeccompTrapped,  // child hit SIGSYS and exited with status 125
    kTimedOut,        // child exceeded run deadline and was terminated via SIGKILL
    kNotReaped,       // child remained uninterruptible past reap deadline after SIGKILL
    kWaitFailed,      // waitpid failed; error holds errno
};

struct ChildOutcome {
    ChildEnd end = ChildEnd::kNotStarted;
    int exit_status = 0;
    int signal = 0;
    int error = 0;
    std::size_t report_length = 0;
};

struct ChildDeadlines {
    std::chrono::milliseconds run{1000};
    std::chrono::milliseconds reap{250};
};

using ChildBody = int (*)(const void *context, int report_fd);

/**
 * Async-signal-safe helper for a disposable child body to write report bytes
 * into report_fd without dynamic allocation. Returns true if all bytes wrote.
 */
bool write_child_report(int report_fd, const void *data, std::size_t length);

/**
 * Runs body(context, report_fd) inside a short-lived forked child process.
 *
 * Safety guarantees:
 * - Serialized process-wide (concurrency = 1) via a mutex to avoid fork storms.
 * - Resolves Bionic's raw sigaction BEFORE fork() so the child never calls
 *   ART libsigchain or dlopen() post-fork.
 * - Child resets SIGSEGV/SIGBUS/SIGABRT/SIGILL to SIG_DFL and installs a
 *   SIGSYS handler terminating immediately with status 125 to prevent debuggerd tombstones.
 * - Uses pipe2(O_CLOEXEC | O_NONBLOCK) + poll() with dual deadlines (run +
 *   SIGKILL + bounded WNOHANG reap) so D-state hangs never block the parent.
 *
 * The child body MUST call only async-signal-safe operations, must not
 * allocate, and should return an exit code in [0, 123] (124/125 are reserved).
 */
ChildOutcome run_disposable_child(uint8_t *report_buf,
                                  std::size_t report_capacity,
                                  ChildDeadlines deadlines,
                                  ChildBody body,
                                  const void *context);

template <typename Body>
ChildOutcome run_disposable_child(uint8_t *report_buf,
                                  std::size_t report_capacity,
                                  ChildDeadlines deadlines,
                                  const Body &body) {
    return run_disposable_child(
            report_buf,
            report_capacity,
            deadlines,
            [](const void *ctx, int report_fd) -> int {
                return (*static_cast<const Body *>(ctx))(report_fd);
            },
            static_cast<const void *>(&body));
}

}  // namespace util
}  // namespace riskengine

#endif  // RISKENGINE_DISPOSABLE_CHILD_H
