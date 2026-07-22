package com.wsttxm.riskenginesdk.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public final class ShellExecutor {
    private static final long DEFAULT_TIMEOUT_MS = 2_000;
    private static final int MAX_OUTPUT_CHARS = 256 * 1024;
    private static final long READER_JOIN_TIMEOUT_MS = 500;

    public enum Status {
        SUCCESS,
        INVALID_COMMAND,
        TIMEOUT,
        NON_ZERO_EXIT,
        INTERRUPTED,
        EXECUTION_ERROR
    }

    /** Immutable outcome that keeps an empty successful response distinct from failure. */
    public static final class Result {
        private final Status status;
        private final String stdout;
        private final String stderr;
        private final Integer exitCode;
        private final long durationMs;
        private final String failureReason;

        private Result(Status status, String stdout, String stderr, Integer exitCode,
                       long durationMs, String failureReason) {
            this.status = status;
            this.stdout = stdout == null ? "" : stdout;
            this.stderr = stderr == null ? "" : stderr;
            this.exitCode = exitCode;
            this.durationMs = Math.max(0, durationMs);
            this.failureReason = failureReason;
        }

        public Status getStatus() { return status; }
        public String getStdout() { return stdout; }
        public String getStderr() { return stderr; }
        public Integer getExitCode() { return exitCode; }
        public long getDurationMs() { return durationMs; }
        public String getFailureReason() { return failureReason; }
        public boolean isSuccess() { return status == Status.SUCCESS; }
    }

    private ShellExecutor() {}

    /**
     * Compatibility helper. Prefer {@link #executeResult(String)} so callers do
     * not confuse execution failure with a successful command that has no output.
     */
    @Deprecated
    public static String execute(String command) {
        return executeResult(command).getStdout();
    }

    /** @see #execute(String) */
    @Deprecated
    public static String execute(String command, long timeoutMs) {
        return executeResult(command, timeoutMs).getStdout();
    }

    public static Result executeResult(String command) {
        return executeResult(command, DEFAULT_TIMEOUT_MS);
    }

    public static Result executeResult(String command, long timeoutMs) {
        long startNanos = System.nanoTime();
        if (command == null || command.isBlank() || timeoutMs <= 0) {
            return result(Status.INVALID_COMMAND, "", "", null, startNanos,
                    "command_or_timeout_invalid");
        }

        Process process = null;
        Thread stdoutReader = null;
        Thread stderrReader = null;
        StringBuffer stdout = new StringBuffer();
        StringBuffer stderr = new StringBuffer();
        try {
            process = new ProcessBuilder("/system/bin/sh", "-c", command).start();
            process.getOutputStream().close();

            stdoutReader = startReader(process.getInputStream(), stdout, "risk-shell-stdout");
            stderrReader = startReader(process.getErrorStream(), stderr, "risk-shell-stderr");

            if (!process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
                terminate(process);
                awaitReaders(stdoutReader, stderrReader);
                CLog.w("Shell command timed out");
                return result(Status.TIMEOUT, stdout.toString(), stderr.toString(), null,
                        startNanos, "timeout");
            }

            awaitReaders(stdoutReader, stderrReader);
            int exitCode = process.exitValue();
            if (exitCode != 0) {
                CLog.w("Shell command failed with exit code " + exitCode);
                return result(Status.NON_ZERO_EXIT, stdout.toString(), stderr.toString(),
                        exitCode, startNanos, "exit_code_" + exitCode);
            }
            return result(Status.SUCCESS, stdout.toString(), stderr.toString(),
                    exitCode, startNanos, null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            if (process != null) {
                terminate(process);
            }
            return result(Status.INTERRUPTED, stdout.toString(), stderr.toString(), null,
                    startNanos, "interrupted");
        } catch (Exception e) {
            if (process != null) {
                terminate(process);
            }
            CLog.e("ShellExecutor failed", e);
            return result(Status.EXECUTION_ERROR, stdout.toString(), stderr.toString(), null,
                    startNanos, e.getClass().getSimpleName());
        }
    }

    private static Result result(Status status, String stdout, String stderr, Integer exitCode,
                                 long startNanos, String failureReason) {
        long durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
        return new Result(status, stdout, stderr, exitCode, durationMs, failureReason);
    }

    private static Thread startReader(InputStream stream, StringBuffer output, String name) {
        Thread thread = new Thread(() -> drainOutput(stream, output), name);
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private static void drainOutput(InputStream stream, StringBuffer output) {
        char[] buffer = new char[4_096];
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                stream, StandardCharsets.UTF_8))) {
            int count;
            while ((count = reader.read(buffer)) != -1) {
                int remaining = MAX_OUTPUT_CHARS - output.length();
                if (remaining > 0) {
                    output.append(buffer, 0, Math.min(count, remaining));
                }
            }
        } catch (IOException ignored) {
            // Destroying a timed-out process closes its streams asynchronously.
        }
    }

    private static void awaitReaders(Thread... readers) throws InterruptedException {
        for (Thread reader : readers) {
            if (reader != null) {
                reader.join(READER_JOIN_TIMEOUT_MS);
            }
        }
    }

    private static void terminate(Process process) {
        process.destroy();
        try {
            if (!process.waitFor(100, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
            }
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
        }
        try {
            process.getInputStream().close();
            process.getErrorStream().close();
        } catch (IOException ignored) {
            // Best effort cleanup.
        }
    }
}
