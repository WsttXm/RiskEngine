package com.wsttxm.riskenginesdk.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public final class ShellExecutor {
    private static final long DEFAULT_TIMEOUT_MS = 2_000;
    private static final int MAX_OUTPUT_CHARS = 256 * 1024;
    private static final long READER_JOIN_TIMEOUT_MS = 500;

    private ShellExecutor() {}

    public static String execute(String command) {
        return execute(command, DEFAULT_TIMEOUT_MS);
    }

    public static String execute(String command, long timeoutMs) {
        if (command == null || command.isBlank() || timeoutMs <= 0) {
            return "";
        }

        Process process = null;
        Thread outputReader = null;
        try {
            process = new ProcessBuilder("/system/bin/sh", "-c", command)
                    .redirectErrorStream(true)
                    .start();
            process.getOutputStream().close();

            StringBuffer output = new StringBuffer();
            Process runningProcess = process;
            outputReader = new Thread(
                    () -> drainOutput(runningProcess, output),
                    "risk-shell-output");
            outputReader.setDaemon(true);
            outputReader.start();

            if (!process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
                terminate(process);
                awaitReader(outputReader);
                CLog.w("Shell command timed out");
                return "";
            }

            awaitReader(outputReader);
            if (process.exitValue() != 0) {
                CLog.w("Shell command failed with exit code " + process.exitValue());
                return "";
            }
            return output.toString();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            if (process != null) {
                terminate(process);
            }
            return "";
        } catch (Exception e) {
            if (process != null) {
                terminate(process);
            }
            CLog.e("ShellExecutor failed", e);
            return "";
        }
    }

    private static void drainOutput(Process process, StringBuffer output) {
        char[] buffer = new char[4_096];
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                process.getInputStream(), StandardCharsets.UTF_8))) {
            int count;
            while ((count = reader.read(buffer)) != -1) {
                int remaining = MAX_OUTPUT_CHARS - output.length();
                if (remaining > 0) {
                    output.append(buffer, 0, Math.min(count, remaining));
                }
            }
        } catch (IOException ignored) {
            // Destroying a timed-out process closes the stream asynchronously.
        }
    }

    private static void awaitReader(Thread reader) throws InterruptedException {
        if (reader == null) {
            return;
        }
        reader.join(READER_JOIN_TIMEOUT_MS);
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
        } catch (IOException ignored) {
            // Best effort cleanup.
        }
    }
}
