package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Crash-safe execution utility with fine-grained per-call timeouts, blocked-thread
 * stacktrace capture, and nested-call starvation protection.
 */
public final class SafeExecutor {

    public static final long TIMEOUT_CRITICAL_MS = ScanTier.CRITICAL.getDefaultTimeoutMs();
    public static final long TIMEOUT_SHORT_MS = ScanTier.FAST.getDefaultTimeoutMs();
    public static final long TIMEOUT_LONG_MS = ScanTier.POSTPONED.getDefaultTimeoutMs();

    private static final int MAX_STACK_FRAMES_LOGGED = 8;

    private static final ThreadLocal<Boolean> RUNNING_INSIDE_SAFE = new ThreadLocal<>();

    private static final Object EXECUTOR_LOCK = new Object();
    private static volatile ThreadPoolExecutor sharedExecutor;

    private SafeExecutor() {}

    /**
     * Exception thrown/returned when a {@link #safeWithTimeout} task exceeds its time budget.
     * Preserves the blocked worker thread's {@link StackTraceElement} snapshot for diagnostics.
     */
    public static final class ExecutionTimeoutException extends Exception {
        private final List<StackTraceElement> executionThreadStackTrace;

        public ExecutionTimeoutException(TimeoutException cause,
                                         StackTraceElement[] stackTrace) {
            super(buildMessage(cause, stackTrace), cause);
            if (stackTrace == null || stackTrace.length == 0) {
                this.executionThreadStackTrace = Collections.emptyList();
            } else {
                this.executionThreadStackTrace = Collections.unmodifiableList(
                        Arrays.asList(Arrays.copyOf(stackTrace, stackTrace.length)));
            }
        }

        public List<StackTraceElement> getExecutionThreadStackTrace() {
            return executionThreadStackTrace;
        }

        private static String buildMessage(TimeoutException cause,
                                           StackTraceElement[] stackTrace) {
            StringBuilder sb = new StringBuilder("Execution timed out");
            if (cause != null && cause.getMessage() != null) {
                sb.append(": ").append(cause.getMessage());
            }
            if (stackTrace != null && stackTrace.length > 0) {
                sb.append("; worker stack=[");
                int limit = Math.min(stackTrace.length, MAX_STACK_FRAMES_LOGGED);
                for (int i = 0; i < limit; i++) {
                    if (i > 0) sb.append(" <- ");
                    sb.append(stackTrace[i]);
                }
                if (stackTrace.length > limit) {
                    sb.append(" ...(+").append(stackTrace.length - limit).append(")");
                }
                sb.append(']');
            }
            return sb.toString();
        }
    }

    /** Immutable outcome wrapper for {@link #safe} and {@link #safeWithTimeout}. */
    public static final class SafeResult<T> {
        private final T value;
        private final Throwable error;
        private final boolean timedOut;
        private final List<StackTraceElement> blockedStackTrace;
        private final boolean nestedCallDetected;

        private SafeResult(T value,
                           Throwable error,
                           boolean timedOut,
                           StackTraceElement[] blockedStackTrace,
                           boolean nestedCallDetected) {
            this.value = value;
            this.error = error;
            this.timedOut = timedOut;
            if (blockedStackTrace == null || blockedStackTrace.length == 0) {
                this.blockedStackTrace = Collections.emptyList();
            } else {
                this.blockedStackTrace = Collections.unmodifiableList(
                        Arrays.asList(Arrays.copyOf(blockedStackTrace, blockedStackTrace.length)));
            }
            this.nestedCallDetected = nestedCallDetected;
        }

        public static <T> SafeResult<T> success(T value) {
            return new SafeResult<>(value, null, false, null, false);
        }

        public static <T> SafeResult<T> success(T value, boolean nestedCallDetected) {
            return new SafeResult<>(value, null, false, null, nestedCallDetected);
        }

        public static <T> SafeResult<T> failure(Throwable error) {
            return new SafeResult<>(null, error, false, null, false);
        }

        public static <T> SafeResult<T> failure(Throwable error, boolean nestedCallDetected) {
            return new SafeResult<>(null, error, false, null, nestedCallDetected);
        }

        public static <T> SafeResult<T> timeout(ExecutionTimeoutException error,
                                                StackTraceElement[] stackTrace) {
            return new SafeResult<>(null, error, true, stackTrace, false);
        }

        public boolean isSuccess() {
            return error == null;
        }

        public T getOrNull() {
            return isSuccess() ? value : null;
        }

        public T getOrDefault(T fallback) {
            return isSuccess() && value != null ? value : fallback;
        }

        public Throwable getError() {
            return error;
        }

        public boolean isTimedOut() {
            return timedOut;
        }

        public List<StackTraceElement> getBlockedStackTrace() {
            return blockedStackTrace;
        }

        public boolean isNestedCallDetected() {
            return nestedCallDetected;
        }
    }

    /** Executes {@code task} inline, catching {@code Exception | LinkageError | OutOfMemoryError}. */
    public static <T> SafeResult<T> safe(Callable<T> task) {
        if (task == null) {
            return SafeResult.failure(new IllegalArgumentException("task must not be null"));
        }
        try {
            return SafeResult.success(task.call());
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return SafeResult.failure(e);
        }
    }

    /** Executes {@code task} using the tier's default timeout budget. */
    public static <T> SafeResult<T> safeWithTimeout(ScanTier tier, Callable<T> task) {
        long timeoutMs = tier == null ? TIMEOUT_SHORT_MS : tier.getDefaultTimeoutMs();
        return safeWithTimeout(timeoutMs, task);
    }

    /** Executes {@code task} on the shared daemon pool with a per-call timeout in milliseconds. */
    public static <T> SafeResult<T> safeWithTimeout(long timeoutMs, Callable<T> task) {
        return safeWithTimeout(getSharedExecutor(), timeoutMs, task);
    }

    /**
     * Runs {@code task} inline via {@link #safe(Callable)} when already executing inside a
     * {@code safeWithTimeout} worker thread (e.g. a collector managed by {@link TaskScheduler}),
     * otherwise guards it with {@link #safeWithTimeout(long, Callable)}.
     */
    public static <T> SafeResult<T> safeWithTimeoutOrInline(long timeoutMs, Callable<T> task) {
        if (isInsideSafeWithTimeout()) {
            return safe(task);
        }
        return safeWithTimeout(timeoutMs, task);
    }

    /**
     * Executes {@code task} on {@code executor} with a strict timeout.
     *
     * <p>If already running inside a {@code safeWithTimeout} worker thread, runs {@code task}
     * inline instead of re-submitting to avoid thread-pool starvation and marks
     * {@link SafeResult#isNestedCallDetected()}.
     */
    public static <T> SafeResult<T> safeWithTimeout(ExecutorService executor,
                                                    long timeoutMs,
                                                    Callable<T> task) {
        if (task == null) {
            return SafeResult.failure(new IllegalArgumentException("task must not be null"));
        }
        if (executor == null) {
            return SafeResult.failure(new IllegalArgumentException("executor must not be null"));
        }
        long effectiveTimeoutMs = Math.max(1L, timeoutMs);

        if (isInsideSafeWithTimeout()) {
            CLog.d("Nested SafeExecutor.safeWithTimeout() detected; executing inline to avoid pool starvation");
            try {
                return SafeResult.success(task.call(), true);
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                return SafeResult.failure(e, true);
            }
        }

        AtomicReference<Thread> executionThread = new AtomicReference<>(null);
        Future<T> future;
        try {
            future = executor.submit(() -> {
                RUNNING_INSIDE_SAFE.set(Boolean.TRUE);
                executionThread.set(Thread.currentThread());
                try {
                    return task.call();
                } finally {
                    executionThread.set(null);
                    RUNNING_INSIDE_SAFE.remove();
                }
            });
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return SafeResult.failure(e);
        }

        try {
            T result = future.get(effectiveTimeoutMs, TimeUnit.MILLISECONDS);
            return SafeResult.success(result);
        } catch (TimeoutException te) {
            Thread blockedThread = executionThread.get();
            StackTraceElement[] stack = blockedThread != null ? blockedThread.getStackTrace() : null;
            future.cancel(true);
            ExecutionTimeoutException timeoutEx = new ExecutionTimeoutException(te, stack);
            CLog.w("SafeExecutor timeout (" + effectiveTimeoutMs + "ms): " + timeoutEx.getMessage());
            return SafeResult.timeout(timeoutEx, stack);
        } catch (ExecutionException ee) {
            Throwable cause = ee.getCause() != null ? ee.getCause() : ee;
            if (cause instanceof Exception
                    || cause instanceof LinkageError
                    || cause instanceof OutOfMemoryError) {
                return SafeResult.failure(cause);
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            return SafeResult.failure(cause);
        } catch (InterruptedException ie) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            return SafeResult.failure(ie);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            future.cancel(true);
            return SafeResult.failure(e);
        }
    }

    /** Returns true if the current thread is executing inside {@link #safeWithTimeout}. */
    public static boolean isInsideSafeWithTimeout() {
        return Boolean.TRUE.equals(RUNNING_INSIDE_SAFE.get());
    }

    private static ExecutorService getSharedExecutor() {
        ThreadPoolExecutor current = sharedExecutor;
        if (current != null && !current.isShutdown()) {
            return current;
        }
        synchronized (EXECUTOR_LOCK) {
            current = sharedExecutor;
            if (current == null || current.isShutdown()) {
                int maxThreads = Math.max(8, Runtime.getRuntime().availableProcessors() * 2);
                AtomicInteger counter = new AtomicInteger(1);
                ThreadFactory factory = runnable -> {
                    Thread t = new Thread(runnable, "RiskEngine-SafeExec-" + counter.getAndIncrement());
                    t.setDaemon(true);
                    return t;
                };
                ThreadPoolExecutor pool = new ThreadPoolExecutor(
                        4,
                        maxThreads,
                        30L,
                        TimeUnit.SECONDS,
                        new SynchronousQueue<>(),
                        factory);
                pool.allowCoreThreadTimeOut(true);
                sharedExecutor = pool;
                current = pool;
            }
            return current;
        }
    }
}
