package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public final class TaskScheduler {
    private static final int THREAD_POOL_SIZE = 4;
    private static final int MAX_QUEUED_COLLECTIONS = 16;

    private final ExecutorService workerExecutor;
    private final ExecutorService coordinatorExecutor;

    public TaskScheduler() {
        workerExecutor = Executors.newFixedThreadPool(
                THREAD_POOL_SIZE, namedThreadFactory("risk-worker"));
        // Coordination must never occupy the worker pool it is waiting on.
        coordinatorExecutor = new ThreadPoolExecutor(
                1,
                1,
                0,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(MAX_QUEUED_COLLECTIONS),
                namedThreadFactory("risk-coordinator"),
                new ThreadPoolExecutor.AbortPolicy());
    }

    /**
     * Tier-weighted execution budgets computed from a single total collection timeout,
     * retiring the legacy rigid 45% collector split.
     */
    public static final class TierBudgets {
        private final long totalBudgetMs;
        private final long criticalBudgetMs;
        private final long fastBudgetMs;
        private final long postponedBudgetMs;

        public TierBudgets(long totalBudgetMs,
                           long criticalBudgetMs,
                           long fastBudgetMs,
                           long postponedBudgetMs) {
            this.totalBudgetMs = totalBudgetMs;
            this.criticalBudgetMs = criticalBudgetMs;
            this.fastBudgetMs = fastBudgetMs;
            this.postponedBudgetMs = postponedBudgetMs;
        }

        public long getTotalBudgetMs() { return totalBudgetMs; }
        public long getCriticalBudgetMs() { return criticalBudgetMs; }
        public long getFastBudgetMs() { return fastBudgetMs; }
        public long getPostponedBudgetMs() { return postponedBudgetMs; }

        public long budgetForTier(ScanTier tier) {
            if (tier == null) return fastBudgetMs;
            switch (tier) {
                case CRITICAL:
                    return criticalBudgetMs;
                case POSTPONED:
                    return postponedBudgetMs;
                case FAST:
                default:
                    return fastBudgetMs;
            }
        }
    }

    /** Task specification pairing a callable with its {@link ScanTier} and per-task timeout. */
    public static final class TieredTask<T> {
        private final String name;
        private final ScanTier tier;
        private final long perTaskTimeoutMs;
        private final Callable<T> callable;

        public TieredTask(String name, ScanTier tier, long perTaskTimeoutMs, Callable<T> callable) {
            this.name = name == null ? "task" : name;
            this.tier = tier == null ? ScanTier.FAST : tier;
            this.perTaskTimeoutMs = perTaskTimeoutMs > 0
                    ? perTaskTimeoutMs
                    : this.tier.getDefaultTimeoutMs();
            this.callable = callable;
        }

        public String getName() { return name; }
        public ScanTier getTier() { return tier; }
        public long getPerTaskTimeoutMs() { return perTaskTimeoutMs; }
        public Callable<T> getCallable() { return callable; }
    }

    /** Structured per-task execution outcome returned by {@link #submitAllWithSafeTimeout}. */
    public static final class TaskOutcome<T> {
        private final String name;
        private final ScanTier tier;
        private final SafeExecutor.SafeResult<T> result;

        public TaskOutcome(String name, ScanTier tier, SafeExecutor.SafeResult<T> result) {
            this.name = name;
            this.tier = tier;
            this.result = result;
        }

        public String getName() { return name; }
        public ScanTier getTier() { return tier; }
        public SafeExecutor.SafeResult<T> getResult() { return result; }
        public boolean isSuccess() { return result != null && result.isSuccess(); }
        public boolean isTimedOut() { return result != null && result.isTimedOut(); }
        public T getValueOrNull() { return result == null ? null : result.getOrNull(); }
    }

    /**
     * Computes dynamic tier-weighted budgets from {@code totalTimeoutMs}:
     * CRITICAL gets high-priority bounded headroom (15% clamped to [150ms, 1000ms] within total),
     * FAST gets 35% of remaining (with fast-tier preference), and POSTPONED/collectors share
     * the remainder so fast detectors are never starved by slow collectors.
     */
    public static TierBudgets computeTierBudgets(long totalTimeoutMs) {
        long total = Math.max(1L, totalTimeoutMs);
        long critical = Math.min(total, Math.min(1000L, Math.max(150L, (total * 15L) / 100L)));
        if (total < 300L) {
            critical = Math.max(1L, (total * 25L) / 100L);
        }
        long afterCritical = Math.max(0L, total - critical);
        long fast = Math.min(afterCritical, Math.max(1L, (total * 35L) / 100L));
        if (afterCritical == 0L) {
            fast = 0L;
        }
        long postponed = Math.max(0L, total - critical - fast);
        return new TierBudgets(total, critical, fast, postponed);
    }

    public <T> Future<T> submit(Callable<T> task) {
        return coordinatorExecutor.submit(task);
    }

    /** Submits a fire-and-forget background task to the bounded worker pool. */
    public Future<?> submitBackground(Runnable task) {
        return workerExecutor.submit(task);
    }

    /** Runs a single callable through {@link SafeExecutor#safeWithTimeout(long, Callable)}. */
    public <T> SafeExecutor.SafeResult<T> executeWithSafeTimeout(long perTaskTimeoutMs,
                                                                 Callable<T> task) {
        return SafeExecutor.safeWithTimeout(perTaskTimeoutMs, task);
    }

    /**
     * Executes a batch of tiered tasks concurrently on the worker pool while routing each task
     * through {@link SafeExecutor#safeWithTimeout(long, Callable)} for fine-grained per-task
     * timeouts and blocked-thread stacktrace diagnostics, bounded by {@code batchTimeoutMs}.
     */
    public <T> List<TaskOutcome<T>> submitAllWithSafeTimeout(List<TieredTask<T>> tasks,
                                                             long batchTimeoutMs) {
        if (tasks == null || tasks.isEmpty() || batchTimeoutMs <= 0) {
            return Collections.emptyList();
        }

        final long deadlineNs = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(batchTimeoutMs);
        List<Callable<TaskOutcome<T>>> wrapped = new ArrayList<>(tasks.size());
        for (TieredTask<T> spec : tasks) {
            wrapped.add(() -> {
                long remainingMs = TimeUnit.NANOSECONDS.toMillis(deadlineNs - System.nanoTime());
                if (remainingMs <= 0) {
                    SafeExecutor.ExecutionTimeoutException timeoutEx =
                            new SafeExecutor.ExecutionTimeoutException(
                                    new java.util.concurrent.TimeoutException("batch_budget_exhausted"),
                                    null);
                    return new TaskOutcome<>(spec.getName(), spec.getTier(),
                            SafeExecutor.SafeResult.timeout(timeoutEx, null));
                }
                long effectivePerTaskMs = Math.min(spec.getPerTaskTimeoutMs(), remainingMs);
                SafeExecutor.SafeResult<T> outcome = SafeExecutor.safeWithTimeout(
                        effectivePerTaskMs, spec.getCallable());
                return new TaskOutcome<>(spec.getName(), spec.getTier(), outcome);
            });
        }

        List<Future<TaskOutcome<T>>> futures;
        try {
            futures = workerExecutor.invokeAll(wrapped, batchTimeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            CLog.e("Tiered task batch interrupted", e);
            return Collections.emptyList();
        } catch (RejectedExecutionException e) {
            CLog.e("Tiered task batch rejected", e);
            return Collections.emptyList();
        }

        List<TaskOutcome<T>> outcomes = new ArrayList<>(tasks.size());
        for (int i = 0; i < futures.size(); i++) {
            Future<TaskOutcome<T>> future = futures.get(i);
            TieredTask<T> spec = tasks.get(i);
            if (future.isCancelled()) {
                SafeExecutor.ExecutionTimeoutException timeoutEx =
                        new SafeExecutor.ExecutionTimeoutException(
                                new java.util.concurrent.TimeoutException("batch_deadline_exceeded"),
                                null);
                outcomes.add(new TaskOutcome<>(spec.getName(), spec.getTier(),
                        SafeExecutor.SafeResult.timeout(timeoutEx, null)));
                continue;
            }
            try {
                TaskOutcome<T> outcome = future.get();
                if (outcome != null) {
                    outcomes.add(outcome);
                }
            } catch (CancellationException ignored) {
                SafeExecutor.ExecutionTimeoutException timeoutEx =
                        new SafeExecutor.ExecutionTimeoutException(
                                new java.util.concurrent.TimeoutException("batch_cancelled"),
                                null);
                outcomes.add(new TaskOutcome<>(spec.getName(), spec.getTier(),
                        SafeExecutor.SafeResult.timeout(timeoutEx, null)));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                CLog.e("Tiered task failed: " + spec.getName(), e);
                outcomes.add(new TaskOutcome<>(spec.getName(), spec.getTier(),
                        SafeExecutor.SafeResult.failure(e)));
            }
        }
        return outcomes;
    }

    /** Executes a batch with one deadline shared by the whole batch. */
    public <T> List<T> submitAllAndWait(List<? extends Callable<T>> tasks, long timeoutMs) {
        if (tasks.isEmpty() || timeoutMs <= 0) {
            return new ArrayList<>();
        }

        List<Future<T>> futures;
        try {
            futures = workerExecutor.invokeAll(tasks, timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            CLog.e("Task batch interrupted", e);
            return new ArrayList<>();
        } catch (RejectedExecutionException e) {
            CLog.e("Task batch rejected", e);
            return new ArrayList<>();
        }

        List<T> results = new ArrayList<>(futures.size());
        for (Future<T> future : futures) {
            if (future.isCancelled()) {
                continue;
            }
            try {
                T result = future.get();
                if (result != null) {
                    results.add(result);
                }
            } catch (CancellationException ignored) {
                // invokeAll cancels unfinished work at the shared deadline.
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                CLog.e("Task execution failed", e);
            }
        }
        return results;
    }

    /** Cancels queued/running work without blocking the caller thread. */
    public void shutdown() {
        coordinatorExecutor.shutdownNow();
        workerExecutor.shutdownNow();
    }

    private static ThreadFactory namedThreadFactory(String prefix) {
        AtomicInteger sequence = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable, prefix + "-" + sequence.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }
}
