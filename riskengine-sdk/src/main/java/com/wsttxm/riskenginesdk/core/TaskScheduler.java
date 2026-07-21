package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.util.CLog;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ArrayBlockingQueue;
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

    public <T> Future<T> submit(Callable<T> task) {
        return coordinatorExecutor.submit(task);
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
