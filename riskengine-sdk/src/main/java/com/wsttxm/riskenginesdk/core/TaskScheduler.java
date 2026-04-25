package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.util.CLog;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class TaskScheduler {
    private static final int THREAD_POOL_SIZE = 4;
    private final ExecutorService executor;

    public TaskScheduler() {
        executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
    }

    public <T> Future<T> submit(Callable<T> task) {
        return executor.submit(task);
    }

    public <T> List<T> submitAllAndWait(List<Callable<T>> tasks, long timeoutMs) {
        List<T> results = new ArrayList<>();
        try {
            List<Future<T>> futures = new ArrayList<>();
            for (Callable<T> task : tasks) {
                futures.add(executor.submit(task));
            }
            for (Future<T> future : futures) {
                try {
                    T result = future.get(timeoutMs, TimeUnit.MILLISECONDS);
                    if (result != null) {
                        results.add(result);
                    }
                } catch (Exception e) {
                    CLog.e("Task execution failed", e);
                }
            }
        } catch (Exception e) {
            CLog.e("TaskScheduler submitAllAndWait failed", e);
        }
        return results;
    }

    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }
    }
}
