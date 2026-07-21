package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.TaskScheduler;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class TaskSchedulerTest {
    @Test
    public void coordinatorDoesNotStarveWorkerPool() throws Exception {
        TaskScheduler scheduler = new TaskScheduler();
        try {
            Future<Integer> future = scheduler.submit(() -> scheduler.submitAllAndWait(
                    List.of((java.util.concurrent.Callable<Integer>) () -> 7), 500).get(0));
            assertEquals(Integer.valueOf(7), future.get(1, TimeUnit.SECONDS));
        } finally {
            scheduler.shutdown();
        }
    }

    @Test
    public void timeoutAppliesToWholeBatch() {
        TaskScheduler scheduler = new TaskScheduler();
        try {
            List<Callable<Integer>> tasks = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                tasks.add(slowTask());
            }
            long start = System.nanoTime();
            List<Integer> results = scheduler.submitAllAndWait(tasks, 100);
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

            assertTrue(results.isEmpty());
            // A per-future timeout would take roughly 20 * 100 ms here. Leave
            // enough headroom for a heavily loaded CI host while still catching it.
            assertTrue("batch exceeded its shared deadline: " + elapsedMs, elapsedMs < 1_500);
        } finally {
            scheduler.shutdown();
        }
    }

    @Test
    public void coordinatorQueueIsBounded() throws Exception {
        TaskScheduler scheduler = new TaskScheduler();
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try {
            scheduler.submit(() -> {
                started.countDown();
                release.await();
                return null;
            });
            assertTrue(started.await(1, TimeUnit.SECONDS));
            for (int i = 0; i < 16; i++) {
                scheduler.submit(() -> null);
            }

            assertThrows(RejectedExecutionException.class,
                    () -> scheduler.submit(() -> null));
        } finally {
            release.countDown();
            scheduler.shutdown();
        }
    }

    private Callable<Integer> slowTask() {
        return () -> {
            Thread.sleep(5_000);
            return 1;
        };
    }
}
