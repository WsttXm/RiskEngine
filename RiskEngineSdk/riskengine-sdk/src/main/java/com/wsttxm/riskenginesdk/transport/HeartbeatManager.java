package com.wsttxm.riskenginesdk.transport;

import com.wsttxm.riskenginesdk.util.CLog;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class HeartbeatManager {
    private ScheduledExecutorService scheduler;
    private ScheduledFuture<?> heartbeatFuture;
    private final Runnable heartbeatTask;

    public HeartbeatManager(Runnable heartbeatTask) {
        this.heartbeatTask = heartbeatTask;
    }

    public void start(long intervalMs) {
        stop();
        scheduler = Executors.newSingleThreadScheduledExecutor();
        heartbeatFuture = scheduler.scheduleAtFixedRate(() -> {
            try {
                heartbeatTask.run();
            } catch (Exception e) {
                CLog.e("Heartbeat failed", e);
            }
        }, intervalMs, intervalMs, TimeUnit.MILLISECONDS);
        CLog.i("Heartbeat started with interval: " + intervalMs + "ms");
    }

    public void stop() {
        if (heartbeatFuture != null) {
            heartbeatFuture.cancel(false);
            heartbeatFuture = null;
        }
        if (scheduler != null) {
            scheduler.shutdown();
            scheduler = null;
        }
    }
}
