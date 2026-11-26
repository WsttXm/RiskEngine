package com.wsttxm.riskenginesdk.detector.probe.virtualization;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.os.Handler;
import android.os.HandlerThread;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * POSTPONED short-window (<= 200ms) MEMS static micro-noise sampler.
 *
 * <p>Physical accelerometers and gyroscopes exhibit non-zero thermal/quantization jitter even
 * while resting motionless on a table. Emulators and cloud phones frequently emit exact constant
 * synthetic values across 8-10 consecutive frames ({@code stddev == 0.0} on all three axes).
 *
 * <p>Anti-FP rule: callers MUST treat {@link Result#isStaticZeroVariance()} as a joint-only
 * corroborating signal paired with battery/camera/hardware anomalies — never as a standalone
 * actionable trigger.
 */
public final class SensorNoiseProbe {
    public static final long DEFAULT_WINDOW_MS = 200L;
    public static final int MIN_FRAMES = 8;
    public static final int TARGET_FRAMES = 10;

    private static final SensorFrameSampler DEFAULT_SAMPLER = new AndroidSensorFrameSampler();

    private SensorNoiseProbe() {}

    public interface SensorFrameSampler {
        Result sample(Context context, long maxWindowMs);
    }

    public static final class Result {
        private final boolean available;
        private final boolean staticZeroVariance;
        private final String sensorType;
        private final int frameCount;
        private final double stdX;
        private final double stdY;
        private final double stdZ;
        private final String reason;

        private Result(boolean available,
                       boolean staticZeroVariance,
                       String sensorType,
                       int frameCount,
                       double stdX,
                       double stdY,
                       double stdZ,
                       String reason) {
            this.available = available;
            this.staticZeroVariance = staticZeroVariance;
            this.sensorType = sensorType == null ? "none" : sensorType;
            this.frameCount = frameCount;
            this.stdX = stdX;
            this.stdY = stdY;
            this.stdZ = stdZ;
            this.reason = reason == null ? "" : reason;
        }

        public static Result observed(String sensorType,
                                      int frameCount,
                                      double stdX,
                                      double stdY,
                                      double stdZ,
                                      boolean staticZeroVariance) {
            return new Result(true, staticZeroVariance, sensorType, frameCount,
                    stdX, stdY, stdZ, staticZeroVariance ? "zero_variance" : "thermal_noise_present");
        }

        public static Result insufficientSamples(String sensorType, int frameCount) {
            return new Result(true, false, sensorType, frameCount,
                    Double.NaN, Double.NaN, Double.NaN, "insufficient_samples");
        }

        public static Result unavailable(String reason) {
            return new Result(false, false, "none", 0,
                    Double.NaN, Double.NaN, Double.NaN, reason);
        }

        public boolean isAvailable() {
            return available;
        }

        public boolean isStaticZeroVariance() {
            return staticZeroVariance;
        }

        public String getSensorType() {
            return sensorType;
        }

        public int getFrameCount() {
            return frameCount;
        }

        public double getStdX() {
            return stdX;
        }

        public double getStdY() {
            return stdY;
        }

        public double getStdZ() {
            return stdZ;
        }

        public String getReason() {
            return reason;
        }
    }

    public static Result sample(Context context) {
        return sample(context, DEFAULT_WINDOW_MS, DEFAULT_SAMPLER);
    }

    public static Result sample(Context context, long maxWindowMs, SensorFrameSampler sampler) {
        SensorFrameSampler effective = sampler != null ? sampler : DEFAULT_SAMPLER;
        long boundedWindow = Math.min(Math.max(maxWindowMs, 20L), DEFAULT_WINDOW_MS);
        try {
            Result res = effective.sample(context, boundedWindow);
            return res != null ? res : Result.unavailable("null_result");
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return Result.unavailable(e.getClass().getSimpleName());
        }
    }

    /**
     * Pure-Java evaluator over sampled 3-axis sensor frames.
     *
     * <p>Flags {@code staticZeroVariance = true} ONLY when at least {@link #MIN_FRAMES} valid
     * 3-axis samples are collected and all three axes exhibit strictly {@code 0.0} standard
     * deviation (exact synthetic constant readings).
     */
    public static Result evaluateSamples(List<float[]> frames, String sensorType) {
        if (frames == null || frames.size() < MIN_FRAMES) {
            return Result.insufficientSamples(sensorType, frames == null ? 0 : frames.size());
        }

        List<float[]> valid = new ArrayList<>(frames.size());
        for (float[] frame : frames) {
            if (frame == null || frame.length < 3) {
                continue;
            }
            if (Float.isNaN(frame[0]) || Float.isInfinite(frame[0])
                    || Float.isNaN(frame[1]) || Float.isInfinite(frame[1])
                    || Float.isNaN(frame[2]) || Float.isInfinite(frame[2])) {
                continue;
            }
            valid.add(frame);
        }

        int n = valid.size();
        if (n < MIN_FRAMES) {
            return Result.insufficientSamples(sensorType, n);
        }

        float firstX = valid.get(0)[0];
        float firstY = valid.get(0)[1];
        float firstZ = valid.get(0)[2];
        boolean allExactEqual = true;

        double sumX = 0.0;
        double sumY = 0.0;
        double sumZ = 0.0;
        for (float[] f : valid) {
            if (f[0] != firstX || f[1] != firstY || f[2] != firstZ) {
                allExactEqual = false;
            }
            sumX += f[0];
            sumY += f[1];
            sumZ += f[2];
        }

        if (allExactEqual) {
            return Result.observed(sensorType, n, 0.0, 0.0, 0.0, true);
        }

        double meanX = sumX / n;
        double meanY = sumY / n;
        double meanZ = sumZ / n;

        double varX = 0.0;
        double varY = 0.0;
        double varZ = 0.0;
        for (float[] f : valid) {
            double dx = f[0] - meanX;
            double dy = f[1] - meanY;
            double dz = f[2] - meanZ;
            varX += dx * dx;
            varY += dy * dy;
            varZ += dz * dz;
        }

        double stdX = Math.sqrt(varX / n);
        double stdY = Math.sqrt(varY / n);
        double stdZ = Math.sqrt(varZ / n);
        boolean zeroVar = stdX == 0.0 && stdY == 0.0 && stdZ == 0.0;
        return Result.observed(sensorType, n, stdX, stdY, stdZ, zeroVar);
    }

    private static final class AndroidSensorFrameSampler implements SensorFrameSampler {
        @Override
        public Result sample(Context context, long maxWindowMs) {
            if (context == null) {
                return Result.unavailable("null_context");
            }
            SensorManager sm;
            try {
                sm = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
            } catch (Exception | LinkageError e) {
                return Result.unavailable(e.getClass().getSimpleName());
            }
            if (sm == null) {
                return Result.unavailable("sensor_service_unavailable");
            }

            Sensor target = null;
            String sensorLabel = "accelerometer";
            try {
                target = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);
                if (target == null) {
                    target = sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE);
                    sensorLabel = "gyroscope";
                }
            } catch (Exception | LinkageError e) {
                return Result.unavailable(e.getClass().getSimpleName());
            }
            if (target == null) {
                return Result.unavailable("no_mems_sensor");
            }

            List<float[]> collected = Collections.synchronizedList(new ArrayList<>(TARGET_FRAMES));
            CountDownLatch latch = new CountDownLatch(TARGET_FRAMES);
            HandlerThread thread = null;
            SensorEventListener listener = new SensorEventListener() {
                @Override
                public void onSensorChanged(SensorEvent event) {
                    if (event == null || event.values == null || event.values.length < 3) {
                        return;
                    }
                    if (collected.size() < TARGET_FRAMES) {
                        collected.add(new float[]{event.values[0], event.values[1], event.values[2]});
                        latch.countDown();
                    }
                }

                @Override
                public void onAccuracyChanged(Sensor sensor, int accuracy) {}
            };

            try {
                thread = new HandlerThread("riskengine-sensor-noise");
                thread.start();
                Handler handler = new Handler(thread.getLooper());
                boolean registered = sm.registerListener(
                        listener, target, SensorManager.SENSOR_DELAY_FASTEST, handler);
                if (!registered) {
                    return Result.unavailable("register_failed");
                }
                latch.await(maxWindowMs, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception | LinkageError e) {
                return Result.unavailable(e.getClass().getSimpleName());
            } finally {
                try {
                    sm.unregisterListener(listener);
                } catch (Exception | LinkageError ignored) {}
                if (thread != null) {
                    try {
                        thread.quitSafely();
                    } catch (Exception | LinkageError ignored) {}
                }
            }

            List<float[]> snapshot;
            synchronized (collected) {
                snapshot = new ArrayList<>(collected);
            }
            return evaluateSamples(snapshot, sensorLabel);
        }
    }
}
