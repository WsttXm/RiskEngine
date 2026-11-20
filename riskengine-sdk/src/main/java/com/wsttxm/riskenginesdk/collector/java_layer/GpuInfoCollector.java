package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.opengl.EGL14;
import android.opengl.EGLConfig;
import android.opengl.EGLContext;
import android.opengl.EGLDisplay;
import android.opengl.EGLSurface;
import android.opengl.GLES20;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Collects GPU identity through a single offscreen EGL pbuffer context shared
 * via {@link SignalSnapshot}.
 *
 * Teardown deliberately destroys only the collector's own surface/context and
 * releases thread-local EGL state without calling {@code eglTerminate} on the
 * process-shared {@code EGL_DEFAULT_DISPLAY}, protecting the host UI
 * RenderThread on sensitive OEM GPU drivers.
 */
public class GpuInfoCollector extends BaseCollector {
    private final SignalSnapshot signals;

    public GpuInfoCollector(Context context) {
        this(context, null);
    }

    public GpuInfoCollector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
    }

    @Override
    public String getName() {
        return "gpu_info";
    }

    /**
     * Probes full GPU metadata once into the supplied result. Used by
     * {@link SignalSnapshot} so the EGL context is created at most once per
     * collection report.
     */
    public static void probeInto(CollectorResult result) {
        probeUncached(result);
    }

    @Override
    protected void collect(CollectorResult result) {
        if (signals == null) {
            probeUncached(result);
            return;
        }
        SignalResult<Map<String, String>> cached = signals.getGpuAttributes();
        if (cached.isSuccess() && cached.getValue() != null) {
            for (Map.Entry<String, String> entry : cached.getValue().entrySet()) {
                result.addValue(entry.getKey(), entry.getValue());
            }
            return;
        }
        if (cached.getStatus() == SignalResult.Status.UNAVAILABLE) {
            result.markUnsupported(cached.getFailureReason());
        } else {
            result.markError(cached.getFailureReason());
        }
    }

    public static Map<String, String> copyValues(CollectorResult source) {
        return new LinkedHashMap<>(source.getValues());
    }

    private static void probeUncached(CollectorResult result) {
        EGLDisplay display = EGL14.EGL_NO_DISPLAY;
        EGLContext eglContext = EGL14.EGL_NO_CONTEXT;
        EGLSurface surface = EGL14.EGL_NO_SURFACE;
        try {
            display = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY);
            if (display == EGL14.EGL_NO_DISPLAY) {
                result.markUnsupported("egl_no_display");
                return;
            }
            int[] version = new int[2];
            if (!EGL14.eglInitialize(display, version, 0, version, 1)) {
                result.markUnsupported("egl_init_failed");
                display = EGL14.EGL_NO_DISPLAY;
                return;
            }
            result.addValue("egl_version", version[0] + "." + version[1]);

            EGLConfig config = choosePbufferConfig(display);
            if (config == null) {
                result.markUnsupported("egl_no_config");
                return;
            }

            int[] contextAttribs = {EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE};
            eglContext = EGL14.eglCreateContext(display, config,
                    EGL14.EGL_NO_CONTEXT, contextAttribs, 0);
            if (eglContext == EGL14.EGL_NO_CONTEXT) {
                result.markUnsupported("egl_no_context");
                return;
            }

            int[] surfaceAttribs = {
                    EGL14.EGL_WIDTH, 1, EGL14.EGL_HEIGHT, 1, EGL14.EGL_NONE
            };
            surface = EGL14.eglCreatePbufferSurface(display, config, surfaceAttribs, 0);
            if (surface == EGL14.EGL_NO_SURFACE
                    || !EGL14.eglMakeCurrent(display, surface, surface, eglContext)) {
                result.markUnsupported("egl_no_surface");
                return;
            }

            addIfPresent(result, "vendor", GLES20.glGetString(GLES20.GL_VENDOR));
            addIfPresent(result, "renderer", GLES20.glGetString(GLES20.GL_RENDERER));
            addIfPresent(result, "version", GLES20.glGetString(GLES20.GL_VERSION));
            addIfPresent(result, "shading_language",
                    GLES20.glGetString(GLES20.GL_SHADING_LANGUAGE_VERSION));

            String extensions = GLES20.glGetString(GLES20.GL_EXTENSIONS);
            if (extensions != null && !extensions.isBlank()) {
                String[] parts = extensions.trim().split("\\s+");
                Arrays.sort(parts);
                result.addValue("extension_count", String.valueOf(parts.length));
                result.addValue("extensions_hash", sha256(String.join(" ", parts)));
            }

            addLimit(result, "max_texture_size", GLES20.GL_MAX_TEXTURE_SIZE);
            addLimit(result, "max_renderbuffer_size", GLES20.GL_MAX_RENDERBUFFER_SIZE);
            addLimit(result, "max_vertex_attribs", GLES20.GL_MAX_VERTEX_ATTRIBS);
        } catch (Exception | LinkageError e) {
            CLog.e("GPU info collection failed", e);
            result.markError(e instanceof Exception
                    ? (Exception) e : new RuntimeException(e.getClass().getSimpleName()));
        } finally {
            releaseQuietly(display, eglContext, surface);
        }
    }

    private static EGLConfig choosePbufferConfig(EGLDisplay display) {
        int[][] candidates = {
                {
                        EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
                        EGL14.EGL_SURFACE_TYPE, EGL14.EGL_PBUFFER_BIT,
                        EGL14.EGL_RED_SIZE, 8,
                        EGL14.EGL_GREEN_SIZE, 8,
                        EGL14.EGL_BLUE_SIZE, 8,
                        EGL14.EGL_NONE
                },
                {
                        EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
                        EGL14.EGL_SURFACE_TYPE, EGL14.EGL_PBUFFER_BIT,
                        EGL14.EGL_NONE
                }
        };
        EGLConfig[] configs = new EGLConfig[1];
        int[] configCount = new int[1];
        for (int[] attribs : candidates) {
            if (EGL14.eglChooseConfig(display, attribs, 0, configs, 0, 1, configCount, 0)
                    && configCount[0] > 0 && configs[0] != null) {
                return configs[0];
            }
        }
        return null;
    }

    private static void releaseQuietly(EGLDisplay display, EGLContext context,
                                       EGLSurface surface) {
        try {
            if (display != EGL14.EGL_NO_DISPLAY) {
                EGL14.eglMakeCurrent(display, EGL14.EGL_NO_SURFACE,
                        EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT);
                if (surface != EGL14.EGL_NO_SURFACE) {
                    EGL14.eglDestroySurface(display, surface);
                }
                if (context != EGL14.EGL_NO_CONTEXT) {
                    EGL14.eglDestroyContext(display, context);
                }
                // Never call eglTerminate on process-shared EGL_DEFAULT_DISPLAY.
            }
            EGL14.eglReleaseThread();
        } catch (Exception | LinkageError ignored) {
            // Teardown is best effort; the values are already recorded.
        }
    }

    private static void addIfPresent(CollectorResult result, String key, String value) {
        if (value != null && !value.isBlank()) {
            result.addValue(key, value.trim());
        }
    }

    private static void addLimit(CollectorResult result, String key, int glEnum) {
        try {
            int[] out = new int[1];
            GLES20.glGetIntegerv(glEnum, out, 0);
            if (out[0] > 0) {
                result.addValue(key, String.valueOf(out[0]));
            }
        } catch (Exception | LinkageError ignored) {
            // Individual limits are optional.
        }
    }

    public static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(bytes.length * 2);
            for (byte item : bytes) {
                hex.append(Character.forDigit((item >>> 4) & 0x0f, 16));
                hex.append(Character.forDigit(item & 0x0f, 16));
            }
            return hex.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
