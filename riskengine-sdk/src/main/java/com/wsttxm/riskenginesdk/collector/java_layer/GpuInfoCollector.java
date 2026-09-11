package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.opengl.EGL14;
import android.opengl.EGLConfig;
import android.opengl.EGLContext;
import android.opengl.EGLDisplay;
import android.opengl.EGLSurface;
import android.opengl.GLES20;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Collects GPU identity through an offscreen EGL pbuffer context.
 *
 * This is the single highest-value fingerprint dimension the SDK was missing.
 * The renderer and vendor strings are hardware-bound, stable across reinstall
 * and factory reset, and simultaneously the strongest available signal for
 * virtualized graphics: emulators and cloud phones surface virgl, virtio,
 * SwiftShader or llvmpipe here even when every Build field has been spoofed.
 *
 * A pbuffer is used rather than a window surface so no Activity or UI thread is
 * required and the collector can run on the engine's worker pool.
 */
public class GpuInfoCollector extends BaseCollector {

    public GpuInfoCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "gpu_info";
    }

    /**
     * Probes GPU identity into the given result without needing a collector
     * instance. Shared with SignalSnapshot so the EGL context is created once
     * per report rather than separately for the collector and the detectors.
     */
    public static void probeInto(CollectorResult result) {
        new GpuInfoCollector(null).collect(result);
    }

    @Override
    protected void collect(CollectorResult result) {
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

            int[] configAttribs = {
                    EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
                    EGL14.EGL_SURFACE_TYPE, EGL14.EGL_PBUFFER_BIT,
                    EGL14.EGL_RED_SIZE, 8,
                    EGL14.EGL_GREEN_SIZE, 8,
                    EGL14.EGL_BLUE_SIZE, 8,
                    EGL14.EGL_NONE
            };
            EGLConfig[] configs = new EGLConfig[1];
            int[] configCount = new int[1];
            if (!EGL14.eglChooseConfig(display, configAttribs, 0, configs, 0, 1,
                    configCount, 0) || configCount[0] == 0) {
                result.markUnsupported("egl_no_config");
                return;
            }

            int[] contextAttribs = {EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE};
            eglContext = EGL14.eglCreateContext(display, configs[0],
                    EGL14.EGL_NO_CONTEXT, contextAttribs, 0);
            if (eglContext == EGL14.EGL_NO_CONTEXT) {
                result.markUnsupported("egl_no_context");
                return;
            }

            int[] surfaceAttribs = {
                    EGL14.EGL_WIDTH, 1, EGL14.EGL_HEIGHT, 1, EGL14.EGL_NONE
            };
            surface = EGL14.eglCreatePbufferSurface(display, configs[0], surfaceAttribs, 0);
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

            // The extension list is long and device-specific. Store a stable
            // hash plus the count: high entropy without a multi-KB field.
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
                EGL14.eglTerminate(display);
            }
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

    static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
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
