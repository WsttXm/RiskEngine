package com.wsttxm.riskenginesdk.collector.native_layer;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.PrivacyUtils;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import java.util.Set;

public class NativeCollectorBridge {
    private final Context context;
    private final SignalSnapshot signals;
    private static final boolean NATIVE_AVAILABLE;
    private static final Set<String> ALLOWED_PROPERTIES = Set.of(
            "service.adb.tcp.port", "persist.adb.tcp.port",
            "ro.build.fingerprint", "ro.build.display.id", "ro.product.model",
            "ro.product.brand", "ro.product.device", "ro.product.manufacturer",
            "ro.hardware", "ro.board.platform", "persist.sys.timezone",
            "gsm.version.baseband", "ro.lineage.version", "ro.cm.version",
            "ro.mokee.version", "ro.rr.version", "ro.pixelexperience.version",
            "ro.modversion"
    );

    static {
        boolean loaded = false;
        try {
            System.loadLibrary("riskengine");
            loaded = true;
        } catch (LinkageError | SecurityException e) {
            CLog.e("Failed to load native library", e);
        }
        NATIVE_AVAILABLE = loaded;
    }

    public NativeCollectorBridge(Context context) {
        this(context, null);
    }

    public NativeCollectorBridge(Context context, SignalSnapshot signals) {
        Context application = context == null ? null : context.getApplicationContext();
        this.context = application != null ? application : context;
        this.signals = signals;
    }

    public static boolean isNativeAvailable() {
        return NATIVE_AVAILABLE;
    }

    public static String getSystemProperty(String name) {
        if (!NATIVE_AVAILABLE || !ALLOWED_PROPERTIES.contains(name)) {
            return "";
        }
        try {
            String value = nativeGetSystemPropertyRaw(name);
            return value == null ? "" : value;
        } catch (Exception | LinkageError e) {
            CLog.e("Native system property lookup failed", e);
            return "";
        }
    }

    // Native methods
    private static native String nativeGetDrmId();
    private static native String nativeGetBootId();
    private static native String nativeGetSystemPropertyRaw(String name);
    private static native String nativeGetCpuInfo();
    private static native long nativeGetDiskSize(String path);
    private static native String nativeGetKernelInfo();

    private static native boolean nativeCheckRootRaw();
    private static native String nativeGetRootEvidenceRaw();
    private static native String nativeGetHookEvidenceRaw();
    private static native String nativeCheckEmulatorFilesRaw();
    private static native int nativeGetThermalZoneCountRaw();
    private static native String nativeGetRuntimeArchRaw();
    private static native int nativeGetTracerPidRaw();

    public static boolean checkRoot() {
        return valueOr(checkRootResult(), false);
    }

    public static SignalResult<Boolean> checkRootResult() {
        return callNativeResult(NativeCollectorBridge::nativeCheckRootRaw);
    }

    public static String getRootEvidence() {
        return valueOr(getRootEvidenceResult(), "");
    }

    public static SignalResult<String> getRootEvidenceResult() {
        return callNativeResult(NativeCollectorBridge::nativeGetRootEvidenceRaw);
    }

    public static String getHookEvidence() {
        return valueOr(getHookEvidenceResult(), "");
    }

    public static SignalResult<String> getHookEvidenceResult() {
        return callNativeResult(NativeCollectorBridge::nativeGetHookEvidenceRaw);
    }

    public static String checkEmulatorFiles() {
        return valueOr(checkEmulatorFilesResult(), "");
    }

    public static SignalResult<String> checkEmulatorFilesResult() {
        return callNativeResult(NativeCollectorBridge::nativeCheckEmulatorFilesRaw);
    }

    public static int getThermalZoneCount() {
        return valueOr(getThermalZoneCountResult(), -1);
    }

    public static SignalResult<Integer> getThermalZoneCountResult() {
        return callNativeResult(NativeCollectorBridge::nativeGetThermalZoneCountRaw);
    }

    public static String getRuntimeArch() {
        return valueOr(getRuntimeArchResult(), "");
    }

    public static SignalResult<String> getRuntimeArchResult() {
        return callNativeResult(NativeCollectorBridge::nativeGetRuntimeArchRaw);
    }

    public static int getTracerPid() {
        return valueOr(getTracerPidResult(), -1);
    }

    public static SignalResult<Integer> getTracerPidResult() {
        return callNativeResult(NativeCollectorBridge::nativeGetTracerPidRaw);
    }

    private static <T> SignalResult<T> callNativeResult(NativeCall<T> call) {
        if (!NATIVE_AVAILABLE) {
            return SignalResult.unavailable("native_library_unavailable");
        }
        try {
            T result = call.run();
            return result == null
                    ? SignalResult.error("native_returned_null")
                    : SignalResult.success(result);
        } catch (Exception | LinkageError e) {
            CLog.e("Native detector call failed", e);
            return SignalResult.error(e.getClass().getSimpleName());
        }
    }

    private static <T> T valueOr(SignalResult<T> result, T fallback) {
        return result != null && result.isSuccess() && result.getValue() != null
                ? result.getValue() : fallback;
    }

    private interface NativeCall<T> {
        T run();
    }
    public BaseCollector getDrmCollector() {
        return new BaseCollector(context) {
            @Override
            public String getName() { return "drm_id"; }

            @Override
            protected void collect(CollectorResult result) {
                if (!ensureNative(result)) return;
                try {
                    String hashed = PrivacyUtils.hashIdentifier(context, nativeGetDrmId());
                    if (!hashed.isEmpty()) result.addValue("widevine_hash", hashed);
                } catch (Exception e) {
                    CLog.e("DRM collector failed", e);
                    result.markError(e);
                }
            }
        };
    }

    public BaseCollector getBootIdCollector() {
        return new BaseCollector(context) {
            @Override
            public String getName() { return "boot_id"; }

            @Override
            protected void collect(CollectorResult result) {
                if (!ensureNative(result)) return;
                try {
                    String hashed = PrivacyUtils.hashIdentifier(context, nativeGetBootId());
                    if (!hashed.isEmpty()) result.addValue("native_hash", hashed);
                } catch (Exception e) {
                    CLog.e("BootId collector failed", e);
                    result.markError(e);
                }
            }
        };
    }

    public BaseCollector getSystemPropertyCollector() {
        return new BaseCollector(context) {
            @Override
            public String getName() { return "system_properties_native"; }

            @Override
            protected void collect(CollectorResult result) {
                if (!ensureNative(result)) return;
                try {
                    String[] props = {
                            "ro.build.fingerprint", "ro.build.display.id",
                            "ro.product.model", "ro.product.brand",
                            "ro.product.device", "ro.product.manufacturer",
                            "ro.hardware", "ro.board.platform",
                            "persist.sys.timezone", "gsm.version.baseband"
                    };
                    for (String prop : props) {
                        SignalResult<String> cached = signals == null
                                ? null : signals.getSystemProperty(prop);
                        String value = cached == null || cached.getValue() == null
                                ? getSystemProperty(prop) : cached.getValue();
                        if (value != null && !value.isEmpty()) {
                            result.addValue(prop, value);
                        }
                    }
                } catch (Exception e) {
                    CLog.e("SystemProperty collector failed", e);
                    result.markError(e);
                }
            }
        };
    }

    public BaseCollector getCpuInfoCollector() {
        return new BaseCollector(context) {
            @Override
            public String getName() { return "cpu_info"; }

            @Override
            protected void collect(CollectorResult result) {
                if (!ensureNative(result)) return;
                try {
                    result.addValue("native", nativeGetCpuInfo());
                } catch (Exception e) {
                    CLog.e("CpuInfo collector failed", e);
                    result.markError(e);
                }
            }
        };
    }

    public BaseCollector getDiskSizeCollector() {
        return new BaseCollector(context) {
            @Override
            public String getName() { return "disk_size"; }

            @Override
            protected void collect(CollectorResult result) {
                if (!ensureNative(result)) return;
                try {
                    long size = nativeGetDiskSize("/data");
                    long sizeStorage = nativeGetDiskSize("/storage/emulated/0");
                    if (size >= 0) result.addValue("native_data", String.valueOf(size));
                    if (sizeStorage >= 0) {
                        result.addValue("native_storage", String.valueOf(sizeStorage));
                    }
                    if (size < 0 && sizeStorage < 0) {
                        result.markUnsupported("statfs_unavailable");
                    }
                } catch (Exception e) {
                    CLog.e("DiskSize collector failed", e);
                    result.markError(e);
                }
            }
        };
    }

    public BaseCollector getKernelInfoCollector() {
        return new BaseCollector(context) {
            @Override
            public String getName() { return "kernel_info"; }

            @Override
            protected void collect(CollectorResult result) {
                if (!ensureNative(result)) return;
                try {
                    result.addValue("native", nativeGetKernelInfo());
                } catch (Exception e) {
                    CLog.e("KernelInfo collector failed", e);
                    result.markError(e);
                }
            }
        };
    }

    private static boolean ensureNative(CollectorResult result) {
        if (NATIVE_AVAILABLE) {
            return true;
        }
        result.markUnsupported("native_library_unavailable");
        return false;
    }
}
