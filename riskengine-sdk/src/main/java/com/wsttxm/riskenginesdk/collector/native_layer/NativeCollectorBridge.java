package com.wsttxm.riskenginesdk.collector.native_layer;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.PrivacyUtils;

import java.util.Set;

public class NativeCollectorBridge {
    private final Context context;
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
        Context application = context == null ? null : context.getApplicationContext();
        this.context = application != null ? application : context;
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
        return callNative(false, NativeCollectorBridge::nativeCheckRootRaw);
    }

    public static String getRootEvidence() {
        return callNative("", NativeCollectorBridge::nativeGetRootEvidenceRaw);
    }

    public static String getHookEvidence() {
        return callNative("", NativeCollectorBridge::nativeGetHookEvidenceRaw);
    }

    public static String checkEmulatorFiles() {
        return callNative("", NativeCollectorBridge::nativeCheckEmulatorFilesRaw);
    }

    public static int getThermalZoneCount() {
        return callNative(-1, NativeCollectorBridge::nativeGetThermalZoneCountRaw);
    }

    public static String getRuntimeArch() {
        return callNative("", NativeCollectorBridge::nativeGetRuntimeArchRaw);
    }

    public static int getTracerPid() {
        return callNative(-1, NativeCollectorBridge::nativeGetTracerPidRaw);
    }

    private static <T> T callNative(T fallback, NativeCall<T> call) {
        if (!NATIVE_AVAILABLE) {
            return fallback;
        }
        try {
            T result = call.run();
            return result == null ? fallback : result;
        } catch (Exception | LinkageError e) {
            CLog.e("Native detector call failed", e);
            return fallback;
        }
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
                        String value = getSystemProperty(prop);
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
