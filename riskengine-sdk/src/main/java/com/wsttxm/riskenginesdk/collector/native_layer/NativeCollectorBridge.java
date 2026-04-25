package com.wsttxm.riskenginesdk.collector.native_layer;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;

public class NativeCollectorBridge {
    private final Context context;

    static {
        try {
            System.loadLibrary("riskengine");
        } catch (UnsatisfiedLinkError e) {
            CLog.e("Failed to load native library", e);
        }
    }

    public NativeCollectorBridge(Context context) {
        this.context = context;
    }

    // Native methods
    public static native String nativeGetDrmId();
    public static native String nativeGetBootId();
    public static native String nativeGetSystemProperty(String name);
    public static native String nativeGetAllSystemProperties();
    public static native String nativeGetCpuInfo();
    public static native long nativeGetDiskSize(String path);
    public static native String nativeGetMacAddress();
    public static native String nativeGetKernelInfo();

    // Root detection
    public static native boolean nativeCheckRoot();
    public static native String nativeGetRootEvidence();

    // Hook detection
    public static native boolean nativeCheckHooks();
    public static native String nativeGetHookEvidence();

    // Emulator detection
    public static native String nativeCheckEmulatorFiles();
    public static native int nativeGetThermalZoneCount();
    public static native String nativeCheckSeccompArch();

    // Debug detection
    public static native int nativeGetTracerPid();
    public static native boolean nativeCheckPtrace();
    public static native String nativeInspectMethodEntryPoint(java.lang.reflect.Executable executable);

    // Anti-tamper
    public static native boolean nativeInitMemoryCrc();
    public static native boolean nativeCheckMemoryCrc();
    public static native boolean nativeCheckMapsRedirect();

    public BaseCollector getDrmCollector() {
        return new BaseCollector(context) {
            @Override
            public String getName() { return "drm_id"; }

            @Override
            protected void collect(CollectorResult result) {
                try {
                    result.addValue("widevine", nativeGetDrmId());
                } catch (Exception e) {
                    CLog.e("DRM collector failed", e);
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
                try {
                    result.addValue("native", nativeGetBootId());
                } catch (Exception e) {
                    CLog.e("BootId collector failed", e);
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
                try {
                    String[] props = {
                            "ro.build.fingerprint", "ro.build.display.id",
                            "ro.product.model", "ro.product.brand",
                            "ro.product.device", "ro.product.manufacturer",
                            "ro.hardware", "ro.board.platform",
                            "ro.serialno", "ro.boot.serialno",
                            "persist.sys.timezone", "gsm.version.baseband"
                    };
                    for (String prop : props) {
                        String value = nativeGetSystemProperty(prop);
                        if (value != null && !value.isEmpty()) {
                            result.addValue(prop, value);
                        }
                    }
                } catch (Exception e) {
                    CLog.e("SystemProperty collector failed", e);
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
                try {
                    result.addValue("native", nativeGetCpuInfo());
                } catch (Exception e) {
                    CLog.e("CpuInfo collector failed", e);
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
                try {
                    long size = nativeGetDiskSize("/data");
                    result.addValue("native_data", String.valueOf(size));
                    long sizeStorage = nativeGetDiskSize("/storage/emulated/0");
                    result.addValue("native_storage", String.valueOf(sizeStorage));
                } catch (Exception e) {
                    CLog.e("DiskSize collector failed", e);
                }
            }
        };
    }

    public BaseCollector getMacNetlinkCollector() {
        return new BaseCollector(context) {
            @Override
            public String getName() { return "mac_netlink"; }

            @Override
            protected void collect(CollectorResult result) {
                try {
                    result.addValue("native", nativeGetMacAddress());
                } catch (Exception e) {
                    CLog.e("MAC netlink collector failed", e);
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
                try {
                    result.addValue("native", nativeGetKernelInfo());
                } catch (Exception e) {
                    CLog.e("KernelInfo collector failed", e);
                }
            }
        };
    }
}
