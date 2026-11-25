package com.wsttxm.riskenginesdk.collector.native_layer;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.PrivacyUtils;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

public class NativeCollectorBridge {
    private static final Object LOAD_LOCK = new Object();
    private static volatile Boolean nativeLoaded;
    private static final Set<String> ALLOWED_PROPERTIES =
            Set.copyOf(Arrays.asList(DetectionLists.ALLOWED_PROPERTIES));

    private final Context context;
    private final SignalSnapshot signals;

    public NativeCollectorBridge(Context context) {
        this(context, null);
    }

    public NativeCollectorBridge(Context context, SignalSnapshot signals) {
        Context application = context == null ? null : context.getApplicationContext();
        this.context = application != null ? application : context;
        this.signals = signals;
    }

    /**
     * Non-blocking query returning whether {@code libriskengine.so} has already been loaded
     * without triggering {@link System#loadLibrary(String)}.
     */
    public static boolean isNativeLoaded() {
        return Boolean.TRUE.equals(nativeLoaded);
    }

    /**
     * Idempotently loads {@code libriskengine.so} on first demand. Designed to be called from
     * background worker threads so {@code RiskEngine.init()} never blocks the Android main thread.
     */
    public static boolean ensureNativeLoaded() {
        Boolean current = nativeLoaded;
        if (current != null) {
            return current;
        }
        synchronized (LOAD_LOCK) {
            current = nativeLoaded;
            if (current != null) {
                return current;
            }
            boolean loaded = false;
            try {
                System.loadLibrary("riskengine");
                loaded = true;
            } catch (LinkageError | Exception e) {
                CLog.e("Failed to load native library", e);
            }
            nativeLoaded = loaded;
            return loaded;
        }
    }

    public static boolean isNativeAvailable() {
        return ensureNativeLoaded();
    }

    public static String getSystemProperty(String name) {
        return valueOr(getSystemPropertyResult(name), "");
    }

    public static SignalResult<String> getSystemPropertyResult(String name) {
        if (name == null || !ALLOWED_PROPERTIES.contains(name)) {
            return SignalResult.unavailable("property_not_allowed");
        }
        return callNativeResult(() -> nativeGetSystemPropertyRaw(name));
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
    private static native String nGetDebugEvidenceRaw();
    private static native boolean nSetAntiDumpableRaw(boolean enable);
    private static native String nGetAdbProtocolEvidenceRaw();
    private static native int nGetSelinuxEnforceRaw();
    private static native String nGetBuildPropFingerprintRaw();
    private static native String nGetProcCmdlineBootPropsRaw();
    private static native String nGetKernelRootEvidenceRaw();
    private static native String nGetMonitorFindingsRaw();
    private static native void nStartMonitorRaw();
    private static native void nStopMonitorRaw();
    private static native void nSetMonitorBackgroundRaw(boolean background);
    private static native String nGetApkSigningInfoRaw(String fallbackSourceDir);
    private static native String nGetBionicPropForensicsRaw();
    private static native String nGetHardwareCpuIdentityRaw();
    private static native String nGetKernelConsistencyRaw();
    private static native String nGetPifPropertiesRaw();
    private static native String nGetCustomRomProbeRaw();
    private static native String nGetKernelSidechannelRaw(boolean includePostponedTiming);
    private static native String nGetSelinuxAuditRaw(int apiLevel, int targetSdk);
    private static native String nGetMountForensicsRaw();
    private static native String nGetZygiskAtexitProbeRaw();
    private static native String nGetVirtualizationTrapsRaw(boolean includePostponedTraps);
    private static native String nGetActiveNetInterfacesRaw();
    private static native String nGetWidevineNdkProbeRaw();
    private static native String nGetTeeBinderProbeRaw(boolean includeHoneypotTiming);
    private static native String nInspectLeafDerRaw(byte[] certDer);
    private static native String nScanActiveAppUidsRaw(int firstUid, int lastUid);
    private static native String nProbeSeccompUidFilterRaw(int firstUid, int lastUid);

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

    /**
     * Collects dual-path TracerPid, per-thread stat ('t'), wchan ('ptrace_stop'),
     * JDWP thread names, and @jdwp-control socket evidence as a {@link NativePayloadCodec} frame.
     */
    public static SignalResult<String> getDebugEvidenceResult() {
        return callNativeResult(NativeCollectorBridge::nGetDebugEvidenceRaw);
    }

    /**
     * Applies {@code prctl(PR_SET_DUMPABLE, enable ? 0 : 1)} when explicitly requested by host
     * configuration ({@code enableAntiDumpable} defaults to {@code false}).
     */
    public static SignalResult<Boolean> setAntiDumpableResult(boolean enable) {
        return callNativeResult(() -> nSetAntiDumpableRaw(enable));
    }

    /**
     * Probes /dev/socket/adbd with sibling ENOENT control, non-blocking zero-byte @jdwp-control
     * abstract socket connect, and init.svc.adbd property as a {@link NativePayloadCodec} frame.
     */
    public static SignalResult<String> getAdbProtocolEvidenceResult() {
        return callNativeResult(NativeCollectorBridge::nGetAdbProtocolEvidenceRaw);
    }

    public static SignalResult<Integer> getSelinuxEnforceResult() {
        return callNativeResult(NativeCollectorBridge::nGetSelinuxEnforceRaw);
    }

    public static SignalResult<String> getBuildPropFingerprintResult() {
        return callNativeResult(NativeCollectorBridge::nGetBuildPropFingerprintRaw);
    }

    public static SignalResult<String> getProcCmdlineBootPropsResult() {
        return callNativeResult(NativeCollectorBridge::nGetProcCmdlineBootPropsRaw);
    }

    public static SignalResult<String> getKernelRootEvidenceResult() {
        return callNativeResult(NativeCollectorBridge::nGetKernelRootEvidenceRaw);
    }

    /**
     * Findings latched by the native background monitor since library load.
     * Covers tampering that arrived after the initial snapshot, which a
     * single-shot collection cannot see.
     */
    public static SignalResult<String> getMonitorFindingsResult() {
        return callNativeResult(NativeCollectorBridge::nGetMonitorFindingsRaw);
    }

    /** Starts or resumes the background monitor after engine initialization. */
    public static void startMonitor() {
        if (!ensureNativeLoaded()) return;
        try {
            nStartMonitorRaw();
        } catch (Exception | LinkageError e) {
            CLog.e("Monitor start failed", e);
        }
    }

    /** Stops the background monitor without triggering library loading if never loaded. */
    public static void stopMonitor() {
        if (!isNativeLoaded()) return;
        try {
            nStopMonitorRaw();
        } catch (Exception | LinkageError e) {
            CLog.e("Monitor stop failed", e);
        }
    }

    /** Notifies the native periodic monitor of foreground/background state transitions. */
    public static void setMonitorBackground(boolean background) {
        if (!isNativeLoaded()) return;
        try {
            nSetMonitorBackgroundRaw(background);
        } catch (Exception | LinkageError e) {
            CLog.e("Monitor background update failed", e);
        }
    }

    public static SignalResult<String> getCpuInfoResult() {
        return callNativeResult(NativeCollectorBridge::nativeGetCpuInfo);
    }

    public static SignalResult<Long> getDiskSizeResult(String path) {
        return callNativeResult(() -> nativeGetDiskSize(path));
    }

    public static SignalResult<String> getKernelInfoResult() {
        return callNativeResult(NativeCollectorBridge::nativeGetKernelInfo);
    }

    /**
     * Reads base.apk signing certificates (APK Signing Scheme v2/v3/v3.1) via raw Linux
     * syscalls and returns a {@link NativePayloadCodec}-encoded frame.
     */
    public static SignalResult<String> getApkSigningInfoResult(String fallbackSourceDir) {
        final String fallback = fallbackSourceDir == null ? "" : fallbackSourceDir;
        return callNativeResult(() -> nGetApkSigningInfoRaw(fallback));
    }

    /**
     * Inspects read-only Bionic {@code /dev/__properties__} area files for resetprop holes,
     * critical {@code ro.*} serial write counters, NUL-tail residuals, and metadata anomalies.
     */
    public static SignalResult<String> getBionicPropForensicsResult() {
        return callNativeResult(NativeCollectorBridge::nGetBionicPropForensicsRaw);
    }

    /**
     * Probes ARM64 EL0 {@code MIDR_EL1} inside a SIGILL-safe disposable child and compares
     * against sysfs and {@code /proc/cpuinfo} using mask {@code 0xfff0ffff}.
     */
    public static SignalResult<String> getHardwareCpuIdentityResult() {
        return callNativeResult(NativeCollectorBridge::nGetHardwareCpuIdentityRaw);
    }

    /**
     * Collects raw {@code __NR_uname} and procfs kernel identity strings for 3-source comparison
     * against Java {@code System.getProperty("os.version")}.
     */
    public static SignalResult<String> getKernelConsistencyResult() {
        return callNativeResult(NativeCollectorBridge::nGetKernelConsistencyRaw);
    }

    /**
     * Scans Bionic properties for PlayIntegrityFix / PixelProps spoofing keys.
     */
    public static SignalResult<String> getPifPropertiesResult() {
        return callNativeResult(NativeCollectorBridge::nGetPifPropertiesRaw);
    }

    /**
     * Probes native custom-ROM signals ({@code libstagefright.so} symbol presence and
     * {@code framework-res.apk} distinct block-device count in {@code /proc/self/maps}).
     */
    public static SignalResult<String> getCustomRomProbeResult() {
        return callNativeResult(NativeCollectorBridge::nGetCustomRomProbeRaw);
    }

    /**
     * Runs kernel root side-channel probes (KernelPatch sys_truncate+mincore, KernelSU
     * reboot/ioctl + fd + devpts xattr, SUSFS setresuid, and optional ARM64 prctl timing).
     */
    public static SignalResult<String> getKernelSidechannelResult(boolean includePostponedTiming) {
        return callNativeResult(() -> nGetKernelSidechannelRaw(includePostponedTiming));
    }

    /**
     * Runs native SELinux deep audit probes (zero-PII Netlink RTM_GETLINK/RTM_GETNEIGH
     * policy-reload leak audit, /sys/fs/selinux/status mmap ABI check, and controlled
     * /proc/thread-self/attr/current context probe).
     */
    public static SignalResult<String> getSelinuxAuditResult(int apiLevel, int targetSdk) {
        return callNativeResult(() -> nGetSelinuxAuditRaw(apiLevel, targetSdk));
    }

    /**
     * Runs native mount table deep forensics (statx STATX_MNT_ID visibility, comma-tokenized
     * system RO 'rw' mounts, /proc/self/{mounts,mountinfo,mountstats} st_mtime parity, and
     * statfs overlay/tmpfs magic checks).
     */
    public static SignalResult<String> getMountForensicsResult() {
        return callNativeResult(NativeCollectorBridge::nGetMountForensicsRaw);
    }

    /**
     * Runs native Zygisk Bionic {@code atexit} array forensics ({@code _ZL7g_array} + SRA splits,
     * non-blocking {@code trylock}, {@code pipe2} read, anonymous callback & >=3 hole runs).
     */
    public static SignalResult<String> getZygiskAtexitProbeResult() {
        return callNativeResult(NativeCollectorBridge::nGetZygiskAtexitProbeRaw);
    }

    /**
     * Runs native virtualization & binary translation probes (Native Bridge on fast path;
     * sacrificial_syscall_pack, sched_yield CV, and ARM64 clock drift inside disposable_child
     * when {@code includePostponedTraps} is {@code true}).
     */
    public static SignalResult<String> getVirtualizationTrapsResult(boolean includePostponedTraps) {
        return callNativeResult(() -> nGetVirtualizationTrapsRaw(includePostponedTraps));
    }

    /**
     * Enumerates active ({@code IFF_UP}) network interface names via zero-permission, zero-PII
     * native {@code NETLINK_ROUTE} {@code RTM_GETLINK} (never reads MAC addresses).
     */
    public static SignalResult<String> getActiveNetInterfacesResult() {
        return callNativeResult(NativeCollectorBridge::nGetActiveNetInterfacesRaw);
    }

    /**
     * Dynamically loads {@code libmediandk.so} via {@code dlopen}/{@code dlsym} and reads
     * non-PII Widevine {@code securityLevel} and {@code systemId} properties as a
     * {@link NativePayloadCodec} frame.
     */
    public static SignalResult<String> getWidevineNdkProbeResult() {
        return callNativeResult(NativeCollectorBridge::nGetWidevineNdkProbeRaw);
    }

    /**
     * Runs the native 5-vector TrickyStore / Binder interceptor probe (maps, libbinder ioctl GOT,
     * 16B ioctl inline hook, BINDER_VERSION 3-way parity, and optional POSTPONED rotating-order
     * Binder Honeypot timing).
     */
    public static SignalResult<String> getTeeBinderProbeResult(boolean includeHoneypotTiming) {
        return callNativeResult(() -> nGetTeeBinderProbeRaw(includeHoneypotTiming));
    }

    /**
     * Runs native X.509 leaf DER structural validation (HEX_TEMPLATE_32 + NON_MINIMAL_LENGTH)
     * cross-verifiable with Java {@code DerReader}.
     */
    public static SignalResult<String> inspectLeafDerResult(byte[] certDer) {
        if (certDer == null || certDer.length == 0) {
            return SignalResult.unavailable("empty_leaf_der");
        }
        return callNativeResult(() -> nInspectLeafDerRaw(certDer));
    }

    /**
     * Scans {@code [firstUid, lastUid]} via {@code getpriority(PRIO_USER, uid)} strictly inside
     * {@code util/disposable_child} and returns a {@link NativePayloadCodec} frame.
     */
    public static SignalResult<String> scanActiveAppUidsResult(int firstUid, int lastUid) {
        return callNativeResult(() -> nScanActiveAppUidsRaw(firstUid, lastUid));
    }

    /**
     * Runs the Linux >= 5.0 {@code SECCOMP_FILTER_FLAG_NEW_LISTENER} user-notif integrity probe
     * for {@code getpriority(PRIO_USER, *)} strictly inside {@code util/disposable_child}.
     */
    public static SignalResult<String> probeSeccompUidFilterResult(int firstUid, int lastUid) {
        return callNativeResult(() -> nProbeSeccompUidFilterRaw(firstUid, lastUid));
    }

    private static <T> SignalResult<T> callNativeResult(NativeCall<T> call) {
        if (!ensureNativeLoaded()) {
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

    private static final String[] NATIVE_SYSTEM_PROPERTIES = {
            "ro.build.fingerprint", "ro.build.display.id",
            "ro.product.model", "ro.product.brand",
            "ro.product.device", "ro.product.manufacturer",
            "ro.hardware", "ro.board.platform",
            "persist.sys.timezone", "gsm.version.baseband",
            "ro.kernel.qemu", "ro.boot.qemu", "ro.hardware.virtual",
            "ro.secure", "ro.debuggable", "ro.build.type"
    };

    public BaseCollector getSystemPropertyCollector() {
        return new BaseCollector(context) {
            @Override
            public String getName() { return "system_properties_native"; }

            @Override
            protected void collect(CollectorResult result) {
                if (!ensureNative(result)) return;
                try {
                    collectSystemProperties(result, android.os.Build.VERSION.SDK_INT,
                            prop -> signals != null
                                    ? signals.getSystemProperty(prop)
                                    : getSystemPropertyResult(prop));
                } catch (Exception e) {
                    CLog.e("SystemProperty collector failed", e);
                    result.markError(e);
                }
            }
        };
    }

    /**
     * Collects native system properties without letting individual SELinux-restricted
     * property failures poison the entire collector into {@link CollectorResult.Status#ERROR}.
     * Partial failures are recorded under {@code partial_errors} while preserving
     * {@link CollectorResult.Status#SUCCESS} whenever at least one property succeeds;
     * {@code ERROR} is set only when every attempted property fails.
     */
    public static void collectSystemProperties(CollectorResult result,
                                               int sdkInt,
                                               Function<String, SignalResult<String>> reader) {
        int succeededCount = 0;
        List<String> failedProps = new ArrayList<>();
        for (String prop : NATIVE_SYSTEM_PROPERTIES) {
            if (sdkInt >= 33
                    && ("ro.hardware.virtual".equals(prop)
                    || "ro.secure".equals(prop)
                    || "ro.debuggable".equals(prop))) {
                continue;
            }
            SignalResult<String> propResult = reader.apply(prop);
            if (propResult == null || !propResult.isSuccess()) {
                failedProps.add(prop);
                continue;
            }
            succeededCount++;
            String value = propResult.getValue();
            if (value != null && !value.isEmpty()) {
                result.addValue(prop, value);
            }
        }
        if (succeededCount == 0 && !failedProps.isEmpty()) {
            result.markError("all_properties_failed:" + String.join(",", failedProps));
        } else if (!failedProps.isEmpty()) {
            result.addValue("partial_errors", String.join(",", failedProps));
        }
    }

    public BaseCollector getCpuInfoCollector() {
        return new BaseCollector(context) {
            @Override
            public String getName() { return "cpu_info"; }

            @Override
            protected void collect(CollectorResult result) {
                if (!ensureNative(result)) return;
                try {
                    SignalResult<String> cached = signals == null ? null : signals.getCpuInfo();
                    String value = cached != null && cached.isSuccess()
                            ? cached.getValue() : nativeGetCpuInfo();
                    if (value != null && !value.isEmpty()) result.addValue("native", value);
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
                    SignalResult<Long> cached = signals == null ? null : signals.getDiskSizeData();
                    long size = cached != null && cached.isSuccess() && cached.getValue() != null
                            ? cached.getValue() : nativeGetDiskSize("/data");
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
                    SignalResult<String> cached = signals == null ? null : signals.getKernelInfo();
                    String value = cached != null && cached.isSuccess()
                            ? cached.getValue() : nativeGetKernelInfo();
                    if (value != null && !value.isEmpty()) result.addValue("native", value);
                } catch (Exception e) {
                    CLog.e("KernelInfo collector failed", e);
                    result.markError(e);
                }
            }
        };
    }

    private static boolean ensureNative(CollectorResult result) {
        if (ensureNativeLoaded()) {
            return true;
        }
        result.markUnsupported("native_library_unavailable");
        return false;
    }
}
