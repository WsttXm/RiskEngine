package com.wsttxm.riskenginesdk.core;

import android.content.Context;
import android.util.DisplayMetrics;
import android.view.WindowManager;

import com.wsttxm.riskenginesdk.collector.java_layer.GpuInfoCollector;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.AdbInspector;
import com.wsttxm.riskenginesdk.util.ShellExecutor;
import com.wsttxm.riskenginesdk.util.ProcfsUtils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/** Per-report cache for expensive signals shared by collectors and detectors. */
public final class SignalSnapshot {
    private final Context context;
    private final ConcurrentMap<String, SignalResult<String>> systemProperties =
            new ConcurrentHashMap<>();
    private final ConcurrentMap<String, SignalResult<String>> textFiles =
            new ConcurrentHashMap<>();
    private final ConcurrentMap<String, ShellExecutor.Result> shellResults =
            new ConcurrentHashMap<>();
    private final ConcurrentMap<String, SignalResult<Boolean>> pathExistence =
            new ConcurrentHashMap<>();
    private volatile SignalResult<AdbInspector.Snapshot> adbState;
    private volatile SignalResult<Set<Integer>> loopbackListeningPorts;
    private volatile SignalResult<List<String>> selfMaps;
    private volatile SignalResult<List<ProcfsUtils.ProcessInfo>> processes;
    private volatile SignalResult<List<String>> containerSignals;
    private volatile SignalResult<Integer> selinuxEnforce;
    private volatile SignalResult<String> buildPropFingerprint;
    private volatile SignalResult<String> cpuInfo;
    private volatile SignalResult<Long> diskSizeData;
    private volatile SignalResult<String> kernelInfo;
    private volatile SignalResult<String> nativeProcessTokens;
    private volatile SignalResult<String> soIntegrity;
    private volatile SignalResult<ScreenMetrics> screenMetrics;
    private volatile SignalResult<GpuIdentity> gpuIdentity;
    private volatile SignalResult<List<String>> networkInterfaceNames;
    private volatile SignalResult<String> mountNamespaceEvidence;
    private volatile SignalResult<String> kernelRootEvidence;
    private volatile SignalResult<String> jniSelfIntegrity;
    private volatile SignalResult<String> sealedVerdict;

    public SignalSnapshot(Context context) {
        Context application = context == null ? null : context.getApplicationContext();
        this.context = application != null ? application : context;
    }

    public void reset() {
        systemProperties.clear();
        textFiles.clear();
        shellResults.clear();
        pathExistence.clear();
        adbState = null;
        loopbackListeningPorts = null;
        selfMaps = null;
        processes = null;
        containerSignals = null;
        selinuxEnforce = null;
        buildPropFingerprint = null;
        cpuInfo = null;
        diskSizeData = null;
        kernelInfo = null;
        nativeProcessTokens = null;
        soIntegrity = null;
        screenMetrics = null;
        gpuIdentity = null;
        networkInterfaceNames = null;
        mountNamespaceEvidence = null;
        kernelRootEvidence = null;
        jniSelfIntegrity = null;
        sealedVerdict = null;
    }

    /** GPU identity strings, shared by the fingerprint and cloud detectors. */
    public static final class GpuIdentity {
        public final String vendor;
        public final String renderer;

        public GpuIdentity(String vendor, String renderer) {
            this.vendor = vendor == null ? "" : vendor;
            this.renderer = renderer == null ? "" : renderer;
        }
    }

    public static final class ScreenMetrics {
        public final int width;
        public final int height;
        public final float xdpi;
        public final float ydpi;
        public final int densityDpi;

        public ScreenMetrics(int width, int height, float xdpi, float ydpi, int densityDpi) {
            this.width = width;
            this.height = height;
            this.xdpi = xdpi;
            this.ydpi = ydpi;
            this.densityDpi = densityDpi;
        }
    }

    public SignalResult<AdbInspector.Snapshot> getAdbState() {
        SignalResult<AdbInspector.Snapshot> cached = adbState;
        if (cached != null) return cached;
        synchronized (this) {
            cached = adbState;
            if (cached == null) {
                try {
                    AdbInspector.Snapshot value = AdbInspector.collectUncached(context, this);
                    cached = SignalResult.success(value);
                } catch (Exception | LinkageError e) {
                    cached = SignalResult.error(e.getClass().getSimpleName());
                }
                adbState = cached;
            }
        }
        return cached;
    }

    public SignalResult<String> getSystemProperty(String name) {
        return systemProperties.computeIfAbsent(name, this::readSystemProperty);
    }

    public SignalResult<Set<Integer>> getLoopbackListeningPorts() {
        SignalResult<Set<Integer>> cached = loopbackListeningPorts;
        if (cached != null) return cached;
        synchronized (this) {
            cached = loopbackListeningPorts;
            if (cached == null) {
                try {
                    cached = SignalResult.success(Collections.unmodifiableSet(
                            ProcfsUtils.findLoopbackListeningPorts()));
                } catch (Exception e) {
                    cached = SignalResult.error(e.getClass().getSimpleName());
                }
                loopbackListeningPorts = cached;
            }
        }
        return cached;
    }

    public SignalResult<List<String>> getSelfMaps() {
        SignalResult<List<String>> cached = selfMaps;
        if (cached != null) return cached;
        synchronized (this) {
            cached = selfMaps;
            if (cached == null) {
                List<String> lines = new ArrayList<>();
                try (BufferedReader reader = new BufferedReader(
                        new FileReader("/proc/self/maps"))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        lines.add(line);
                    }
                    cached = SignalResult.success(Collections.unmodifiableList(lines));
                } catch (Exception e) {
                    cached = SignalResult.error(e.getClass().getSimpleName());
                }
                selfMaps = cached;
            }
        }
        return cached;
    }

    public SignalResult<String> getTextFile(String path) {
        return textFiles.computeIfAbsent(path, key -> {
            try {
                File file = new File(key);
                if (!file.exists() || !file.canRead()) {
                    return SignalResult.unavailable("file_unreadable");
                }
                return SignalResult.success(ProcfsUtils.readFile(key));
            } catch (Exception e) {
                return SignalResult.error(e.getClass().getSimpleName());
            }
        });
    }

    public ShellExecutor.Result getShellResult(String command) {
        return shellResults.computeIfAbsent(command, ShellExecutor::executeResult);
    }

    public boolean pathExists(String path) {
        SignalResult<Boolean> result = getPathExists(path);
        return result.isSuccess() && Boolean.TRUE.equals(result.getValue());
    }

    public SignalResult<Boolean> getPathExists(String path) {
        return pathExistence.computeIfAbsent(path, key -> {
            try {
                return SignalResult.success(new File(key).exists());
            } catch (SecurityException e) {
                return SignalResult.error(e.getClass().getSimpleName());
            }
        });
    }

    public SignalResult<List<ProcfsUtils.ProcessInfo>> getProcesses() {
        SignalResult<List<ProcfsUtils.ProcessInfo>> cached = processes;
        if (cached != null) return cached;
        synchronized (this) {
            cached = processes;
            if (cached == null) {
                try {
                    List<ProcfsUtils.ProcessInfo> value = ProcfsUtils.snapshotProcesses();
                    cached = SignalResult.success(Collections.unmodifiableList(value));
                } catch (Exception e) {
                    cached = SignalResult.error(e.getClass().getSimpleName());
                }
                processes = cached;
            }
        }
        return cached;
    }

    public SignalResult<List<String>> getContainerSignals() {
        SignalResult<List<String>> cached = containerSignals;
        if (cached != null) return cached;
        synchronized (this) {
            cached = containerSignals;
            if (cached == null) {
                try {
                    List<String> signals = new ArrayList<>();
                    String[] cgroupPaths = {"/proc/1/cgroup", "/proc/self/cgroup"};
                    String[] keywords = {"docker", "lxc", "container", "kubepods", "podman"};
                    for (String path : cgroupPaths) {
                        SignalResult<String> file = getTextFile(path);
                        String content = file.getValue() == null
                                ? "" : file.getValue().toLowerCase(java.util.Locale.ROOT);
                        for (String keyword : keywords) {
                            if (content.contains(keyword)) {
                                signals.add("cgroup:" + keyword);
                                break;
                            }
                        }
                    }
                    SignalResult<String> mounts = getTextFile("/proc/self/mountinfo");
                    if (mounts.getValue() != null
                            && mounts.getValue().toLowerCase(java.util.Locale.ROOT)
                            .contains(" overlay ")) {
                        signals.add("mount_overlay");
                    }
                    SignalResult<String> cmdlineFile = getTextFile("/proc/self/cmdline");
                    String cmdline = cmdlineFile.getValue() == null ? ""
                            : cmdlineFile.getValue().replace('\0', ' ').trim();
                    if (!cmdline.isEmpty() && context != null
                            && !cmdline.contains(context.getPackageName())) {
                        signals.add("cmdline_mismatch");
                    }
                    cached = SignalResult.success(Collections.unmodifiableList(signals));
                } catch (Exception e) {
                    cached = SignalResult.error(e.getClass().getSimpleName());
                }
                containerSignals = cached;
            }
        }
        return cached;
    }

    public SignalResult<Integer> getSelinuxEnforce() {
        return cachedNative(selinuxEnforce, v -> selinuxEnforce = v,
                NativeCollectorBridge::getSelinuxEnforceResult);
    }

    public SignalResult<String> getBuildPropFingerprint() {
        return cachedNative(buildPropFingerprint, v -> buildPropFingerprint = v,
                NativeCollectorBridge::getBuildPropFingerprintResult);
    }

    public SignalResult<String> getCpuInfo() {
        return cachedNative(cpuInfo, v -> cpuInfo = v, NativeCollectorBridge::getCpuInfoResult);
    }

    public SignalResult<Long> getDiskSizeData() {
        return cachedNative(diskSizeData, v -> diskSizeData = v,
                () -> NativeCollectorBridge.getDiskSizeResult("/data"));
    }

    public SignalResult<String> getKernelInfo() {
        return cachedNative(kernelInfo, v -> kernelInfo = v,
                NativeCollectorBridge::getKernelInfoResult);
    }

    public SignalResult<String> getNativeProcessTokens() {
        return cachedNative(nativeProcessTokens, v -> nativeProcessTokens = v,
                NativeCollectorBridge::scanProcessTokensResult);
    }

    public SignalResult<String> getSoIntegrity() {
        return cachedNative(soIntegrity, v -> soIntegrity = v,
                NativeCollectorBridge::getSoIntegrityResult);
    }

    public SignalResult<ScreenMetrics> getScreenMetrics() {
        SignalResult<ScreenMetrics> cached = screenMetrics;
        if (cached != null) return cached;
        synchronized (this) {
            cached = screenMetrics;
            if (cached == null) {
                try {
                    if (context == null) {
                        cached = SignalResult.unavailable("context_unavailable");
                    } else {
                        WindowManager wm = (WindowManager) context.getSystemService(Context.WINDOW_SERVICE);
                        DisplayMetrics dm = context.getResources().getDisplayMetrics();
                        int width = dm.widthPixels;
                        int height = dm.heightPixels;
                        if (wm != null) {
                            android.graphics.Rect bounds = wm.getMaximumWindowMetrics().getBounds();
                            width = bounds.width();
                            height = bounds.height();
                        }
                        cached = SignalResult.success(new ScreenMetrics(
                                width, height, dm.xdpi, dm.ydpi, dm.densityDpi));
                    }
                } catch (Exception e) {
                    cached = SignalResult.error(e.getClass().getSimpleName());
                }
                screenMetrics = cached;
            }
        }
        return cached;
    }

    private interface NativeFetch<T> {
        SignalResult<T> get();
    }

    private interface NativeCache<T> {
        void set(SignalResult<T> value);
    }

    private <T> SignalResult<T> cachedNative(SignalResult<T> cached, NativeCache<T> store,
                                             NativeFetch<T> fetch) {
        if (cached != null) return cached;
        synchronized (this) {
            // Re-read via fetch only once; store holds the field write.
            SignalResult<T> value;
            try {
                if (!NativeCollectorBridge.isNativeAvailable()) {
                    value = SignalResult.unavailable("native_library_unavailable");
                } else {
                    value = fetch.get();
                }
            } catch (Exception | LinkageError e) {
                value = SignalResult.error(e.getClass().getSimpleName());
            }
            store.set(value);
            return value;
        }
    }

    public SignalResult<String> getMountNamespaceEvidence() {
        return cachedNative(mountNamespaceEvidence, v -> mountNamespaceEvidence = v,
                NativeCollectorBridge::getMountNamespaceEvidenceResult);
    }

    public SignalResult<String> getKernelRootEvidence() {
        return cachedNative(kernelRootEvidence, v -> kernelRootEvidence = v,
                NativeCollectorBridge::getKernelRootEvidenceResult);
    }

    public SignalResult<String> getJniSelfIntegrity() {
        return cachedNative(jniSelfIntegrity, v -> jniSelfIntegrity = v,
                NativeCollectorBridge::getJniSelfIntegrityResult);
    }

    /** The native-sealed verdict for this collection. Issued once per report. */
    public SignalResult<String> getSealedVerdict() {
        return cachedNative(sealedVerdict, v -> sealedVerdict = v,
                NativeCollectorBridge::getSealedVerdictResult);
    }

    /**
     * Reads GPU vendor and renderer once per report through an offscreen EGL
     * context. Cached because creating a context is comparatively expensive and
     * both the fingerprint collector and the cloud detector need the values.
     */
    public SignalResult<GpuIdentity> getGpuIdentity() {
        SignalResult<GpuIdentity> cached = gpuIdentity;
        if (cached != null) return cached;
        synchronized (this) {
            cached = gpuIdentity;
            if (cached == null) {
                try {
                    CollectorResult probe = new CollectorResult("gpu_probe");
                    GpuInfoCollector.probeInto(probe);
                    String vendor = probe.getValues().get("vendor");
                    String renderer = probe.getValues().get("renderer");
                    if (vendor == null && renderer == null) {
                        cached = SignalResult.unavailable(
                                probe.getError() == null ? "egl_unavailable" : probe.getError());
                    } else {
                        cached = SignalResult.success(new GpuIdentity(vendor, renderer));
                    }
                } catch (Exception | LinkageError e) {
                    cached = SignalResult.error(e.getClass().getSimpleName());
                }
                gpuIdentity = cached;
            }
        }
        return cached;
    }

    /**
     * Interface names from sysfs, falling back to the Java enumeration. Both
     * paths are used because a hook on one is common and they should agree.
     */
    public SignalResult<List<String>> getNetworkInterfaceNames() {
        SignalResult<List<String>> cached = networkInterfaceNames;
        if (cached != null) return cached;
        synchronized (this) {
            cached = networkInterfaceNames;
            if (cached == null) {
                List<String> names = new ArrayList<>();
                try {
                    File[] entries = new File("/sys/class/net").listFiles();
                    if (entries != null) {
                        for (File entry : entries) {
                            names.add(entry.getName());
                        }
                    }
                    if (names.isEmpty()) {
                        java.util.Enumeration<java.net.NetworkInterface> list =
                                java.net.NetworkInterface.getNetworkInterfaces();
                        while (list != null && list.hasMoreElements()) {
                            names.add(list.nextElement().getName());
                        }
                    }
                    cached = names.isEmpty()
                            ? SignalResult.unavailable("no_interfaces")
                            : SignalResult.success(Collections.unmodifiableList(names));
                } catch (Exception e) {
                    cached = SignalResult.error(e.getClass().getSimpleName());
                }
                networkInterfaceNames = cached;
            }
        }
        return cached;
    }

    /**
     * Reads a system property through the native accessor only.
     *
     * The previous implementation forked /system/bin/sh to run getprop when the
     * native read came back empty. That was removed: fork/exec is noisy, is
     * itself hookable, can be blocked by policy, and an empty property is a
     * legitimate answer rather than a failure needing a second opinion.
     */
    private SignalResult<String> readSystemProperty(String name) {
        if (!NativeCollectorBridge.isNativeAvailable()) {
            return SignalResult.unavailable("native_library_unavailable");
        }
        try {
            String value = NativeCollectorBridge.getSystemProperty(name);
            if (value == null) {
                return SignalResult.unavailable("property_read_failed");
            }
            String trimmed = value.trim();
            return trimmed.isEmpty()
                    ? SignalResult.empty("") : SignalResult.success(trimmed);
        } catch (Exception | LinkageError e) {
            return SignalResult.error(e.getClass().getSimpleName());
        }
    }
}
