package com.wsttxm.riskenginesdk.core;

import android.content.Context;
import android.util.DisplayMetrics;
import android.view.WindowManager;

import com.wsttxm.riskenginesdk.attestation.AttestationCapability;
import com.wsttxm.riskenginesdk.collector.java_layer.GpuInfoCollector;
import com.wsttxm.riskenginesdk.collector.java_layer.MediaCodecCollector;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.process.IsolatedProbeClient;
import com.wsttxm.riskenginesdk.util.AdbInspector;
import com.wsttxm.riskenginesdk.util.InstallTokenSanitizer;
import com.wsttxm.riskenginesdk.util.ShellExecutor;
import com.wsttxm.riskenginesdk.util.ProcfsUtils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Consumer;
import java.util.function.Supplier;

/** Per-report cache for expensive signals shared by collectors and detectors. */
public final class SignalSnapshot {
    private final Context context;
    private final ConcurrentMap<String, Object> signalLocks = new ConcurrentHashMap<>();
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
    private volatile SignalResult<ScreenMetrics> screenMetrics;
    private volatile SignalResult<Map<String, String>> gpuAttributes;
    private volatile SignalResult<GpuIdentity> gpuIdentity;
    private volatile SignalResult<List<String>> networkInterfaceNames;
    private volatile SignalResult<String> nativeRootEvidence;
    private volatile SignalResult<String> kernelRootEvidence;
    private volatile SignalResult<Map<String, String>> procCmdlineBootProps;
    private volatile SignalResult<Integer> possibleCpuCores;
    private volatile SignalResult<String> nativeApkSigningInfo;
    private volatile SignalResult<String> bionicPropForensics;
    private volatile SignalResult<String> customRomProbe;
    private volatile SignalResult<String> kernelSidechannelEvidence;
    private volatile SignalResult<String> kernelSidechannelTimingEvidence;
    private volatile SignalResult<String> selinuxAuditEvidence;
    private volatile SignalResult<String> zygiskAtexitProbe;
    private volatile SignalResult<String> virtualizationTrapsFast;
    private volatile SignalResult<String> virtualizationTrapsPostponed;
    private volatile SignalResult<MediaCodecCollector.CodecSummary> mediaCodecSummary;
    private volatile SignalResult<IsolatedProbeClient.IsolatedMountReport> isolatedMountReport;
    private volatile SignalResult<IsolatedProbeClient.IsolatedGrantReport> isolatedGrantReport;
    private volatile SignalResult<AttestationCapability.AttestationSnapshot> attestationSnapshot;
    private volatile SignalResult<String> teeBinderProbeFast;
    private volatile SignalResult<String> teeBinderProbePostponed;

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
        screenMetrics = null;
        gpuAttributes = null;
        gpuIdentity = null;
        networkInterfaceNames = null;
        nativeRootEvidence = null;
        kernelRootEvidence = null;
        procCmdlineBootProps = null;
        possibleCpuCores = null;
        nativeApkSigningInfo = null;
        bionicPropForensics = null;
        customRomProbe = null;
        kernelSidechannelEvidence = null;
        kernelSidechannelTimingEvidence = null;
        selinuxAuditEvidence = null;
        zygiskAtexitProbe = null;
        virtualizationTrapsFast = null;
        virtualizationTrapsPostponed = null;
        mediaCodecSummary = null;
        isolatedMountReport = null;
        isolatedGrantReport = null;
        attestationSnapshot = null;
        teeBinderProbeFast = null;
        teeBinderProbePostponed = null;
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

    private Object lockFor(String signalKey) {
        return signalLocks.computeIfAbsent(signalKey, k -> new Object());
    }

    public SignalResult<AdbInspector.Snapshot> getAdbState() {
        SignalResult<AdbInspector.Snapshot> cached = adbState;
        if (cached != null) return cached;
        synchronized (lockFor("adbState")) {
            cached = adbState;
            if (cached == null) {
                try {
                    AdbInspector.Snapshot value = AdbInspector.collectUncached(context, this);
                    cached = SignalResult.success(value);
                } catch (Exception | LinkageError | OutOfMemoryError e) {
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
        synchronized (lockFor("loopbackListeningPorts")) {
            cached = loopbackListeningPorts;
            if (cached == null) {
                try {
                    cached = ProcfsUtils.findLoopbackListeningPortsResult();
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
        synchronized (lockFor("selfMaps")) {
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

    /** Returns {@link #getSelfMaps()} lines with Android random Base64 install tokens stripped. */
    public SignalResult<List<String>> getSanitizedSelfMaps() {
        SignalResult<List<String>> raw = getSelfMaps();
        if (raw == null || !raw.isSuccess() || raw.getValue() == null) {
            return raw;
        }
        List<String> rawLines = raw.getValue();
        List<String> sanitized = new ArrayList<>(rawLines.size());
        for (String line : rawLines) {
            sanitized.add(InstallTokenSanitizer.stripInstallTokens(line));
        }
        return SignalResult.success(Collections.unmodifiableList(sanitized));
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
        synchronized (lockFor("processes")) {
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
        synchronized (lockFor("containerSignals")) {
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
                } catch (Exception | LinkageError | OutOfMemoryError e) {
                    cached = SignalResult.error(e.getClass().getSimpleName());
                }
                containerSignals = cached;
            }
        }
        return cached;
    }

    public SignalResult<Integer> getSelinuxEnforce() {
        return cachedNative("selinuxEnforce", () -> selinuxEnforce, v -> selinuxEnforce = v,
                NativeCollectorBridge::getSelinuxEnforceResult);
    }

    public SignalResult<String> getBuildPropFingerprint() {
        return cachedNative("buildPropFingerprint", () -> buildPropFingerprint,
                v -> buildPropFingerprint = v,
                NativeCollectorBridge::getBuildPropFingerprintResult);
    }

    public SignalResult<String> getCpuInfo() {
        return cachedNative("cpuInfo", () -> cpuInfo, v -> cpuInfo = v,
                NativeCollectorBridge::getCpuInfoResult);
    }

    public SignalResult<Long> getDiskSizeData() {
        return cachedNative("diskSizeData", () -> diskSizeData, v -> diskSizeData = v,
                () -> NativeCollectorBridge.getDiskSizeResult("/data"));
    }

    public SignalResult<String> getKernelInfo() {
        return cachedNative("kernelInfo", () -> kernelInfo, v -> kernelInfo = v,
                NativeCollectorBridge::getKernelInfoResult);
    }

    public SignalResult<ScreenMetrics> getScreenMetrics() {
        SignalResult<ScreenMetrics> cached = screenMetrics;
        if (cached != null) return cached;
        synchronized (lockFor("screenMetrics")) {
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
                } catch (Exception | LinkageError | OutOfMemoryError e) {
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

    private <T> SignalResult<T> cachedNative(String lockKey,
                                             Supplier<SignalResult<T>> load,
                                             Consumer<SignalResult<T>> store,
                                             NativeFetch<T> fetch) {
        SignalResult<T> cached = load.get();
        if (cached != null) return cached;
        synchronized (lockFor(lockKey)) {
            cached = load.get();
            if (cached != null) return cached;
            SignalResult<T> value;
            try {
                if (!NativeCollectorBridge.isNativeAvailable()) {
                    value = SignalResult.unavailable("native_library_unavailable");
                } else {
                    value = fetch.get();
                }
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                value = SignalResult.error(e.getClass().getSimpleName());
            }
            store.accept(value);
            return value;
        }
    }

    public SignalResult<String> getNativeRootEvidence() {
        return cachedNative("nativeRootEvidence", () -> nativeRootEvidence,
                v -> nativeRootEvidence = v,
                NativeCollectorBridge::getRootEvidenceResult);
    }

    public SignalResult<String> getKernelRootEvidence() {
        return cachedNative("kernelRootEvidence", () -> kernelRootEvidence,
                v -> kernelRootEvidence = v,
                NativeCollectorBridge::getKernelRootEvidenceResult);
    }

    public SignalResult<String> getNativeApkSigningInfo() {
        return cachedNative("nativeApkSigningInfo", () -> nativeApkSigningInfo,
                v -> nativeApkSigningInfo = v,
                () -> NativeCollectorBridge.getApkSigningInfoResult(resolveApplicationSourceDir()));
    }

    /** Cached native Bionic {@code /dev/__properties__} binary forensics frame. */
    public SignalResult<String> getBionicPropForensics() {
        return cachedNative("bionicPropForensics", () -> bionicPropForensics,
                v -> bionicPropForensics = v,
                NativeCollectorBridge::getBionicPropForensicsResult);
    }

    /** Cached native custom-ROM probe frame (libstagefright symbol + framework-res block devices). */
    public SignalResult<String> getCustomRomProbe() {
        return cachedNative("customRomProbe", () -> customRomProbe,
                v -> customRomProbe = v,
                NativeCollectorBridge::getCustomRomProbeResult);
    }

    /** Cached native kernel root side-channel forensics frame (disposable_child + optional timing). */
    public SignalResult<String> getKernelSidechannelEvidence(boolean includePostponedTiming) {
        if (includePostponedTiming) {
            return cachedNative("kernelSidechannelTimingEvidence",
                    () -> kernelSidechannelTimingEvidence,
                    v -> kernelSidechannelTimingEvidence = v,
                    () -> NativeCollectorBridge.getKernelSidechannelResult(true));
        }
        return cachedNative("kernelSidechannelEvidence",
                () -> kernelSidechannelEvidence,
                v -> kernelSidechannelEvidence = v,
                () -> NativeCollectorBridge.getKernelSidechannelResult(false));
    }

    /** Cached native SELinux deep audit & Netlink policy-reload leak forensics frame. */
    public SignalResult<String> getSelinuxAuditEvidence() {
        return cachedNative("selinuxAuditEvidence",
                () -> selinuxAuditEvidence,
                v -> selinuxAuditEvidence = v,
                () -> NativeCollectorBridge.getSelinuxAuditResult(
                        android.os.Build.VERSION.SDK_INT, resolveTargetSdkVersion()));
    }

    /** Cached native Zygisk Bionic {@code atexit} array forensics frame. */
    public SignalResult<String> getZygiskAtexitProbe() {
        return cachedNative("zygiskAtexitProbe",
                () -> zygiskAtexitProbe,
                v -> zygiskAtexitProbe = v,
                NativeCollectorBridge::getZygiskAtexitProbeResult);
    }

    /** Cached native virtualization & binary translation traps frame (separate FAST vs POSTPONED slots). */
    public SignalResult<String> getVirtualizationTraps(boolean includePostponedTraps) {
        if (includePostponedTraps) {
            return cachedNative("virtualizationTrapsPostponed",
                    () -> virtualizationTrapsPostponed,
                    v -> virtualizationTrapsPostponed = v,
                    () -> NativeCollectorBridge.getVirtualizationTrapsResult(true));
        }
        return cachedNative("virtualizationTrapsFast",
                () -> virtualizationTrapsFast,
                v -> virtualizationTrapsFast = v,
                () -> NativeCollectorBridge.getVirtualizationTrapsResult(false));
    }

    private int resolveTargetSdkVersion() {
        try {
            if (context != null && context.getApplicationInfo() != null
                    && context.getApplicationInfo().targetSdkVersion > 0) {
                return context.getApplicationInfo().targetSdkVersion;
            }
        } catch (Exception | LinkageError ignored) {
            // Fail closed (0) when ApplicationInfo is unavailable so API 30-32 / targetSdk<32
            // processes never over-enforce Netlink restrictions and false-positive.
        }
        return 0;
    }

    /**
     * Runs the ephemeral {@code RiskIsolatedProbeService} cross-process mount diff once per
     * snapshot and caches the outcome. Returns {@code UNAVAILABLE} when disabled in config.
     */
    public SignalResult<IsolatedProbeClient.IsolatedMountReport> getIsolatedMountReport(
            boolean enabled) {
        if (!enabled) {
            return SignalResult.unavailable("isolated_probe_disabled");
        }
        SignalResult<IsolatedProbeClient.IsolatedMountReport> cached = isolatedMountReport;
        if (cached != null) return cached;
        synchronized (lockFor("isolatedMountReport")) {
            cached = isolatedMountReport;
            if (cached == null) {
                try {
                    cached = IsolatedProbeClient.probeMountView(context, this, true);
                } catch (Exception | LinkageError | OutOfMemoryError e) {
                    cached = SignalResult.error(e.getClass().getSimpleName());
                }
                isolatedMountReport = cached;
            }
        }
        return cached;
    }

    /**
     * Runs the ephemeral {@code RiskIsolatedProbeService} Keystore2 Domain.APP vs Domain.GRANT
     * chain-split probe once per snapshot and caches the outcome.
     */
    public SignalResult<IsolatedProbeClient.IsolatedGrantReport> getIsolatedGrantReport(
            boolean enabled) {
        if (!enabled) {
            return SignalResult.unavailable("isolated_probe_disabled");
        }
        SignalResult<IsolatedProbeClient.IsolatedGrantReport> cached = isolatedGrantReport;
        if (cached != null) return cached;
        synchronized (lockFor("isolatedGrantReport")) {
            cached = isolatedGrantReport;
            if (cached == null) {
                try {
                    cached = IsolatedProbeClient.probeGrantDomainChain(context, true);
                } catch (Exception | LinkageError | OutOfMemoryError e) {
                    cached = SignalResult.unavailable(e.getClass().getSimpleName());
                }
                isolatedGrantReport = cached;
            }
        }
        return cached;
    }

    /**
     * Collects hardware Key Attestation (StrongBox -> TEE fallback) once per scan and caches it
     * for {@code BootloaderProbe}, {@code TeeIntegrityDetector}, and {@code DataAggregator}.
     */
    public SignalResult<AttestationCapability.AttestationSnapshot> getAttestationSnapshot(
            boolean enabled) {
        if (!enabled) {
            return SignalResult.unavailable("tee_attestation_disabled");
        }
        SignalResult<AttestationCapability.AttestationSnapshot> cached = attestationSnapshot;
        if (cached != null) return cached;
        synchronized (lockFor("attestationSnapshot")) {
            cached = attestationSnapshot;
            if (cached == null) {
                try {
                    AttestationCapability.AttestationSnapshot snap =
                            new AttestationCapability().collect();
                    if (snap != null && snap.isAvailable()) {
                        cached = SignalResult.success(snap);
                    } else {
                        String reason = snap != null && snap.getFailureReason() != null
                                ? snap.getFailureReason()
                                : "tee_attestation_unavailable";
                        cached = SignalResult.unavailable(reason);
                    }
                } catch (Exception | LinkageError | OutOfMemoryError e) {
                    cached = SignalResult.error(e.getClass().getSimpleName());
                }
                attestationSnapshot = cached;
            }
        }
        return cached;
    }

    /** Cached native TEE / TrickyStore 5-vector probe frame (separate slots with/without honeypot timing). */
    public SignalResult<String> getTeeBinderProbe(boolean includeHoneypotTiming) {
        if (includeHoneypotTiming) {
            return cachedNative("teeBinderProbePostponed",
                    () -> teeBinderProbePostponed,
                    v -> teeBinderProbePostponed = v,
                    () -> NativeCollectorBridge.getTeeBinderProbeResult(true));
        }
        return cachedNative("teeBinderProbeFast",
                () -> teeBinderProbeFast,
                v -> teeBinderProbeFast = v,
                () -> NativeCollectorBridge.getTeeBinderProbeResult(false));
    }

    private String resolveApplicationSourceDir() {
        if (context == null) {
            return "";
        }
        try {
            android.content.pm.ApplicationInfo appInfo = context.getApplicationInfo();
            return appInfo != null && appInfo.sourceDir != null ? appInfo.sourceDir : "";
        } catch (Exception | LinkageError e) {
            return "";
        }
    }

    // Internal test seams for deterministic JVM unit tests (not part of public SDK contract).
    public void seedCpuInfoForTest(SignalResult<String> value) {
        this.cpuInfo = value;
    }

    public void seedDiskSizeDataForTest(SignalResult<Long> value) {
        this.diskSizeData = value;
    }

    public void seedKernelInfoForTest(SignalResult<String> value) {
        this.kernelInfo = value;
    }

    public void seedSelinuxEnforceForTest(SignalResult<Integer> value) {
        this.selinuxEnforce = value;
    }

    public void seedNativeRootEvidenceForTest(SignalResult<String> value) {
        this.nativeRootEvidence = value;
    }

    public void seedPathExistsForTest(String path, SignalResult<Boolean> value) {
        if (path != null && value != null) {
            this.pathExistence.put(path, value);
        }
    }

    public void seedTextFileForTest(String path, SignalResult<String> value) {
        if (path != null && value != null) {
            this.textFiles.put(path, value);
        }
    }

    public void seedSystemPropertyForTest(String name, SignalResult<String> value) {
        if (name != null && value != null) {
            this.systemProperties.put(name, value);
        }
    }

    public void seedSelfMapsForTest(SignalResult<List<String>> value) {
        this.selfMaps = value;
    }

    public void seedLoopbackListeningPortsForTest(SignalResult<Set<Integer>> value) {
        this.loopbackListeningPorts = value;
    }

    public void seedProcessesForTest(SignalResult<List<ProcfsUtils.ProcessInfo>> value) {
        this.processes = value;
    }

    public void seedContainerSignalsForTest(SignalResult<List<String>> value) {
        this.containerSignals = value;
    }

    public void seedBuildPropFingerprintForTest(SignalResult<String> value) {
        this.buildPropFingerprint = value;
    }

    public void seedScreenMetricsForTest(SignalResult<ScreenMetrics> value) {
        this.screenMetrics = value;
    }

    public void seedGpuIdentityForTest(SignalResult<GpuIdentity> value) {
        this.gpuIdentity = value;
    }

    public void seedNetworkInterfaceNamesForTest(SignalResult<List<String>> value) {
        this.networkInterfaceNames = value;
    }

    public void seedProcCmdlineBootPropsForTest(SignalResult<Map<String, String>> value) {
        this.procCmdlineBootProps = value;
    }

    public void seedPossibleCpuCoreCountForTest(SignalResult<Integer> value) {
        this.possibleCpuCores = value;
    }

    public void seedAdbStateForTest(SignalResult<AdbInspector.Snapshot> value) {
        this.adbState = value;
    }

    public void seedNativeApkSigningInfoForTest(SignalResult<String> value) {
        this.nativeApkSigningInfo = value;
    }

    public void seedBionicPropForensicsForTest(SignalResult<String> value) {
        this.bionicPropForensics = value;
    }

    public void seedCustomRomProbeForTest(SignalResult<String> value) {
        this.customRomProbe = value;
    }

    public void seedKernelSidechannelEvidenceForTest(SignalResult<String> value) {
        this.kernelSidechannelEvidence = value;
        this.kernelSidechannelTimingEvidence = value;
    }

    public void seedKernelSidechannelEvidenceForTest(boolean includePostponedTiming,
                                                     SignalResult<String> value) {
        if (includePostponedTiming) {
            this.kernelSidechannelTimingEvidence = value;
        } else {
            this.kernelSidechannelEvidence = value;
        }
    }

    public void seedSelinuxAuditEvidenceForTest(SignalResult<String> value) {
        this.selinuxAuditEvidence = value;
    }

    public void seedZygiskAtexitProbeForTest(SignalResult<String> value) {
        this.zygiskAtexitProbe = value;
    }

    public void seedVirtualizationTrapsForTest(boolean includePostponedTraps,
                                               SignalResult<String> value) {
        if (includePostponedTraps) {
            this.virtualizationTrapsPostponed = value;
        } else {
            this.virtualizationTrapsFast = value;
        }
    }

    public void seedIsolatedMountReportForTest(
            SignalResult<IsolatedProbeClient.IsolatedMountReport> value) {
        this.isolatedMountReport = value;
    }

    public void seedIsolatedGrantReportForTest(
            SignalResult<IsolatedProbeClient.IsolatedGrantReport> value) {
        this.isolatedGrantReport = value;
    }

    public void seedMediaCodecSummaryForTest(
            SignalResult<MediaCodecCollector.CodecSummary> value) {
        this.mediaCodecSummary = value;
    }

    public void seedAttestationSnapshotForTest(
            SignalResult<AttestationCapability.AttestationSnapshot> value) {
        this.attestationSnapshot = value;
    }

    public void seedTeeBinderProbeForTest(boolean includeHoneypotTiming, SignalResult<String> value) {
        if (includeHoneypotTiming) {
            this.teeBinderProbePostponed = value;
        } else {
            this.teeBinderProbeFast = value;
        }
    }

    /** Cached MediaCodec hardware/software codec summary shared by emulator and cloud detectors. */
    public SignalResult<MediaCodecCollector.CodecSummary> getMediaCodecSummary() {
        SignalResult<MediaCodecCollector.CodecSummary> cached = mediaCodecSummary;
        if (cached != null) return cached;
        synchronized (lockFor("mediaCodecSummary")) {
            cached = mediaCodecSummary;
            if (cached == null) {
                try {
                    MediaCodecCollector.CodecSummary summary =
                            MediaCodecCollector.readSystemCodecsSummary();
                    cached = summary != null
                            ? SignalResult.success(summary)
                            : SignalResult.unavailable("media_codec_unavailable");
                } catch (Exception | LinkageError | OutOfMemoryError e) {
                    cached = SignalResult.unavailable(e.getClass().getSimpleName());
                }
                mediaCodecSummary = cached;
            }
        }
        return cached;
    }

    /** Boot parameters extracted from /proc/cmdline via native raw syscall. */
    public SignalResult<Map<String, String>> getProcCmdlineBootProps() {
        return cachedNative("procCmdlineBootProps", () -> procCmdlineBootProps,
                v -> procCmdlineBootProps = v, () -> {
            SignalResult<String> raw = NativeCollectorBridge.getProcCmdlineBootPropsResult();
            if (!raw.isSuccess()) {
                return raw.getStatus() == SignalResult.Status.UNAVAILABLE
                        ? SignalResult.unavailable(raw.getFailureReason())
                        : SignalResult.error(raw.getFailureReason());
            }
            Map<String, String> parsed = new LinkedHashMap<>();
            String text = raw.getValue();
            if (text != null && !text.isBlank()) {
                for (String pair : text.split(";")) {
                    int eq = pair.indexOf('=');
                    if (eq > 0 && eq + 1 < pair.length()) {
                        parsed.put(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim());
                    }
                }
            }
            return parsed.isEmpty()
                    ? SignalResult.empty(Collections.emptyMap())
                    : SignalResult.success(Collections.unmodifiableMap(parsed));
        });
    }

    /** Physical possible CPU count from sysfs (unaffected by runtime hotplug offline). */
    public SignalResult<Integer> getPossibleCpuCoreCount() {
        SignalResult<Integer> cached = possibleCpuCores;
        if (cached != null) return cached;
        synchronized (lockFor("possibleCpuCores")) {
            cached = possibleCpuCores;
            if (cached == null) {
                try {
                    String raw = ProcfsUtils.readFirstLine("/sys/devices/system/cpu/possible");
                    if (raw == null || raw.isBlank()) {
                        raw = ProcfsUtils.readFirstLine("/sys/devices/system/cpu/present");
                    }
                    int count = parseCpuRangeCount(raw);
                    cached = count > 0
                            ? SignalResult.success(count)
                            : SignalResult.unavailable("cpu_possible_unavailable");
                } catch (Exception e) {
                    cached = SignalResult.error(e.getClass().getSimpleName());
                }
                possibleCpuCores = cached;
            }
        }
        return cached;
    }

    static int parseCpuRangeCount(String raw) {
        if (raw == null || raw.isBlank()) return -1;
        int total = 0;
        for (String part : raw.trim().split(",")) {
            String segment = part.trim();
            if (segment.isEmpty()) continue;
            int dash = segment.indexOf('-');
            try {
                if (dash < 0) {
                    Integer.parseInt(segment);
                    total += 1;
                } else {
                    int start = Integer.parseInt(segment.substring(0, dash).trim());
                    int end = Integer.parseInt(segment.substring(dash + 1).trim());
                    if (end >= start) {
                        total += (end - start + 1);
                    }
                }
            } catch (NumberFormatException ignored) {
                return -1;
            }
        }
        return total > 0 ? total : -1;
    }

    /**
     * Full GPU attributes from a single offscreen EGL pbuffer probe, shared by
     * {@link GpuInfoCollector} and {@link #getGpuIdentity()}.
     */
    public SignalResult<Map<String, String>> getGpuAttributes() {
        SignalResult<Map<String, String>> cached = gpuAttributes;
        if (cached != null) return cached;
        synchronized (lockFor("gpuAttributes")) {
            cached = gpuAttributes;
            if (cached == null) {
                try {
                    CollectorResult probe = new CollectorResult("gpu_probe");
                    GpuInfoCollector.probeInto(probe);
                    probe.finish();
                    if (probe.getStatus() == CollectorResult.Status.SUCCESS
                            && !probe.getValues().isEmpty()) {
                        cached = SignalResult.success(Collections.unmodifiableMap(
                                GpuInfoCollector.copyValues(probe)));
                    } else if (probe.getStatus() == CollectorResult.Status.ERROR) {
                        cached = SignalResult.error(
                                probe.getError() == null ? "egl_error" : probe.getError());
                    } else {
                        cached = SignalResult.unavailable(
                                probe.getError() == null ? "egl_unavailable" : probe.getError());
                    }
                } catch (Exception | LinkageError | OutOfMemoryError e) {
                    cached = SignalResult.error(e.getClass().getSimpleName());
                }
                gpuAttributes = cached;
            }
        }
        return cached;
    }

    /**
     * Reads GPU vendor and renderer from the cached single EGL probe.
     */
    public SignalResult<GpuIdentity> getGpuIdentity() {
        SignalResult<GpuIdentity> cached = gpuIdentity;
        if (cached != null) return cached;
        synchronized (lockFor("gpuIdentity")) {
            cached = gpuIdentity;
            if (cached == null) {
                SignalResult<Map<String, String>> attrs = getGpuAttributes();
                if (!attrs.isSuccess() || attrs.getValue() == null) {
                    cached = attrs.getStatus() == SignalResult.Status.ERROR
                            ? SignalResult.error(attrs.getFailureReason())
                            : SignalResult.unavailable(attrs.getFailureReason());
                } else {
                    String vendor = attrs.getValue().get("vendor");
                    String renderer = attrs.getValue().get("renderer");
                    if (vendor == null && renderer == null) {
                        cached = SignalResult.unavailable("gpu_identity_missing");
                    } else {
                        cached = SignalResult.success(new GpuIdentity(vendor, renderer));
                    }
                }
                gpuIdentity = cached;
            }
        }
        return cached;
    }

    /**
     * Active interface names collected with zero permissions via native {@code NETLINK_ROUTE}
     * {@code RTM_GETLINK} ({@code IFF_UP} only, zero MAC/PII), falling back to {@code /sys/class/net}
     * and {@link java.net.NetworkInterface#getNetworkInterfaces()} when native is unavailable.
     */
    public SignalResult<List<String>> getNetworkInterfaceNames() {
        SignalResult<List<String>> cached = networkInterfaceNames;
        if (cached != null) return cached;
        synchronized (lockFor("networkInterfaceNames")) {
            cached = networkInterfaceNames;
            if (cached == null) {
                List<String> names = new ArrayList<>();
                try {
                    // 1. Native NETLINK_ROUTE RTM_GETLINK (works on Android 11+ with zero permissions)
                    if (NativeCollectorBridge.isNativeAvailable()) {
                        SignalResult<String> nativeIfaces =
                                NativeCollectorBridge.getActiveNetInterfacesResult();
                        if (nativeIfaces != null && nativeIfaces.isSuccess()
                                && nativeIfaces.getValue() != null
                                && !nativeIfaces.getValue().isBlank()) {
                            for (String part : nativeIfaces.getValue().split(",")) {
                                String trimmed = part.trim();
                                if (!trimmed.isEmpty() && !names.contains(trimmed)) {
                                    names.add(trimmed);
                                }
                            }
                        }
                    }
                    // 2. /sys/class/net fallback (when readable on older APIs or JVM host)
                    if (names.isEmpty()) {
                        File[] entries = new File("/sys/class/net").listFiles();
                        if (entries != null) {
                            for (File entry : entries) {
                                names.add(entry.getName());
                            }
                        }
                    }
                    // 3. Java NetworkInterface fallback
                    if (names.isEmpty()) {
                        try {
                            java.util.Enumeration<java.net.NetworkInterface> list =
                                    java.net.NetworkInterface.getNetworkInterfaces();
                            while (list != null && list.hasMoreElements()) {
                                java.net.NetworkInterface ni = list.nextElement();
                                if (ni == null) continue;
                                String ifaceName = ni.getName();
                                if (ifaceName == null || ifaceName.isBlank()) continue;
                                if (!isInterfaceActiveOrAddressed(ni)) continue;
                                names.add(ifaceName);
                            }
                        } catch (SecurityException | java.net.SocketException e) {
                            cached = SignalResult.unavailable("net_iface_unavailable");
                            networkInterfaceNames = cached;
                            return cached;
                        }
                    }
                    cached = names.isEmpty()
                            ? SignalResult.unavailable("no_interfaces")
                            : SignalResult.success(Collections.unmodifiableList(names));
                } catch (Exception | LinkageError | OutOfMemoryError e) {
                    cached = SignalResult.error(e.getClass().getSimpleName());
                }
                networkInterfaceNames = cached;
            }
        }
        return cached;
    }

    /**
     * Prefers interfaces that are UP (filtering stock DOWN kernel interfaces such as {@code tunl0}).
     * When {@code isUp()} throws {@link java.net.SocketException} or {@link SecurityException}
     * (e.g. {@code ioctl(SIOCGIFFLAGS)} restricted without {@code INTERNET}), falls back to checking
     * whether the interface holds at least one assigned address from {@code getifaddrs()}.
     */
    private static boolean isInterfaceActiveOrAddressed(java.net.NetworkInterface ni) {
        try {
            return ni.isUp();
        } catch (Exception | LinkageError ignored) {
            try {
                java.util.Enumeration<java.net.InetAddress> addrs = ni.getInetAddresses();
                return addrs != null && addrs.hasMoreElements();
            } catch (Exception | LinkageError ignoredAgain) {
                return false;
            }
        }
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
            SignalResult<String> result = NativeCollectorBridge.getSystemPropertyResult(name);
            if (!result.isSuccess() || result.getValue() == null) {
                return result;
            }
            String trimmed = result.getValue().trim();
            return trimmed.isEmpty()
                    ? SignalResult.empty("") : SignalResult.success(trimmed);
        } catch (Exception | LinkageError e) {
            return SignalResult.error(e.getClass().getSimpleName());
        }
    }
}
