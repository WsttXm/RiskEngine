package com.wsttxm.riskenginesdk.detector.probe.hook;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.DeadObjectException;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;

import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Multi-vector LSPosed / Xposed postponed probe:
 * <ol>
 *   <li>Binder magic {@code 0x5F4C5350} ({@code '_LSP'}) against {@code activity} and {@code serial}
 *       system service binders (zero crash on {@code SecurityException}/{@code RemoteException}).</li>
 *   <li>Zygote permission-to-supplemental-GID audit comparing granted permissions against
 *       {@code /proc/self/status} {@code Groups:} and AOSP {@code platform.xml} mappings.</li>
 *   <li>Protected-API exception stack + {@link Thread#getAllStackTraces()} +
 *       {@link Thread#getDefaultUncaughtExceptionHandler()} inspection.</li>
 * </ol>
 */
public final class LsposedProbe {

    public static final String EVIDENCE_FAMILY = "xposed";
    public static final int LSP_BINDER_MAGIC = 0x5F4C5350; // 1598837584 ('_LSP')
    private static final String BRIDGE_DESCRIPTOR = "LSPosed";
    private static final int BRIDGE_ACTION_GET_BINDER = 2;

    private static final String[] FRAMEWORK_TOKENS = {
            "lsposed", "lspd", "xposed", "lsplant", "edxposed"
    };

    private static final String[] STACK_SIGNATURES = {
            "de.robv.android.xposed.xposedbridge.main",
            "de.robv.android.xposed.xposedbridge.handlehookedmethod",
            "de.robv.android.xposed.xposedbridge.invokeoriginalmethodnative",
            "lsposedbridge",
            "edxposedbridge",
            "xc_methodhook",
            "lsphooker_",
            "callbeforehookedmethod",
            "callafterhookedmethod",
            "invokeoriginalmethod",
            "(lsp)",
    };

    private static final class GidRule {
        final String permission;
        final String shortLabel;
        final int[] expectedGids;

        GidRule(String permission, String shortLabel, int... expectedGids) {
            this.permission = permission;
            this.shortLabel = shortLabel;
            this.expectedGids = expectedGids;
        }
    }

    private static final List<GidRule> GID_AUDIT_RULES = Collections.unmodifiableList(Arrays.asList(
            new GidRule(Manifest.permission.INTERNET, "INTERNET", 3003),
            new GidRule(Manifest.permission.BLUETOOTH_ADMIN, "BLUETOOTH_ADMIN", 3001),
            new GidRule(Manifest.permission.BLUETOOTH, "BLUETOOTH", 3002),
            new GidRule("android.permission.NET_TUNNELING", "NET_TUNNELING", 1016),
            new GidRule("android.permission.READ_LOGS", "READ_LOGS", 1007),
            new GidRule("android.permission.ACCESS_MTP", "ACCESS_MTP", 1024),
            new GidRule("android.permission.NET_ADMIN", "NET_ADMIN", 3005),
            new GidRule("android.permission.MAINLINE_NETWORK_STACK", "MAINLINE_NETWORK_STACK", 3005, 3004),
            new GidRule("android.permission.ACCESS_CACHE_FILESYSTEM", "ACCESS_CACHE_FILESYSTEM", 2001),
            new GidRule("android.permission.DIAGNOSTIC", "DIAGNOSTIC", 1004, 2002),
            new GidRule("android.permission.READ_NETWORK_USAGE_HISTORY", "READ_NETWORK_USAGE_HISTORY", 3006),
            new GidRule("android.permission.UPDATE_DEVICE_STATS", "UPDATE_DEVICE_STATS", 3007),
            new GidRule("android.permission.LOOP_RADIO", "LOOP_RADIO", 1030),
            new GidRule("android.permission.MANAGE_VOICE_KEYPHRASES", "MANAGE_VOICE_KEYPHRASES", 1005),
            new GidRule("android.permission.ACCESS_BROADCAST_RADIO", "ACCESS_BROADCAST_RADIO", 1013),
            new GidRule("android.permission.USE_RESERVED_DISK", "USE_RESERVED_DISK", 1065),
            new GidRule("android.permission.WRITE_SECURITY_LOG", "WRITE_SECURITY_LOG", 1091),
            new GidRule("android.permission.VIRTUAL_INPUT_DEVICE", "VIRTUAL_INPUT_DEVICE", 3011),
            new GidRule("android.permission.MANAGE_VIRTUAL_MACHINE", "MANAGE_VIRTUAL_MACHINE", 3013)
    ));

    private LsposedProbe() {}

    /** Injectable seam enabling deterministic pure-JVM unit tests of all 3 LSPosed sub-probes. */
    public interface Environment {
        IBinder getServiceBinder(String serviceName);

        boolean transactMagic(IBinder binder, String serviceName) throws Throwable;

        Set<String> getGrantedPermissions(Context context);

        String readProcSelfStatus(SignalSnapshot signals);

        StackTraceElement[] captureProtectedApiExceptionStack(Context context);

        Map<Thread, StackTraceElement[]> getAllStackTraces();

        Thread.UncaughtExceptionHandler getDefaultUncaughtExceptionHandler();
    }

    private static final Environment DEFAULT_ENV = new Environment() {
        @Override
        public IBinder getServiceBinder(String serviceName) {
            try {
                Class<?> sm = Class.forName("android.os.ServiceManager");
                Method getService = sm.getMethod("getService", String.class);
                Object res = getService.invoke(null, serviceName);
                return res instanceof IBinder ? (IBinder) res : null;
            } catch (Exception | LinkageError e) {
                return null;
            }
        }

        @Override
        public boolean transactMagic(IBinder binder, String serviceName) throws Throwable {
            Parcel data = null;
            Parcel reply = null;
            try {
                data = Parcel.obtain();
                reply = Parcel.obtain();
                if ("activity".equals(serviceName)) {
                    data.writeInterfaceToken(BRIDGE_DESCRIPTOR);
                    data.writeInt(BRIDGE_ACTION_GET_BINDER);
                    data.writeString("");
                } else {
                    data.writeInt(Process.myUid());
                    data.writeInt(Process.myPid());
                    data.writeString("riskengine_probe");
                }
                return binder.transact(LSP_BINDER_MAGIC, data, reply, 0);
            } finally {
                if (data != null) {
                    try { data.recycle(); } catch (Exception ignored) {}
                }
                if (reply != null) {
                    try { reply.recycle(); } catch (Exception ignored) {}
                }
            }
        }

        @Override
        public Set<String> getGrantedPermissions(Context context) {
            if (context == null) return Collections.emptySet();
            try {
                PackageManager pm = context.getPackageManager();
                if (pm == null) return Collections.emptySet();
                PackageInfo info = readSelfPackageInfo(pm, context.getPackageName());
                return extractGrantedPermissions(info);
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                return Collections.emptySet();
            }
        }

        @Override
        public String readProcSelfStatus(SignalSnapshot signals) {
            if (signals != null) {
                SignalResult<String> res = signals.getTextFile("/proc/self/status");
                if (res != null && res.isSuccess() && res.getValue() != null) {
                    return res.getValue();
                }
            }
            return null;
        }

        @Override
        public StackTraceElement[] captureProtectedApiExceptionStack(Context context) {
            if (context != null) {
                try {
                    PackageManager pm = context.getPackageManager();
                    if (pm != null) {
                        pm.getPackageInfo("com.riskengine.nonexistent.lsposed.probe", 0);
                    }
                } catch (Throwable t) {
                    return t.getStackTrace();
                }
            }
            return new Throwable().getStackTrace();
        }

        @Override
        public Map<Thread, StackTraceElement[]> getAllStackTraces() {
            try {
                return Thread.getAllStackTraces();
            } catch (Exception | LinkageError e) {
                return Collections.emptyMap();
            }
        }

        @Override
        public Thread.UncaughtExceptionHandler getDefaultUncaughtExceptionHandler() {
            try {
                return Thread.getDefaultUncaughtExceptionHandler();
            } catch (Exception | LinkageError e) {
                return null;
            }
        }
    };

    /** Immutable outcome of running all LSPosed sub-probes. */
    public static final class ProbeResult {
        private final List<String> strongTokens;
        private final List<String> mediumTokens;
        private final List<EvidenceItem> evidenceItems;
        private final int subProbesRun;

        ProbeResult(List<String> strongTokens,
                    List<String> mediumTokens,
                    List<EvidenceItem> evidenceItems,
                    int subProbesRun) {
            this.strongTokens = Collections.unmodifiableList(strongTokens);
            this.mediumTokens = Collections.unmodifiableList(mediumTokens);
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
            this.subProbesRun = Math.max(0, subProbesRun);
        }

        public List<String> getStrongTokens() { return strongTokens; }
        public List<String> getMediumTokens() { return mediumTokens; }
        public List<EvidenceItem> getEvidenceItems() { return evidenceItems; }
        public int getSubProbesRun() { return subProbesRun; }
        public boolean hasFindings() { return !evidenceItems.isEmpty(); }
    }

    /** Executes all LSPosed sub-probes with default platform environment. */
    public static ProbeResult probe(Context context, SignalSnapshot signals) {
        return probe(context, signals, DEFAULT_ENV);
    }

    /** Executes all LSPosed sub-probes with an injectable environment (for JVM unit tests). */
    public static ProbeResult probe(Context context, SignalSnapshot signals, Environment env) {
        Environment effective = env != null ? env : DEFAULT_ENV;
        Set<String> strong = new LinkedHashSet<>();
        Set<String> medium = new LinkedHashSet<>();
        List<EvidenceItem> items = new ArrayList<>();
        int ran = 0;

        ran += probeBinderBridge(effective, "activity", strong, medium, items);
        ran += probeBinderBridge(effective, "serial", strong, medium, items);
        ran += probeZygotePermissionGids(context, signals, effective, strong, items);
        ran += probeStacksAndHandler(context, effective, strong, medium, items);

        return new ProbeResult(
                new ArrayList<>(strong), new ArrayList<>(medium), items, ran);
    }

    private static int probeBinderBridge(Environment env,
                                         String serviceName,
                                         Set<String> strong,
                                         Set<String> medium,
                                         List<EvidenceItem> items) {
        IBinder binder;
        try {
            binder = env.getServiceBinder(serviceName);
        } catch (Throwable t) {
            return 0;
        }
        if (binder == null) {
            return 0;
        }
        try {
            if ("serial".equals(serviceName)) {
                try {
                    String desc = binder.getInterfaceDescriptor();
                    if (containsFrameworkToken(desc)) {
                        String tok = "lsposed_binder_serial_descriptor";
                        if (strong.add(tok)) {
                            items.add(new EvidenceItem(
                                    tok, EvidenceItem.SourceLayer.JAVA,
                                    "binder:serial", desc, EVIDENCE_FAMILY, EvidenceItem.Rank.STRONG));
                        }
                    }
                } catch (Throwable ignored) {}
            }
            boolean handled = env.transactMagic(binder, serviceName);
            if (handled) {
                String tok = "lsposed_binder_" + serviceName + "_bridge";
                if (strong.add(tok)) {
                    items.add(new EvidenceItem(
                            tok, EvidenceItem.SourceLayer.JAVA,
                            "binder:" + serviceName,
                            "magic=0x5F4C5350",
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                }
            }
        } catch (DeadObjectException ignored) {
            // Transient dead service is never a threat.
        } catch (SecurityException se) {
            if (containsFrameworkToken(se.getMessage())) {
                String tok = "lsposed_binder_" + serviceName + "_exception";
                if (strong.add(tok)) {
                    items.add(new EvidenceItem(
                            tok, EvidenceItem.SourceLayer.JAVA,
                            "binder:" + serviceName,
                            se.getMessage(),
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                }
            }
        } catch (Throwable t) {
            if (containsFrameworkToken(t.getMessage())) {
                String tok = "lsposed_binder_" + serviceName + "_throwable";
                if (medium.add(tok)) {
                    items.add(new EvidenceItem(
                            tok, EvidenceItem.SourceLayer.JAVA,
                            "binder:" + serviceName,
                            t.getMessage(),
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.MEDIUM));
                }
            }
        }
        return 1;
    }

    private static int probeZygotePermissionGids(Context context,
                                                 SignalSnapshot signals,
                                                 Environment env,
                                                 Set<String> strong,
                                                 List<EvidenceItem> items) {
        try {
            Set<String> granted = env.getGrantedPermissions(context);
            if (granted == null || granted.isEmpty()) {
                return 0;
            }
            List<GidRule> applicable = new ArrayList<>();
            for (GidRule rule : GID_AUDIT_RULES) {
                if (granted.contains(rule.permission)) {
                    applicable.add(rule);
                }
            }
            if (applicable.isEmpty()) {
                return 1;
            }
            String statusContent = env.readProcSelfStatus(signals);
            Set<Integer> currentGids = parseProcessGroups(statusContent);
            if (currentGids == null) {
                return 0;
            }
            for (GidRule rule : applicable) {
                List<Integer> missing = new ArrayList<>();
                for (int gid : rule.expectedGids) {
                    if (!currentGids.contains(gid)) {
                        missing.add(gid);
                    }
                }
                if (!missing.isEmpty()) {
                    String tok = "lsposed_zygote_gid_mismatch:" + rule.shortLabel.toLowerCase(Locale.ROOT);
                    if (strong.add(tok)) {
                        items.add(new EvidenceItem(
                                "lsposed_zygote_gid_mismatch",
                                EvidenceItem.SourceLayer.JAVA,
                                rule.permission,
                                "missing_gids=" + missing,
                                EVIDENCE_FAMILY,
                                EvidenceItem.Rank.STRONG));
                    }
                }
            }
            return 1;
        } catch (Throwable t) {
            return 0;
        }
    }

    private static int probeStacksAndHandler(Context context,
                                             Environment env,
                                             Set<String> strong,
                                             Set<String> medium,
                                             List<EvidenceItem> items) {
        int ran = 0;
        // 1. Protected API exception stack trace.
        try {
            StackTraceElement[] protectedFrames = env.captureProtectedApiExceptionStack(context);
            if (protectedFrames != null) {
                ran++;
                String hit = matchStackSignature(protectedFrames);
                if (hit != null) {
                    String tok = "lsposed_protected_api_stack:" + hit;
                    if (strong.add(tok)) {
                        items.add(new EvidenceItem(
                                "lsposed_protected_api_stack",
                                EvidenceItem.SourceLayer.JAVA,
                                "protected_api_stack",
                                hit,
                                EVIDENCE_FAMILY,
                                EvidenceItem.Rank.STRONG));
                    }
                }
            }
        } catch (Throwable ignored) {}

        // 2. Thread.getAllStackTraces() across all live JVM threads.
        try {
            Map<Thread, StackTraceElement[]> allStacks = env.getAllStackTraces();
            if (allStacks != null) {
                ran++;
                for (Map.Entry<Thread, StackTraceElement[]> entry : allStacks.entrySet()) {
                    String hit = matchStackSignature(entry.getValue());
                    if (hit != null) {
                        String threadName = entry.getKey() == null ? "thread" : entry.getKey().getName();
                        String tok = "lsposed_all_threads_stack:" + hit;
                        if (strong.add(tok)) {
                            items.add(new EvidenceItem(
                                    "lsposed_all_threads_stack",
                                    EvidenceItem.SourceLayer.JAVA,
                                    "thread:" + threadName,
                                    hit,
                                    EVIDENCE_FAMILY,
                                    EvidenceItem.Rank.STRONG));
                        }
                        break;
                    }
                }
            }
        } catch (Throwable ignored) {}

        // 3. Thread.getDefaultUncaughtExceptionHandler() inspection.
        try {
            Thread.UncaughtExceptionHandler handler = env.getDefaultUncaughtExceptionHandler();
            ran++;
            if (handler != null) {
                String clsName = handler.getClass().getName();
                if (containsFrameworkToken(clsName)) {
                    String tok = "lsposed_uncaught_handler:" + clsName;
                    if (medium.add(tok)) {
                        items.add(new EvidenceItem(
                                "lsposed_uncaught_handler",
                                EvidenceItem.SourceLayer.JAVA,
                                "DefaultUncaughtExceptionHandler",
                                clsName,
                                EVIDENCE_FAMILY,
                                EvidenceItem.Rank.MEDIUM));
                    }
                }
            }
        } catch (Throwable ignored) {}

        return ran;
    }

    /** Parses the {@code Groups:} line of {@code /proc/self/status}; returns {@code null} if absent. */
    public static Set<Integer> parseProcessGroups(String statusContent) {
        if (statusContent == null || statusContent.isEmpty()) {
            return null;
        }
        for (String line : statusContent.split("\\r?\\n")) {
            if (line.startsWith("Groups:")) {
                String rest = line.substring("Groups:".length()).trim();
                Set<Integer> groups = new LinkedHashSet<>();
                if (!rest.isEmpty()) {
                    for (String tok : rest.split("\\s+")) {
                        if (tok.isEmpty()) continue;
                        try {
                            groups.add(Integer.parseInt(tok));
                        } catch (NumberFormatException ignored) {}
                    }
                }
                return groups;
            }
        }
        return null;
    }

    static String matchStackSignature(StackTraceElement[] frames) {
        if (frames == null || frames.length == 0) return null;
        String selfName = LsposedProbe.class.getName();
        for (StackTraceElement frame : frames) {
            if (frame == null) continue;
            String cls = frame.getClassName();
            if (cls == null
                    || cls.startsWith("java.lang.Thread")
                    || cls.startsWith("java.lang.Throwable")
                    || cls.startsWith(selfName)) {
                continue;
            }
            String rendered = frame.toString().toLowerCase(Locale.ROOT);
            for (String sig : STACK_SIGNATURES) {
                if (rendered.contains(sig)) {
                    return sig;
                }
            }
        }
        return null;
    }

    private static boolean containsFrameworkToken(String text) {
        if (text == null || text.isEmpty()) return false;
        String lower = text.toLowerCase(Locale.ROOT);
        for (String tok : FRAMEWORK_TOKENS) {
            if (lower.contains(tok)) {
                return true;
            }
        }
        return false;
    }

    @SuppressWarnings("deprecation")
    private static PackageInfo readSelfPackageInfo(PackageManager pm, String pkgName)
            throws PackageManager.NameNotFoundException {
        if (Build.VERSION.SDK_INT >= 33) {
            return pm.getPackageInfo(pkgName,
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS));
        }
        return pm.getPackageInfo(pkgName, PackageManager.GET_PERMISSIONS);
    }

    private static Set<String> extractGrantedPermissions(PackageInfo info) {
        if (info == null || info.requestedPermissions == null) {
            return Collections.emptySet();
        }
        int[] flags = info.requestedPermissionsFlags;
        Set<String> granted = new LinkedHashSet<>();
        for (int i = 0; i < info.requestedPermissions.length; i++) {
            String perm = info.requestedPermissions[i];
            if (perm == null) continue;
            if (flags != null && i < flags.length
                    && (flags[i] & PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0) {
                granted.add(perm);
            }
        }
        return granted;
    }
}
