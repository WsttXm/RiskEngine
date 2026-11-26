package com.wsttxm.riskenginesdk.detector.probe.threat;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteException;
import android.os.SystemClock;

import com.wsttxm.riskenginesdk.model.EvidenceItem;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Android 15–17 (API >= 35) {@code PermissionService.checkUidPermission} vs
 * {@code getPackagesForUid} asymmetry probe.
 *
 * <p>On Android 15–17, {@code PermissionService.checkUidPermission} evaluates UID permission
 * tables under {@code SYSTEM_UID} context without calling-UID package filtering, whereas
 * {@code getPackagesForUid} is filtered by calling UID (and hooked by HMA). When an ordinary
 * foreign app UID holds a non-instant normal permission yet {@code getPackagesForUid(uid)}
 * repeatedly returns empty while pre/post self-controls pass, it exposes package-visibility
 * hiding.</p>
 *
 * <p>Adheres strictly to {@code D66}: uses public {@link IBinder#transact(int, Parcel, Parcel, int)}
 * + {@link Parcel} wire serialization against {@code permissionmgr}/{@code package} services
 * (zero blocked {@code $Stub.asInterface} hidden-API reflection), enforces a hard {@code 1000ms}
 * wall-clock budget, and marks truncated scans as {@link ProbeState#PARTIAL}.</p>
 */
public final class HmaPermissionServiceProbe {

    public static final String FAMILY_HMA_HIDING = "hma_hiding";
    public static final int MIN_API_LEVEL = 35;
    public static final int PER_USER_RANGE = 100_000;
    public static final int FIRST_APP_ID = 10_000;
    public static final int LAST_APP_ID = 19_999;
    public static final int UID_SPAN = 10_000;
    public static final long DEFAULT_BUDGET_MS = 1_000L;
    private static final int MAX_CANDIDATES = 16;

    public static final String DESC_PERMISSION_MANAGER = "android.permission.IPermissionManager";
    public static final String DESC_PACKAGE_MANAGER = "android.content.pm.IPackageManager";
    private static final String INTERNET_PERMISSION = "android.permission.INTERNET";

    /** Normal permissions without {@code PROTECTION_FLAG_INSTANT} on Android 15–17. */
    public static final List<String> NON_INSTANT_PERMISSIONS = Collections.unmodifiableList(
            Arrays.asList(
                    "android.permission.RECEIVE_BOOT_COMPLETED",
                    "android.permission.ACCESS_WIFI_STATE",
                    "android.permission.REORDER_TASKS"
            ));

    public enum ProbeState {
        DETECTED,
        CLEAN,
        PARTIAL,
        UNAVAILABLE,
        UNSUPPORTED
    }

    /** Injectable environment adapter for deterministic JVM unit tests. */
    public interface Environment {
        int getSdkInt();
        int getMyUid();
        String getMyPackageName();
        boolean hasFullPackageVisibility();
        boolean isCallerInternetGranted();
        boolean areProbePermissionsNonInstant();
        Boolean checkUidPermissionWire(int uid, String permission);
        String[] getPackagesForUidWire(int uid);
        long elapsedRealtimeMs();
    }

    public static final class ProbeOutcome {
        private final ProbeState state;
        private final List<EvidenceItem> evidenceItems;
        private final List<String> details;
        private final int checkedUids;
        private final boolean truncated;
        private final String diagnostic;

        ProbeOutcome(ProbeState state,
                     List<EvidenceItem> evidenceItems,
                     List<String> details,
                     int checkedUids,
                     boolean truncated,
                     String diagnostic) {
            this.state = state;
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
            this.details = Collections.unmodifiableList(details);
            this.checkedUids = checkedUids;
            this.truncated = truncated;
            this.diagnostic = diagnostic == null ? "" : diagnostic;
        }

        public ProbeState getState() {
            return state;
        }

        public List<EvidenceItem> getEvidenceItems() {
            return evidenceItems;
        }

        public List<String> getDetails() {
            return details;
        }

        public int getCheckedUids() {
            return checkedUids;
        }

        public boolean isTruncated() {
            return truncated;
        }

        public String getDiagnostic() {
            return diagnostic;
        }

        public boolean isDetected() {
            return !evidenceItems.isEmpty();
        }
    }

    private final Environment env;
    private final long budgetMs;

    public HmaPermissionServiceProbe(Context context) {
        this(defaultEnvironment(context), DEFAULT_BUDGET_MS);
    }

    public HmaPermissionServiceProbe(Environment env) {
        this(env, DEFAULT_BUDGET_MS);
    }

    public HmaPermissionServiceProbe(Environment env, long budgetMs) {
        this.env = env;
        this.budgetMs = budgetMs > 0 ? budgetMs : DEFAULT_BUDGET_MS;
    }

    public ProbeOutcome probe() {
        if (env == null) {
            return outcome(ProbeState.UNAVAILABLE, Collections.emptyList(),
                    Collections.emptyList(), 0, false, "env_null");
        }

        final int sdkInt;
        final int selfUid;
        final String selfPkg;
        final boolean fullVisibility;
        final boolean internetGranted;
        final boolean nonInstantOk;
        try {
            sdkInt = env.getSdkInt();
            selfUid = env.getMyUid();
            selfPkg = env.getMyPackageName();
            fullVisibility = env.hasFullPackageVisibility();
            internetGranted = env.isCallerInternetGranted();
            nonInstantOk = env.areProbePermissionsNonInstant();
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return outcome(ProbeState.UNAVAILABLE, Collections.emptyList(),
                    Collections.emptyList(), 0, false, "env_init_error");
        }

        if (sdkInt < MIN_API_LEVEL) {
            return outcome(ProbeState.UNSUPPORTED, Collections.emptyList(),
                    Collections.emptyList(), 0, false, "api_below_35:" + sdkInt);
        }
        if (!fullVisibility) {
            return outcome(ProbeState.UNAVAILABLE, Collections.emptyList(),
                    Collections.emptyList(), 0, false, "permission_limited");
        }
        if (selfUid < 0 || selfPkg == null || selfPkg.isBlank()) {
            return outcome(ProbeState.UNSUPPORTED, Collections.emptyList(),
                    Collections.emptyList(), 0, false, "invalid_caller_identity");
        }
        int userBase = (selfUid / PER_USER_RANGE) * PER_USER_RANGE;
        int selfAppId = selfUid - userBase;
        if (selfAppId < FIRST_APP_ID || selfAppId > LAST_APP_ID || !nonInstantOk) {
            return outcome(ProbeState.UNSUPPORTED, Collections.emptyList(),
                    Collections.emptyList(), 0, false, "unsupported_caller_or_perms");
        }

        // Pre-scan self-control verification
        if (!controlsPass(selfUid, selfPkg, internetGranted)) {
            return outcome(ProbeState.UNAVAILABLE, Collections.emptyList(),
                    Collections.emptyList(), 0, false, "control_before_failed");
        }

        int firstUid = userBase + FIRST_APP_ID;
        long startedMs = safeNowMs();
        int checked = 0;
        int candidates = 0;
        boolean truncated = false;
        boolean binderError = false;
        List<Integer> hiddenUids = new ArrayList<>();

        for (int offset = 0; offset < UID_SPAN; offset++) {
            if ((safeNowMs() - startedMs) >= budgetMs) {
                truncated = true;
                break;
            }
            int uid = firstUid + offset;
            if (uid == selfUid) {
                checked++;
                continue;
            }

            List<String> granted = new ArrayList<>(3);
            for (String perm : NON_INSTANT_PERMISSIONS) {
                Boolean res = safeCheckUidPermission(uid, perm);
                if (res == null) {
                    binderError = true;
                    break;
                }
                if (res) {
                    granted.add(perm);
                }
            }
            if (binderError) {
                break;
            }
            if (granted.isEmpty()) {
                checked++;
                continue;
            }

            String[] pkgs = safeGetPackagesForUid(uid);
            if (pkgs == null) {
                binderError = true;
                break;
            }
            if (pkgs.length > 0) {
                checked++;
                continue;
            }

            candidates++;
            if (candidates > MAX_CANDIDATES) {
                truncated = true;
                break;
            }

            // Re-verify uncached permission + packages pair to filter transient uninstall races
            boolean repeatedGranted = false;
            for (String perm : granted) {
                Boolean again = safeCheckUidPermission(uid, perm);
                if (again == null) {
                    binderError = true;
                    break;
                }
                if (again) {
                    repeatedGranted = true;
                    break;
                }
            }
            if (binderError) {
                break;
            }
            String[] retryPkgs = safeGetPackagesForUid(uid);
            if (retryPkgs == null) {
                binderError = true;
                break;
            }
            checked++;
            if (repeatedGranted && retryPkgs.length == 0) {
                hiddenUids.add(uid);
            }
        }

        // Post-scan self-control verification: failure invalidates all findings (zero FP!)
        if (!controlsPass(selfUid, selfPkg, internetGranted)) {
            return outcome(ProbeState.UNAVAILABLE, Collections.emptyList(),
                    Collections.emptyList(), checked, truncated, "control_after_failed");
        }

        if (!hiddenUids.isEmpty()) {
            String summary = "hidden_uids=" + hiddenUids.size() + ",checked=" + checked;
            List<String> details = Collections.singletonList("hma_permission_service_diff:" + summary);
            List<EvidenceItem> items = Collections.singletonList(new EvidenceItem(
                    "hma_permission_service_diff",
                    EvidenceItem.SourceLayer.JAVA,
                    "permission_service",
                    summary,
                    FAMILY_HMA_HIDING,
                    EvidenceItem.Rank.STRONG));
            return outcome(ProbeState.DETECTED, items, details, checked, truncated,
                    "detected:" + summary);
        }

        if (binderError) {
            return outcome(ProbeState.UNAVAILABLE, Collections.emptyList(),
                    Collections.emptyList(), checked, truncated, "binder_error");
        }

        if (truncated || checked < UID_SPAN) {
            return outcome(ProbeState.PARTIAL, Collections.emptyList(),
                    Collections.emptyList(), checked, true,
                    "partial:checked=" + checked + "/" + UID_SPAN);
        }

        return outcome(ProbeState.CLEAN, Collections.emptyList(),
                Collections.emptyList(), checked, false, "clean:" + checked);
    }

    private boolean controlsPass(int selfUid, String selfPkg, boolean internetGranted) {
        String[] selfPkgs = safeGetPackagesForUid(selfUid);
        if (selfPkgs == null || !Arrays.asList(selfPkgs).contains(selfPkg)) {
            return false;
        }
        Boolean internetCheck = safeCheckUidPermission(selfUid, INTERNET_PERMISSION);
        if (internetCheck == null || internetCheck != internetGranted) {
            return false;
        }
        Boolean emptyPermCheck = safeCheckUidPermission(selfUid, "");
        return Boolean.FALSE.equals(emptyPermCheck);
    }

    private Boolean safeCheckUidPermission(int uid, String permission) {
        try {
            return env.checkUidPermissionWire(uid, permission);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return null;
        }
    }

    private String[] safeGetPackagesForUid(int uid) {
        try {
            return env.getPackagesForUidWire(uid);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return null;
        }
    }

    private long safeNowMs() {
        try {
            return env.elapsedRealtimeMs();
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return 0L;
        }
    }

    private static ProbeOutcome outcome(ProbeState state,
                                        List<EvidenceItem> items,
                                        List<String> details,
                                        int checked,
                                        boolean truncated,
                                        String diag) {
        return new ProbeOutcome(state, items, details, checked, truncated, diag);
    }

    /**
     * Public {@link IBinder#transact} wire serializer for Android 15–17
     * {@code IPermissionManager.checkUidPermission(int uid, String permissionName, int deviceId)}
     * returning {@code 0} (GRANTED) or {@code -1} (DENIED).
     */
    public static Boolean transactPermissionMgrCheckUidPermission(IBinder binder,
                                                                  int transactionCode,
                                                                  int uid,
                                                                  String permission,
                                                                  int deviceId) {
        if (binder == null || permission == null) {
            return null;
        }
        Parcel data = null;
        Parcel reply = null;
        try {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            data.writeInterfaceToken(DESC_PERMISSION_MANAGER);
            data.writeInt(uid);
            data.writeString(permission);
            data.writeInt(deviceId);
            if (!binder.transact(transactionCode, data, reply, 0)) {
                return null;
            }
            reply.readException();
            int result = reply.readInt();
            if (result == PackageManager.PERMISSION_GRANTED) {
                return Boolean.TRUE;
            }
            if (result == PackageManager.PERMISSION_DENIED) {
                return Boolean.FALSE;
            }
            return null;
        } catch (RemoteException | RuntimeException | LinkageError | OutOfMemoryError e) {
            return null;
        } finally {
            if (data != null) {
                data.recycle();
            }
            if (reply != null) {
                reply.recycle();
            }
        }
    }

    /**
     * Public {@link IBinder#transact} wire serializer for
     * {@code IPackageManager.checkUidPermission(String permName, int uid)} returning {@code 0}
     * (GRANTED) or {@code -1} (DENIED).
     */
    public static Boolean transactPackageMgrCheckUidPermission(IBinder binder,
                                                               int transactionCode,
                                                               String permission,
                                                               int uid) {
        if (binder == null || permission == null) {
            return null;
        }
        Parcel data = null;
        Parcel reply = null;
        try {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            data.writeInterfaceToken(DESC_PACKAGE_MANAGER);
            data.writeString(permission);
            data.writeInt(uid);
            if (!binder.transact(transactionCode, data, reply, 0)) {
                return null;
            }
            reply.readException();
            int result = reply.readInt();
            if (result == PackageManager.PERMISSION_GRANTED) {
                return Boolean.TRUE;
            }
            if (result == PackageManager.PERMISSION_DENIED) {
                return Boolean.FALSE;
            }
            return null;
        } catch (RemoteException | RuntimeException | LinkageError | OutOfMemoryError e) {
            return null;
        } finally {
            if (data != null) {
                data.recycle();
            }
            if (reply != null) {
                reply.recycle();
            }
        }
    }

    /**
     * Public {@link IBinder#transact} wire serializer for {@code getPackagesForUid(int uid)}.
     */
    public static String[] transactGetPackagesForUid(IBinder binder,
                                                     String interfaceDescriptor,
                                                     int transactionCode,
                                                     int uid) {
        if (binder == null || interfaceDescriptor == null) {
            return null;
        }
        Parcel data = null;
        Parcel reply = null;
        try {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            data.writeInterfaceToken(interfaceDescriptor);
            data.writeInt(uid);
            if (!binder.transact(transactionCode, data, reply, 0)) {
                return null;
            }
            reply.readException();
            String[] pkgs = reply.createStringArray();
            return pkgs == null ? new String[0] : pkgs;
        } catch (RemoteException | RuntimeException | LinkageError | OutOfMemoryError e) {
            return null;
        } finally {
            if (data != null) {
                data.recycle();
            }
            if (reply != null) {
                reply.recycle();
            }
        }
    }

    /**
     * Strictly verifies a positive + negative control pair for a wire {@code checkUidPermission}
     * endpoint. Requires {@code callerInternetGranted == true} so an always-DENIED stub or wrong
     * transaction code can NEVER falsely calibrate.
     */
    public static boolean verifyWirePermissionControl(boolean callerInternetGranted,
                                                      Boolean internetResult,
                                                      Boolean emptyPermResult) {
        if (!callerInternetGranted) {
            return false;
        }
        return Boolean.TRUE.equals(internetResult) && Boolean.FALSE.equals(emptyPermResult);
    }

    private static Environment defaultEnvironment(Context context) {
        if (context == null) {
            return null;
        }
        Context resolved = context;
        try {
            Context app = context.getApplicationContext();
            if (app != null) {
                resolved = app;
            }
        } catch (Exception | LinkageError | OutOfMemoryError ignored) {
            resolved = context;
        }
        final Context appCtx = resolved;
        return new Environment() {
            @Override
            public int getSdkInt() {
                return Build.VERSION.SDK_INT;
            }

            @Override
            public int getMyUid() {
                return Process.myUid();
            }

            @Override
            public String getMyPackageName() {
                return appCtx.getPackageName();
            }

            @Override
            public boolean hasFullPackageVisibility() {
                return appCtx.checkSelfPermission(Manifest.permission.QUERY_ALL_PACKAGES)
                        == PackageManager.PERMISSION_GRANTED;
            }

            @Override
            public boolean isCallerInternetGranted() {
                PackageManager pm = appCtx.getPackageManager();
                return pm != null && pm.checkPermission(INTERNET_PERMISSION, appCtx.getPackageName())
                        == PackageManager.PERMISSION_GRANTED;
            }

            @Override
            public boolean areProbePermissionsNonInstant() {
                PackageManager pm = appCtx.getPackageManager();
                if (pm == null) {
                    return false;
                }
                for (String perm : NON_INSTANT_PERMISSIONS) {
                    try {
                        PermissionInfo info = pm.getPermissionInfo(perm, 0);
                        if ((info.getProtectionFlags() & PermissionInfo.PROTECTION_FLAG_INSTANT) != 0) {
                            return false;
                        }
                    } catch (Exception | LinkageError | OutOfMemoryError e) {
                        return false;
                    }
                }
                return true;
            }

            @Override
            public Boolean checkUidPermissionWire(int uid, String permission) {
                // Avoid blind non-VINTF AIDL transaction-code guessing on IPermissionManager;
                // public Context.checkPermission(permission, -1, uid) routes directly to
                // ActivityManagerService -> PermissionService.checkUidPermission on API 35-37
                // with zero hidden-API reflection.
                try {
                    int granted = appCtx.checkPermission(permission, -1, uid);
                    if (granted == PackageManager.PERMISSION_GRANTED) {
                        return Boolean.TRUE;
                    }
                    if (granted == PackageManager.PERMISSION_DENIED) {
                        return Boolean.FALSE;
                    }
                    return null;
                } catch (Exception | LinkageError | OutOfMemoryError e) {
                    return null;
                }
            }

            @Override
            public String[] getPackagesForUidWire(int uid) {
                PackageManager pm = appCtx.getPackageManager();
                if (pm == null) {
                    return null;
                }
                String[] pkgs = pm.getPackagesForUid(uid);
                return pkgs == null ? new String[0] : pkgs;
            }

            @Override
            public long elapsedRealtimeMs() {
                return SystemClock.elapsedRealtime();
            }
        };
    }
}
