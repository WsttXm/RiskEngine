package com.wsttxm.riskenginesdk.detector.probe.threat;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Process;
import android.os.SystemClock;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Native UID visibility & seccomp user-notif side-channel probe for HideMyApplist (HMA / HMA-OSS).
 *
 * <p>Combines two native probes executed strictly inside {@code util/disposable_child}:
 * <ol>
 *   <li>{@code SECCOMP_FILTER_FLAG_NEW_LISTENER} (Linux >= 5.0, zero permissions): detects
 *       foreign seccomp user-notif listeners ({@code EBUSY}), {@code SIGSYS}-trapped
 *       {@code getpriority(PRIO_USER)}, or higher-priority suppression of {@code getpriority}
 *       notifications across the caller's app UID range.</li>
 *   <li>{@code syscall(__NR_getpriority, PRIO_USER, uid)} active-app-UID scanning cross-checked
 *       against uncached Binder {@link PackageManager#getPackagesForUid(int)} (excluding self,
 *       system, and isolated UIDs, bounded by wall-clock budget and guarded by pre/post
 *       self-control checks plus single-UID re-verification). Only runs the foreign-UID
 *       cross-check when the host holds {@code QUERY_ALL_PACKAGES} so Android 11+ stock package
 *       visibility never produces false positives.</li>
 * </ol>
 */
public final class HmaUidVisibilityProbe {

    public static final String FAMILY_HMA_HIDING = "hma_hiding";
    public static final int PER_USER_RANGE = 100_000;
    public static final int FIRST_APP_ID = 10_000;
    public static final int LAST_APP_ID = 19_999;
    public static final long DEFAULT_BUDGET_MS = 1_000L;
    private static final int MAX_RECHECKS = 16;

    public enum ProbeState {
        DETECTED,
        CLEAN,
        PARTIAL,
        UNAVAILABLE,
        UNSUPPORTED
    }

    /** Injectable environment adapter for deterministic JVM unit tests. */
    public interface Environment {
        int getMyUid();
        String getMyPackageName();
        boolean hasFullPackageVisibility();
        SignalResult<String> scanActiveAppUids(int firstUid, int lastUid);
        SignalResult<String> probeSeccompUidFilter(int firstUid, int lastUid);
        String[] getPackagesForUid(int uid);
        long elapsedRealtimeMs();
    }

    public static final class ProbeOutcome {
        private final ProbeState state;
        private final List<EvidenceItem> evidenceItems;
        private final List<String> details;
        private final boolean truncated;
        private final String diagnostic;

        ProbeOutcome(ProbeState state,
                     List<EvidenceItem> evidenceItems,
                     List<String> details,
                     boolean truncated,
                     String diagnostic) {
            this.state = state;
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
            this.details = Collections.unmodifiableList(details);
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

    public HmaUidVisibilityProbe(Context context) {
        this(defaultEnvironment(context), DEFAULT_BUDGET_MS);
    }

    public HmaUidVisibilityProbe(Environment env) {
        this(env, DEFAULT_BUDGET_MS);
    }

    public HmaUidVisibilityProbe(Environment env, long budgetMs) {
        this.env = env;
        this.budgetMs = budgetMs > 0 ? budgetMs : DEFAULT_BUDGET_MS;
    }

    public ProbeOutcome probe() {
        if (env == null) {
            return new ProbeOutcome(
                    ProbeState.UNAVAILABLE,
                    Collections.emptyList(),
                    Collections.emptyList(),
                    false,
                    "env_null");
        }

        final int selfUid;
        final String selfPkg;
        try {
            selfUid = env.getMyUid();
            selfPkg = env.getMyPackageName();
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return new ProbeOutcome(
                    ProbeState.UNAVAILABLE,
                    Collections.emptyList(),
                    Collections.emptyList(),
                    false,
                    "self_identity_error");
        }

        if (selfUid < 0) {
            return new ProbeOutcome(
                    ProbeState.UNSUPPORTED,
                    Collections.emptyList(),
                    Collections.emptyList(),
                    false,
                    "invalid_self_uid");
        }
        int userBase = (selfUid / PER_USER_RANGE) * PER_USER_RANGE;
        int selfAppId = selfUid - userBase;
        if (selfAppId < FIRST_APP_ID || selfAppId > LAST_APP_ID) {
            return new ProbeOutcome(
                    ProbeState.UNSUPPORTED,
                    Collections.emptyList(),
                    Collections.emptyList(),
                    false,
                    "caller_outside_app_uid_range");
        }

        int firstUid = userBase + FIRST_APP_ID;
        int lastUid = userBase + LAST_APP_ID;

        List<EvidenceItem> items = new ArrayList<>();
        List<String> details = new ArrayList<>();
        List<String> diagnostics = new ArrayList<>();
        boolean truncated = false;
        boolean anyUsableCheck = false;
        boolean anyUnsupported = false;

        // 1. Zero-permission Linux >= 5.0 SECCOMP_FILTER_FLAG_NEW_LISTENER integrity check
        SeccompEval seccompEval = evaluateSeccomp(firstUid, lastUid, items, details);
        diagnostics.add("seccomp=" + seccompEval.tag);
        if (seccompEval.usable) {
            anyUsableCheck = true;
        }
        if (seccompEval.unsupported) {
            anyUnsupported = true;
        }

        // 2. Active App UID (getpriority PRIO_USER) vs uncached Binder getPackagesForUid
        boolean fullVisibility;
        try {
            fullVisibility = env.hasFullPackageVisibility();
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            fullVisibility = false;
        }

        if (!fullVisibility) {
            diagnostics.add("uid_vis=permission_limited");
        } else {
            UidVisEval visEval = evaluateUidVisibility(
                    selfUid, selfPkg, firstUid, lastUid, items, details);
            diagnostics.add("uid_vis=" + visEval.tag);
            if (visEval.usable) {
                anyUsableCheck = true;
            }
            if (visEval.unsupported) {
                anyUnsupported = true;
            }
            if (visEval.truncated) {
                truncated = true;
            }
        }

        String diag = String.join(";", diagnostics);
        if (!items.isEmpty()) {
            return new ProbeOutcome(ProbeState.DETECTED, items, details, truncated, diag);
        }
        if (truncated) {
            return new ProbeOutcome(ProbeState.PARTIAL, items, details, true, diag);
        }
        if (anyUsableCheck) {
            return new ProbeOutcome(ProbeState.CLEAN, items, details, false, diag);
        }
        if (anyUnsupported) {
            return new ProbeOutcome(ProbeState.UNSUPPORTED, items, details, false, diag);
        }
        return new ProbeOutcome(ProbeState.UNAVAILABLE, items, details, false, diag);
    }

    private static final class SeccompEval {
        final boolean usable;
        final boolean unsupported;
        final String tag;

        SeccompEval(boolean usable, boolean unsupported, String tag) {
            this.usable = usable;
            this.unsupported = unsupported;
            this.tag = tag;
        }
    }

    private SeccompEval evaluateSeccomp(int firstUid,
                                        int lastUid,
                                        List<EvidenceItem> items,
                                        List<String> details) {
        SignalResult<String> raw;
        try {
            raw = env.probeSeccompUidFilter(firstUid, lastUid);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return new SeccompEval(false, false, "exception");
        }
        if (raw == null || !raw.isSuccess() || raw.getValue() == null || raw.getValue().isEmpty()) {
            return new SeccompEval(false, false, "native_unavailable");
        }

        NativePayloadCodec.DecodedPayload payload = NativePayloadCodec.decodePayload(raw.getValue());
        if (payload.isMalformed()) {
            return new SeccompEval(false, false, "malformed");
        }
        if (payload.getStatus() == NativePayloadCodec.Status.UNSUPPORTED) {
            return new SeccompEval(false, true, "unsupported");
        }
        if (payload.getStatus() == NativePayloadCodec.Status.RESTRICTED) {
            return new SeccompEval(false, false, "restricted");
        }
        if (payload.getStatus() != NativePayloadCodec.Status.OK) {
            return new SeccompEval(false, false, "error_" + payload.getErrno());
        }

        Map<String, String> rec = findRecordByKind(payload.getRecords(), "seccomp_uid");
        if (rec == null) {
            return new SeccompEval(false, false, "missing_record");
        }

        String installStatus = rec.getOrDefault("install_status", "");
        int installError = parseInt(rec.get("install_error"), -1);
        String queryOutcome = rec.getOrDefault("query_outcome", "");
        int queried = parseInt(rec.get("queried"), -1);
        int notified = parseInt(rec.get("notified"), -1);
        int firstSuppressed = parseInt(rec.get("first_suppressed"), -1);
        int lastSuppressed = parseInt(rec.get("last_suppressed"), -1);

        if ("foreign_listener".equals(installStatus) && installError == 16 /* EBUSY */) {
            details.add("hma_seccomp_foreign_listener:EBUSY");
            items.add(new EvidenceItem(
                    "hma_seccomp_foreign_listener",
                    EvidenceItem.SourceLayer.NATIVE,
                    "seccomp_uid",
                    "EBUSY",
                    FAMILY_HMA_HIDING,
                    EvidenceItem.Rank.STRONG));
            return new SeccompEval(true, false, "foreign_listener");
        }
        if ("unsupported".equals(installStatus)) {
            return new SeccompEval(false, true, "unsupported");
        }
        if ("restricted".equals(installStatus)) {
            return new SeccompEval(false, false, "restricted");
        }
        if (!"installed".equals(installStatus)) {
            return new SeccompEval(false, false, installStatus.isEmpty() ? "install_failed" : installStatus);
        }

        if ("trapped".equals(queryOutcome)) {
            details.add("hma_seccomp_query_trapped:notified=" + notified);
            items.add(new EvidenceItem(
                    "hma_seccomp_query_trapped",
                    EvidenceItem.SourceLayer.NATIVE,
                    "seccomp_uid",
                    "SIGSYS:notified=" + notified,
                    FAMILY_HMA_HIDING,
                    EvidenceItem.Rank.STRONG));
            return new SeccompEval(true, false, "query_trapped");
        }
        if (!"complete".equals(queryOutcome) || queried <= 0) {
            return new SeccompEval(false, false, "incomplete_" + queryOutcome);
        }
        if (notified < 0 || notified > queried) {
            return new SeccompEval(false, false, "invalid_counts");
        }
        if (notified < queried) {
            int suppressed = queried - notified;
            if (firstSuppressed < firstUid
                    || lastSuppressed > lastUid
                    || lastSuppressed < firstSuppressed
                    || suppressed > (lastSuppressed - firstSuppressed + 1)
                    || (suppressed == 1 && firstSuppressed != lastSuppressed)) {
                return new SeccompEval(false, false, "invalid_suppressed_bounds");
            }
            String val = "suppressed=" + suppressed + ",range=" + firstSuppressed + "-" + lastSuppressed;
            details.add("hma_seccomp_suppressed:" + val);
            items.add(new EvidenceItem(
                    "hma_seccomp_suppressed",
                    EvidenceItem.SourceLayer.NATIVE,
                    "seccomp_uid",
                    val,
                    FAMILY_HMA_HIDING,
                    EvidenceItem.Rank.STRONG));
            return new SeccompEval(true, false, "suppressed");
        }
        return new SeccompEval(true, false, "clean");
    }

    private static final class UidVisEval {
        final boolean usable;
        final boolean unsupported;
        final boolean truncated;
        final String tag;

        UidVisEval(boolean usable, boolean unsupported, boolean truncated, String tag) {
            this.usable = usable;
            this.unsupported = unsupported;
            this.truncated = truncated;
            this.tag = tag;
        }
    }

    private UidVisEval evaluateUidVisibility(int selfUid,
                                             String selfPkg,
                                             int firstUid,
                                             int lastUid,
                                             List<EvidenceItem> items,
                                             List<String> details) {
        if (selfPkg == null || selfPkg.isBlank()) {
            return new UidVisEval(false, false, false, "missing_self_pkg");
        }

        long startMs = safeNowMs();
        SignalResult<String> raw;
        try {
            raw = env.scanActiveAppUids(firstUid, lastUid);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return new UidVisEval(false, false, false, "native_exception");
        }
        if (raw == null || !raw.isSuccess() || raw.getValue() == null || raw.getValue().isEmpty()) {
            return new UidVisEval(false, false, false, "native_unavailable");
        }

        NativePayloadCodec.DecodedPayload payload = NativePayloadCodec.decodePayload(raw.getValue());
        if (payload.isMalformed()) {
            return new UidVisEval(false, false, false, "malformed");
        }
        if (payload.getStatus() == NativePayloadCodec.Status.UNSUPPORTED) {
            return new UidVisEval(false, true, false, "unsupported");
        }
        if (payload.getStatus() == NativePayloadCodec.Status.RESTRICTED) {
            return new UidVisEval(false, false, false, "restricted");
        }
        if (payload.getStatus() != NativePayloadCodec.Status.OK) {
            return new UidVisEval(false, false, false, "error_" + payload.getErrno());
        }

        boolean scanComplete = "1".equals(payload.getHeaderField("complete"));
        Set<Integer> activeAppUids = new LinkedHashSet<>();
        for (Map<String, String> rec : payload.getRecords()) {
            if (!"active_uid".equals(rec.get("kind"))) {
                continue;
            }
            int uid = parseInt(rec.get("uid"), -1);
            if (isEligibleForeignAppUid(uid, selfUid, firstUid, lastUid)) {
                activeAppUids.add(uid);
            }
        }

        // Self-control BEFORE cross-check: Binder getPackagesForUid(selfUid) MUST contain selfPkg.
        if (!selfControlValid(selfUid, selfPkg)) {
            return new UidVisEval(false, false, false, "self_control_before_failed");
        }

        List<Integer> confirmedHidden = new ArrayList<>();
        int rechecks = 0;
        boolean budgetTruncated = !scanComplete;

        for (int uid : activeAppUids) {
            if ((safeNowMs() - startMs) >= budgetMs) {
                budgetTruncated = true;
                break;
            }
            String[] pkgs = safeGetPackagesForUid(uid);
            if (pkgs == null) {
                // Exception / transient Binder failure — do not treat as hidden.
                continue;
            }
            if (pkgs.length > 0) {
                continue;
            }
            rechecks++;
            if (rechecks > MAX_RECHECKS) {
                budgetTruncated = true;
                break;
            }
            // Re-verify single UID to defeat process-exit TOCTOU race conditions.
            if (isUidStillActive(uid)) {
                String[] retryPkgs = safeGetPackagesForUid(uid);
                if (retryPkgs != null && retryPkgs.length == 0) {
                    confirmedHidden.add(uid);
                }
            }
        }

        // Self-control AFTER cross-check: if Binder stopped resolving even self, discard findings.
        if (!selfControlValid(selfUid, selfPkg)) {
            return new UidVisEval(false, false, false, "self_control_after_failed");
        }

        if (!confirmedHidden.isEmpty()) {
            String summary = "hidden_count=" + confirmedHidden.size();
            details.add("hma_uid_visibility_hidden:" + summary);
            items.add(new EvidenceItem(
                    "hma_uid_visibility_hidden",
                    EvidenceItem.SourceLayer.NATIVE,
                    "uid_visibility",
                    summary,
                    FAMILY_HMA_HIDING,
                    EvidenceItem.Rank.STRONG));
            return new UidVisEval(true, false, budgetTruncated, "hidden_detected");
        }

        return new UidVisEval(true, false, budgetTruncated, budgetTruncated ? "partial" : "clean");
    }

    private boolean isUidStillActive(int uid) {
        try {
            SignalResult<String> single = env.scanActiveAppUids(uid, uid);
            if (single == null || !single.isSuccess() || single.getValue() == null) {
                return false;
            }
            NativePayloadCodec.DecodedPayload parsed = NativePayloadCodec.decodePayload(single.getValue());
            if (!parsed.isOk()) {
                return false;
            }
            for (Map<String, String> rec : parsed.getRecords()) {
                if ("active_uid".equals(rec.get("kind")) && parseInt(rec.get("uid"), -1) == uid) {
                    return true;
                }
            }
            return false;
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return false;
        }
    }

    private boolean selfControlValid(int selfUid, String selfPkg) {
        String[] pkgs = safeGetPackagesForUid(selfUid);
        if (pkgs == null || pkgs.length == 0) {
            return false;
        }
        return Arrays.asList(pkgs).contains(selfPkg);
    }

    /**
     * Returns an array of packages (empty array if Binder returned {@code null} cleanly) or
     * {@code null} if the Binder call threw an exception/error (failure != empty).
     */
    private String[] safeGetPackagesForUid(int uid) {
        try {
            String[] pkgs = env.getPackagesForUid(uid);
            return pkgs == null ? new String[0] : pkgs;
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return null;
        }
    }

    private static boolean isEligibleForeignAppUid(int uid,
                                                   int selfUid,
                                                   int firstUid,
                                                   int lastUid) {
        if (uid < firstUid || uid > lastUid || uid == selfUid) {
            return false;
        }
        int appId = uid % PER_USER_RANGE;
        return appId >= FIRST_APP_ID && appId <= LAST_APP_ID;
    }

    private long safeNowMs() {
        try {
            return env.elapsedRealtimeMs();
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return 0L;
        }
    }

    private static Map<String, String> findRecordByKind(List<Map<String, String>> records,
                                                        String kind) {
        for (Map<String, String> rec : records) {
            if (kind.equals(rec.get("kind"))) {
                return rec;
            }
        }
        return null;
    }

    private static int parseInt(String raw, int fallback) {
        if (raw == null || raw.isEmpty()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
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
            public SignalResult<String> scanActiveAppUids(int firstUid, int lastUid) {
                return NativeCollectorBridge.scanActiveAppUidsResult(firstUid, lastUid);
            }

            @Override
            public SignalResult<String> probeSeccompUidFilter(int firstUid, int lastUid) {
                return NativeCollectorBridge.probeSeccompUidFilterResult(firstUid, lastUid);
            }

            @Override
            public String[] getPackagesForUid(int uid) {
                PackageManager pm = appCtx.getPackageManager();
                return pm == null ? new String[0] : pm.getPackagesForUid(uid);
            }

            @Override
            public long elapsedRealtimeMs() {
                return SystemClock.elapsedRealtime();
            }
        };
    }
}
