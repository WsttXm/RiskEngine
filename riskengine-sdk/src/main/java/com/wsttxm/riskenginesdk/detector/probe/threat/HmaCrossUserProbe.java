package com.wsttxm.riskenginesdk.detector.probe.threat;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;

import com.wsttxm.riskenginesdk.model.EvidenceItem;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * HMA cross-user permission-exception suppression probe.
 *
 * <p>On stock Android (API 30+), invoking {@code getPackageInfo}/{@code getApplicationInfo} with
 * {@code MATCH_ANY_USER (0x00400000)} or cross-user {@code sendBroadcastAsUser} without
 * {@code INTERACT_ACROSS_USERS} throws {@link SecurityException} even for the caller's own
 * package. HideMyApplist hooks that intercept package queries before AOSP's permission check
 * suppress the {@link SecurityException} into {@link PackageManager.NameNotFoundException} or a
 * {@code null}/empty return.</p>
 *
 * <p>Pairs every scan with pre- and post-scan caller-package controls; if either control fails
 * to throw {@link SecurityException} (e.g. OEM quirk or privileged host), degrades cleanly to
 * {@link ProbeState#UNAVAILABLE} with zero false positives. Uses public APIs only (zero blocked
 * hidden-API reflection per {@code D66}).</p>
 */
public final class HmaCrossUserProbe {

    public static final String FAMILY_HMA_HIDING = "hma_hiding";
    /** AOSP {@code PackageManager.MATCH_ANY_USER} flag bit ({@code 0x00400000}). */
    public static final int MATCH_ANY_USER = 0x00400000;
    private static final int MAX_TARGETS = 24;

    public enum CallOutcome {
        SECURITY_EXCEPTION,
        NAME_NOT_FOUND,
        NULL_OR_RETURNED,
        UNAVAILABLE,
        FAILED
    }

    public enum ProbeState {
        DETECTED,
        CLEAN,
        UNAVAILABLE
    }

    /** Injectable adapter for cross-user calls (supports pure-JVM tests & broadcast vectors). */
    public interface CrossUserAdapter {
        String getCallerPackageName();
        CallOutcome queryPackageInfoAnyUser(String packageName);
        CallOutcome queryApplicationInfoAnyUser(String packageName);
        /** Optional cross-user broadcast vector; returns {@code UNAVAILABLE} when unused. */
        default CallOutcome sendCrossUserBroadcast(String packageName) {
            return CallOutcome.UNAVAILABLE;
        }
    }

    public static final class ProbeOutcome {
        private final ProbeState state;
        private final List<EvidenceItem> evidenceItems;
        private final List<String> details;
        private final Set<String> suppressedPackages;
        private final String diagnostic;

        ProbeOutcome(ProbeState state,
                     List<EvidenceItem> evidenceItems,
                     List<String> details,
                     Set<String> suppressedPackages,
                     String diagnostic) {
            this.state = state;
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
            this.details = Collections.unmodifiableList(details);
            this.suppressedPackages = Collections.unmodifiableSet(suppressedPackages);
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

        public Set<String> getSuppressedPackages() {
            return suppressedPackages;
        }

        public String getDiagnostic() {
            return diagnostic;
        }

        public boolean isDetected() {
            return !evidenceItems.isEmpty();
        }
    }

    @FunctionalInterface
    private interface SurfaceCall {
        CallOutcome invoke(String packageName);
    }

    private final CrossUserAdapter adapter;

    public HmaCrossUserProbe(Context context) {
        this(defaultAdapter(context));
    }

    public HmaCrossUserProbe(CrossUserAdapter adapter) {
        this.adapter = adapter;
    }

    public ProbeOutcome probe(Collection<String> targetPackages) {
        if (adapter == null) {
            return unavailable("adapter_null");
        }
        String callerPkg;
        try {
            callerPkg = adapter.getCallerPackageName();
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return unavailable("caller_pkg_error");
        }
        if (callerPkg == null || callerPkg.isBlank()) {
            return unavailable("caller_pkg_blank");
        }

        List<String> targets = sanitizeTargets(targetPackages, callerPkg);
        if (targets.isEmpty()) {
            return unavailable("no_targets");
        }

        List<EvidenceItem> items = new ArrayList<>();
        List<String> details = new ArrayList<>();
        Set<String> suppressedAll = new LinkedHashSet<>();
        List<String> diags = new ArrayList<>();
        boolean anyUsableSurface = false;

        anyUsableSurface |= runSurface(
                "pkg_info_any_user",
                callerPkg,
                targets,
                adapter::queryPackageInfoAnyUser,
                items,
                details,
                suppressedAll,
                diags);

        anyUsableSurface |= runSurface(
                "app_info_any_user",
                callerPkg,
                targets,
                adapter::queryApplicationInfoAnyUser,
                items,
                details,
                suppressedAll,
                diags);

        anyUsableSurface |= runSurface(
                "broadcast_as_user",
                callerPkg,
                targets,
                adapter::sendCrossUserBroadcast,
                items,
                details,
                suppressedAll,
                diags);

        String diag = String.join(";", diags);
        if (!items.isEmpty()) {
            return new ProbeOutcome(ProbeState.DETECTED, items, details, suppressedAll, diag);
        }
        if (anyUsableSurface) {
            return new ProbeOutcome(ProbeState.CLEAN, items, details, suppressedAll, diag);
        }
        return new ProbeOutcome(ProbeState.UNAVAILABLE, items, details, suppressedAll, diag);
    }

    private boolean runSurface(String surfaceName,
                               String callerPkg,
                               List<String> targets,
                               SurfaceCall call,
                               List<EvidenceItem> items,
                               List<String> details,
                               Set<String> suppressedAll,
                               List<String> diags) {
        CallOutcome before = safeInvoke(call, callerPkg);
        if (before != CallOutcome.SECURITY_EXCEPTION) {
            diags.add(surfaceName + "=control_before_" + before.name());
            return false;
        }

        List<String> surfaceSuppressed = new ArrayList<>();
        boolean sawInconsistent = false;
        boolean sawUsableTarget = false;
        for (String pkg : targets) {
            CallOutcome first = safeInvoke(call, pkg);
            CallOutcome second = safeInvoke(call, pkg);
            if (isSuppressedOutcome(first) && isSuppressedOutcome(second)) {
                surfaceSuppressed.add(pkg);
                sawUsableTarget = true;
            } else if (first == CallOutcome.SECURITY_EXCEPTION
                    && second == CallOutcome.SECURITY_EXCEPTION) {
                sawUsableTarget = true;
            } else {
                sawInconsistent = true;
            }
        }

        CallOutcome after = safeInvoke(call, callerPkg);
        if (after != CallOutcome.SECURITY_EXCEPTION) {
            diags.add(surfaceName + "=control_after_" + after.name());
            return false;
        }

        if (!surfaceSuppressed.isEmpty()) {
            suppressedAll.addAll(surfaceSuppressed);
            String val = surfaceName + ":count=" + surfaceSuppressed.size();
            details.add("hma_cross_user_suppression:" + val);
            items.add(new EvidenceItem(
                    "hma_cross_user_suppression",
                    EvidenceItem.SourceLayer.JAVA,
                    surfaceName,
                    val,
                    FAMILY_HMA_HIDING,
                    EvidenceItem.Rank.STRONG));
            diags.add(surfaceName + "=suppressed_" + surfaceSuppressed.size());
            return true;
        }

        diags.add(surfaceName + ((!sawUsableTarget || sawInconsistent) ? "=inconclusive" : "=clean"));
        return sawUsableTarget && !sawInconsistent;
    }

    private static boolean isSuppressedOutcome(CallOutcome outcome) {
        return outcome == CallOutcome.NAME_NOT_FOUND || outcome == CallOutcome.NULL_OR_RETURNED;
    }

    private static CallOutcome safeInvoke(SurfaceCall call, String pkg) {
        try {
            CallOutcome out = call.invoke(pkg);
            return out == null ? CallOutcome.FAILED : out;
        } catch (SecurityException e) {
            return CallOutcome.SECURITY_EXCEPTION;
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return CallOutcome.FAILED;
        }
    }

    private static List<String> sanitizeTargets(Collection<String> raw, String callerPkg) {
        if (raw == null || raw.isEmpty()) {
            return Collections.emptyList();
        }
        Set<String> unique = new LinkedHashSet<>();
        for (String pkg : raw) {
            if (pkg == null || pkg.isBlank()) {
                continue;
            }
            String trimmed = pkg.trim();
            if (!trimmed.equals(callerPkg)) {
                unique.add(trimmed);
                if (unique.size() >= MAX_TARGETS) {
                    break;
                }
            }
        }
        return new ArrayList<>(unique);
    }

    private static ProbeOutcome unavailable(String diag) {
        return new ProbeOutcome(
                ProbeState.UNAVAILABLE,
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptySet(),
                diag);
    }

    private static CrossUserAdapter defaultAdapter(Context context) {
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
        final PackageManager pm;
        try {
            pm = appCtx.getPackageManager();
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return null;
        }
        if (pm == null) {
            return null;
        }
        return new CrossUserAdapter() {
            @Override
            public String getCallerPackageName() {
                return appCtx.getPackageName();
            }

            @Override
            @SuppressLint("WrongConstant")
            public CallOutcome queryPackageInfoAnyUser(String packageName) {
                try {
                    if (Build.VERSION.SDK_INT >= 33) {
                        pm.getPackageInfo(
                                packageName, PackageManager.PackageInfoFlags.of(MATCH_ANY_USER));
                    } else {
                        getPackageInfoLegacy(pm, packageName, MATCH_ANY_USER);
                    }
                    return CallOutcome.NULL_OR_RETURNED;
                } catch (SecurityException e) {
                    return CallOutcome.SECURITY_EXCEPTION;
                } catch (PackageManager.NameNotFoundException e) {
                    return CallOutcome.NAME_NOT_FOUND;
                } catch (Exception | LinkageError | OutOfMemoryError e) {
                    return CallOutcome.FAILED;
                }
            }

            @Override
            @SuppressLint("WrongConstant")
            public CallOutcome queryApplicationInfoAnyUser(String packageName) {
                try {
                    if (Build.VERSION.SDK_INT >= 33) {
                        pm.getApplicationInfo(
                                packageName, PackageManager.ApplicationInfoFlags.of(MATCH_ANY_USER));
                    } else {
                        getApplicationInfoLegacy(pm, packageName, MATCH_ANY_USER);
                    }
                    return CallOutcome.NULL_OR_RETURNED;
                } catch (SecurityException e) {
                    return CallOutcome.SECURITY_EXCEPTION;
                } catch (PackageManager.NameNotFoundException e) {
                    return CallOutcome.NAME_NOT_FOUND;
                } catch (Exception | LinkageError | OutOfMemoryError e) {
                    return CallOutcome.FAILED;
                }
            }
        };
    }

    @SuppressWarnings("deprecation")
    @SuppressLint("WrongConstant")
    private static Object getPackageInfoLegacy(PackageManager pm, String pkg, int flags)
            throws PackageManager.NameNotFoundException {
        return pm.getPackageInfo(pkg, flags);
    }

    @SuppressWarnings("deprecation")
    @SuppressLint("WrongConstant")
    private static Object getApplicationInfoLegacy(PackageManager pm, String pkg, int flags)
            throws PackageManager.NameNotFoundException {
        return pm.getApplicationInfo(pkg, flags);
    }
}
