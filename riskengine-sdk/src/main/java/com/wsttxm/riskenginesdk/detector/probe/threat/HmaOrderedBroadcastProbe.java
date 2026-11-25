package com.wsttxm.riskenginesdk.detector.probe.threat;

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.SystemClock;

import com.wsttxm.riskenginesdk.model.EvidenceItem;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Ordered Broadcast {@code resultTo} asymmetry probe for HideMyApplist / HMA-OSS.
 *
 * <p>Detects two distinct HMA-OSS defects using 100% public {@link Context#sendOrderedBroadcast}
 * paired with host self-control broadcasts:
 * <ol>
 *   <li><b>HMA-OSS #173</b>: hooked broadcast dispatch invokes {@code resultTo} with
 *       {@code isOrderedBroadcast() == true} (or corrupted result code/data/extras/intent),
 *       whereas AOSP delivers the final {@code resultTo} callback with
 *       {@code isOrderedBroadcast() == false}.</li>
 *   <li><b>HMA-OSS #164</b>: hooked broadcast dispatch drops the final {@code resultTo} callback
 *       completely for targeted hidden packages while interleaved self-control broadcasts
 *       complete consistently.</li>
 * </ol>
 *
 * <p>Any failure of the initial or interleaved self-control pair degrades cleanly to
 * {@link ProbeState#UNAVAILABLE} (zero false positives).</p>
 */
public final class HmaOrderedBroadcastProbe {

    public static final String FAMILY_HMA_HIDING = "hma_hiding";
    public static final int RESULT_CODE = 0x484D41;
    public static final long DEFAULT_CALLBACK_TIMEOUT_MS = 400L;
    public static final long DEFAULT_BATCH_BUDGET_MS = 2_000L;
    private static final String TOKEN_KEY = "re_hma_token";
    private static final int MAX_TARGETS = 10;

    public enum CallbackFailure {
        NONE,
        TIMED_OUT,
        PERMISSION_DENIED,
        FAILED
    }

    public enum ProbeState {
        DETECTED,
        CLEAN,
        PARTIAL,
        UNAVAILABLE
    }

    /** Single ordered-broadcast {@code resultTo} observation. */
    public static final class CallbackObservation {
        private final boolean received;
        private final boolean ordered;
        private final boolean sticky;
        private final boolean payloadPreserved;
        private final boolean intentPreserved;
        private final CallbackFailure failure;

        public CallbackObservation(boolean received,
                                   boolean ordered,
                                   boolean sticky,
                                   boolean payloadPreserved,
                                   boolean intentPreserved,
                                   CallbackFailure failure) {
            this.received = received;
            this.ordered = ordered;
            this.sticky = sticky;
            this.payloadPreserved = payloadPreserved;
            this.intentPreserved = intentPreserved;
            this.failure = failure == null ? CallbackFailure.NONE : failure;
        }

        public static CallbackObservation cleanConsistent() {
            return new CallbackObservation(true, false, false, true, true, CallbackFailure.NONE);
        }

        public static CallbackObservation timedOut() {
            return new CallbackObservation(false, false, false, false, false, CallbackFailure.TIMED_OUT);
        }

        public static CallbackObservation failed(CallbackFailure failure) {
            return new CallbackObservation(false, false, false, false, false, failure);
        }

        public boolean isReceived() {
            return received;
        }

        public boolean isOrdered() {
            return ordered;
        }

        public boolean isSticky() {
            return sticky;
        }

        public boolean isPayloadPreserved() {
            return payloadPreserved;
        }

        public boolean isIntentPreserved() {
            return intentPreserved;
        }

        public CallbackFailure getFailure() {
            return failure;
        }

        public boolean isTimedOut() {
            return !received && failure == CallbackFailure.TIMED_OUT;
        }

        /** True iff callback arrived cleanly matching AOSP final {@code resultTo} semantics. */
        public boolean isConsistent() {
            return received
                    && failure == CallbackFailure.NONE
                    && !ordered
                    && !sticky
                    && payloadPreserved
                    && intentPreserved;
        }
    }

    /** Injectable transport adapter for pure-JVM unit tests. */
    public interface BroadcastTransport {
        String getCallerPackageName();
        CallbackObservation sendAndAwait(String targetPackage);
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

    private final Context context;
    private final BroadcastTransport customTransport;
    private final long callbackTimeoutMs;
    private final long batchBudgetMs;

    public HmaOrderedBroadcastProbe(Context context) {
        Context resolved = context;
        if (context != null) {
            try {
                Context app = context.getApplicationContext();
                if (app != null) {
                    resolved = app;
                }
            } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                resolved = context;
            }
        }
        this.context = resolved;
        this.customTransport = null;
        this.callbackTimeoutMs = DEFAULT_CALLBACK_TIMEOUT_MS;
        this.batchBudgetMs = DEFAULT_BATCH_BUDGET_MS;
    }

    public HmaOrderedBroadcastProbe(BroadcastTransport transport) {
        this(transport, DEFAULT_BATCH_BUDGET_MS);
    }

    public HmaOrderedBroadcastProbe(BroadcastTransport transport, long batchBudgetMs) {
        this.context = null;
        this.customTransport = transport;
        this.callbackTimeoutMs = DEFAULT_CALLBACK_TIMEOUT_MS;
        this.batchBudgetMs = batchBudgetMs > 0 ? batchBudgetMs : DEFAULT_BATCH_BUDGET_MS;
    }

    public ProbeOutcome probe(Collection<String> targetPackages) {
        if (customTransport != null) {
            return runWithTransport(customTransport, targetPackages);
        }
        if (context == null) {
            return unavailable("context_null");
        }
        if (isMainThread()) {
            return unavailable("main_thread");
        }
        HandlerThread thread = new HandlerThread("re-hma-bcast");
        try {
            thread.start();
            Handler handler = new Handler(thread.getLooper());
            BroadcastTransport transport = createAndroidTransport(context, handler, callbackTimeoutMs);
            return runWithTransport(transport, targetPackages);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return unavailable("handler_thread_error");
        } finally {
            try {
                thread.quitSafely();
            } catch (Exception | LinkageError ignored) {
                // Best-effort shutdown.
            }
        }
    }

    private static boolean isMainThread() {
        try {
            Looper main = Looper.getMainLooper();
            return main != null && Looper.myLooper() == main;
        } catch (Exception | LinkageError e) {
            return false;
        }
    }

    private ProbeOutcome runWithTransport(BroadcastTransport transport,
                                          Collection<String> targetPackages) {
        final String callerPkg;
        try {
            callerPkg = transport.getCallerPackageName();
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

        // Initial self-control pair: MUST succeed before probing any target.
        CallbackObservation initialControl = safeSend(transport, callerPkg);
        if (!initialControl.isConsistent()) {
            return unavailable("initial_control_failed:" + initialControl.getFailure().name());
        }

        long startedMs = safeNowMs(transport);
        List<EvidenceItem> items = new ArrayList<>();
        List<String> details = new ArrayList<>();
        int completedTargets = 0;
        int usableTargets = 0;
        int controlFailures = 0;
        boolean budgetExpired = false;

        for (String targetPkg : targets) {
            if ((safeNowMs(transport) - startedMs) >= batchBudgetMs) {
                budgetExpired = true;
                break;
            }
            CallbackObservation before = safeSend(transport, callerPkg);
            if (!before.isConsistent()) {
                controlFailures++;
                continue;
            }
            CallbackObservation first = safeSend(transport, targetPkg);
            CallbackObservation between = safeSend(transport, callerPkg);
            if (!between.isConsistent()) {
                controlFailures++;
                continue;
            }
            CallbackObservation repeat = safeSend(transport, targetPkg);
            CallbackObservation after = safeSend(transport, callerPkg);
            if (!after.isConsistent()) {
                controlFailures++;
                continue;
            }

            completedTargets++;

            // HMA-OSS 173: callback delivered cleanly twice but violates final resultTo semantics
            if (first.isReceived() && repeat.isReceived()
                    && first.getFailure() == CallbackFailure.NONE
                    && repeat.getFailure() == CallbackFailure.NONE
                    && !first.isConsistent() && !repeat.isConsistent()) {
                usableTargets++;
                String reason = (first.isOrdered() && repeat.isOrdered())
                        ? "isOrderedBroadcast=true"
                        : "semantic_mismatch";
                details.add("hma_ordered_broadcast_semantic:" + targetPkg + ":" + reason);
                items.add(new EvidenceItem(
                        "hma_ordered_broadcast_semantic",
                        EvidenceItem.SourceLayer.JAVA,
                        targetPkg,
                        reason,
                        FAMILY_HMA_HIDING,
                        EvidenceItem.Rank.STRONG));
            } else if (first.isTimedOut() && repeat.isTimedOut()) {
                usableTargets++;
                // HMA-OSS 164: repeated missing final resultTo callback with passing interleaved controls
                details.add("hma_ordered_broadcast_missing_result:" + targetPkg);
                items.add(new EvidenceItem(
                        "hma_ordered_broadcast_missing_result",
                        EvidenceItem.SourceLayer.JAVA,
                        targetPkg,
                        "repeated_missing_resultTo",
                        FAMILY_HMA_HIDING,
                        EvidenceItem.Rank.STRONG));
            } else if (first.isConsistent() && repeat.isConsistent()) {
                usableTargets++;
            }
        }

        String diag = "completed=" + completedTargets + "/" + targets.size()
                + ";usable=" + usableTargets
                + ";ctrl_fail=" + controlFailures
                + ";budget_expired=" + budgetExpired;
        if (!items.isEmpty()) {
            return new ProbeOutcome(ProbeState.DETECTED, items, details, budgetExpired, diag);
        }
        if (usableTargets == 0) {
            return new ProbeOutcome(
                    budgetExpired ? ProbeState.PARTIAL : ProbeState.UNAVAILABLE,
                    items, details, budgetExpired, diag);
        }
        if (budgetExpired || completedTargets < targets.size()) {
            return new ProbeOutcome(ProbeState.PARTIAL, items, details, true, diag);
        }
        return new ProbeOutcome(ProbeState.CLEAN, items, details, false, diag);
    }

    private static CallbackObservation safeSend(BroadcastTransport transport, String targetPkg) {
        try {
            CallbackObservation obs = transport.sendAndAwait(targetPkg);
            return obs == null ? CallbackObservation.failed(CallbackFailure.FAILED) : obs;
        } catch (SecurityException e) {
            return CallbackObservation.failed(CallbackFailure.PERMISSION_DENIED);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return CallbackObservation.failed(CallbackFailure.FAILED);
        }
    }

    private static long safeNowMs(BroadcastTransport transport) {
        try {
            return transport.elapsedRealtimeMs();
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return 0L;
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
                false,
                diag);
    }

    private static BroadcastTransport createAndroidTransport(Context appCtx,
                                                             Handler handler,
                                                             long timeoutMs) {
        final String callerPkg = appCtx.getPackageName();
        final String uniqueSuffix = UUID.randomUUID().toString().replace("-", "");
        final String absentComponent = callerPkg + ".AbsentHmaReceiver_" + uniqueSuffix;
        final String action = callerPkg + ".HMA_PROBE_" + uniqueSuffix;

        return new BroadcastTransport() {
            @Override
            public String getCallerPackageName() {
                return callerPkg;
            }

            @Override
            public CallbackObservation sendAndAwait(String targetPackage) {
                final String token = UUID.randomUUID().toString();
                final Intent sent = new Intent(action);
                sent.setComponent(new ComponentName(targetPackage, absentComponent));
                sent.addFlags(Intent.FLAG_RECEIVER_FOREGROUND);
                sent.putExtra(TOKEN_KEY, token);
                final Intent expected = new Intent(sent);

                final CountDownLatch latch = new CountDownLatch(1);
                final AtomicReference<CallbackObservation> ref = new AtomicReference<>();
                BroadcastReceiver resultReceiver = new BroadcastReceiver() {
                    @Override
                    public void onReceive(Context ctx, Intent intent) {
                        CallbackObservation obs;
                        try {
                            Bundle extras = getResultExtras(false);
                            boolean payloadOk = getResultCode() == RESULT_CODE
                                    && token.equals(getResultData())
                                    && extras != null
                                    && token.equals(extras.getString(TOKEN_KEY));
                            boolean intentOk = intent != null
                                    && intent.filterEquals(expected)
                                    && token.equals(intent.getStringExtra(TOKEN_KEY));
                            obs = new CallbackObservation(
                                    true,
                                    isOrderedBroadcast(),
                                    isInitialStickyBroadcast(),
                                    payloadOk,
                                    intentOk,
                                    CallbackFailure.NONE);
                        } catch (Exception | LinkageError | OutOfMemoryError e) {
                            obs = CallbackObservation.failed(CallbackFailure.FAILED);
                        }
                        ref.compareAndSet(null, obs);
                        latch.countDown();
                    }
                };

                try {
                    Bundle initialExtras = new Bundle();
                    initialExtras.putString(TOKEN_KEY, token);
                    appCtx.sendOrderedBroadcast(
                            sent, null, resultReceiver, handler,
                            RESULT_CODE, token, initialExtras);
                } catch (SecurityException e) {
                    return CallbackObservation.failed(CallbackFailure.PERMISSION_DENIED);
                } catch (Exception | LinkageError | OutOfMemoryError e) {
                    return CallbackObservation.failed(CallbackFailure.FAILED);
                }

                try {
                    if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                        return CallbackObservation.timedOut();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return CallbackObservation.failed(CallbackFailure.FAILED);
                }
                CallbackObservation received = ref.get();
                return received != null ? received : CallbackObservation.timedOut();
            }

            @Override
            public long elapsedRealtimeMs() {
                return SystemClock.elapsedRealtime();
            }
        };
    }
}
