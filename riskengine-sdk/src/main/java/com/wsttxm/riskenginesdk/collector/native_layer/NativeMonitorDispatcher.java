package com.wsttxm.riskenginesdk.collector.native_layer;

import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.ThreatEvent;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Static JNI upcall receiver for event-driven runtime tamper detections from
 * {@code periodic_monitor.cpp}.
 *
 * <p>{@code JNI_OnLoad} pre-caches this class via {@code NewGlobalRef} and the
 * {@link #onNativeThreatDetected(String, String)} {@code jmethodID} so the attached
 * native monitor pthread never invokes {@code FindClass}.
 */
public final class NativeMonitorDispatcher {

    /** Listener notified asynchronously when the native periodic monitor latches a threat. */
    public interface MonitorEventListener {
        void onMonitorThreat(ThreatEvent event);
    }

    private static final CopyOnWriteArrayList<MonitorEventListener> LISTENERS =
            new CopyOnWriteArrayList<>();

    private NativeMonitorDispatcher() {}

    public static void addListener(MonitorEventListener listener) {
        if (listener != null) {
            LISTENERS.addIfAbsent(listener);
        }
    }

    public static void removeListener(MonitorEventListener listener) {
        if (listener != null) {
            LISTENERS.remove(listener);
        }
    }

    public static void clearListeners() {
        LISTENERS.clear();
    }

    /**
     * Invoked directly by native {@code periodic_monitor.cpp} with zero native mutexes held.
     * Never throws back across the JNI boundary.
     */
    public static void onNativeThreatDetected(String token, String sourceDetail) {
        try {
            if (token == null || token.isBlank()) {
                return;
            }
            ThreatEvent event = buildThreatEvent(token.trim(), sourceDetail);
            for (MonitorEventListener listener : LISTENERS) {
                try {
                    listener.onMonitorThreat(event);
                } catch (Exception | LinkageError | OutOfMemoryError e) {
                    CLog.e("NativeMonitorDispatcher listener failed", e);
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("NativeMonitorDispatcher upcall failed", e);
        }
    }

    static ThreatEvent buildThreatEvent(String token, String sourceDetail) {
        String lower = token.toLowerCase(Locale.ROOT);
        String detectorName = "hook_framework";
        String family = "hook_integrity";
        RiskLevel level = RiskLevel.HIGH;
        int score = 8;
        EvidenceItem.Rank rank = EvidenceItem.Rank.STRONG;

        if (lower.startsWith("late_tracer_attached")) {
            detectorName = "debug";
            family = "debugger";
            level = RiskLevel.HIGH;
            score = 8;
            rank = EvidenceItem.Rank.STRONG;
        } else if (lower.startsWith("late_text_mismatch")
                || lower.startsWith("jni_self_hook:")
                || lower.startsWith("fn_prologue_hook:")
                || lower.startsWith("late_wx_self")
                || lower.startsWith("late_memfd_elf")) {
            detectorName = "hook_framework";
            family = "hook_integrity";
            level = RiskLevel.DEADLY;
            score = 10;
            rank = EvidenceItem.Rank.STRONG;
        } else if (lower.startsWith("late_frida_fd")
                || lower.startsWith("late_module:frida")) {
            detectorName = "hook_framework";
            family = "frida";
            level = RiskLevel.HIGH;
            score = 8;
            rank = EvidenceItem.Rank.STRONG;
        } else if (lower.startsWith("late_module:lsposed")) {
            detectorName = "hook_framework";
            family = "xposed";
            level = RiskLevel.HIGH;
            score = 8;
            rank = EvidenceItem.Rank.STRONG;
        } else if (lower.startsWith("late_wx_art")) {
            detectorName = "hook_framework";
            family = "hook_integrity";
            level = RiskLevel.MEDIUM;
            score = 4;
            rank = EvidenceItem.Rank.MEDIUM;
        }

        String code = extractCode(token);
        String location = (sourceDetail == null || sourceDetail.isBlank())
                ? "periodic_monitor"
                : sourceDetail;
        EvidenceItem item = new EvidenceItem(
                code,
                EvidenceItem.SourceLayer.NATIVE,
                location,
                token,
                family,
                rank
        );
        return new ThreatEvent(
                detectorName,
                level,
                ScanTier.CRITICAL,
                score,
                token,
                Collections.singletonList(token),
                Collections.singletonList(item),
                Collections.singleton(family),
                true,
                System.currentTimeMillis()
        );
    }

    private static String extractCode(String token) {
        int colon = token.indexOf(':');
        return colon > 0 ? token.substring(0, colon) : token;
    }
}
