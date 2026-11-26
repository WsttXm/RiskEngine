package com.wsttxm.riskenginesdk.detector.probe.consistency;

import android.media.MediaDrm;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SafeExecutor;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.detector.ConsistencyDetector;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Dual-source Widevine DRM parity probe (Java {@link MediaDrm} vs NDK {@code AMediaDrm}).
 *
 * <p>Runs strictly inside {@link ConsistencyDetector#detectPostponed} under a bounded
 * {@link SafeExecutor} timeout. Flags:
 * <ul>
 *   <li>Java vs NDK mismatch on {@code securityLevel} or {@code systemId} (Java hook indicator)</li>
 *   <li>L1 sentinel {@code systemId=2147483647} (invalid/wiped keybox fallback)</li>
 *   <li>{@code HW_SECURE_ALL} session downgrade despite advertised {@code L1}</li>
 * </ul>
 * Never reads or logs raw {@code deviceUniqueId} PII. Maps unavailable/unsupported Widevine
 * cleanly to {@code UNAVAILABLE}/{@code UNSUPPORTED} with zero false positives.
 */
public final class WidevineParityProbe {

    public static final UUID WIDEVINE_UUID =
            new UUID(0xEDEF8BA979D64ACEL, 0xA3C827DCD51D21EDL);
    public static final String SENTINEL_SYSTEM_ID = "2147483647";
    public static final long DEFAULT_TIMEOUT_MS = 1_500L;

    private WidevineParityProbe() {
    }

    /** Java-side non-PII Widevine snapshot. */
    public static final class JavaWidevineSnapshot {
        private final boolean supported;
        private final boolean available;
        private final String securityLevel;
        private final String systemId;
        private final Boolean hwSecureAllSupported;
        private final Integer actualSessionSecurityLevel;
        private final String failureReason;

        public JavaWidevineSnapshot(
                boolean supported,
                boolean available,
                String securityLevel,
                String systemId,
                Boolean hwSecureAllSupported,
                Integer actualSessionSecurityLevel,
                String failureReason) {
            this.supported = supported;
            this.available = available;
            this.securityLevel = securityLevel;
            this.systemId = systemId;
            this.hwSecureAllSupported = hwSecureAllSupported;
            this.actualSessionSecurityLevel = actualSessionSecurityLevel;
            this.failureReason = failureReason;
        }

        public boolean isSupported() {
            return supported;
        }

        public boolean isAvailable() {
            return available;
        }

        public String getSecurityLevel() {
            return securityLevel;
        }

        public String getSystemId() {
            return systemId;
        }

        public Boolean getHwSecureAllSupported() {
            return hwSecureAllSupported;
        }

        public Integer getActualSessionSecurityLevel() {
            return actualSessionSecurityLevel;
        }

        public String getFailureReason() {
            return failureReason;
        }

        public static JavaWidevineSnapshot unsupported(String reason) {
            return new JavaWidevineSnapshot(false, false, null, null, null, null, reason);
        }

        public static JavaWidevineSnapshot unavailable(String reason) {
            return new JavaWidevineSnapshot(false, false, null, null, null, null, reason);
        }
    }

    /** NDK-side non-PII Widevine snapshot decoded from NativePayloadCodec. */
    public static final class NdkWidevineSnapshot {
        private final boolean available;
        private final boolean supported;
        private final String securityLevel;
        private final String systemId;
        private final String failureReason;

        public NdkWidevineSnapshot(
                boolean available,
                boolean supported,
                String securityLevel,
                String systemId,
                String failureReason) {
            this.available = available;
            this.supported = supported;
            this.securityLevel = securityLevel;
            this.systemId = systemId;
            this.failureReason = failureReason;
        }

        public boolean isAvailable() {
            return available;
        }

        public boolean isSupported() {
            return supported;
        }

        public String getSecurityLevel() {
            return securityLevel;
        }

        public String getSystemId() {
            return systemId;
        }

        public String getFailureReason() {
            return failureReason;
        }

        public static NdkWidevineSnapshot unavailable(String reason) {
            return new NdkWidevineSnapshot(false, false, null, null, reason);
        }
    }

    /** Injectable Java reader for pure-JVM unit tests. */
    public interface JavaWidevineReader {
        JavaWidevineSnapshot read();
    }

    /** Injectable NDK reader for pure-JVM unit tests. */
    public interface NdkWidevineReader {
        SignalResult<String> readRawFrame();
    }

    public static final class ProbeResult {
        private final SignalResult.Status status;
        private final String failureReason;
        private final Set<String> strongTokens;
        private final Set<String> mediumTokens;
        private final List<EvidenceItem> evidenceItems;

        ProbeResult(
                SignalResult.Status status,
                String failureReason,
                Set<String> strongTokens,
                Set<String> mediumTokens,
                List<EvidenceItem> evidenceItems) {
            this.status = status;
            this.failureReason = failureReason;
            this.strongTokens = Collections.unmodifiableSet(strongTokens);
            this.mediumTokens = Collections.unmodifiableSet(mediumTokens);
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
        }

        public SignalResult.Status getStatus() {
            return status;
        }

        public boolean isUsable() {
            return status == SignalResult.Status.SUCCESS;
        }

        public String getFailureReason() {
            return failureReason;
        }

        public Set<String> getStrongTokens() {
            return strongTokens;
        }

        public Set<String> getMediumTokens() {
            return mediumTokens;
        }

        public List<EvidenceItem> getEvidenceItems() {
            return evidenceItems;
        }

        public boolean hasFindings() {
            return !strongTokens.isEmpty() || !mediumTokens.isEmpty() || !evidenceItems.isEmpty();
        }
    }

    public static final JavaWidevineReader DEFAULT_JAVA_READER = WidevineParityProbe::readAndroidJavaWidevine;
    public static final NdkWidevineReader DEFAULT_NDK_READER = NativeCollectorBridge::getWidevineNdkProbeResult;

    public static ProbeResult probe() {
        return probe(DEFAULT_JAVA_READER, DEFAULT_NDK_READER, DEFAULT_TIMEOUT_MS);
    }

    public static ProbeResult probe(
            JavaWidevineReader javaReader,
            NdkWidevineReader ndkReader,
            long timeoutMs) {
        JavaWidevineReader jReader = javaReader == null ? DEFAULT_JAVA_READER : javaReader;
        NdkWidevineReader nReader = ndkReader == null ? DEFAULT_NDK_READER : ndkReader;
        long effectiveTimeout = timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS;

        SafeExecutor.SafeResult<JavaWidevineSnapshot> javaExec =
                SafeExecutor.safeWithTimeoutOrInline(effectiveTimeout, jReader::read);
        JavaWidevineSnapshot javaSnap = javaExec.getOrNull() != null
                ? javaExec.getOrNull()
                : JavaWidevineSnapshot.unavailable(
                        javaExec.isTimedOut() ? "java_drm_timeout" : "java_drm_error");

        SafeExecutor.SafeResult<SignalResult<String>> ndkExec =
                SafeExecutor.safeWithTimeoutOrInline(effectiveTimeout, nReader::readRawFrame);
        NdkWidevineSnapshot ndkSnap;
        if (ndkExec.getOrNull() != null) {
            ndkSnap = decodeNdkFrame(ndkExec.getOrNull());
        } else {
            ndkSnap = NdkWidevineSnapshot.unavailable(
                    ndkExec.isTimedOut() ? "ndk_drm_timeout" : "ndk_drm_error");
        }

        return evaluate(javaSnap, ndkSnap);
    }

    public static NdkWidevineSnapshot decodeNdkFrame(SignalResult<String> rawFrame) {
        if (rawFrame == null || !rawFrame.isSuccess() || rawFrame.getValue() == null) {
            String reason = rawFrame == null ? "ndk_null" : rawFrame.getFailureReason();
            return NdkWidevineSnapshot.unavailable(reason == null ? "ndk_unavailable" : reason);
        }
        NativePayloadCodec.DecodedPayload decoded = NativePayloadCodec.decodePayload(rawFrame.getValue());
        if (decoded.getStatus() == NativePayloadCodec.Status.UNSUPPORTED) {
            return new NdkWidevineSnapshot(
                    false, false, null, null, decoded.getHeaderField("reason"));
        }
        if (!decoded.isOk()) {
            return NdkWidevineSnapshot.unavailable(
                    "ndk_status_" + decoded.getStatus().name().toLowerCase(Locale.ROOT));
        }
        String supported = decoded.getHeaderField("supported");
        if (!"1".equals(supported)) {
            return new NdkWidevineSnapshot(false, false, null, null, "ndk_not_supported");
        }
        String secLevel = decoded.getHeaderField("security_level");
        String sysId = decoded.getHeaderField("system_id");
        return new NdkWidevineSnapshot(true, true, secLevel, sysId, null);
    }

    public static ProbeResult evaluate(JavaWidevineSnapshot javaSnap, NdkWidevineSnapshot ndkSnap) {
        Set<String> strong = new LinkedHashSet<>();
        Set<String> medium = new LinkedHashSet<>();
        List<EvidenceItem> items = new ArrayList<>();

        boolean javaAvail = javaSnap != null && javaSnap.isAvailable() && javaSnap.isSupported();
        boolean ndkAvail = ndkSnap != null && ndkSnap.isAvailable() && ndkSnap.isSupported();

        if (!javaAvail && !ndkAvail) {
            String reason = javaSnap != null && javaSnap.getFailureReason() != null
                    ? javaSnap.getFailureReason()
                    : (ndkSnap != null && ndkSnap.getFailureReason() != null
                            ? ndkSnap.getFailureReason()
                            : "widevine_unavailable");
            return new ProbeResult(SignalResult.Status.UNAVAILABLE, reason, strong, medium, items);
        }

        String javaSec = normalizeLevel(javaAvail ? javaSnap.getSecurityLevel() : null);
        String ndkSec = normalizeLevel(ndkAvail ? ndkSnap.getSecurityLevel() : null);
        String javaSys = normalizeId(javaAvail ? javaSnap.getSystemId() : null);
        String ndkSys = normalizeId(ndkAvail ? ndkSnap.getSystemId() : null);

        // 1. Java vs NDK dual-source parity (Java MediaDrm hook detection)
        if (!javaSec.isEmpty() && !ndkSec.isEmpty() && !javaSec.equals(ndkSec)) {
            String val = "java=" + javaSec + ",ndk=" + ndkSec;
            strong.add("widevine_java_ndk_mismatch:securityLevel");
            items.add(new EvidenceItem(
                    "widevine_java_ndk_mismatch",
                    EvidenceItem.SourceLayer.JAVA,
                    "securityLevel",
                    val,
                    ConsistencyDetector.FAMILY_HW_SPOOF,
                    EvidenceItem.Rank.STRONG));
            items.add(new EvidenceItem(
                    "widevine_java_ndk_mismatch",
                    EvidenceItem.SourceLayer.NATIVE,
                    "securityLevel",
                    val,
                    ConsistencyDetector.FAMILY_HW_SPOOF,
                    EvidenceItem.Rank.STRONG));
        }

        if (!javaSys.isEmpty() && !ndkSys.isEmpty() && !javaSys.equals(ndkSys)) {
            String val = "java=" + javaSys + ",ndk=" + ndkSys;
            strong.add("widevine_java_ndk_mismatch:systemId");
            items.add(new EvidenceItem(
                    "widevine_java_ndk_mismatch",
                    EvidenceItem.SourceLayer.JAVA,
                    "systemId",
                    val,
                    ConsistencyDetector.FAMILY_HW_SPOOF,
                    EvidenceItem.Rank.STRONG));
            items.add(new EvidenceItem(
                    "widevine_java_ndk_mismatch",
                    EvidenceItem.SourceLayer.NATIVE,
                    "systemId",
                    val,
                    ConsistencyDetector.FAMILY_HW_SPOOF,
                    EvidenceItem.Rank.STRONG));
        }

        // 2. L1 sentinel systemId=2147483647 (corrupted/wiped keybox fallback)
        boolean javaL1Sentinel = "L1".equals(javaSec) && SENTINEL_SYSTEM_ID.equals(javaSys);
        boolean ndkL1Sentinel = "L1".equals(ndkSec) && SENTINEL_SYSTEM_ID.equals(ndkSys);
        if (javaL1Sentinel || ndkL1Sentinel) {
            medium.add("widevine_l1_sentinel_system_id");
            EvidenceItem.SourceLayer layer = ndkL1Sentinel && !javaL1Sentinel
                    ? EvidenceItem.SourceLayer.NATIVE
                    : EvidenceItem.SourceLayer.JAVA;
            items.add(new EvidenceItem(
                    "widevine_l1_sentinel_system_id",
                    layer,
                    "widevine.systemId",
                    "L1:systemId=" + SENTINEL_SYSTEM_ID,
                    ConsistencyDetector.FAMILY_HW_SPOOF,
                    EvidenceItem.Rank.MEDIUM));
        }

        // 3. HW_SECURE_ALL session downgrade despite advertised L1 + HW_SECURE_ALL capability
        if (javaAvail && "L1".equals(javaSec)
                && Boolean.TRUE.equals(javaSnap.getHwSecureAllSupported())
                && javaSnap.getActualSessionSecurityLevel() != null
                && isBelowHwSecureAll(javaSnap.getActualSessionSecurityLevel())) {
            medium.add("widevine_hw_secure_all_downgrade");
            items.add(new EvidenceItem(
                    "widevine_hw_secure_all_downgrade",
                    EvidenceItem.SourceLayer.JAVA,
                    "widevine.session",
                    "actual_level=" + javaSnap.getActualSessionSecurityLevel(),
                    ConsistencyDetector.FAMILY_HW_SPOOF,
                    EvidenceItem.Rank.MEDIUM));
        }

        return new ProbeResult(SignalResult.Status.SUCCESS, null, strong, medium, items);
    }

    private static boolean isBelowHwSecureAll(int sessionLevel) {
        // MediaDrm.SECURITY_LEVEL_SW_SECURE_CRYPTO (1) .. HW_SECURE_DECODE (4) < HW_SECURE_ALL (5)
        return sessionLevel >= MediaDrm.SECURITY_LEVEL_SW_SECURE_CRYPTO
                && sessionLevel < MediaDrm.SECURITY_LEVEL_HW_SECURE_ALL;
    }

    private static JavaWidevineSnapshot readAndroidJavaWidevine() {
        MediaDrm drm = null;
        byte[] sessionId = null;
        try {
            if (!MediaDrm.isCryptoSchemeSupported(WIDEVINE_UUID)) {
                return JavaWidevineSnapshot.unsupported("widevine_unsupported");
            }
            Boolean hwSecureAllSupported = null;
            try {
                hwSecureAllSupported = MediaDrm.isCryptoSchemeSupported(
                        WIDEVINE_UUID, "video/mp4", MediaDrm.SECURITY_LEVEL_HW_SECURE_ALL);
            } catch (Exception | LinkageError ignored) {
                // Keep null if query unsupported
            }

            drm = new MediaDrm(WIDEVINE_UUID);
            String secLevel = safeGetProperty(drm, "securityLevel");
            String sysId = safeGetProperty(drm, "systemId");

            Integer actualSessionLevel = null;
            if ("L1".equalsIgnoreCase(secLevel != null ? secLevel.trim() : "")) {
                try {
                    sessionId = drm.openSession();
                    if (sessionId != null) {
                        actualSessionLevel = drm.getSecurityLevel(sessionId);
                    }
                } catch (Exception | LinkageError ignored) {
                    // Resource busy / not provisioned is never a threat
                }
            }

            return new JavaWidevineSnapshot(
                    true, true, secLevel, sysId, hwSecureAllSupported, actualSessionLevel, null);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return JavaWidevineSnapshot.unavailable(e.getClass().getSimpleName());
        } finally {
            if (drm != null) {
                if (sessionId != null) {
                    try {
                        drm.closeSession(sessionId);
                    } catch (Exception | LinkageError ignored) {
                    }
                }
                try {
                    drm.close();
                } catch (Exception | LinkageError ignored) {
                }
            }
        }
    }

    private static String safeGetProperty(MediaDrm drm, String key) {
        try {
            String val = drm.getPropertyString(key);
            return val == null ? null : val.trim();
        } catch (Exception | LinkageError e) {
            return null;
        }
    }

    private static String normalizeLevel(String raw) {
        if (raw == null) {
            return "";
        }
        String trimmed = raw.trim();
        return trimmed.isEmpty() ? "" : trimmed.toUpperCase(Locale.ROOT);
    }

    private static String normalizeId(String raw) {
        if (raw == null) {
            return "";
        }
        return raw.trim();
    }
}
