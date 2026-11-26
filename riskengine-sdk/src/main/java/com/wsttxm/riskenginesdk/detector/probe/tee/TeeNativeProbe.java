package com.wsttxm.riskenginesdk.detector.probe.tee;

import com.wsttxm.riskenginesdk.attestation.DerReader;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Java consumer for the native 5-vector TrickyStore / Binder interceptor probe
 * ({@code tee_binder_probe.cpp}) and cross-layer Leaf DER structural validation.
 *
 * <p>All findings are emitted under the {@value #FAMILY_TEE_TAMPER} evidence family.
 * Confirmed {@code libbinder.so} GOT hook, 16-byte {@code ioctl} inline hook, or
 * 3-way {@code BINDER_VERSION} backend divergence emits {@code tee_binder_ioctl_hook}
 * ({@link EvidenceItem.Rank#STRONG}).</p>
 */
public final class TeeNativeProbe {

    public static final String FAMILY_TEE_TAMPER = "tee_tamper";

    /** Injectable adapter for deterministic JVM unit testing. */
    public interface NativeTeeAdapter {
        SignalResult<String> getTeeBinderProbe(boolean includeHoneypotTiming);
        SignalResult<String> inspectLeafDer(byte[] leafDer);
    }

    public static final class ProbeResult {
        private final boolean usable;
        private final String failureReason;
        private final Set<String> strongTokens;
        private final Set<String> mediumTokens;
        private final List<EvidenceItem> evidenceItems;

        ProbeResult(
                boolean usable,
                String failureReason,
                Set<String> strongTokens,
                Set<String> mediumTokens,
                List<EvidenceItem> evidenceItems) {
            this.usable = usable;
            this.failureReason = failureReason;
            this.strongTokens = Collections.unmodifiableSet(strongTokens);
            this.mediumTokens = Collections.unmodifiableSet(mediumTokens);
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
        }

        public boolean isUsable() {
            return usable;
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

    private TeeNativeProbe() {
    }

    public static ProbeResult run(
            SignalSnapshot signals, byte[] leafCertDer, boolean includeHoneypotTiming) {
        NativeTeeAdapter adapter = new NativeTeeAdapter() {
            @Override
            public SignalResult<String> getTeeBinderProbe(boolean includeTiming) {
                return signals != null
                        ? signals.getTeeBinderProbe(includeTiming)
                        : NativeCollectorBridge.getTeeBinderProbeResult(includeTiming);
            }

            @Override
            public SignalResult<String> inspectLeafDer(byte[] der) {
                return NativeCollectorBridge.inspectLeafDerResult(der);
            }
        };
        return run(adapter, leafCertDer, includeHoneypotTiming);
    }

    public static ProbeResult run(
            NativeTeeAdapter adapter, byte[] leafCertDer, boolean includeHoneypotTiming) {
        Set<String> strong = new LinkedHashSet<>();
        Set<String> medium = new LinkedHashSet<>();
        List<EvidenceItem> items = new ArrayList<>();

        boolean anyUsable = false;
        String lastFailure = null;

        // 1. Parse native 5-vector TrickyStore / Binder probe
        if (adapter != null) {
            SignalResult<String> binderRaw;
            try {
                binderRaw = adapter.getTeeBinderProbe(includeHoneypotTiming);
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                binderRaw = SignalResult.error(e.getClass().getSimpleName());
            }

            if (binderRaw != null && binderRaw.isSuccess()
                    && binderRaw.getValue() != null && !binderRaw.getValue().isEmpty()) {
                NativePayloadCodec.DecodedPayload decoded =
                        NativePayloadCodec.decodePayload(binderRaw.getValue());
                if (decoded.isOk()) {
                    anyUsable = true;
                    parseBinderRecords(decoded.getRecords(), strong, medium, items);
                } else {
                    lastFailure = "tee_binder_" + decoded.getStatus().name().toLowerCase(java.util.Locale.ROOT);
                }
            } else if (binderRaw != null) {
                lastFailure = binderRaw.getFailureReason();
            }
        }

        // 2. Cross-layer Leaf DER validation (Java DerReader + Native native_inspect_leaf_der)
        if (leafCertDer != null && leafCertDer.length > 0) {
            anyUsable = true;
            DerReader.LeafDerInspection javaInsp = DerReader.inspectLeafDer(leafCertDer);

            Boolean nativeHex32 = null;
            Boolean nativeNonMin = null;
            Boolean nativeStructInvalid = null;

            if (adapter != null) {
                try {
                    SignalResult<String> nativeDerRaw = adapter.inspectLeafDer(leafCertDer);
                    if (nativeDerRaw != null && nativeDerRaw.isSuccess()
                            && nativeDerRaw.getValue() != null) {
                        NativePayloadCodec.DecodedPayload decoded =
                                NativePayloadCodec.decodePayload(nativeDerRaw.getValue());
                        if (decoded.isOk()) {
                            nativeHex32 = "1".equals(decoded.getHeaderField("hex_template_32"));
                            nativeNonMin = "1".equals(decoded.getHeaderField("non_minimal_length"));
                            nativeStructInvalid = "1".equals(decoded.getHeaderField("structure_invalid"));
                        }
                    }
                } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                    // Java inspection still stands; unavailability is not a threat
                }
            }

            boolean hex32Hit = javaInsp.isHexTemplate32Detected() || Boolean.TRUE.equals(nativeHex32);
            if (hex32Hit) {
                strong.add("tee_leaf_der_hex_template");
                if (javaInsp.isHexTemplate32Detected()) {
                    items.add(new EvidenceItem(
                            "tee_leaf_der_hex_template",
                            EvidenceItem.SourceLayer.JAVA,
                            "leaf_cert.der",
                            "HEX_TEMPLATE_32",
                            FAMILY_TEE_TAMPER,
                            EvidenceItem.Rank.STRONG));
                }
                if (Boolean.TRUE.equals(nativeHex32)) {
                    items.add(new EvidenceItem(
                            "tee_leaf_der_hex_template",
                            EvidenceItem.SourceLayer.NATIVE,
                            "leaf_cert.der",
                            "HEX_TEMPLATE_32",
                            FAMILY_TEE_TAMPER,
                            EvidenceItem.Rank.STRONG));
                }
            }

            boolean nonMinHit = javaInsp.isNonMinimalLengthDetected() || Boolean.TRUE.equals(nativeNonMin);
            if (nonMinHit) {
                medium.add("tee_leaf_der_non_minimal_ber");
                if (javaInsp.isNonMinimalLengthDetected()) {
                    items.add(new EvidenceItem(
                            "tee_leaf_der_non_minimal_ber",
                            EvidenceItem.SourceLayer.JAVA,
                            "leaf_cert.der",
                            "NON_MINIMAL_LENGTH",
                            FAMILY_TEE_TAMPER,
                            EvidenceItem.Rank.MEDIUM));
                }
                if (Boolean.TRUE.equals(nativeNonMin)) {
                    items.add(new EvidenceItem(
                            "tee_leaf_der_non_minimal_ber",
                            EvidenceItem.SourceLayer.NATIVE,
                            "leaf_cert.der",
                            "NON_MINIMAL_LENGTH",
                            FAMILY_TEE_TAMPER,
                            EvidenceItem.Rank.MEDIUM));
                }
            }

            // Cross-layer parity mismatch (e.g., Java DerReader or native bridge hooked)
            if (nativeHex32 != null && nativeNonMin != null && nativeStructInvalid != null) {
                boolean parityConflict = (javaInsp.isHexTemplate32Detected() != nativeHex32)
                        || (javaInsp.isNonMinimalLengthDetected() != nativeNonMin)
                        || (javaInsp.isStructureInvalid() != nativeStructInvalid);
                if (parityConflict) {
                    strong.add("tee_leaf_der_parity_mismatch");
                    items.add(new EvidenceItem(
                            "tee_leaf_der_parity_mismatch",
                            EvidenceItem.SourceLayer.NATIVE,
                            "leaf_cert.der",
                            "java_vs_native_der_divergence",
                            FAMILY_TEE_TAMPER,
                            EvidenceItem.Rank.STRONG));
                }
            }
        }

        return new ProbeResult(anyUsable, anyUsable ? null : lastFailure, strong, medium, items);
    }

    private static void parseBinderRecords(
            List<Map<String, String>> records,
            Set<String> strong,
            Set<String> medium,
            List<EvidenceItem> items) {
        if (records == null) {
            return;
        }
        for (Map<String, String> rec : records) {
            String kind = rec.get("kind");
            if (kind == null || kind.isEmpty()) {
                continue;
            }
            switch (kind) {
                case "maps_artifact": {
                    String token = rec.getOrDefault("token", "unknown");
                    String path = rec.getOrDefault("path", "/proc/self/maps");
                    strong.add("tee_tricky_maps:" + token);
                    items.add(new EvidenceItem(
                            "tee_tricky_maps",
                            EvidenceItem.SourceLayer.NATIVE,
                            path,
                            token,
                            FAMILY_TEE_TAMPER,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "got_ioctl_hook": {
                    String hookLib = rec.getOrDefault("hook_lib", "unknown");
                    String val = "got=" + rec.getOrDefault("got", "")
                            + ",real=" + rec.getOrDefault("real", "")
                            + ",lib=" + hookLib;
                    strong.add("tee_binder_ioctl_hook");
                    items.add(new EvidenceItem(
                            "tee_binder_ioctl_hook",
                            EvidenceItem.SourceLayer.NATIVE,
                            "libbinder.so:got:ioctl",
                            val,
                            FAMILY_TEE_TAMPER,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "inline_ioctl_hook": {
                    String reason = rec.getOrDefault("reason", "inline_mismatch");
                    String lib = rec.getOrDefault("lib", rec.getOrDefault("hook_lib", "libc.so"));
                    strong.add("tee_binder_ioctl_hook");
                    items.add(new EvidenceItem(
                            "tee_binder_ioctl_hook",
                            EvidenceItem.SourceLayer.NATIVE,
                            "ioctl:inline",
                            reason + ":" + lib,
                            FAMILY_TEE_TAMPER,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "binder_version_mismatch": {
                    String detail = rec.getOrDefault("detail", "3way_divergence");
                    strong.add("tee_binder_ioctl_hook");
                    items.add(new EvidenceItem(
                            "tee_binder_ioctl_hook",
                            EvidenceItem.SourceLayer.NATIVE,
                            "/dev/binder:BINDER_VERSION",
                            detail,
                            FAMILY_TEE_TAMPER,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "honeypot_timing_anomaly": {
                    String val = "hits=" + rec.getOrDefault("hits", "?")
                            + ",gap_ns=" + rec.getOrDefault("median_gap_ns", "0")
                            + ",floor_ns=" + rec.getOrDefault("noise_floor_ns", "0")
                            + ",ratio_pct=" + rec.getOrDefault("ratio_pct", "0");
                    medium.add("tee_binder_honeypot_timing");
                    items.add(new EvidenceItem(
                            "tee_binder_honeypot_timing",
                            EvidenceItem.SourceLayer.NATIVE,
                            "/dev/binder:keystore2_honeypot",
                            val,
                            FAMILY_TEE_TAMPER,
                            EvidenceItem.Rank.MEDIUM));
                    break;
                }
                default:
                    break;
            }
        }
    }
}
