package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.os.Build;

import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;

public class CustomRomDetector extends BaseDetector {
    public static final String EVIDENCE_FAMILY = "custom_rom";

    private final SignalSnapshot signals;
    private final Supplier<String> osBrandSupplier;

    // Stock OEM Android distributions are intentionally excluded.
    private static final String[][] COMMUNITY_ROM_PROPS = {
            {"ro.lineage.version", "LineageOS"},
            {"ro.cm.version", "CyanogenMod"},
            {"ro.mokee.version", "MoKee"},
            {"ro.rr.version", "ResurrectionRemix"},
            {"ro.pixelexperience.version", "PixelExperience"},
            {"ro.modversion", "ModVersion"}
    };

    public CustomRomDetector(Context context) {
        this(context, new SignalSnapshot(context), CustomRomDetector::queryHarmonyOsBrand);
    }

    public CustomRomDetector(Context context, SignalSnapshot signals) {
        this(context, signals, CustomRomDetector::queryHarmonyOsBrand);
    }

    public CustomRomDetector(Context context,
                             SignalSnapshot signals,
                             Supplier<String> osBrandSupplier) {
        super(context);
        this.signals = signals;
        this.osBrandSupplier = osBrandSupplier != null
                ? osBrandSupplier
                : CustomRomDetector::queryHarmonyOsBrand;
    }

    @Override
    public String getName() {
        return "custom_rom";
    }

    @Override
    protected DetectionResult detect() {
        List<String> evidence = new ArrayList<>();
        List<EvidenceItem> evidenceItems = new ArrayList<>();
        SignalResult<String> fingerprint = signals.getSystemProperty("ro.build.fingerprint");
        if (!fingerprint.isSuccess() || valueOf(fingerprint).isEmpty()) {
            return unavailable("system_properties_unavailable");
        }
        String fpValue = valueOf(fingerprint);
        boolean authenticPixel = isAuthenticGooglePixel(fpValue);
        boolean harmonyOs = isHarmonyOs();

        CheckCoverage coverage = new CheckCoverage();
        coverage.success();
        for (String[] romProperty : COMMUNITY_ROM_PROPS) {
            SignalResult<String> property = signals.getSystemProperty(romProperty[0]);
            if (!property.isSuccess()) {
                coverage.failure(romProperty[0] + ":" + property.getFailureReason());
                continue;
            }
            coverage.success();
            String value = valueOf(property);
            if (!value.isEmpty()) {
                // Suppress PixelExperience false positives on authentic google/Pixel* devices.
                if (authenticPixel && "ro.pixelexperience.version".equals(romProperty[0])) {
                    continue;
                }
                evidence.add("community_rom:" + romProperty[1] + "=" + value);
                evidenceItems.add(new EvidenceItem(
                        "community_rom",
                        EvidenceItem.SourceLayer.JAVA,
                        romProperty[0],
                        romProperty[1] + "=" + value,
                        EVIDENCE_FAMILY,
                        EvidenceItem.Rank.WEAK));
            }
        }

        if (!harmonyOs) {
            SignalResult<String> fileFingerprint = signals.getBuildPropFingerprint();
            if (fileFingerprint.isSuccess() && fileFingerprint.getValue() != null
                    && !fileFingerprint.getValue().isEmpty()
                    && !fileFingerprint.getValue().equals(fpValue)) {
                evidence.add("prop_mismatch:fingerprint");
                evidenceItems.add(new EvidenceItem(
                        "prop_mismatch",
                        EvidenceItem.SourceLayer.NATIVE,
                        "build.prop:ro.build.fingerprint",
                        "mismatch",
                        EVIDENCE_FAMILY,
                        EvidenceItem.Rank.WEAK));
            }
        }

        checkNativeCustomRomProbe(harmonyOs, evidence, evidenceItems, coverage);

        if (!evidence.isEmpty()) {
            // A community ROM is context, not proof of compromise/root; stays LOW/1 informational
            // in standard scenes (elevated only in DIAGNOSTIC via CorrelationEngine).
            return result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, true,
                    evidence, String.join("; ", evidence), coverage)
                    .withEvidenceItems(evidenceItems);
        }
        return safe(coverage);
    }

    private void checkNativeCustomRomProbe(boolean harmonyOs,
                                           List<String> evidence,
                                           List<EvidenceItem> items,
                                           CheckCoverage coverage) {
        SignalResult<String> raw = signals.getCustomRomProbe();
        if (raw == null || !raw.isSuccess() || raw.getValue() == null || raw.getValue().isEmpty()) {
            return;
        }
        NativePayloadCodec.DecodedPayload decoded = NativePayloadCodec.decodePayload(raw.getValue());
        if (!decoded.isOk()) {
            return;
        }
        coverage.success();

        for (Map<String, String> rec : decoded.getRecords()) {
            String kind = rec.get("kind");
            if ("stagefright_symbol".equals(kind)) {
                String path = rec.getOrDefault("path", "libstagefright.so");
                String source = rec.getOrDefault("source", "disk");
                evidence.add("stagefright_custom_symbol:" + path);
                items.add(new EvidenceItem(
                        "stagefright_custom_symbol",
                        EvidenceItem.SourceLayer.NATIVE,
                        path,
                        "source=" + source,
                        EVIDENCE_FAMILY,
                        EvidenceItem.Rank.WEAK));
            } else if ("framework_res_multi_dev".equals(kind) && !harmonyOs) {
                int devCount = parseIntSafe(rec.get("dev_count"));
                if (devCount > 1) {
                    String devs = rec.getOrDefault("devs", "");
                    evidence.add("framework_res_multi_dev:" + devCount);
                    items.add(new EvidenceItem(
                            "framework_res_multi_dev",
                            EvidenceItem.SourceLayer.NATIVE,
                            "framework-res.apk",
                            devs.isEmpty() ? ("devs=" + devCount) : ("count=" + devCount + ",devs=" + devs),
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.WEAK));
                }
            }
        }
    }

    boolean isAuthenticGooglePixel(String fingerprint) {
        String brand = readPropOrBuild("ro.product.brand", Build.BRAND);
        if (brand.isEmpty() && fingerprint != null) {
            int slash = fingerprint.indexOf('/');
            if (slash > 0) {
                brand = fingerprint.substring(0, slash);
            }
        }
        String model = readPropOrBuild("ro.product.model", Build.MODEL);
        return "google".equalsIgnoreCase(brand.trim())
                && model.trim().toLowerCase(Locale.ROOT).startsWith("pixel");
    }

    boolean isHarmonyOs() {
        try {
            String brand = osBrandSupplier.get();
            return brand != null && "harmony".equalsIgnoreCase(brand.trim());
        } catch (Exception | LinkageError e) {
            return false;
        }
    }

    /**
     * Safely queries {@code com.huawei.system.BuildEx.getOsBrand()} via guarded reflection
     * (zero uncaught exceptions on non-Huawei/HarmonyOS devices).
     */
    public static String queryHarmonyOsBrand() {
        try {
            Class<?> buildEx = Class.forName("com.huawei.system.BuildEx");
            Method getOsBrand = buildEx.getMethod("getOsBrand");
            Object result = getOsBrand.invoke(null);
            return result instanceof String ? ((String) result).trim() : "";
        } catch (Exception | LinkageError e) {
            return "";
        }
    }

    private String readPropOrBuild(String propName, String buildFallback) {
        SignalResult<String> prop = signals.getSystemProperty(propName);
        if (prop != null && prop.isSuccess() && prop.getValue() != null && !prop.getValue().isBlank()) {
            return prop.getValue().trim();
        }
        return buildFallback == null ? "" : buildFallback.trim();
    }

    private static int parseIntSafe(String raw) {
        if (raw == null || raw.isBlank()) return 0;
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static String valueOf(SignalResult<String> result) {
        return result.getValue() == null ? "" : result.getValue().trim();
    }
}
