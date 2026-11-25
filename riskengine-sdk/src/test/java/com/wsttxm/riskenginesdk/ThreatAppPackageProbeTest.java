package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.detector.probe.threat.ThreatAppPackageProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.ThreatAppSignatureLibrary;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class ThreatAppPackageProbeTest {

    private static final String KSU_OFFICIAL_SHA =
            "c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6";
    private static final String HMA_OSS_SHA =
            "dd5f995a223eac038b0b5147b5cfc69ae911ebcc04e2af5fb0e8a4eb68dbb9de";
    private static final String CUSTOM_CERT_SHA =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    @Test
    public void threatAppPolicyBuilderIsImmutableAndNormalizesCerts() {
        ThreatAppPolicy.Builder builder = new ThreatAppPolicy.Builder()
                .additionalPackages("com.custom.cheat", "  com.custom.cheat2  ")
                .additionalCertSha256s(
                        "AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:"
                                + "AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA")
                .addDangerousPermissionCombo(
                        "overlay_and_a11y",
                        "android.permission.SYSTEM_ALERT_WINDOW",
                        "android.permission.BIND_ACCESSIBILITY_SERVICE")
                .enableHmaProbes(false)
                .enableThanoxIpcProbe(true);

        ThreatAppPolicy first = builder.build();
        builder.additionalPackages("com.mutated.later");
        ThreatAppPolicy second = builder.build();

        assertEquals(2, first.getAdditionalPackages().size());
        assertEquals(3, second.getAdditionalPackages().size());
        assertTrue(first.getAdditionalCertSha256s().contains(CUSTOM_CERT_SHA));
        assertEquals(1, first.getDangerousPermissionCombos().size());
        assertFalse(first.isEnableHmaUidVisibilityProbe());
        assertFalse(first.isEnableHmaCrossUserProbe());
        assertFalse(first.isEnableHmaOrderedBroadcastProbe());
        assertFalse(first.isEnableHmaPermissionServiceProbe());
        assertTrue(first.isEnableThanoxIpcProbe());
        assertTrue(first.isAnyHmaProbeEnabled());
    }

    @Test(expected = IllegalArgumentException.class)
    public void threatAppPolicyRejectsMalformedSha256() {
        new ThreatAppPolicy.Builder().additionalCertSha256s("not-a-valid-sha256");
    }

    @Test
    public void riskEngineConfigWiresAdditionalThreatPackagesAndPolicy() {
        ThreatAppPolicy policy = new ThreatAppPolicy.Builder()
                .additionalPackages("com.policy.pkg")
                .enableHmaProbes(false)
                .build();

        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .additionalThreatPackages("com.extra.pkg1", "com.extra.pkg2")
                .threatAppPolicy(policy)
                .build();

        assertTrue(config.isEnableThreatAppDetection());
        assertEquals(2, config.getAdditionalThreatPackages().size());
        assertEquals(policy, config.getThreatAppPolicy());

        ThreatAppPolicy effective = config.getEffectiveThreatAppPolicy();
        assertTrue(effective.getAdditionalPackages().contains("com.policy.pkg"));
        assertTrue(effective.getAdditionalPackages().contains("com.extra.pkg1"));
        assertTrue(effective.getAdditionalPackages().contains("com.extra.pkg2"));
        assertFalse(effective.isAnyHmaProbeEnabled());
    }

    private static final String APATCH_OFFICIAL_CERT_SHA =
            "d71dadc0ca07bdf594383bfb2a445134a07339f12a27044a1b326981acf5f319";
    private static final String APATCH_WRONG_APK_FILE_SHA =
            "d6bf0dbcab95fb9a3aa111c35efd945267bcce3a41377c3297c3c1a9eab421a5";

    @Test
    public void signatureLibraryCoversAllTenRequiredOfficialToolsAndSeparatesCategories() {
        List<String> requiredIds = Arrays.asList(
                "kernelsu", "ksu_next", "sukisu", "magisk", "apatch",
                "lsposed", "hidemyapplist", "gameguardian", "luckypatcher", "shizuku");
        List<String> verifiedCertIds = Arrays.asList(
                "kernelsu", "ksu_next", "sukisu", "magisk", "apatch", "hidemyapplist");
        List<String> forbiddenSyntheticPatterns = Arrays.asList(
                "0123456789", "9876543210", "abcdef0123", "7a9b8c7d6e5f");

        Map<String, ThreatAppSignatureLibrary.ToolSignature> byId = new HashMap<>();
        for (ThreatAppSignatureLibrary.ToolSignature sig : ThreatAppSignatureLibrary.getSignatures()) {
            byId.put(sig.getToolId(), sig);
            for (String sha : sig.getOfficialCertSha256s()) {
                assertEquals("Cert must be 64-char hex for " + sig.getToolId(), 64, sha.length());
                for (String synthetic : forbiddenSyntheticPatterns) {
                    assertFalse("Synthetic placeholder hex forbidden in " + sig.getToolId(),
                            sha.contains(synthetic));
                }
            }
        }
        for (String id : requiredIds) {
            ThreatAppSignatureLibrary.ToolSignature sig = byId.get(id);
            assertNotNull("Missing required signature entry: " + id, sig);
            assertFalse("Package names required for " + id, sig.getPackageNames().isEmpty());
        }
        for (String id : verifiedCertIds) {
            ThreatAppSignatureLibrary.ToolSignature sig = byId.get(id);
            assertFalse("Verified official cert required for " + id,
                    sig.getOfficialCertSha256s().isEmpty());
        }

        // APatch must carry its real signing cert DER SHA-256, never the APK file SHA-256.
        assertTrue(byId.get("apatch").getOfficialCertSha256s().contains(APATCH_OFFICIAL_CERT_SHA));
        assertFalse(byId.get("apatch").getOfficialCertSha256s().contains(APATCH_WRONG_APK_FILE_SHA));
        assertEquals(byId.get("apatch"),
                ThreatAppSignatureLibrary.matchByCertSha256(APATCH_OFFICIAL_CERT_SHA));
        assertNull(ThreatAppSignatureLibrary.matchByCertSha256(APATCH_WRONG_APK_FILE_SHA));

        assertTrue(byId.get("kernelsu").isRootManager());
        assertTrue(byId.get("ksu_next").isRootManager());
        assertTrue(byId.get("sukisu").isRootManager());
        assertTrue(byId.get("magisk").isRootManager());
        assertTrue(byId.get("apatch").isRootManager());

        assertEquals(ThreatAppSignatureLibrary.Category.APP_HIDER,
                byId.get("hidemyapplist").getCategory());
        assertEquals(ThreatAppSignatureLibrary.Category.THREAT_TOOL,
                byId.get("lsposed").getCategory());
        assertEquals(ThreatAppSignatureLibrary.Category.THREAT_TOOL,
                byId.get("gameguardian").getCategory());
        assertEquals(ThreatAppSignatureLibrary.Category.THREAT_TOOL,
                byId.get("luckypatcher").getCategory());
        assertEquals(ThreatAppSignatureLibrary.Category.THREAT_TOOL,
                byId.get("shizuku").getCategory());
    }

    @Test
    public void multipleNativePayloadsOnSamePackageSurviveDataAggregatorMerge() {
        String apatchPkg = "me.bmax.apatch";
        ThreatAppPackageProbe.InspectedApp apatch = new ThreatAppPackageProbe.InspectedApp(
                apatchPkg,
                Collections.singletonList(APATCH_OFFICIAL_CERT_SHA),
                "/data/app/~~xyz/me.bmax.apatch/lib/arm64",
                Collections.emptyList(),
                null);

        Set<String> multiPayloads = new LinkedHashSet<>(
                Arrays.asList("libapd.so", "libkptools.so", "libkpatch.so"));
        ThreatAppPackageProbe probe = new ThreatAppPackageProbe(
                (pkg, includePerms) -> apatchPkg.equals(pkg) ? apatch : null,
                (dir, payloads) -> ThreatAppPackageProbe.PayloadScanResult.observed(multiPayloads),
                app -> "me.bmax.apatch.magica.AppZygotePreload");

        ThreatAppPackageProbe.ProbeOutcome outcome = probe.probePackages(
                Collections.singletonList(apatchPkg), ThreatAppPolicy.DEFAULT);

        assertTrue(outcome.isRootManagerDetected());
        assertTrue(outcome.getDetails().contains("threat_app_cert:apatch:" + apatchPkg));
        assertTrue(outcome.getDetails().contains("threat_app_native_payload:libapd.so:" + apatchPkg));
        assertTrue(outcome.getDetails().contains("threat_app_native_payload:libkptools.so:" + apatchPkg));
        assertTrue(outcome.getDetails().contains("threat_app_native_payload:libkpatch.so:" + apatchPkg));

        List<EvidenceItem> merged = DataAggregator.mergeEvidenceItems(outcome.getEvidenceItems());
        EvidenceItem payloadItem = null;
        EvidenceItem certItem = null;
        for (EvidenceItem item : merged) {
            if ("threat_app_native_payload".equals(item.getCode())) {
                payloadItem = item;
            } else if ("threat_app_cert".equals(item.getCode())) {
                certItem = item;
            }
        }
        assertNotNull("Official APatch cert item must match", certItem);
        assertEquals("root_fw", certItem.getEvidenceFamily());
        assertNotNull("Aggregated native payload item must survive merge", payloadItem);
        assertEquals("libapd.so,libkptools.so,libkpatch.so", payloadItem.getValue());
        assertEquals("root_fw", payloadItem.getEvidenceFamily());
    }

    @Test
    public void demoReportFormatterCoversAllPhase4AndAdbEvidenceCodes() throws IOException {
        Path formatterPath = Path.of(
                "../demo/src/main/java/com/wsttxm/riskenginesdk/demo/ui/ReportFormatter.java");
        if (!Files.exists(formatterPath)) {
            return;
        }
        String src = new String(Files.readAllBytes(formatterPath), StandardCharsets.UTF_8);
        List<String> requiredCodes = Arrays.asList(
                "threat_app_cert", "threat_app_custom_cert", "threat_app_native_payload",
                "threat_app_zygote_preload", "threat_app_package", "threat_app_custom_pkg",
                "threat_app_perm_combo", "hma_uid_visibility_hidden",
                "hma_seccomp_foreign_listener", "hma_seccomp_query_trapped",
                "hma_seccomp_suppressed", "hma_cross_user_suppression",
                "hma_ordered_broadcast_missing_result", "hma_ordered_broadcast_semantic",
                "hma_permission_service_diff", "thanox_ipc_active",
                "adb_tcp_port", "proxy_tool_cert");
        for (String code : requiredCodes) {
            assertTrue("Demo ReportFormatter missing EvidenceMeta for code: " + code,
                    src.contains("m.put(\"" + code + "\""));
        }
    }

    @Test
    public void renamedRootManagerMatchedByRotatedCertLineageNativePayloadAndZygotePreload() {
        String renamedPkg = "com.disguised.calculator";
        String rotatedNewCert = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        ThreatAppPackageProbe.InspectedApp disguisedKsu = new ThreatAppPackageProbe.InspectedApp(
                renamedPkg,
                // Active v3 rotated signer + historical official KernelSU cert in lineage
                Arrays.asList(rotatedNewCert, KSU_OFFICIAL_SHA),
                "/data/app/~~abc/com.disguised.calculator/lib/arm64",
                Collections.emptyList(),
                null);

        AtomicInteger statCalls = new AtomicInteger();
        ThreatAppPackageProbe probe = new ThreatAppPackageProbe(
                (pkg, includePerms) -> renamedPkg.equals(pkg) ? disguisedKsu : null,
                (dir, payloads) -> {
                    statCalls.incrementAndGet();
                    assertTrue(payloads.contains("libksud.so"));
                    assertTrue(payloads.contains("libapd.so"));
                    assertTrue(payloads.contains("libmagisk.so"));
                    return ThreatAppPackageProbe.PayloadScanResult.observed(
                            Collections.singleton("libksud.so"));
                },
                app -> "com.disguised.calculator.magica.AppZygotePreload");

        ThreatAppPackageProbe.ProbeOutcome outcome = probe.probePackages(
                Collections.singletonList(renamedPkg), ThreatAppPolicy.DEFAULT);

        assertTrue(outcome.hasFindings());
        assertTrue(outcome.isRootManagerDetected());
        assertFalse(outcome.isAppHiderDetected());
        assertEquals(1, statCalls.get());
        assertEquals(3, outcome.getEvidenceItems().size());
        for (EvidenceItem item : outcome.getEvidenceItems()) {
            assertEquals("root_fw", item.getEvidenceFamily());
            assertEquals(EvidenceItem.Rank.STRONG, item.getRank());
            assertEquals(renamedPkg, item.getLocation());
        }
        assertTrue(outcome.getDetails().contains("threat_app_cert:kernelsu:" + renamedPkg));
        assertTrue(outcome.getDetails().contains("threat_app_native_payload:libksud.so:" + renamedPkg));
        assertTrue(outcome.getDetails().contains("threat_app_zygote_preload:kernelsu:" + renamedPkg));
    }

    @Test
    public void appHiderAndCustomPolicyRulesProduceExpectedFamilies() {
        String hmaPkg = "org.frknkrc44.hma_oss";
        String customPkg = "com.rogue.overlay.bot";

        Map<String, ThreatAppPackageProbe.InspectedApp> installed = new HashMap<>();
        installed.put(hmaPkg, new ThreatAppPackageProbe.InspectedApp(
                hmaPkg,
                Collections.singletonList(HMA_OSS_SHA),
                null,
                Collections.emptyList(),
                null));
        installed.put(customPkg, new ThreatAppPackageProbe.InspectedApp(
                customPkg,
                Collections.singletonList(CUSTOM_CERT_SHA),
                null,
                Arrays.asList(
                        "android.permission.SYSTEM_ALERT_WINDOW",
                        "android.permission.BIND_ACCESSIBILITY_SERVICE"),
                null));

        ThreatAppPolicy policy = new ThreatAppPolicy.Builder()
                .additionalPackages(customPkg)
                .additionalCertSha256s(CUSTOM_CERT_SHA)
                .addDangerousPermissionCombo(
                        "fraud_combo",
                        "android.permission.SYSTEM_ALERT_WINDOW",
                        "android.permission.BIND_ACCESSIBILITY_SERVICE")
                .build();

        ThreatAppPackageProbe probe = new ThreatAppPackageProbe(
                (pkg, includePerms) -> installed.get(pkg),
                (dir, payloads) -> ThreatAppPackageProbe.PayloadScanResult.observed(Collections.emptySet()),
                app -> null);

        ThreatAppPackageProbe.ProbeOutcome outcome = probe.probe(policy);
        assertTrue(outcome.hasFindings());
        assertFalse(outcome.isRootManagerDetected());
        assertTrue(outcome.isAppHiderDetected());
        assertTrue(outcome.isThreatToolDetected());

        boolean sawHmaFamily = false;
        boolean sawCustomCert = false;
        boolean sawPermCombo = false;
        for (EvidenceItem item : outcome.getEvidenceItems()) {
            if ("threat_app_cert".equals(item.getCode()) && hmaPkg.equals(item.getLocation())) {
                assertEquals("hma_hiding", item.getEvidenceFamily());
                sawHmaFamily = true;
            }
            if ("threat_app_custom_cert".equals(item.getCode()) && customPkg.equals(item.getLocation())) {
                assertEquals("threat_app", item.getEvidenceFamily());
                sawCustomCert = true;
            }
            if ("threat_app_perm_combo".equals(item.getCode()) && customPkg.equals(item.getLocation())) {
                assertEquals("fraud_combo", item.getValue());
                sawPermCombo = true;
            }
        }
        assertTrue(sawHmaFamily);
        assertTrue(sawCustomCert);
        assertTrue(sawPermCombo);
    }

    @Test
    public void visibilityLossAndCleanAppsProduceZeroFalsePositives() {
        String benignPkg = "com.example.benign";
        ThreatAppPackageProbe.InspectedApp benign = new ThreatAppPackageProbe.InspectedApp(
                benignPkg,
                Collections.singletonList("1111111111111111111111111111111111111111111111111111111111111111"),
                "/data/app/benign/lib/arm64",
                Collections.singletonList("android.permission.INTERNET"),
                null);

        ThreatAppPackageProbe probe = new ThreatAppPackageProbe(
                (pkg, includePerms) -> benignPkg.equals(pkg) ? benign : null,
                (dir, payloads) -> ThreatAppPackageProbe.PayloadScanResult.failed("errno_13"),
                app -> {
                    throw new SecurityException("denied");
                });

        ThreatAppPackageProbe.ProbeOutcome outcome = probe.probePackages(
                Collections.singletonList(benignPkg), ThreatAppPolicy.DEFAULT);

        assertFalse("SELinux EACCES / SecurityException must never become a threat",
                outcome.hasFindings());
        assertEquals(1, outcome.getPayloadDirectoryFailures());
        assertNull(ThreatAppSignatureLibrary.matchByZygotePreload("com.example.AppZygotePreload"));
    }

    @Test
    public void sha256LowerHexMatchesKnownVector() {
        assertEquals(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                ThreatAppPackageProbe.sha256LowerHex("abc".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void threatAppPackagesAreSingleSourceSyncedAcrossIniGeneratedListsAndManifestQueries()
            throws IOException {
        Path ini = Path.of("src/main/resources/lists/artifact_paths.ini");
        List<String> iniPackages = parseIniSection(Files.readAllLines(ini), "threat_app_packages");
        assertFalse("artifact_paths.ini [threat_app_packages] must not be empty",
                iniPackages.isEmpty());
        assertEquals(iniPackages, Arrays.asList(DetectionLists.THREAT_APP_PACKAGES));

        String manifest = new String(
                Files.readAllBytes(Path.of("src/main/AndroidManifest.xml")),
                StandardCharsets.UTF_8);
        assertFalse("SDK AndroidManifest.xml must declare zero <uses-permission>",
                manifest.contains("<uses-permission"));

        Set<String> declaredQueries = new LinkedHashSet<>();
        Matcher matcher = Pattern.compile("<package\\s+android:name=\"([^\"]+)\"").matcher(manifest);
        while (matcher.find()) {
            declaredQueries.add(matcher.group(1));
        }

        for (String pkg : DetectionLists.THREAT_APP_PACKAGES) {
            assertTrue("Missing <queries> for threat_app pkg: " + pkg,
                    declaredQueries.contains(pkg));
        }
        for (ThreatAppSignatureLibrary.ToolSignature sig : ThreatAppSignatureLibrary.getSignatures()) {
            for (String pkg : sig.getPackageNames()) {
                assertTrue("SignatureLibrary pkg missing from [threat_app_packages]: " + pkg,
                        iniPackages.contains(pkg));
                assertTrue("SignatureLibrary pkg missing from <queries>: " + pkg,
                        declaredQueries.contains(pkg));
            }
        }
    }

    private static List<String> parseIniSection(List<String> lines, String sectionName) {
        List<String> result = new ArrayList<>();
        String current = null;
        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (line.startsWith("[") && line.endsWith("]")) {
                current = line.substring(1, line.length() - 1);
                continue;
            }
            if (sectionName.equals(current)) {
                result.add(line);
            }
        }
        return result;
    }
}
