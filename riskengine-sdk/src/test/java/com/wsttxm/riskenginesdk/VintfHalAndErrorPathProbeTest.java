package com.wsttxm.riskenginesdk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.wsttxm.riskenginesdk.attestation.AttestationRecord;
import com.wsttxm.riskenginesdk.detector.probe.tee.KeyMintQuirks;
import com.wsttxm.riskenginesdk.detector.probe.tee.VintfHalAndErrorPathProbe;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit tests for {@link KeyMintQuirks} and {@link VintfHalAndErrorPathProbe}:
 * (1) Samsung &amp; Xiaomi/Redmi/POCO MediaTek {@code updateAadOperation} exemptions,
 * (2) KeyMint VTS {@code get_vendor_api_level()} resolution,
 * (3) VINTF KeyMint AIDL / Keymaster HIDL manifest parsing &amp; strict/relaxed version parity,
 * (4) {@code OperationErrorPath} ({@code >0x8000} oversized input &amp; post-abort invalidation),
 * (5) Unreadable/unavailable degradation with zero false positives and guaranteed alias cleanup.
 */
public class VintfHalAndErrorPathProbeTest {

    @Test
    public void keyMintQuirks_samsungAndXiaomiMtkExempted_othersFlagged() {
        // Samsung on Qualcomm or Exynos -> exempted
        assertTrue(KeyMintQuirks.isUpdateAadAcceptanceExpected(
                new KeyMintQuirks.VendorIdentity("samsung", "samsung", "qcom", "kalama")));
        assertTrue(KeyMintQuirks.isUpdateAadAcceptanceExpected(
                new KeyMintQuirks.VendorIdentity("Samsung", "galaxy", "s5e9945", "")));

        // Xiaomi / Redmi / POCO on MediaTek -> exempted
        assertTrue(KeyMintQuirks.isUpdateAadAcceptanceExpected(
                new KeyMintQuirks.VendorIdentity("Xiaomi", "Redmi", "mt6897", "mt6897")));
        assertTrue(KeyMintQuirks.isUpdateAadAcceptanceExpected(
                new KeyMintQuirks.VendorIdentity("Xiaomi", "POCO", "qcom", "MT6989")));

        // Xiaomi on Qualcomm -> NOT exempted
        assertFalse(KeyMintQuirks.isUpdateAadAcceptanceExpected(
                new KeyMintQuirks.VendorIdentity("Xiaomi", "Xiaomi", "qcom", "pineapple")));

        // Pixel / OPPO / vivo on Tensor or MediaTek -> NOT exempted
        assertFalse(KeyMintQuirks.isUpdateAadAcceptanceExpected(
                new KeyMintQuirks.VendorIdentity("Google", "google", "gs201", "gs201")));
        assertFalse(KeyMintQuirks.isUpdateAadAcceptanceExpected(
                new KeyMintQuirks.VendorIdentity("OPPO", "OPPO", "mt6989", "mt6989")));
        assertFalse(KeyMintQuirks.isUpdateAadAcceptanceExpected(null));
    }

    @Test
    public void keyMintQuirks_vendorApiLevelMirrorsAospVtsPrecedence() {
        Map<String, String> props = new HashMap<>();
        props.put("ro.vendor.api_level", "202504");
        props.put("ro.board.api_level", "33");
        props.put("ro.product.first_api_level", "34");
        assertEquals(
                Integer.valueOf(202504),
                KeyMintQuirks.resolveVendorApiLevel(props::get).getLevel());

        props.remove("ro.vendor.api_level");
        // min(product=34, board=33) == 33
        assertEquals(
                Integer.valueOf(33),
                KeyMintQuirks.resolveVendorApiLevel(props::get).getLevel());

        props.remove("ro.board.api_level");
        // board absent -> productApi=34
        assertEquals(
                Integer.valueOf(34),
                KeyMintQuirks.resolveVendorApiLevel(props::get).getLevel());

        props.clear();
        assertFalse(KeyMintQuirks.resolveVendorApiLevel(props::get).isAvailable());
    }

    @Test
    public void vintfKeyMintAidl_strictVsRelaxedVendorApiAndVersionlessDefault() {
        final String vintfV3Xml =
                "<manifest version=\"1.0\" type=\"device\">\n"
                + "  <hal format=\"aidl\">\n"
                + "    <name>android.hardware.security.keymint</name>\n"
                + "    <version>3</version>\n"
                + "    <fqname>IKeyMintDevice/default</fqname>\n"
                + "  </hal>\n"
                + "</manifest>";

        VintfHalAndErrorPathProbe.VintfManifestSource src = () -> Collections.singletonList(
                VintfHalAndErrorPathProbe.ManifestEntry.readable(
                        "/vendor/etc/vintf/manifest/android.hardware.security.keymint.xml",
                        vintfV3Xml));

        AttestationRecord rec200 = AttestationRecord.builder()
                .valid(true)
                .attestationVersion(200)
                .keymasterVersion(200)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .build();

        // On vendor API 202504 (<= 36): KeyMint 200 <= declared 300 is permitted by VTS
        VintfHalAndErrorPathProbe.VintfVersionResult relaxedOk =
                VintfHalAndErrorPathProbe.inspectVintfHalVersion(
                        rec200, src, k -> "ro.vendor.api_level".equals(k) ? "202504" : null);
        assertEquals(VintfHalAndErrorPathProbe.VintfAnomalyKind.NONE, relaxedOk.getAnomalyKind());

        // On vendor API 202604 (> 202504): lagging 200 vs declared 300 is a hard MISMATCH
        VintfHalAndErrorPathProbe.VintfVersionResult strictFail =
                VintfHalAndErrorPathProbe.inspectVintfHalVersion(
                        rec200, src, k -> "ro.vendor.api_level".equals(k) ? "202604" : null);
        assertEquals(
                VintfHalAndErrorPathProbe.VintfAnomalyKind.MISMATCH,
                strictFail.getAnomalyKind());

        // Versionless AIDL <hal> defaults to version 1 (100/100)
        final String versionlessXml =
                "<manifest version=\"1.0\" type=\"device\">"
                + "<hal format=\"aidl\">"
                + "<name>android.hardware.security.keymint</name>"
                + "<interface><name>IKeyMintDevice</name><instance>default</instance></interface>"
                + "</hal></manifest>";
        AttestationRecord rec100 = AttestationRecord.builder()
                .valid(true)
                .attestationVersion(100)
                .keymasterVersion(100)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .build();
        VintfHalAndErrorPathProbe.VintfVersionResult v1Ok =
                VintfHalAndErrorPathProbe.inspectVintfHalVersion(
                        rec100,
                        () -> Collections.singletonList(
                                VintfHalAndErrorPathProbe.ManifestEntry.readable(
                                        "/vendor/etc/vintf/manifest/keymint.xml", versionlessXml)),
                        k -> "33");
        assertEquals(VintfHalAndErrorPathProbe.VintfAnomalyKind.NONE, v1Ok.getAnomalyKind());

        // Split km=300 / att=200 on VINTF v3: allowed on vendor API <= 202504, rejected on > 202504
        AttestationRecord split300And200 = AttestationRecord.builder()
                .valid(true)
                .keymasterVersion(300)
                .attestationVersion(200)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .build();
        assertEquals(
                VintfHalAndErrorPathProbe.VintfAnomalyKind.NONE,
                VintfHalAndErrorPathProbe.inspectVintfHalVersion(
                        split300And200, src, k -> "202504").getAnomalyKind());
        assertEquals(
                VintfHalAndErrorPathProbe.VintfAnomalyKind.MISMATCH,
                VintfHalAndErrorPathProbe.inspectVintfHalVersion(
                        split300And200, src, k -> "202604").getAnomalyKind());

        // SOFTWARE fallback attestation (km=400, att=400, tier=SOFTWARE) must NOT compare against /vendor VINTF v3
        AttestationRecord software400 = AttestationRecord.builder()
                .valid(true)
                .keymasterVersion(400)
                .attestationVersion(400)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.SOFTWARE)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.SOFTWARE)
                .build();
        assertEquals(
                VintfHalAndErrorPathProbe.VintfAnomalyKind.NO_ATTESTED_VERSION,
                VintfHalAndErrorPathProbe.inspectVintfHalVersion(
                        software400, src, k -> "202504").getAnomalyKind());
    }

    @Test
    public void vintfKeymasterHidl_preservesFqnameInstanceBindingAndDetectsTierOrFamilyMismatch() {
        // default is 4.0 (km=4, att=3); strongbox is 4.1 (km=41, att=4).
        // Must NOT synthesize default@4.1!
        final String hidlXml =
                "<manifest version=\"1.0\" type=\"device\">\n"
                + "  <hal format=\"hidl\">\n"
                + "    <name>android.hardware.keymaster</name>\n"
                + "    <fqname>@4.0::IKeymasterDevice/default</fqname>\n"
                + "    <fqname>@4.1::IKeymasterDevice/strongbox</fqname>\n"
                + "  </hal>\n"
                + "</manifest>";

        VintfHalAndErrorPathProbe.VintfManifestSource src = () -> Arrays.asList(
                // Unrelated broken vendor XML fragment must NOT poison Keymaster result
                VintfHalAndErrorPathProbe.ManifestEntry.readable(
                        "/vendor/etc/vintf/manifest/audio_broken.xml", "<<not_xml"),
                VintfHalAndErrorPathProbe.ManifestEntry.readable(
                        "/vendor/etc/vintf/manifest/keymaster.xml", hidlXml));

        AttestationRecord tee40 = AttestationRecord.builder()
                .valid(true)
                .keymasterVersion(4)
                .attestationVersion(3)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .build();
        assertEquals(
                VintfHalAndErrorPathProbe.VintfAnomalyKind.NONE,
                VintfHalAndErrorPathProbe.inspectVintfHalVersion(tee40, src, k -> null)
                        .getAnomalyKind());

        // Claiming 41/4 on TRUSTED_ENVIRONMENT (default) when only strongbox is 4.1 -> MISMATCH
        AttestationRecord spoofedTee41 = AttestationRecord.builder()
                .valid(true)
                .keymasterVersion(41)
                .attestationVersion(4)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .build();
        assertEquals(
                VintfHalAndErrorPathProbe.VintfAnomalyKind.MISMATCH,
                VintfHalAndErrorPathProbe.inspectVintfHalVersion(spoofedTee41, src, k -> null)
                        .getAnomalyKind());

        // Tier mismatch (attestation=STRONGBOX vs keymaster=TRUSTED_ENVIRONMENT) -> MISMATCH
        AttestationRecord tierSplit = AttestationRecord.builder()
                .valid(true)
                .keymasterVersion(100)
                .attestationVersion(100)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.STRONGBOX)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .build();
        assertEquals(
                VintfHalAndErrorPathProbe.VintfAnomalyKind.MISMATCH,
                VintfHalAndErrorPathProbe.inspectVintfHalVersion(tierSplit, src, k -> "34")
                        .getAnomalyKind());
    }

    @Test
    public void operationErrorPathAndProbeRun_detectsViolationsHonorsQuirksAndCleansUp() {
        final String vintfXml =
                "<manifest version=\"1.0\" type=\"device\">"
                + "<hal format=\"aidl\"><name>android.hardware.security.keymint</name>"
                + "<version>2</version><fqname>IKeyMintDevice/default</fqname></hal></manifest>";
        final VintfHalAndErrorPathProbe.VintfManifestSource vintfSrc = () -> Collections.singletonList(
                VintfHalAndErrorPathProbe.ManifestEntry.readable(
                        "/vendor/etc/vintf/manifest/keymint.xml", vintfXml));

        AttestationRecord cleanRec = AttestationRecord.builder()
                .valid(true)
                .keymasterVersion(200)
                .attestationVersion(200)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .build();

        // 1. Samsung accepting updateAad while enforcing >0x8000 & post-abort -> 0 findings (0 FP)
        final List<String> samsungCleaned = new ArrayList<>();
        VintfHalAndErrorPathProbe.ProbeResult samsungClean = VintfHalAndErrorPathProbe.run(
                cleanRec,
                vintfSrc,
                k -> "34",
                new VintfHalAndErrorPathProbe.OperationErrorPathAdapter() {
                    @Override
                    public int getSdkInt() {
                        return 34;
                    }

                    @Override
                    public KeyMintQuirks.VendorIdentity getVendorIdentity() {
                        return new KeyMintQuirks.VendorIdentity("samsung", "samsung", "qcom", "kalama");
                    }

                    @Override
                    public VintfHalAndErrorPathProbe.OperationErrorPathResult executeErrorPathProbe(
                            String alias) {
                        return new VintfHalAndErrorPathProbe.OperationErrorPathResult(
                                true, false, false, true, true, false, "ok");
                    }

                    @Override
                    public void deleteAlias(String alias) {
                        samsungCleaned.add(alias);
                    }
                });
        assertTrue(samsungClean.isUsable());
        assertFalse(samsungClean.hasFindings());
        assertEquals(1, samsungCleaned.size());

        // 1b. Stock Google Pixel 6 (oriole/gs101 Trusty KeyMint v2) accepting updateAad while
        // enforcing >0x8000 & post-abort -> 0 actionable findings (0 FP)
        VintfHalAndErrorPathProbe.ProbeResult pixelClean = VintfHalAndErrorPathProbe.run(
                cleanRec,
                vintfSrc,
                k -> "33",
                new VintfHalAndErrorPathProbe.OperationErrorPathAdapter() {
                    @Override
                    public int getSdkInt() {
                        return 33;
                    }

                    @Override
                    public KeyMintQuirks.VendorIdentity getVendorIdentity() {
                        return new KeyMintQuirks.VendorIdentity("Google", "google", "oriole", "gs101");
                    }

                    @Override
                    public VintfHalAndErrorPathProbe.OperationErrorPathResult executeErrorPathProbe(
                            String alias) {
                        return new VintfHalAndErrorPathProbe.OperationErrorPathResult(
                                true, false, false, true, true, false, "pixel6_trusty_ok");
                    }

                    @Override
                    public void deleteAlias(String alias) {
                    }
                });
        assertTrue(pixelClean.isUsable());
        assertFalse(pixelClean.hasFindings());
        assertTrue(pixelClean.getErrorPathResult().isUpdateAadUnexpectedlyAccepted());

        // 2. Tampered Pixel accepting >0x8000 + post-abort + VINTF mismatch -> STRONG findings
        AttestationRecord mismatchedRec = AttestationRecord.builder()
                .valid(true)
                .keymasterVersion(300)
                .attestationVersion(300)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .build();
        final List<String> tamperedCleaned = new ArrayList<>();
        VintfHalAndErrorPathProbe.ProbeResult tampered = VintfHalAndErrorPathProbe.run(
                mismatchedRec,
                vintfSrc,
                k -> "34",
                new VintfHalAndErrorPathProbe.OperationErrorPathAdapter() {
                    @Override
                    public int getSdkInt() {
                        return 34;
                    }

                    @Override
                    public KeyMintQuirks.VendorIdentity getVendorIdentity() {
                        return new KeyMintQuirks.VendorIdentity("Google", "google", "husky", "zuma");
                    }

                    @Override
                    public VintfHalAndErrorPathProbe.OperationErrorPathResult executeErrorPathProbe(
                            String alias) {
                        return new VintfHalAndErrorPathProbe.OperationErrorPathResult(
                                true, false, false, false, false, true, "diverged");
                    }

                    @Override
                    public void deleteAlias(String alias) {
                        tamperedCleaned.add(alias);
                    }
                });
        assertTrue(tampered.isUsable());
        assertTrue(tampered.hasFindings());
        assertTrue(tampered.getStrongTokens().contains(
                VintfHalAndErrorPathProbe.CODE_VINTF_HAL_MISMATCH));
        assertTrue(tampered.getStrongTokens().contains(
                VintfHalAndErrorPathProbe.CODE_ERROR_PATH_DIVERGED));
        assertFalse(tampered.getMediumTokens().contains(
                VintfHalAndErrorPathProbe.CODE_UPDATE_AAD_ACCEPTED));
        assertTrue(tampered.getErrorPathResult().isUpdateAadUnexpectedlyAccepted());
        for (EvidenceItem item : tampered.getEvidenceItems()) {
            assertEquals("tee_tamper", item.getEvidenceFamily());
        }
        assertEquals(1, tamperedCleaned.size());

        // 3. Unreadable VINTF + hidden-API exception -> usable=false, 0 FP, alias still cleaned
        final List<String> errCleaned = new ArrayList<>();
        VintfHalAndErrorPathProbe.ProbeResult unreadable = VintfHalAndErrorPathProbe.run(
                cleanRec,
                () -> Collections.singletonList(
                        VintfHalAndErrorPathProbe.ManifestEntry.unreadable(
                                "/vendor/etc/vintf/manifest/keymint.xml", "EACCES")),
                k -> null,
                new VintfHalAndErrorPathProbe.OperationErrorPathAdapter() {
                    @Override
                    public int getSdkInt() {
                        return 34;
                    }

                    @Override
                    public KeyMintQuirks.VendorIdentity getVendorIdentity() {
                        return new KeyMintQuirks.VendorIdentity("Google", "google", "husky", "zuma");
                    }

                    @Override
                    public VintfHalAndErrorPathProbe.OperationErrorPathResult executeErrorPathProbe(
                            String alias) {
                        throw new SecurityException("binder_blocked");
                    }

                    @Override
                    public void deleteAlias(String alias) {
                        errCleaned.add(alias);
                    }
                });
        assertFalse(unreadable.isUsable());
        assertFalse(unreadable.hasFindings());
        assertNotNull(unreadable.getFailureReason());
        assertEquals(1, errCleaned.size());
    }
}
