package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.detector.probe.tee.TeeNativeProbe;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/**
 * Unit tests for P3-5: {@link TeeNativeProbe} 5-vector TrickyStore / Binder payload parsing
 * and cross-layer Leaf DER validation.
 */
public class TeeNativeProbeTest {

    @Test
    public void cleanNativeFrameAndCleanLeafDerProduceZeroFindings() {
        byte[] cleanDer = buildCleanDer();
        TeeNativeProbe.NativeTeeAdapter adapter = stubAdapter(
                SignalResult.success(
                        "status=OK\terrno=0\tmaps_hits=0\tgot_checked=1\tgot_hits=0"
                                + "\tinline_checked=1\tinline_hits=0\tversion_checked=3\tversion_hits=0"
                                + "\thoneypot_checked=3\thoneypot_hits=0"),
                SignalResult.success(
                        "status=OK\terrno=0\thex_template_32=0\tnon_minimal_length=0\tstructure_invalid=0"));

        TeeNativeProbe.ProbeResult res = TeeNativeProbe.run(adapter, cleanDer, true);
        assertTrue(res.isUsable());
        assertFalse(res.hasFindings());
        assertTrue(res.getEvidenceItems().isEmpty());
    }

    @Test
    public void allFiveTrickyStoreVectorsEmitExpectedTeeTamperEvidence() {
        String frame = "status=OK\terrno=0\tmaps_hits=1\tgot_hits=1\tinline_hits=1\tversion_hits=1\thoneypot_hits=1\n"
                + "kind=maps_artifact\ttoken=trickystore\tpath=/data/adb/modules/tricky_store/libtrickystore.so\n"
                + "kind=got_ioctl_hook\tgot=0x7f123400\treal=0x7a000100\thook_lib=/data/local/tmp/libhook.so\n"
                + "kind=inline_ioctl_hook\treason=disk_mem_16b_mismatch\tlib=/apex/com.android.runtime/lib64/bionic/libc.so\n"
                + "kind=binder_version_mismatch\tmismatch_rounds=3\tdetail=libc\\=0/0/8;sys\\=0/0/8;asm\\=-1/22/0\n"
                + "kind=honeypot_timing_anomaly\thits=3\tmedian_gap_ns=85000\tgap_mad_ns=1200\tnoise_floor_ns=15000\tratio_pct=420";

        TeeNativeProbe.ProbeResult res = TeeNativeProbe.run(
                stubAdapter(SignalResult.success(frame), SignalResult.unavailable("unused")),
                null,
                true);

        assertTrue(res.isUsable());
        assertTrue(res.hasFindings());
        assertTrue(res.getStrongTokens().contains("tee_tricky_maps:trickystore"));
        assertTrue(res.getStrongTokens().contains("tee_binder_ioctl_hook"));
        assertTrue(res.getMediumTokens().contains("tee_binder_honeypot_timing"));

        long ioctlItems = res.getEvidenceItems().stream()
                .filter(i -> "tee_binder_ioctl_hook".equals(i.getCode())
                        && TeeNativeProbe.FAMILY_TEE_TAMPER.equals(i.getEvidenceFamily())
                        && i.getRank() == EvidenceItem.Rank.STRONG)
                .count();
        assertEquals("GOT + inline + 3-way mismatch should each record a tee_binder_ioctl_hook item",
                3L, ioctlItems);
        assertTrue(res.getEvidenceItems().stream().anyMatch(
                i -> "tee_tricky_maps".equals(i.getCode())
                        && TeeNativeProbe.FAMILY_TEE_TAMPER.equals(i.getEvidenceFamily())));
        assertTrue(res.getEvidenceItems().stream().anyMatch(
                i -> "tee_binder_honeypot_timing".equals(i.getCode())
                        && i.getRank() == EvidenceItem.Rank.MEDIUM));
    }

    @Test
    public void leafDerHexTemplateAndNonMinimalBerCrossCheckWithNative() {
        // Construct a leaf DER with both a 32-hex UTF8String followed by SEQUENCE and a non-minimal length TLV
        byte[] hexUtf8 = tlv(0x0C, "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII));
        byte[] nonMinBer = new byte[] {0x04, (byte) 0x81, 0x02, 0x41, 0x42};
        byte[] badLeaf = seq(hexUtf8, nonMinBer, seq(tlv(0x02, new byte[] {0x01})));

        // Both Java and Native agree -> dual-layer JAVA+NATIVE findings, no parity conflict
        TeeNativeProbe.ProbeResult agreed = TeeNativeProbe.run(
                stubAdapter(
                        SignalResult.success("status=OK\terrno=0"),
                        SignalResult.success(
                                "status=OK\terrno=0\thex_template_32=1\tnon_minimal_length=1\tstructure_invalid=0\n"
                                        + "kind=der_finding\tcode=HEX_TEMPLATE_32\n"
                                        + "kind=der_finding\tcode=NON_MINIMAL_LENGTH")),
                badLeaf,
                false);
        assertTrue(agreed.getStrongTokens().contains("tee_leaf_der_hex_template"));
        assertTrue(agreed.getMediumTokens().contains("tee_leaf_der_non_minimal_ber"));
        assertFalse(agreed.getStrongTokens().contains("tee_leaf_der_parity_mismatch"));
        assertTrue(agreed.getEvidenceItems().stream().anyMatch(
                i -> "tee_leaf_der_hex_template".equals(i.getCode())
                        && i.getMergedSources().contains(EvidenceItem.SourceLayer.JAVA)));
        assertTrue(agreed.getEvidenceItems().stream().anyMatch(
                i -> "tee_leaf_der_hex_template".equals(i.getCode())
                        && i.getMergedSources().contains(EvidenceItem.SourceLayer.NATIVE)));

        // If native claims clean while Java detects anomaly -> parity mismatch emitted
        TeeNativeProbe.ProbeResult conflict = TeeNativeProbe.run(
                stubAdapter(
                        SignalResult.success("status=OK\terrno=0"),
                        SignalResult.success(
                                "status=OK\terrno=0\thex_template_32=0\tnon_minimal_length=0\tstructure_invalid=0")),
                badLeaf,
                false);
        assertTrue(conflict.getStrongTokens().contains("tee_leaf_der_parity_mismatch"));
    }

    @Test
    public void unavailableNativeFrameDegradesCleanlyWithZeroFp() {
        TeeNativeProbe.ProbeResult res = TeeNativeProbe.run(
                stubAdapter(
                        SignalResult.unavailable("native_library_unavailable"),
                        SignalResult.unavailable("native_library_unavailable")),
                null,
                true);
        assertFalse(res.isUsable());
        assertFalse(res.hasFindings());
        assertEquals("native_library_unavailable", res.getFailureReason());
    }

    @Test
    public void googleStrongBoxIssuerSerial32Hex_producesZeroFpAndNoParityMismatch() {
        // Real Pixel 6 Titan M2 StrongBox leaf cert shape: Issuer serialNumber is 32-char hex
        byte[] issuerDn = seq(
                tlv(0x31, seq(tlv(0x06, new byte[] {0x55, 0x04, 0x05}),
                        tlv(0x13, "06842f84bcbadbd196405bfd6a6349eb".getBytes(StandardCharsets.US_ASCII)))));
        byte[] subjectDn = seq(
                tlv(0x31, seq(tlv(0x06, new byte[] {0x55, 0x04, 0x03}),
                        tlv(0x13, "Android Keystore Key".getBytes(StandardCharsets.US_ASCII)))));
        byte[] sigAlg = seq(tlv(0x06, new byte[] {0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x04, 0x03, 0x02}));
        byte[] validity = seq(
                tlv(0x17, "260101000000Z".getBytes(StandardCharsets.US_ASCII)),
                tlv(0x17, "360101000000Z".getBytes(StandardCharsets.US_ASCII)));
        byte[] spki = seq(sigAlg, tlv(0x03, new byte[] {0x00, 0x04, 0x01, 0x02}));
        byte[] tbs = seq(
                tlv(0xA0, tlv(0x02, new byte[] {0x02})),
                tlv(0x02, new byte[] {0x01}),
                sigAlg, issuerDn, validity, subjectDn, spki);
        byte[] pixelLeafCert = seq(tbs, sigAlg, tlv(0x03, new byte[] {0x00, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}));

        String cleanBinder = "status=OK\terrno=0\tmaps_hits=0\tgot_hits=0\tinline_hits=0\tversion_hits=0\thoneypot_hits=0";
        String cleanNativeDer = "status=OK\terrno=0\thex_template_32=0\tnon_minimal_length=0\tstructure_invalid=0";

        TeeNativeProbe.ProbeResult res = TeeNativeProbe.run(
                stubAdapter(SignalResult.success(cleanBinder), SignalResult.success(cleanNativeDer)),
                pixelLeafCert,
                true);
        assertTrue(res.isUsable());
        assertFalse("Pixel 6 StrongBox Issuer serialNumber=32hex must produce 0 FP", res.hasFindings());
        assertTrue(res.getStrongTokens().isEmpty());
        assertTrue(res.getMediumTokens().isEmpty());
    }

    private static TeeNativeProbe.NativeTeeAdapter stubAdapter(
            SignalResult<String> binder, SignalResult<String> der) {
        return new TeeNativeProbe.NativeTeeAdapter() {
            @Override
            public SignalResult<String> getTeeBinderProbe(boolean includeHoneypotTiming) {
                return binder;
            }

            @Override
            public SignalResult<String> inspectLeafDer(byte[] leafDer) {
                return der;
            }
        };
    }

    private static byte[] buildCleanDer() {
        return seq(
                seq(tlv(0x02, new byte[] {0x02}), tlv(0x0C, "ValidKeyCert".getBytes(StandardCharsets.US_ASCII))),
                seq(tlv(0x02, new byte[] {0x01})));
    }

    private static byte[] seq(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.write(p, 0, p.length);
        }
        return tlv(0x30, out.toByteArray());
    }

    private static byte[] tlv(int tag, byte[] val) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        if (val.length < 0x80) {
            out.write(val.length);
        } else if (val.length <= 0xFF) {
            out.write(0x81);
            out.write(val.length);
        } else {
            out.write(0x82);
            out.write((val.length >>> 8) & 0xFF);
            out.write(val.length & 0xFF);
        }
        out.write(val, 0, val.length);
        return out.toByteArray();
    }
}
