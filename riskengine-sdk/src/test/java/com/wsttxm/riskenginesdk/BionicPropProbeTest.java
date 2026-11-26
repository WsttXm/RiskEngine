package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.probe.consistency.BionicPropProbe;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class BionicPropProbeTest {

    @Test
    public void cleanOkPayloadProducesZeroTamperEvidence() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("sdk", "35");
        headers.put("areas_scanned", "12");
        headers.put("hole_areas", "0");
        headers.put("hole_total", "0");
        headers.put("ro_checked", "18");

        String frame = NativePayloadCodec.encodePayload(
                NativePayloadCodec.Status.OK, 0, headers, Collections.emptyList());

        BionicPropProbe.ProbeResult res = BionicPropProbe.parsePayload(frame);
        assertTrue(res.isUsable());
        assertEquals(12, res.getAreasScanned());
        assertEquals(18, res.getRoChecked());
        assertFalse(res.hasAnyTamper());
        assertFalse(res.hasStrongTamper());
        assertTrue(res.getEvidenceItems().isEmpty());
        assertTrue(res.getTokens().isEmpty());
    }

    @Test
    public void restrictedUnsupportedErrorAndMalformedFramesNeverEmitThreats() {
        String restricted = NativePayloadCodec.encodePayload(
                NativePayloadCodec.Status.RESTRICTED, 13, null, Collections.emptyList());
        String unsupported = NativePayloadCodec.encodePayload(
                NativePayloadCodec.Status.UNSUPPORTED, 0, null, Collections.emptyList());
        String error = NativePayloadCodec.encodePayload(
                NativePayloadCodec.Status.ERROR, 5, null, Collections.emptyList());

        for (String payload : Arrays.asList(restricted, unsupported, error, "", "corrupt_frame")) {
            BionicPropProbe.ProbeResult res = BionicPropProbe.parsePayload(payload);
            assertFalse("Non-OK/malformed frame must not be usable", res.isUsable());
            assertFalse(res.hasAnyTamper());
            assertTrue(res.getEvidenceItems().isEmpty());
        }
    }

    @Test
    public void parsesHoleSerialNulTailMetaAndSelinuxAnomaliesIntoPropTamperEvidenceItems() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("sdk", "34");
        headers.put("areas_scanned", "10");
        headers.put("ro_checked", "18");

        Map<String, String> criticalHole = new LinkedHashMap<>();
        criticalHole.put("kind", "hole");
        criticalHole.put("context", "u:object_r:adbd_config_prop:s0");
        criticalHole.put("count", "2");
        criticalHole.put("high_priority", "1");
        criticalHole.put("ranges", "@0x120+128,@0x260+64");

        Map<String, String> normalHole = new LinkedHashMap<>();
        normalHole.put("kind", "hole");
        normalHole.put("context", "u:object_r:default_prop:s0");
        normalHole.put("count", "1");
        normalHole.put("high_priority", "0");
        normalHole.put("ranges", "@0x400+96");

        Map<String, String> serialMod = new LinkedHashMap<>();
        serialMod.put("kind", "serial_modified");
        serialMod.put("prop", "ro.boot.verifiedbootstate");
        serialMod.put("write_count", "1");
        serialMod.put("serial", "0x5000002");
        serialMod.put("context", "u:object_r:bootloader_prop:s0");

        Map<String, String> nulTail = new LinkedHashMap<>();
        nulTail.put("kind", "nul_tail");
        nulTail.put("prop", "ro.boot.verifiedbootstate");
        nulTail.put("value", "green");
        nulTail.put("nonzero_bytes", "1");
        nulTail.put("context", "u:object_r:bootloader_prop:s0");

        Map<String, String> metaAnom = new LinkedHashMap<>();
        metaAnom.put("kind", "meta_anomaly");
        metaAnom.put("context", "u:object_r:shell_prop:s0");
        metaAnom.put("detail", "uid=0,gid=0,mode=0666");

        Map<String, String> selinuxAnom = new LinkedHashMap<>();
        selinuxAnom.put("kind", "selinux_anomaly");
        selinuxAnom.put("context", "u:object_r:default_prop:s0");
        selinuxAnom.put("xattr", "u:object_r:magisk_file:s0");

        String frame = NativePayloadCodec.encodePayload(
                NativePayloadCodec.Status.OK,
                0,
                headers,
                Arrays.asList(criticalHole, normalHole, serialMod, nulTail, metaAnom, selinuxAnom));

        SignalSnapshot snapshot = new SignalSnapshot(null);
        snapshot.seedBionicPropForensicsForTest(SignalResult.success(frame));

        BionicPropProbe.ProbeResult res = BionicPropProbe.probe(snapshot);
        assertTrue(res.isUsable());
        assertTrue(res.hasAnyTamper());
        assertTrue(res.hasStrongTamper());
        assertEquals(6, res.getEvidenceItems().size());

        // Every EvidenceItem belongs to prop_tamper family and NATIVE layer
        for (EvidenceItem item : res.getEvidenceItems()) {
            assertEquals(BionicPropProbe.EVIDENCE_FAMILY, item.getEvidenceFamily());
            assertEquals(EvidenceItem.SourceLayer.NATIVE, item.getPrimarySource());
        }

        // Critical hole (adbd_config_prop) -> STRONG; normal hole -> MEDIUM
        assertEquals("prop_area_hole_critical", res.getEvidenceItems().get(0).getCode());
        assertEquals(EvidenceItem.Rank.STRONG, res.getEvidenceItems().get(0).getRank());
        assertEquals("prop_area_hole", res.getEvidenceItems().get(1).getCode());
        assertEquals(EvidenceItem.Rank.MEDIUM, res.getEvidenceItems().get(1).getRank());

        // Serial modified & NUL-tail residual -> STRONG
        assertEquals("prop_ro_serial_modified", res.getEvidenceItems().get(2).getCode());
        assertEquals(EvidenceItem.Rank.STRONG, res.getEvidenceItems().get(2).getRank());
        assertEquals("ro.boot.verifiedbootstate", res.getEvidenceItems().get(2).getLocation());

        assertEquals("prop_ro_nul_tail_residual", res.getEvidenceItems().get(3).getCode());
        assertEquals(EvidenceItem.Rank.STRONG, res.getEvidenceItems().get(3).getRank());
        assertTrue(res.getEvidenceItems().get(3).getValue().contains("val=green"));
        assertTrue(res.getEvidenceItems().get(3).getValue().contains("trailing_nonzero=1"));

        // Metadata anomaly -> MEDIUM; SELinux xattr anomaly -> STRONG
        assertEquals("prop_area_meta_anomaly", res.getEvidenceItems().get(4).getCode());
        assertEquals(EvidenceItem.Rank.MEDIUM, res.getEvidenceItems().get(4).getRank());
        assertEquals("prop_area_selinux_anomaly", res.getEvidenceItems().get(5).getCode());
        assertEquals(EvidenceItem.Rank.STRONG, res.getEvidenceItems().get(5).getRank());
    }
}
