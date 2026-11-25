package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class EvidenceItemTest {

    @Test
    public void evidenceItemIsImmutableAndAlwaysIncludesPrimarySource() {
        EnumSet<EvidenceItem.SourceLayer> mutable = EnumSet.of(EvidenceItem.SourceLayer.NATIVE);
        EvidenceItem item = new EvidenceItem(
                "su_binary",
                EvidenceItem.SourceLayer.JAVA,
                mutable,
                "/system/xbin/su",
                "exists",
                "root_fw",
                EvidenceItem.Rank.STRONG);

        // Mutating caller's set must not affect the immutable EvidenceItem.
        mutable.add(EvidenceItem.SourceLayer.HARDWARE);
        assertEquals(EnumSet.of(EvidenceItem.SourceLayer.JAVA, EvidenceItem.SourceLayer.NATIVE),
                item.getMergedSources());
        assertThrows(UnsupportedOperationException.class,
                () -> item.getMergedSources().add(EvidenceItem.SourceLayer.ISOLATED));
    }

    @Test
    public void dataAggregatorAutoMergesSameCodeAndLocationAcrossJavaAndNative() {
        EvidenceItem javaFinding = new EvidenceItem(
                "su_binary",
                EvidenceItem.SourceLayer.JAVA,
                "/system/xbin/su",
                "file_exists",
                "root_fw",
                EvidenceItem.Rank.MEDIUM);
        EvidenceItem nativeFinding = new EvidenceItem(
                "su_binary",
                EvidenceItem.SourceLayer.NATIVE,
                "/system/xbin/su",
                "raw_fstatat_exists",
                "root_fw",
                EvidenceItem.Rank.STRONG);
        EvidenceItem distinctLocation = new EvidenceItem(
                "su_binary",
                EvidenceItem.SourceLayer.NATIVE,
                "/sbin/su",
                "raw_fstatat_exists",
                "root_fw",
                EvidenceItem.Rank.STRONG);

        DetectionResult rootResult = new DetectionResult(
                "root",
                RiskLevel.HIGH,
                DetectionStatus.DANGER,
                8,
                10,
                false,
                DetectionExecutionStatus.RISK,
                3,
                3,
                0,
                Collections.emptyList(),
                Arrays.asList("su_found:/system/xbin/su", "native:su:/system/xbin/su", "native:su:/sbin/su"),
                Arrays.asList(javaFinding, nativeFinding, distinctLocation),
                "su_found:/system/xbin/su");

        RiskReport report = new DataAggregator().aggregate(
                Collections.emptyList(), Collections.singletonList(rootResult));

        DetectionResult aggregated = report.getDetections().stream()
                .filter(r -> "root".equals(r.getDetectorName()))
                .findFirst()
                .orElseThrow();
        List<EvidenceItem> merged = aggregated.getEvidenceItems();
        assertEquals("Same (code, location) must merge into one while distinct location stays separate",
                2, merged.size());

        EvidenceItem first = merged.get(0);
        assertEquals("su_binary", first.getCode());
        assertEquals("/system/xbin/su", first.getLocation());
        assertEquals(EvidenceItem.Rank.STRONG, first.getRank());
        assertEquals(EvidenceItem.SourceLayer.NATIVE, first.getPrimarySource());
        assertEquals(Set.of(EvidenceItem.SourceLayer.JAVA, EvidenceItem.SourceLayer.NATIVE),
                first.getMergedSources());

        EvidenceItem second = merged.get(1);
        assertEquals("/sbin/su", second.getLocation());
        assertEquals(Set.of(EvidenceItem.SourceLayer.NATIVE), second.getMergedSources());
    }

    @Test
    public void crossDetectorSameCodeAndLocationPropagatesMergedSourcesAndHighestRank() {
        EvidenceItem javaWeak = new EvidenceItem(
                "frida_maps",
                EvidenceItem.SourceLayer.JAVA,
                "/data/local/tmp/libfrida.so",
                "maps_entry",
                "frida",
                EvidenceItem.Rank.WEAK);
        EvidenceItem nativeStrong = new EvidenceItem(
                "frida_maps",
                EvidenceItem.SourceLayer.NATIVE,
                "/data/local/tmp/libfrida.so",
                "maps_rx_entry",
                "frida",
                EvidenceItem.Rank.STRONG);

        DetectionResult detA = new DetectionResult(
                "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER, 9, 10, false,
                DetectionExecutionStatus.RISK, 1, 1, 0,
                Collections.emptyList(), List.of("maps:frida"), List.of(javaWeak), "maps:frida");
        DetectionResult detB = new DetectionResult(
                "debug", RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                DetectionExecutionStatus.RISK, 1, 1, 0,
                Collections.emptyList(), List.of("native:frida"), List.of(nativeStrong), "native:frida");

        RiskReport report = new DataAggregator().aggregate(
                Collections.emptyList(), Arrays.asList(detA, detB));

        DetectionResult hookOut = report.getDetections().stream()
                .filter(r -> "hook_framework".equals(r.getDetectorName()))
                .findFirst()
                .orElseThrow();
        assertEquals(1, hookOut.getEvidenceItems().size());
        EvidenceItem merged = hookOut.getEvidenceItems().get(0);
        assertEquals(Set.of(EvidenceItem.SourceLayer.JAVA, EvidenceItem.SourceLayer.NATIVE),
                merged.getMergedSources());
        assertEquals(EvidenceItem.Rank.STRONG, merged.getRank());
        assertTrue(hookOut.getDetails().contains("maps:frida"));
    }

    @Test
    public void detectionResultTransformsPreserveEvidenceItems() {
        EvidenceItem item = new EvidenceItem(
                "self_text_tampered",
                EvidenceItem.SourceLayer.NATIVE,
                "libriskengine.so",
                "sha256_mismatch",
                "hook_integrity",
                EvidenceItem.Rank.STRONG);
        DetectionResult base = new DetectionResult(
                "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER, 9, 10, false,
                DetectionExecutionStatus.RISK, 1, 1, 0,
                Collections.emptyList(), List.of("inline_hook:self"), List.of(item), "inline_hook:self");

        assertEquals(List.of(item), base.withInformational(true).getEvidenceItems());
        assertEquals(List.of(item), base.asInformationalDuplicate().getEvidenceItems());
        assertThrows(UnsupportedOperationException.class,
                () -> base.getEvidenceItems().add(item));
    }
}
