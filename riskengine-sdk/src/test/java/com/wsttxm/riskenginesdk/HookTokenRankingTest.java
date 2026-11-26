package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.CorrelationEngine;
import com.wsttxm.riskenginesdk.core.EvidenceFamily;
import com.wsttxm.riskenginesdk.core.HookEvidenceClassifier;
import com.wsttxm.riskenginesdk.detector.probe.hook.SelfIntegrityProbe;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class HookTokenRankingTest {
    @Test
    public void inlineHookIsStrongAndGmainIsIgnored() {
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("inline_hook:openat"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("got_hook:connect"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("text_mismatch:self"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("late_text_mismatch"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("jni_self_hook:slot_0"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("fn_prologue_hook:root_ev"));
        assertEquals(HookEvidenceClassifier.Rank.IGNORE,
                HookEvidenceClassifier.rank("thread:gmain"));
        assertEquals(HookEvidenceClassifier.Rank.WEAK,
                HookEvidenceClassifier.rank("frida_port_open:27042"));
        assertEquals(HookEvidenceClassifier.Rank.IGNORE,
                HookEvidenceClassifier.rank("art_native_flag:invoke"));
        assertEquals(HookEvidenceClassifier.Rank.IGNORE,
                HookEvidenceClassifier.rank("loader_depth:2"));
        assertEquals(HookEvidenceClassifier.Rank.IGNORE,
                HookEvidenceClassifier.rank("passes:2746"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("late_wx_self"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("late_memfd_elf"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("late_frida_fd"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("fd:linjector"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("fd:frida:frida-agent.so"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("anon_elf_exec:0x7f100000"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("stealth_so_hidden_in_maps:libinject.so"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("sigaction_anon_handler:SIGSEGV"));
        assertEquals(HookEvidenceClassifier.Rank.MEDIUM,
                HookEvidenceClassifier.rank("thread:pool-frida"));
        assertEquals(HookEvidenceClassifier.Rank.MEDIUM,
                HookEvidenceClassifier.rank("thread:pool-spawner"));
        assertEquals(HookEvidenceClassifier.Rank.MEDIUM,
                HookEvidenceClassifier.rank("thread:frida-helper"));
        assertEquals(HookEvidenceClassifier.Rank.MEDIUM,
                HookEvidenceClassifier.rank("thread:gdbus"));
        assertEquals(HookEvidenceClassifier.Rank.MEDIUM,
                HookEvidenceClassifier.rank("stealth_so_unlinked:libhidden.so"));

        assertEquals("frida", EvidenceFamily.familyOf("fd:linjector"));
        assertEquals("frida", EvidenceFamily.familyOf("thread:pool-spawner"));
        assertEquals("frida", EvidenceFamily.familyOf("thread:gdbus"));
        assertEquals("hook_integrity", EvidenceFamily.familyOf("anon_elf_exec:0x7f100000"));
        assertEquals("hook_integrity", EvidenceFamily.familyOf("stealth_so_hidden_in_maps:libx.so"));
        assertEquals("hook_integrity", EvidenceFamily.familyOf("sigaction_anon_handler:SIGTRAP"));
    }

    @Test
    public void fdLinjectorHardTriggersDeadlyInRiskReport() {
        DetectionResult hook = new DetectionResult(
                "hook_framework",
                RiskLevel.HIGH,
                DetectionStatus.DANGER,
                8,
                10,
                false,
                List.of("fd:linjector"),
                "fd:linjector");
        RiskReport report = new RiskReport(new DeviceFingerprint(), List.of(hook));
        assertEquals(RiskLevel.DEADLY, report.getOverallRiskLevel());
    }

    @Test
    public void selfIntegrityProbeDecodesPayloadWithCommasAndEqualsWithoutSanitization() {
        String mapsPath = "/data/app/~~abc==/com.foo,bar-1/base.apk!/lib/arm64-v8a/libfrida.so";
        Map<String, String> rec1 = new LinkedHashMap<>();
        rec1.put("token", "maps:frida:" + mapsPath);
        rec1.put("code", "frida_maps");
        rec1.put("location", mapsPath);
        rec1.put("value", "r-xp");
        rec1.put("family", "frida");

        Map<String, String> rec2 = new LinkedHashMap<>();
        rec2.put("token", "text_mismatch:self");
        rec2.put("code", "text_mismatch");
        rec2.put("location", "/data/app/~~abc==/com.foo,bar-1/base.apk");
        rec2.put("value", "sha256_window_off=0x1000");
        rec2.put("family", "hook_integrity");

        String wire = NativePayloadCodec.encodePayload(
                NativePayloadCodec.Status.OK,
                0,
                Collections.singletonMap("v", "2"),
                Arrays.asList(rec1, rec2));

        SelfIntegrityProbe.ProbeResult result = SelfIntegrityProbe.parseNativeHookPayload(wire);
        assertEquals(NativePayloadCodec.Status.OK, result.getStatus());
        assertFalse(result.isMalformed());
        assertTrue(result.hasSelfIntegrityTamper());
        assertEquals(2, result.getTokens().size());
        assertEquals("maps:frida:" + mapsPath, result.getTokens().get(0));
        assertEquals("text_mismatch:self", result.getTokens().get(1));

        assertEquals(2, result.getEvidenceItems().size());
        EvidenceItem fridaItem = result.getEvidenceItems().get(0);
        assertEquals("frida_maps", fridaItem.getCode());
        assertEquals(mapsPath, fridaItem.getLocation());
        assertEquals(EvidenceItem.SourceLayer.NATIVE, fridaItem.getPrimarySource());
        assertEquals(EvidenceItem.Rank.STRONG, fridaItem.getRank());

        EvidenceItem integrityItem = result.getEvidenceItems().get(1);
        assertEquals("text_mismatch", integrityItem.getCode());
        assertEquals("hook_integrity", integrityItem.getEvidenceFamily());
        assertEquals("sha256_window_off=0x1000", integrityItem.getValue());
        assertEquals(EvidenceItem.Rank.STRONG, integrityItem.getRank());
    }

    @Test
    public void selfIntegrityProbeNeverTurnsRestrictedOrErrorStatusIntoThreat() {
        String restrictedWire = NativePayloadCodec.encodePayload(
                NativePayloadCodec.Status.RESTRICTED, 13,
                Collections.singletonMap("reason", "selinux_denied"),
                Collections.singletonList(Collections.singletonMap("token", "text_mismatch:self")));

        SelfIntegrityProbe.ProbeResult parsed =
                SelfIntegrityProbe.parseNativeHookPayload(restrictedWire);
        assertEquals(NativePayloadCodec.Status.RESTRICTED, parsed.getStatus());
        assertEquals(13, parsed.getErrno());
        assertFalse(parsed.hasSelfIntegrityTamper());
        assertTrue(parsed.getTokens().isEmpty());
        assertTrue(parsed.getEvidenceItems().isEmpty());

        // Malformed payload claiming status=OK must also be rejected without emitting threats.
        String malformedOk = "status=OK\terrno=bad_int\ntoken=text_mismatch:self\tcode=text_mismatch";
        SelfIntegrityProbe.ProbeResult malformed =
                SelfIntegrityProbe.parseNativeHookPayload(malformedOk);
        assertTrue(malformed.isMalformed());
        assertFalse(malformed.hasSelfIntegrityTamper());
        assertTrue(malformed.getTokens().isEmpty());
        assertTrue(malformed.getEvidenceItems().isEmpty());

        // Clean-device ART context token (loader_depth) must remain INFO with null family.
        Map<String, String> loaderDepth = new LinkedHashMap<>();
        loaderDepth.put("token", "loader_depth:2");
        loaderDepth.put("code", "loader_depth");
        loaderDepth.put("location", "2");
        loaderDepth.put("value", "loader_depth:2");
        String cleanWire = NativePayloadCodec.encodePayload(
                NativePayloadCodec.Status.OK, 0,
                Collections.singletonMap("v", "2"),
                Collections.singletonList(loaderDepth));
        SelfIntegrityProbe.ProbeResult cleanParsed =
                SelfIntegrityProbe.parseNativeHookPayload(cleanWire);
        assertFalse(cleanParsed.isMalformed());
        assertFalse(cleanParsed.hasSelfIntegrityTamper());
        assertEquals(1, cleanParsed.getEvidenceItems().size());
        assertEquals(EvidenceItem.Rank.INFO, cleanParsed.getEvidenceItems().get(0).getRank());
        assertNull(cleanParsed.getEvidenceItems().get(0).getEvidenceFamily());
    }

    @Test
    public void ruleC6TriggersDeadly10WhenNativeSelfIntegrityTamperedAndJavaClean() {
        EvidenceItem selfTamper = new EvidenceItem(
                "text_mismatch",
                EvidenceItem.SourceLayer.NATIVE,
                "/data/app/base.apk",
                "sha256_window_off=0x4000",
                "hook_integrity",
                EvidenceItem.Rank.STRONG);
        DetectionResult hook = new DetectionResult(
                "hook_framework",
                RiskLevel.HIGH,
                DetectionStatus.DANGER,
                8,
                10,
                false,
                DetectionExecutionStatus.RISK,
                4,
                4,
                0,
                Collections.emptyList(),
                List.of("text_mismatch:self"),
                List.of(selfTamper),
                "text_mismatch:self");

        DetectionResult correlated = CorrelationEngine.correlate(
                Collections.singletonList(hook), CollectScene.STANDARD);
        assertNotNull(correlated);
        assertEquals(RiskLevel.DEADLY, correlated.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, correlated.getStatus());
        assertEquals(10, correlated.getScore());
        assertFalse(correlated.isInformational());
        assertTrue(correlated.getDetails().contains("C6:bridge_or_integrity_tamper"));
        assertEquals(1, correlated.getEvidenceItems().size());
        assertEquals("bridge_or_integrity_tamper",
                correlated.getEvidenceItems().get(0).getCode());
    }

    @Test
    public void ruleC6TriggersDeadly10OnUnsatisfiedLinkErrorWithStealthSignals() {
        DetectionResult hook = new DetectionResult(
                "hook_framework",
                RiskLevel.UNKNOWN,
                DetectionStatus.UNKNOWN,
                0,
                10,
                true,
                DetectionExecutionStatus.PARTIAL,
                4,
                3,
                1,
                List.of("native_hook:UnsatisfiedLinkError"),
                Collections.emptyList(),
                "");
        DetectionResult root = new DetectionResult(
                "root",
                RiskLevel.MEDIUM,
                DetectionStatus.WARNING,
                4,
                10,
                false,
                List.of("native:syscall_mismatch:/system/xbin/su"),
                "native:syscall_mismatch:/system/xbin/su");

        DetectionResult correlated = CorrelationEngine.correlate(
                Arrays.asList(hook, root), CollectScene.STANDARD);
        assertNotNull(correlated);
        assertEquals(RiskLevel.DEADLY, correlated.getRiskLevel());
        assertEquals(10, correlated.getScore());
        assertTrue(correlated.getDetails().contains("C6:bridge_or_integrity_tamper"));
    }

    @Test
    public void ruleC6DoesNotFalsePositiveWhenNativeUnavailableWithoutStealth() {
        DetectionResult hook = new DetectionResult(
                "hook_framework",
                RiskLevel.SAFE,
                DetectionStatus.NORMAL,
                0,
                10,
                false,
                DetectionExecutionStatus.PARTIAL,
                4,
                3,
                1,
                List.of("native_hook:unavailable"),
                Collections.emptyList(),
                "");
        assertNull(CorrelationEngine.correlate(
                Collections.singletonList(hook), CollectScene.STANDARD));
    }
}
