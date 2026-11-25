package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.probe.root.KernelSidechannelProbe;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class KernelSidechannelProbeTest {

    @Test
    public void cleanPayloadProducesZeroFindingsAndPreservesHeaderFlags() {
        String payload = "status=OK\terrno=0\tkp_negative_trusted=1\tprobes_run=4\tdevpts_checked=2\ttiming_ran=1\ttiming_consecutive_hits=0";
        KernelSidechannelProbe.ProbeResult res = KernelSidechannelProbe.parsePayload(payload);
        assertTrue(res.isUsable());
        assertTrue(res.isKpNegativeTrusted());
        assertTrue(res.isTimingRan());
        assertEquals(4, res.getProbesRun());
        assertFalse(res.hasAny());
        assertFalse(res.hasStrong());
        assertFalse(res.hasMedium());
    }

    @Test
    public void strongKernelSidechannelHitsEmitRootFwStrongEvidenceItems() {
        String payload = "status=OK\terrno=0\tkp_negative_trusted=0\tprobes_run=4\tdevpts_checked=3\ttiming_ran=0\ttiming_consecutive_hits=0\n"
                + "kind=kernelpatch_truncate_hit\thits=4\tchecked=4\tkernel=6.1.75-android14\n"
                + "kind=ksu_reboot_ioctl\tversion=12100\tflags=1\tfeatures=3\tsafe_mode=0\n"
                + "kind=ksu_driver_fd\tfd=42\ttarget=anon_inode:[ksu_driver]\n"
                + "kind=devpts_ksu_xattr\tpath=/dev/pts/1\tcontext=u:object_r:ksu_file:s0\n"
                + "kind=susfs_setresuid_sigkill\tuid=10250\ttarget_uid=10000";

        SignalSnapshot snapshot = new SignalSnapshot(null);
        snapshot.seedKernelSidechannelEvidenceForTest(SignalResult.success(payload));

        KernelSidechannelProbe.ProbeResult res = KernelSidechannelProbe.probe(snapshot, false);
        assertTrue(res.isUsable());
        assertTrue(res.hasStrong());
        assertFalse(res.hasMedium());
        assertEquals(5, res.getStrongTokens().size());
        assertEquals(5, res.getEvidenceItems().size());
        assertTrue(res.getStrongTokens().contains("kernelpatch_truncate_hit"));
        assertTrue(res.getStrongTokens().contains("ksu_reboot_ioctl:v12100"));
        assertTrue(res.getStrongTokens().contains("ksu_driver_fd:42"));
        assertTrue(res.getStrongTokens().contains("devpts_ksu_xattr:/dev/pts/1"));
        assertTrue(res.getStrongTokens().contains("susfs_setresuid_sigkill"));
        assertTrue(res.getEvidenceItems().stream().allMatch(
                i -> "root_fw".equals(i.getEvidenceFamily())
                        && i.getPrimarySource() == EvidenceItem.SourceLayer.NATIVE
                        && i.getRank() == EvidenceItem.Rank.STRONG));
    }

    @Test
    public void prctlTimingSidechannelRequiresThreeConsecutiveHitsAndEmitsMediumWarningOnly() {
        // Fewer than 3 consecutive hits MUST be ignored (anti-FP).
        String weakPayload = "status=OK\terrno=0\tkp_negative_trusted=1\tprobes_run=4\ttiming_ran=1\ttiming_consecutive_hits=2\n"
                + "kind=ksu_prctl_timing_anomaly\tcpu=0\tconsecutive_hits=2\tmetrics=z\\=3.4";
        KernelSidechannelProbe.ProbeResult weak = KernelSidechannelProbe.parsePayload(weakPayload);
        assertTrue(weak.isUsable());
        assertFalse(weak.hasAny());

        // 3 consecutive same-core hits emit MEDIUM (WARNING), never STRONG.
        String hitPayload = "status=OK\terrno=0\tkp_negative_trusted=1\tprobes_run=4\ttiming_ran=1\ttiming_consecutive_hits=3\n"
                + "kind=ksu_prctl_timing_anomaly\tcpu=4\tconsecutive_hits=3\tmetrics=cpu\\=4,t_med\\=180.0,c_med\\=110.0,z\\=5.10,cos\\=0.420";
        KernelSidechannelProbe.ProbeResult hit = KernelSidechannelProbe.parsePayload(hitPayload);
        assertTrue(hit.isUsable());
        assertFalse(hit.hasStrong());
        assertTrue(hit.hasMedium());
        assertEquals(1, hit.getMediumTokens().size());
        assertEquals("ksu_prctl_timing_anomaly:cpu4", hit.getMediumTokens().get(0));
        assertEquals(EvidenceItem.Rank.MEDIUM, hit.getEvidenceItems().get(0).getRank());
        assertEquals("root_fw", hit.getEvidenceItems().get(0).getEvidenceFamily());
    }

    @Test
    public void visibilityLossAndMalformedPayloadsNeverEscalateToThreat() {
        KernelSidechannelProbe.ProbeResult restricted = KernelSidechannelProbe.parsePayload(
                "status=RESTRICTED\terrno=13\tprobes_run=0");
        assertFalse(restricted.isUsable());
        assertEquals(NativePayloadCodec.Status.RESTRICTED, restricted.getStatus());
        assertFalse(restricted.hasAny());

        KernelSidechannelProbe.ProbeResult malformed = KernelSidechannelProbe.parsePayload("not_valid");
        assertFalse(malformed.isUsable());
        assertTrue(malformed.isMalformed());
        assertFalse(malformed.hasAny());

        KernelSidechannelProbe.ProbeResult nullSnap = KernelSidechannelProbe.probe(null, true);
        assertFalse(nullSnap.isUsable());
        assertFalse(nullSnap.hasAny());
    }

    @Test
    public void signalSnapshotSeparatesFastAndTimingSidechannelCaches() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        snapshot.seedKernelSidechannelEvidenceForTest(false, SignalResult.success(
                "status=OK\terrno=0\tkp_negative_trusted=1\tprobes_run=3\ttiming_ran=0\ttiming_consecutive_hits=0"));
        snapshot.seedKernelSidechannelEvidenceForTest(true, SignalResult.success(
                "status=OK\terrno=0\tkp_negative_trusted=1\tprobes_run=4\ttiming_ran=1\ttiming_consecutive_hits=3\n"
                        + "kind=ksu_prctl_timing_anomaly\tcpu=2\tconsecutive_hits=3\tmetrics=z\\=4.2"));

        KernelSidechannelProbe.ProbeResult noTiming = KernelSidechannelProbe.probe(snapshot, false);
        assertTrue(noTiming.isUsable());
        assertFalse(noTiming.isTimingRan());
        assertFalse(noTiming.hasAny());

        KernelSidechannelProbe.ProbeResult withTiming = KernelSidechannelProbe.probe(snapshot, true);
        assertTrue(withTiming.isUsable());
        assertTrue(withTiming.isTimingRan());
        assertTrue(withTiming.hasMedium());
        assertEquals("ksu_prctl_timing_anomaly:cpu2", withTiming.getMediumTokens().get(0));
    }

    @Test
    public void modernKernelPatchSupercallHelloMagicEmitsStrongRootFwEvidence() {
        String payload = "status=OK\terrno=0\tkp_negative_trusted=1\tprobes_run=4\tdevpts_checked=0\ttiming_ran=0\ttiming_consecutive_hits=0\n"
                + "kind=kernelpatch_supercall_hello\tmagic=0x11581158\tkernel=5.10.149-android13\n"
                + "kind=kernelpatch_truncate_hit\thits=4\tmodern_hits=4\tchecked=4\tkernel=5.10.149-android13";

        KernelSidechannelProbe.ProbeResult res = KernelSidechannelProbe.parsePayload(payload);
        assertTrue(res.isUsable());
        assertTrue(res.hasStrong());
        assertFalse(res.hasMedium());
        assertEquals(2, res.getStrongTokens().size());
        assertTrue(res.getStrongTokens().contains("kernelpatch_supercall_hello"));
        assertTrue(res.getStrongTokens().contains("kernelpatch_truncate_hit"));
        assertEquals("kernelpatch_supercall_hello", res.getEvidenceItems().get(0).getCode());
        assertEquals("sys_truncate", res.getEvidenceItems().get(0).getLocation());
        assertEquals(EvidenceItem.Rank.STRONG, res.getEvidenceItems().get(0).getRank());
        assertEquals("root_fw", res.getEvidenceItems().get(0).getEvidenceFamily());
    }
}
