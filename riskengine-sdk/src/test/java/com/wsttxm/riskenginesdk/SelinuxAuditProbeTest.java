package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.probe.root.SelinuxAuditProbe;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SelinuxAuditProbeTest {

    @Test
    public void netlinkRestrictionGatingMatchesAndroidApiAndTargetSdkMatrix() {
        // RTM_GETLINK: ((sdk >= 30 && targetSdk >= 30) || sdk >= 33)
        assertFalse(SelinuxAuditProbe.isNetlinkGetLinkRestricted(29, 29));
        assertFalse(SelinuxAuditProbe.isNetlinkGetLinkRestricted(30, 29));
        assertFalse(SelinuxAuditProbe.isNetlinkGetLinkRestricted(32, 29));
        assertTrue(SelinuxAuditProbe.isNetlinkGetLinkRestricted(30, 30));
        assertTrue(SelinuxAuditProbe.isNetlinkGetLinkRestricted(33, 29));
        assertTrue(SelinuxAuditProbe.isNetlinkGetLinkRestricted(36, 36));

        // RTM_GETNEIGH: (sdk >= 33 && targetSdk >= 32)
        assertFalse(SelinuxAuditProbe.isNetlinkGetNeighRestricted(32, 32));
        assertFalse(SelinuxAuditProbe.isNetlinkGetNeighRestricted(33, 31));
        assertTrue(SelinuxAuditProbe.isNetlinkGetNeighRestricted(33, 32));
        assertTrue(SelinuxAuditProbe.isNetlinkGetNeighRestricted(36, 36));
    }

    @Test
    public void enforcedStockDeviceProducesZeroFindings() {
        String payload = "status=OK\terrno=0\tprobes_evaluated=3"
                + "\tlink_applicable=1\tlink_enforced=1"
                + "\tneigh_applicable=1\tneigh_enforced=1"
                + "\tstatus_abi_evaluated=1\tctx_probe_state=UNAVAILABLE";
        SelinuxAuditProbe.ProbeResult res = SelinuxAuditProbe.parsePayload(payload);
        assertTrue(res.isUsable());
        assertTrue(res.isLinkEnforced());
        assertTrue(res.isNeighEnforced());
        assertTrue(res.isStatusAbiEvaluated());
        assertFalse(res.isContextControlsComplete());
        assertFalse(res.hasAny());
    }

    @Test
    public void netlinkLeaksStatusAbiViolationsAndControlledContextsEmitZeroPiiStrongEvidence() {
        String payload = "status=OK\terrno=0\tprobes_evaluated=4"
                + "\tlink_applicable=1\tlink_enforced=0"
                + "\tneigh_applicable=1\tneigh_enforced=0"
                + "\tstatus_abi_evaluated=1\tctx_probe_state=COMPLETE\n"
                + "kind=netlink_link_leak\tif_kind=wifi\n"
                + "kind=netlink_neigh_leak\tleaked=1\n"
                + "kind=selinux_status_abi_violation\trequest=MPROTECT_WRITE\n"
                + "kind=selinux_context_type_present\ttype=ksu_file";

        SignalSnapshot snapshot = new SignalSnapshot(null);
        snapshot.seedSelinuxAuditEvidenceForTest(SignalResult.success(payload));

        SelinuxAuditProbe.ProbeResult res = SelinuxAuditProbe.probe(snapshot);
        assertTrue(res.isUsable());
        assertTrue(res.hasStrong());
        assertEquals(4, res.getStrongTokens().size());
        assertTrue(res.getStrongTokens().contains("netlink_link_leak:wifi"));
        assertTrue(res.getStrongTokens().contains("netlink_neigh_leak"));
        assertTrue(res.getStrongTokens().contains("selinux_status_abi:MPROTECT_WRITE"));
        assertTrue(res.getStrongTokens().contains("selinux_context_type:ksu_file"));
        assertTrue(res.getEvidenceItems().stream().allMatch(
                i -> "root_fw".equals(i.getEvidenceFamily())
                        && i.getPrimarySource() == EvidenceItem.SourceLayer.NATIVE
                        && i.getRank() == EvidenceItem.Rank.STRONG));

        // Verify zero raw MAC/IP PII could leak even if an unexpected string were in if_kind.
        String sanitizedPayload = "status=OK\terrno=0\tprobes_evaluated=1\tctx_probe_state=UNAVAILABLE\n"
                + "kind=netlink_link_leak\tif_kind=aa:bb:cc:dd:ee:ff";
        SelinuxAuditProbe.ProbeResult sanitized = SelinuxAuditProbe.parsePayload(sanitizedPayload);
        assertEquals("netlink_link_leak:physical", sanitized.getStrongTokens().get(0));
        assertFalse(sanitized.getEvidenceItems().get(0).getValue().contains("aa:bb"));
    }

    @Test
    public void failedContextControlGroupSuppressesAllContextFindings() {
        // If ctx_probe_state != COMPLETE, any selinux_context_type_present record MUST be ignored.
        String payload = "status=OK\terrno=0\tprobes_evaluated=1\tctx_probe_state=UNAVAILABLE\n"
                + "kind=selinux_context_type_present\ttype=magisk";
        SelinuxAuditProbe.ProbeResult res = SelinuxAuditProbe.parsePayload(payload);
        assertTrue(res.isUsable());
        assertFalse(res.isContextControlsComplete());
        assertFalse(res.hasAny());
    }

    @Test
    public void visibilityLossAndMalformedPayloadsNeverEscalateToThreat() {
        SelinuxAuditProbe.ProbeResult restricted = SelinuxAuditProbe.parsePayload(
                "status=RESTRICTED\terrno=13\tprobes_evaluated=0");
        assertFalse(restricted.isUsable());
        assertEquals(NativePayloadCodec.Status.RESTRICTED, restricted.getStatus());
        assertFalse(restricted.hasAny());

        SelinuxAuditProbe.ProbeResult malformed = SelinuxAuditProbe.parsePayload("bad");
        assertFalse(malformed.isUsable());
        assertTrue(malformed.isMalformed());
        assertFalse(malformed.hasAny());
    }
}
