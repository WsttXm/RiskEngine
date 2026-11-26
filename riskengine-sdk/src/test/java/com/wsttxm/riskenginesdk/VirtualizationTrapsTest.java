package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class VirtualizationTrapsTest {

    @Test
    public void signalSnapshotSeparatesFastAndPostponedVirtualizationTrapSlots() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        String fastPayload = "status=OK\terrno=0\tpostponed=0\tnative_bridge_hits=1"
                + "\tsyscall_pack_ran=0\tseccomp_trapped=0\ttiming_ran=0\tclock_ran=0\n"
                + "kind=native_bridge_maps\tpath=/system/lib64/libhoudini.so";
        String postponedPayload = "status=OK\terrno=0\tpostponed=1\tnative_bridge_hits=1"
                + "\tsyscall_pack_ran=1\tseccomp_trapped=0\ttiming_ran=1\tclock_ran=1\n"
                + "kind=native_bridge_maps\tpath=/system/lib64/libhoudini.so\n"
                + "kind=sacrificial_syscall_mismatch\tsyscall=statx\tmismatches=3\tlibc_errno=2\traw_errno=1\n"
                + "kind=sched_yield_low_cv\tcv=0.0120\tmean_ns=1800\tsuspicious=3\tseverity=INFO\n"
                + "kind=arm64_clock_drift\tfreq=19200000\tcounter_ns=90000000\twall_ns=1000000\tsuspicious=2";

        snapshot.seedVirtualizationTrapsForTest(false, SignalResult.success(fastPayload));
        snapshot.seedVirtualizationTrapsForTest(true, SignalResult.success(postponedPayload));

        SignalResult<String> fast = snapshot.getVirtualizationTraps(false);
        SignalResult<String> postponed = snapshot.getVirtualizationTraps(true);

        assertTrue(fast.isSuccess());
        assertTrue(postponed.isSuccess());

        NativePayloadCodec.DecodedPayload fastDecoded = NativePayloadCodec.decodePayload(fast.getValue());
        assertTrue(fastDecoded.isOk());
        assertEquals("0", fastDecoded.getHeaderField("postponed"));
        assertEquals(1, fastDecoded.getRecords().size());
        assertEquals("native_bridge_maps", fastDecoded.getRecords().get(0).get("kind"));

        NativePayloadCodec.DecodedPayload postDecoded = NativePayloadCodec.decodePayload(postponed.getValue());
        assertTrue(postDecoded.isOk());
        assertEquals("1", postDecoded.getHeaderField("postponed"));
        assertEquals("1", postDecoded.getHeaderField("syscall_pack_ran"));
        assertEquals("1", postDecoded.getHeaderField("timing_ran"));
        assertEquals("1", postDecoded.getHeaderField("clock_ran"));
        assertEquals(4, postDecoded.getRecords().size());

        Map<String, String> syscallRec = postDecoded.getRecords().get(1);
        assertEquals("sacrificial_syscall_mismatch", syscallRec.get("kind"));
        assertEquals("statx", syscallRec.get("syscall"));
        assertEquals("3", syscallRec.get("mismatches"));

        Map<String, String> yieldRec = postDecoded.getRecords().get(2);
        assertEquals("sched_yield_low_cv", yieldRec.get("kind"));
        assertEquals("INFO", yieldRec.get("severity"));

        Map<String, String> clockRec = postDecoded.getRecords().get(3);
        assertEquals("arm64_clock_drift", clockRec.get("kind"));
        assertEquals("19200000", clockRec.get("freq"));
    }

    @Test
    public void seccompTrappedAndRestrictedPayloadsCarryZeroThreatRecords() {
        String seccompClean = "status=OK\terrno=0\tpostponed=1\tnative_bridge_hits=0"
                + "\tsyscall_pack_ran=1\tseccomp_trapped=1\ttiming_ran=1\tclock_ran=0";
        NativePayloadCodec.DecodedPayload decoded = NativePayloadCodec.decodePayload(seccompClean);
        assertTrue(decoded.isOk());
        assertEquals("1", decoded.getHeaderField("seccomp_trapped"));
        assertTrue(decoded.getRecords().isEmpty());

        NativePayloadCodec.DecodedPayload restricted =
                NativePayloadCodec.decodePayload("status=RESTRICTED\terrno=13");
        assertFalse(restricted.isOk());
        assertTrue(restricted.getRecords().isEmpty());
    }
}
