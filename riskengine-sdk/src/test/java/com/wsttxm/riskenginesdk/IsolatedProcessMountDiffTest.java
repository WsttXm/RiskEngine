package com.wsttxm.riskenginesdk;

import android.content.ComponentName;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Binder;
import android.os.IBinder;

import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.process.IsolatedProbeClient;
import com.wsttxm.riskenginesdk.process.MountViewNormalizer;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class IsolatedProcessMountDiffTest {

    private static final String CLEAN_MOUNT_SYSTEM =
            "50 1 253:0 / /system ro,relatime shared:1 - ext4 /dev/block/dm-0 ro,seclabel";
    private static final String CLEAN_MOUNT_DEV_TMPFS_A =
            "21 1 0:18 / /dev rw,nosuid,relatime shared:2 - devtmpfs tmpfs rw,seclabel,size=3812340k,nr_inodes=953085,nr_blocks=953085,mode=755";
    private static final String CLEAN_MOUNT_DEV_TMPFS_B =
            "21 1 0:18 / /dev rw,nosuid,relatime shared:2 - devtmpfs tmpfs rw,seclabel,size=3800000k,nr_inodes=950000,mode=755";
    private static final String CLEAN_MOUNT_ROOTFS_A =
            "1 0 0:1 / / ro,relatime shared:1 - rootfs rootfs ro,size=102400k,nr_inodes=25600";
    private static final String CLEAN_MOUNT_ROOTFS_B =
            "1 0 0:1 / / ro,relatime shared:1 - rootfs rootfs ro,nr_blocks=12800";
    private static final String CLEAN_MOUNT_TMPFS_MNT_A =
            "35 1 0:21 / /mnt rw,nosuid,nodev,noexec,relatime shared:3 - tmpfs tmpfs rw,seclabel,size=409600k,nr_inodes=102400,mode=755";
    private static final String CLEAN_MOUNT_TMPFS_MNT_B =
            "35 1 0:21 / /mnt rw,nosuid,nodev,noexec,relatime shared:3 - tmpfs tmpfs rw,seclabel,mode=755";

    private static final String SHAMIKO_HIDDEN_OVERLAY =
            "912 50 0:91 / /system/bin ro,relatime shared:1 - overlay KSU rw,seclabel,lowerdir=/data/adb/modules/mod1/system/bin:/system/bin";
    private static final String MAGISK_HIDDEN_ADB =
            "913 1 0:92 / /data/adb/modules rw,relatime shared:5 - tmpfs magisk rw,seclabel,mode=755";

    @Test
    public void normalizerSortsByPeerGroupMountPointAndMountIdAndStripsDynamicShmemOptions() {
        List<String> viewA = Arrays.asList(
                CLEAN_MOUNT_TMPFS_MNT_A,
                CLEAN_MOUNT_SYSTEM,
                CLEAN_MOUNT_DEV_TMPFS_A,
                CLEAN_MOUNT_ROOTFS_A);
        // Same logical mounts in shuffled order with altered shmem size=/nr_inodes=/nr_blocks=
        List<String> viewB = Arrays.asList(
                CLEAN_MOUNT_ROOTFS_B,
                CLEAN_MOUNT_DEV_TMPFS_B,
                CLEAN_MOUNT_TMPFS_MNT_B,
                CLEAN_MOUNT_SYSTEM);

        List<MountViewNormalizer.ParsedMountEntry> sorted = MountViewNormalizer.normalize(viewA);
        assertEquals(4, sorted.size());
        // peerGroup 1: "/" (id 1) before "/system" (id 50), then peerGroup 2 "/dev", then peerGroup 3 "/mnt"
        assertEquals("/", sorted.get(0).mountPoint);
        assertEquals(1, sorted.get(0).peerGroup);
        assertEquals("/system", sorted.get(1).mountPoint);
        assertEquals(1, sorted.get(1).peerGroup);
        assertEquals("/dev", sorted.get(2).mountPoint);
        assertEquals(2, sorted.get(2).peerGroup);
        assertEquals("/mnt", sorted.get(3).mountPoint);
        assertEquals(3, sorted.get(3).peerGroup);

        MountViewNormalizer.MountDiffResult diff = MountViewNormalizer.diffViews(viewA, viewB);
        assertTrue("Dynamic tmpfs/devtmpfs/rootfs sizing must produce 0 diff entries",
                diff.isIdenticalAfterNormalization());
        assertTrue(diff.getIsolatedOnlyEntries().isEmpty());
        assertTrue(diff.getSuspiciousHiddenMounts().isEmpty());
        assertFalse(diff.hasSelectiveUnmountEvidence());
    }

    @Test
    public void normalizerDetectsSelectiveMainProcessUnmountOfMagiskOrKsuOverlay() {
        List<String> mainLines = Arrays.asList(
                CLEAN_MOUNT_ROOTFS_A,
                CLEAN_MOUNT_SYSTEM,
                CLEAN_MOUNT_DEV_TMPFS_A);
        List<String> isolatedLines = Arrays.asList(
                CLEAN_MOUNT_ROOTFS_B,
                CLEAN_MOUNT_SYSTEM,
                CLEAN_MOUNT_DEV_TMPFS_B,
                SHAMIKO_HIDDEN_OVERLAY,
                MAGISK_HIDDEN_ADB);

        MountViewNormalizer.MountDiffResult diff =
                MountViewNormalizer.diffViews(mainLines, isolatedLines);
        assertFalse(diff.isIdenticalAfterNormalization());
        assertEquals(2, diff.getIsolatedOnlyEntries().size());
        assertEquals(2, diff.getSuspiciousHiddenMounts().size());
        assertTrue(diff.hasSelectiveUnmountEvidence());
        assertTrue(diff.getDirectRootTokens().stream().anyMatch(t -> t.contains("ksu:")));
        assertTrue(diff.getDirectRootTokens().stream().anyMatch(t -> t.contains("magisk:")));
    }

    @Test
    public void normalizerIgnoresLegitimateSandboxStorageMountDifferences() {
        List<String> mainLines = Arrays.asList(CLEAN_MOUNT_ROOTFS_A, CLEAN_MOUNT_SYSTEM);
        // Android 11+ Zygote mounts tmpfs directly onto exact base paths (without trailing slash)
        // as well as child storage paths for isolatedProcess sandboxes.
        String sandboxStorageChild =
                "120 1 0:55 / /storage/emulated/0 rw,nosuid,nodev - fuse /dev/fuse rw,user_id=0";
        String exactStorage =
                "121 1 0:56 / /storage ro,nosuid,nodev - tmpfs tmpfs rw,seclabel,mode=755";
        String exactDataData =
                "122 1 0:57 / /data/data ro,nosuid,nodev - tmpfs tmpfs rw,seclabel,mode=755";
        String exactDataUser =
                "123 1 0:58 / /data/user ro,nosuid,nodev - tmpfs tmpfs rw,seclabel,mode=755";
        String exactDataUserDe =
                "124 1 0:59 / /data/user_de ro,nosuid,nodev - tmpfs tmpfs rw,seclabel,mode=755";
        String exactDataMirror =
                "125 1 0:60 / /data_mirror ro,nosuid,nodev - tmpfs tmpfs rw,seclabel,mode=755";
        List<String> isolatedLines = Arrays.asList(
                CLEAN_MOUNT_ROOTFS_A, CLEAN_MOUNT_SYSTEM,
                sandboxStorageChild, exactStorage, exactDataData,
                exactDataUser, exactDataUserDe, exactDataMirror);

        MountViewNormalizer.MountDiffResult diff =
                MountViewNormalizer.diffViews(mainLines, isolatedLines);
        assertEquals(6, diff.getIsolatedOnlyEntries().size());
        assertTrue("Expected sandbox base & child paths must not trigger suspicious hidden mount",
                diff.getSuspiciousHiddenMounts().isEmpty());
        assertTrue(diff.getDirectRootTokens().isEmpty());
        assertFalse(diff.hasSelectiveUnmountEvidence());
    }

    @Test
    public void normalizerAvoidsFalsePositivesOnBenignKsuSubstringsAndSharedMounts() {
        String benignWorksuite =
                "60 1 253:1 / /data/data/com.worksuite.app rw,relatime shared:4 - ext4 /dev/block/dm-1 rw";
        String benignBanksu =
                "61 1 253:1 / /data/user/0/com.banksu.mobile rw,relatime shared:4 - ext4 /dev/block/dm-1 rw";
        String sharedDebugRamdisk =
                "62 1 0:62 / /debug_ramdisk ro,relatime shared:1 - tmpfs tmpfs ro,seclabel";

        // 1. Identical shared mounts (including shared /debug_ramdisk or benign ksu-substring packages) -> 0 evidence
        List<String> identicalView = Arrays.asList(
                CLEAN_MOUNT_ROOTFS_A, CLEAN_MOUNT_SYSTEM,
                benignWorksuite, benignBanksu, sharedDebugRamdisk);
        MountViewNormalizer.MountDiffResult identicalDiff =
                MountViewNormalizer.diffViews(identicalView, identicalView);
        assertTrue(identicalDiff.isIdenticalAfterNormalization());
        assertTrue(identicalDiff.getDirectRootTokens().isEmpty());
        assertFalse(identicalDiff.hasSelectiveUnmountEvidence());

        // 2. Even if benign worksuite/banksu sandbox path only exists in isolated view, "ksu" substring must NOT trigger
        List<String> mainOnlyBase = Arrays.asList(CLEAN_MOUNT_ROOTFS_A, CLEAN_MOUNT_SYSTEM);
        List<String> isoWithBenign = Arrays.asList(
                CLEAN_MOUNT_ROOTFS_A, CLEAN_MOUNT_SYSTEM, benignWorksuite, benignBanksu);
        MountViewNormalizer.MountDiffResult benignDiff =
                MountViewNormalizer.diffViews(mainOnlyBase, isoWithBenign);
        assertTrue("Benign substrings worksuite/banksu must not match ksu token",
                benignDiff.getDirectRootTokens().isEmpty());
        assertTrue(benignDiff.getSuspiciousHiddenMounts().isEmpty());
        assertFalse(benignDiff.hasSelectiveUnmountEvidence());
    }

    @Test
    public void isolatedProbeServiceFailsClosedWhenNotRunningIsolated() {
        IBinder denied = IsolatedProbeClient.bindServiceForTest(() -> false, new Intent());
        assertNull("onBind() must fail closed when Process.isIsolated() is false", denied);

        IBinder allowed = IsolatedProbeClient.bindServiceForTest(() -> true, new Intent());
        assertNotNull("onBind() should return binder when Process.isIsolated() is true", allowed);
    }

    @Test
    public void clientReturnsUnsupportedWhenDisabledWithoutBinding() {
        AtomicInteger bindCalls = new AtomicInteger();
        Context ctx = stubContext();
        SignalSnapshot signals = new SignalSnapshot(ctx);

        SignalResult<IsolatedProbeClient.IsolatedMountReport> result =
                IsolatedProbeClient.probeMountViewForTest(
                        ctx, signals, false, 500L,
                        new IsolatedProbeClient.ServiceProbeAdapter() {
                            @Override public boolean isServiceDeclared(Context c, Intent i) { return true; }
                            @Override public boolean bind(Context c, Intent i, ServiceConnection conn) {
                                bindCalls.incrementAndGet();
                                return true;
                            }
                            @Override public void unbind(Context c, ServiceConnection conn) {}
                            @Override public String transactMountView(IBinder binder) { return ""; }
                        });

        assertEquals(SignalResult.Status.UNAVAILABLE, result.getStatus());
        assertEquals("isolated_probe_disabled", result.getFailureReason());
        assertEquals(0, bindCalls.get());
    }

    @Test
    public void clientDegradesCleanlyWhenHostStripsServiceViaToolsNodeRemove() {
        AtomicInteger bindCalls = new AtomicInteger();
        Context ctx = stubContext();
        SignalSnapshot signals = new SignalSnapshot(ctx);

        SignalResult<IsolatedProbeClient.IsolatedMountReport> result =
                IsolatedProbeClient.probeMountViewForTest(
                        ctx, signals, true, 500L,
                        new IsolatedProbeClient.ServiceProbeAdapter() {
                            @Override public boolean isServiceDeclared(Context c, Intent i) { return false; }
                            @Override public boolean bind(Context c, Intent i, ServiceConnection conn) {
                                bindCalls.incrementAndGet();
                                return false;
                            }
                            @Override public void unbind(Context c, ServiceConnection conn) {}
                            @Override public String transactMountView(IBinder binder) { return ""; }
                        });

        assertEquals(SignalResult.Status.UNAVAILABLE, result.getStatus());
        assertEquals(0, bindCalls.get());
    }

    @Test
    public void clientAlwaysUnbindsInFinallyAcrossSuccessTimeoutAndTransactFailure() {
        Context ctx = stubContext();
        SignalSnapshot signals = new SignalSnapshot(ctx);
        signals.seedTextFileForTest("/proc/self/mountinfo",
                SignalResult.success(CLEAN_MOUNT_ROOTFS_A + "\n" + CLEAN_MOUNT_SYSTEM));

        // 1. Success path -> returns diff and unbinds exactly once
        AtomicInteger unbindSuccess = new AtomicInteger();
        SignalResult<IsolatedProbeClient.IsolatedMountReport> ok =
                IsolatedProbeClient.probeMountViewForTest(
                        ctx, signals, true, 1000L,
                        new IsolatedProbeClient.ServiceProbeAdapter() {
                            @Override public boolean isServiceDeclared(Context c, Intent i) { return true; }
                            @Override public boolean bind(Context c, Intent i, ServiceConnection conn) {
                                conn.onServiceConnected(
                                        new ComponentName("com.test", "Svc"), new Binder());
                                return true;
                            }
                            @Override public void unbind(Context c, ServiceConnection conn) {
                                unbindSuccess.incrementAndGet();
                            }
                            @Override public String transactMountView(IBinder binder) {
                                return CLEAN_MOUNT_ROOTFS_B + "\n" + CLEAN_MOUNT_SYSTEM
                                        + "\n" + SHAMIKO_HIDDEN_OVERLAY;
                            }
                        });
        assertTrue(ok.isSuccess());
        assertNotNull(ok.getValue());
        assertTrue(ok.getValue().getDiffResult().hasSelectiveUnmountEvidence());
        assertEquals(1, unbindSuccess.get());

        // 2. Connect timeout path -> UNAVAILABLE and still unbinds exactly once
        AtomicInteger unbindTimeout = new AtomicInteger();
        SignalResult<IsolatedProbeClient.IsolatedMountReport> timedOut =
                IsolatedProbeClient.probeMountViewForTest(
                        ctx, signals, true, 80L,
                        new IsolatedProbeClient.ServiceProbeAdapter() {
                            @Override public boolean isServiceDeclared(Context c, Intent i) { return true; }
                            @Override public boolean bind(Context c, Intent i, ServiceConnection conn) {
                                // Never calls onServiceConnected
                                return true;
                            }
                            @Override public void unbind(Context c, ServiceConnection conn) {
                                unbindTimeout.incrementAndGet();
                            }
                            @Override public String transactMountView(IBinder binder) { return ""; }
                        });
        assertEquals(SignalResult.Status.UNAVAILABLE, timedOut.getStatus());
        assertEquals(1, unbindTimeout.get());

        // 3. Binder transact exception path -> ERROR and still unbinds exactly once
        AtomicInteger unbindError = new AtomicInteger();
        SignalResult<IsolatedProbeClient.IsolatedMountReport> err =
                IsolatedProbeClient.probeMountViewForTest(
                        ctx, signals, true, 1000L,
                        new IsolatedProbeClient.ServiceProbeAdapter() {
                            @Override public boolean isServiceDeclared(Context c, Intent i) { return true; }
                            @Override public boolean bind(Context c, Intent i, ServiceConnection conn) {
                                conn.onServiceConnected(
                                        new ComponentName("com.test", "Svc"), new Binder());
                                return true;
                            }
                            @Override public void unbind(Context c, ServiceConnection conn) {
                                unbindError.incrementAndGet();
                            }
                            @Override public String transactMountView(IBinder binder) {
                                throw new RuntimeException("simulated remote binder failure");
                            }
                        });
        assertEquals(SignalResult.Status.ERROR, err.getStatus());
        assertEquals(1, unbindError.get());
    }

    @Test
    public void manifestAndProguardRulesSatisfyIsolatedProcessAndZeroPermissionRedLines()
            throws Exception {
        String manifest = new String(
                Files.readAllBytes(Path.of("src/main/AndroidManifest.xml")),
                StandardCharsets.UTF_8);
        assertFalse("SDK manifest MUST NOT declare <uses-permission>",
                manifest.contains("<uses-permission"));
        assertTrue(manifest.contains(".process.RiskIsolatedProbeService"));
        assertTrue(manifest.contains("android:isolatedProcess=\"true\""));
        assertTrue(manifest.contains("android:exported=\"false\""));

        String rules = new String(
                Files.readAllBytes(Path.of("consumer-rules.pro")),
                StandardCharsets.UTF_8);
        assertTrue(rules.contains(
                "-keep public class com.wsttxm.riskenginesdk.process.RiskIsolatedProbeService { *; }"));
    }

    private static Context stubContext() {
        return new ContextWrapper(null) {
            @Override
            public Context getApplicationContext() {
                return this;
            }
        };
    }
}
