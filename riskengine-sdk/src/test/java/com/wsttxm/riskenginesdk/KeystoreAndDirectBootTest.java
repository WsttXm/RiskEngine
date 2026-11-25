package com.wsttxm.riskenginesdk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;

import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.core.EvidenceFamily;
import com.wsttxm.riskenginesdk.core.FingerprintIdBuilder;
import com.wsttxm.riskenginesdk.core.FingerprintStore;
import com.wsttxm.riskenginesdk.core.KeystoreBackingStore;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.DevicePosture;
import com.wsttxm.riskenginesdk.model.FingerprintId;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.util.RiskReportJsonSerializer;

import org.json.JSONObject;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pure-JVM verification suite for Phase 1 P1-4:
 * - AES-256-GCM wrapping with random 12-byte IV, 128-bit tag, and AAD binding
 * - StrongBoxUnavailableException -> TEE fallback and KeyInfo security level tracking
 * - device_binding_broken detection on cloned/missing key and tampered ciphertext (HIGH/8)
 * - DirectBoot locked user safety (never calls moveSharedPreferencesFrom) and one-time CE->DE migration
 * - KeyPermanentlyInvalidatedException sentinel surfacing lockscreen_or_biometric_reset
 */
public class KeystoreAndDirectBootTest {

    @Test
    public void aesGcmRoundTripUsesRandom12ByteIv128BitTagAndAadBinding() {
        InMemoryKeyProvider provider = new InMemoryKeyProvider(false, false);
        KeystoreBackingStore store = new KeystoreBackingStore(provider);

        String plaintext = "anchor-hw-digest-测试-1234567890abcdef";
        String wrapped1 = store.wrap(plaintext, "anchor_hw");
        String wrapped2 = store.wrap(plaintext, "anchor_hw");

        assertNotNull(wrapped1);
        assertNotNull(wrapped2);
        assertTrue(KeystoreBackingStore.isWrapped(wrapped1));
        assertNotEquals("Each AES-GCM encryption must generate a fresh random IV",
                wrapped1, wrapped2);

        // Verify envelope format: v2gcm:<12B IV>:<ciphertext + 16B tag>
        String body = wrapped1.substring(KeystoreBackingStore.ENVELOPE_PREFIX.length());
        String[] parts = body.split(":");
        assertEquals(2, parts.length);
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] ct = Base64.getDecoder().decode(parts[1]);
        assertEquals("GCM IV must be exactly 12 bytes", 12, iv.length);
        assertEquals("GCM ciphertext must equal plaintext UTF-8 length + 16-byte 128-bit tag",
                plaintext.getBytes(StandardCharsets.UTF_8).length + 16, ct.length);

        KeystoreBackingStore.UnwrapResult ok1 = store.unwrap(wrapped1, "anchor_hw");
        KeystoreBackingStore.UnwrapResult ok2 = store.unwrap(wrapped2, "anchor_hw");
        assertEquals(KeystoreBackingStore.UnwrapStatus.OK, ok1.getStatus());
        assertEquals(plaintext, ok1.getPlaintext());
        assertEquals(KeystoreBackingStore.UnwrapStatus.OK, ok2.getStatus());
        assertEquals(plaintext, ok2.getPlaintext());
        assertEquals(DevicePosture.KeystoreSecurityLevel.STRONGBOX, store.getSecurityLevel());

        // Cross-field AAD substitution must fail GCM authentication.
        KeystoreBackingStore.UnwrapResult wrongAad = store.unwrap(wrapped1, "salt");
        assertEquals(KeystoreBackingStore.UnwrapStatus.TAMPERED_OR_AUTH_FAILED,
                wrongAad.getStatus());
        assertTrue(wrongAad.isDeviceBindingBroken());
        assertEquals("gcm_auth_tag_failed", wrongAad.getReason());
    }

    @Test
    public void strongBoxUnavailableExceptionFallsBackToTeeAndRecordsSecurityLevel() {
        InMemoryKeyProvider provider = new InMemoryKeyProvider(true, false);
        KeystoreBackingStore store = new KeystoreBackingStore(provider);

        String wrapped = store.wrap("secret-salt-value", "salt");
        assertNotNull(wrapped);
        assertTrue("StrongBox fallback flag must be set", store.wasStrongBoxFallbackTriggered());
        assertEquals(1, provider.strongBoxAttempts.get());
        assertEquals(1, provider.teeAttempts.get());
        assertEquals(DevicePosture.KeystoreSecurityLevel.TEE, store.getSecurityLevel());

        KeystoreBackingStore.UnwrapResult unwrapped = store.unwrap(wrapped, "salt");
        assertEquals(KeystoreBackingStore.UnwrapStatus.OK, unwrapped.getStatus());
        assertEquals("secret-salt-value", unwrapped.getPlaintext());
    }

    @Test
    public void missingKeyOnClonedDeviceTriggersDeviceBindingBrokenHigh8WithoutOverwritingAnchor() {
        InMemorySharedPreferences clonedPrefs = new InMemorySharedPreferences();
        InMemoryKeyProvider sourceDeviceKeys = new InMemoryKeyProvider(false, false);
        FingerprintStore sourceStore = new FingerprintStore(
                clonedPrefs, new KeystoreBackingStore(sourceDeviceKeys));

        List<CollectorResult> collectors = buildSampleCollectors("Adreno 750", "build-1");
        DataAggregator sourceAggregator = new DataAggregator(sourceStore);
        RiskReport firstReport = sourceAggregator.aggregate(
                collectors, List.of(), CollectScene.STANDARD);
        assertEquals(RiskLevel.SAFE, firstReport.getOverallRiskLevel());

        String originalAnchorCipher = clonedPrefs.getString("anchor_hw", "");
        String originalSaltCipher = clonedPrefs.getString("salt", "");
        assertTrue("anchor_hw must be stored encrypted",
                KeystoreBackingStore.isWrapped(originalAnchorCipher));
        assertTrue("salt must be stored encrypted",
                KeystoreBackingStore.isWrapped(originalSaltCipher));

        // Simulate copying riskengine_fp.xml onto another physical device whose Keystore
        // does not have riskengine_fp_wrap_key.
        InMemoryKeyProvider targetDeviceKeys = new InMemoryKeyProvider(false, false);
        FingerprintStore clonedStore = new FingerprintStore(
                clonedPrefs, new KeystoreBackingStore(targetDeviceKeys));
        DataAggregator clonedAggregator = new DataAggregator(clonedStore);

        for (int attempt = 1; attempt <= 2; attempt++) {
            RiskReport report = clonedAggregator.aggregate(
                    collectors, List.of(), CollectScene.STANDARD);
            DetectionResult continuity = findDetector(report, "fingerprint_continuity");
            assertNotNull("Attempt " + attempt + " must emit fingerprint_continuity", continuity);
            assertEquals(RiskLevel.HIGH, continuity.getRiskLevel());
            assertEquals(DetectionStatus.DANGER, continuity.getStatus());
            assertEquals(8, continuity.getScore());
            assertFalse("device_binding_broken must be actionable in STANDARD",
                    continuity.isInformational());
            assertTrue(continuity.getDetails().contains("device_binding_broken"));
            assertTrue(continuity.getDetails().contains("device_binding_reason:keystore_key_missing"));
            assertTrue(EvidenceFamily.families(continuity.getDetails()).contains("device_binding"));
            assertEquals(RiskLevel.HIGH, report.getOverallRiskLevel());
            assertEquals(72, report.getRiskScore());
        }

        // Neither salt nor anchor_hw may be auto-overwritten on device_binding_broken.
        assertEquals(originalAnchorCipher, clonedPrefs.getString("anchor_hw", ""));
        assertEquals(originalSaltCipher, clonedPrefs.getString("salt", ""));
        assertEquals("Must never auto-generate replacement key during unwrap",
                0, targetDeviceKeys.strongBoxAttempts.get() + targetDeviceKeys.teeAttempts.get());
    }

    @Test
    public void tamperedCiphertextTriggersDeviceBindingBrokenHigh8AndPreservesAnchor() {
        InMemorySharedPreferences prefs = new InMemorySharedPreferences();
        InMemoryKeyProvider provider = new InMemoryKeyProvider(false, false);
        FingerprintStore store = new FingerprintStore(prefs, new KeystoreBackingStore(provider));

        List<CollectorResult> collectors = buildSampleCollectors("Adreno 750", "build-1");
        DataAggregator aggregator = new DataAggregator(store);
        RiskReport baseline = aggregator.aggregate(collectors, List.of(), CollectScene.STANDARD);
        assertEquals(RiskLevel.SAFE, baseline.getOverallRiskLevel());

        // Flip a byte in the GCM authentication tag of anchor_hw.
        String originalAnchor = prefs.getString("anchor_hw", "");
        String tamperedAnchor = flipLastCiphertextByte(originalAnchor);
        prefs.edit().putString("anchor_hw", tamperedAnchor).commit();

        RiskReport tamperedReport = aggregator.aggregate(
                collectors, List.of(), CollectScene.PAYMENT);
        DetectionResult continuity = findDetector(tamperedReport, "fingerprint_continuity");
        assertNotNull(continuity);
        assertEquals(RiskLevel.HIGH, continuity.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, continuity.getStatus());
        assertEquals(8, continuity.getScore());
        assertFalse(continuity.isInformational());
        assertTrue(continuity.getDetails().contains("device_binding_broken"));
        assertTrue(continuity.getDetails().contains("device_binding_reason:gcm_auth_tag_failed"));
        assertTrue(EvidenceFamily.families(continuity.getDetails()).contains("device_binding"));
        // Tampered anchor remains untouched (not laundered).
        assertEquals(tamperedAnchor, prefs.getString("anchor_hw", ""));
    }

    @Test
    public void directBootLockedUserNeverCallsMoveSharedPreferencesFromAndNeverCrashes() {
        InMemorySharedPreferences cePrefs = new InMemorySharedPreferences();
        cePrefs.edit().putString("salt", "legacy-ce-salt").commit();
        InMemorySharedPreferences dePrefs = new InMemorySharedPreferences();
        AtomicBoolean unlocked = new AtomicBoolean(false);
        DirectBootTestContext ceContext = new DirectBootTestContext(cePrefs, dePrefs, unlocked);

        InMemoryKeyProvider provider = new InMemoryKeyProvider(false, false);
        FingerprintStore store = new FingerprintStore(
                ceContext,
                new KeystoreBackingStore(provider),
                ctx -> unlocked.get());

        // Under DirectBoot (locked user), CE access would throw IllegalStateException.
        // Store must use DE storage cleanly and never call moveSharedPreferencesFrom.
        String salt = store.getOrCreateSalt();
        assertNotNull(salt);
        assertFalse(salt.isEmpty());
        assertNotEquals("Must not read CE salt while locked", "legacy-ce-salt", salt);
        assertEquals("moveSharedPreferencesFrom must NEVER be called while locked",
                0, ceContext.movePrefsCallCount.get());
        assertEquals("CE SharedPreferences must NEVER be touched while locked",
                0, ceContext.cePrefsAccessCount.get());
        assertTrue("DE storage must hold wrapped salt",
                KeystoreBackingStore.isWrapped(dePrefs.getString("salt", "")));

        FingerprintId id = FingerprintIdBuilder.build(
                buildSampleFingerprint("Adreno 750", "build-1"), salt);
        FingerprintStore.Continuity continuity = store.recordAndCompare(id);
        assertEquals(FingerprintStore.State.FIRST_OBSERVATION, continuity.getState());
        assertFalse(continuity.isDeviceBindingBroken());
        assertEquals(0, ceContext.movePrefsCallCount.get());
    }

    @Test
    public void unlockedUserPerformsOneTimeCeToDeMigrationWithoutRepeating() {
        InMemorySharedPreferences cePrefs = new InMemorySharedPreferences();
        InMemorySharedPreferences dePrefs = new InMemorySharedPreferences();

        // Seed legacy CE store with salt + hardware anchor before v2 upgrade.
        String legacySalt = "0123456789abcdef0123456789abcdef";
        FingerprintId legacyId = FingerprintIdBuilder.build(
                buildSampleFingerprint("Adreno 750", "build-1"), legacySalt);
        cePrefs.edit()
                .putString("salt", legacySalt)
                .putString("anchor_hw", legacyId.getHardwareId())
                .putString("anchor_hw_buckets", encodeBuckets(legacyId.getHardwareBucketDigests()))
                .putString("last_hw", legacyId.getHardwareId())
                .putString("last_hw_buckets", encodeBuckets(legacyId.getHardwareBucketDigests()))
                .putString("last_sys", legacyId.getSystemId())
                .commit();

        AtomicBoolean unlocked = new AtomicBoolean(true);
        DirectBootTestContext ceContext = new DirectBootTestContext(cePrefs, dePrefs, unlocked);
        InMemoryKeyProvider provider = new InMemoryKeyProvider(false, false);

        FingerprintStore store = new FingerprintStore(
                ceContext,
                new KeystoreBackingStore(provider),
                ctx -> unlocked.get());

        // First unlocked access migrates CE -> DE exactly once and preserves the legacy salt.
        assertEquals(legacySalt, store.getOrCreateSalt());
        assertEquals("Unlocked user must perform one-time CE->DE migration",
                1, ceContext.movePrefsCallCount.get());
        assertTrue(cePrefs.getAll().isEmpty());

        FingerprintStore.Continuity continuity = store.recordAndCompare(legacyId);
        assertEquals(FingerprintStore.State.STABLE, continuity.getState());
        assertFalse(continuity.isDeviceBindingBroken());
        assertEquals(1, ceContext.movePrefsCallCount.get());

        // Subsequent cold start with a new FingerprintStore instance must NOT repeat migration.
        FingerprintStore restartedStore = new FingerprintStore(
                ceContext,
                new KeystoreBackingStore(provider),
                ctx -> unlocked.get());
        assertEquals(legacySalt, restartedStore.getOrCreateSalt());
        assertEquals("Persisted de_migrated_v2 flag prevents repeated migration",
                1, ceContext.movePrefsCallCount.get());
    }

    @Test
    public void keyPermanentlyInvalidatedExceptionSurfacesLockscreenOrBiometricReset()
            throws Exception {
        InMemorySharedPreferences prefs = new InMemorySharedPreferences();
        InMemoryKeyProvider provider = new InMemoryKeyProvider(false, true);
        KeystoreBackingStore backingStore = new KeystoreBackingStore(provider);
        FingerprintStore store = new FingerprintStore(prefs, backingStore);

        assertEquals(KeystoreBackingStore.SentinelStatus.PERMANENTLY_INVALIDATED,
                backingStore.probeLockscreenSentinel());

        List<CollectorResult> collectors = buildSampleCollectors("Adreno 750", "build-1");
        RiskReport report = new DataAggregator(store).aggregate(
                collectors, List.of(), CollectScene.STANDARD);

        // Lockscreen/biometric reset is a security posture signal, NOT device_binding_broken.
        assertEquals(RiskLevel.SAFE, report.getOverallRiskLevel());
        assertTrue(report.getDevicePosture().isLockscreenOrBiometricReset());
        assertEquals("true",
                report.getFingerprint().getResults().get("fingerprint_id")
                        .getValues().get("lockscreen_or_biometric_reset"));

        JSONObject json = new JSONObject(RiskReportJsonSerializer.serialize(report));
        assertTrue(json.getJSONObject("devicePosture").getBoolean("lockscreenOrBiometricReset"));
    }

    @Test
    public void explicitResetFingerprintBaselineRecoversAfterBrokenBinding() {
        InMemorySharedPreferences prefs = new InMemorySharedPreferences();
        FingerprintStore sourceStore = new FingerprintStore(
                prefs, new KeystoreBackingStore(new InMemoryKeyProvider(false, false)));
        List<CollectorResult> collectors = buildSampleCollectors("Adreno 750", "build-1");
        new DataAggregator(sourceStore).aggregate(collectors, List.of(), CollectScene.STANDARD);

        // Cloned onto new device -> broken binding.
        FingerprintStore newDeviceStore = new FingerprintStore(
                prefs, new KeystoreBackingStore(new InMemoryKeyProvider(false, false)));
        RiskReport broken = new DataAggregator(newDeviceStore).aggregate(
                collectors, List.of(), CollectScene.STANDARD);
        assertEquals(RiskLevel.HIGH, broken.getOverallRiskLevel());

        // Host explicitly confirms legitimate replacement and resets baseline.
        newDeviceStore.resetBaseline();

        RiskReport fresh = new DataAggregator(newDeviceStore).aggregate(
                collectors, List.of(), CollectScene.STANDARD);
        assertEquals(RiskLevel.SAFE, fresh.getOverallRiskLevel());
        assertEquals("FIRST_OBSERVATION",
                fresh.getFingerprint().getResults().get("fingerprint_id")
                        .getValues().get("continuity"));
    }

    @Test
    public void transientKeystoreWrapFailureOnBoundDeviceDoesNotWritePlaintextOrFalseTriggerBrokenBinding() {
        InMemorySharedPreferences prefs = new InMemorySharedPreferences();
        InMemoryKeyProvider provider = new InMemoryKeyProvider(false, false);
        FingerprintStore store = new FingerprintStore(prefs, new KeystoreBackingStore(provider));
        DataAggregator aggregator = new DataAggregator(store);

        List<CollectorResult> collectors = buildSampleCollectors("Adreno 750", "build-1");
        RiskReport first = aggregator.aggregate(collectors, List.of(), CollectScene.STANDARD);
        assertEquals(RiskLevel.SAFE, first.getOverallRiskLevel());
        assertTrue(prefs.getBoolean("keystore_bound", false));

        String anchorCipherBefore = prefs.getString("anchor_hw", "");
        String lastHwCipherBefore = prefs.getString("last_hw", "");
        assertTrue(KeystoreBackingStore.isWrapped(anchorCipherBefore));
        assertTrue(KeystoreBackingStore.isWrapped(lastHwCipherBefore));

        // Simulate transient keystore2/HAL failure occurring during wrap() after unwrap() succeeds:
        // first 7 loadKey calls succeed (getOrCreateSalt + 6 readProtectedValue checks),
        // subsequent loadKey/generateKey calls throw ProviderException transiently.
        provider.loadCallCount.set(0);
        provider.failAfterLoadCalls.set(7);
        RiskReport duringOutage = aggregator.aggregate(collectors, List.of(), CollectScene.STANDARD);
        assertTrue("Test must actually trigger transient wrap outage",
                provider.loadCallCount.get() > 7);
        assertEquals("Transient wrap failure must NOT falsely escalate to DANGER",
                RiskLevel.SAFE, duringOutage.getOverallRiskLevel());
        assertTrue("anchor_hw must remain ciphertext on disk",
                KeystoreBackingStore.isWrapped(prefs.getString("anchor_hw", "")));
        assertTrue("last_hw must remain ciphertext on disk",
                KeystoreBackingStore.isWrapped(prefs.getString("last_hw", "")));
        assertEquals(anchorCipherBefore, prefs.getString("anchor_hw", ""));
        assertEquals(lastHwCipherBefore, prefs.getString("last_hw", ""));

        // Once keystore recovers, subsequent observations remain STABLE with zero false positives.
        provider.failAfterLoadCalls.set(-1);
        RiskReport recovered = aggregator.aggregate(collectors, List.of(), CollectScene.STANDARD);
        assertEquals(RiskLevel.SAFE, recovered.getOverallRiskLevel());
        assertEquals("STABLE",
                recovered.getFingerprint().getResults().get("fingerprint_id")
                        .getValues().get("continuity"));
        assertEquals("false",
                recovered.getFingerprint().getResults().get("fingerprint_id")
                        .getValues().get("device_binding_broken"));
    }

    @Test
    public void deletingSaltFromKeystoreBoundStoreTriggersDeviceBindingBrokenWithoutGeneratingNewKey() {
        InMemorySharedPreferences prefs = new InMemorySharedPreferences();
        InMemoryKeyProvider sourceProvider = new InMemoryKeyProvider(false, false);
        FingerprintStore sourceStore = new FingerprintStore(
                prefs, new KeystoreBackingStore(sourceProvider));
        List<CollectorResult> collectors = buildSampleCollectors("Adreno 750", "build-1");
        RiskReport initial = new DataAggregator(sourceStore).aggregate(
                collectors, List.of(), CollectScene.STANDARD);
        assertEquals(RiskLevel.SAFE, initial.getOverallRiskLevel());
        String originalAnchorCipher = prefs.getString("anchor_hw", "");

        // Attacker deletes only the salt entry from riskengine_fp.xml.
        prefs.edit().remove("salt").commit();

        // Case 1: Same device (key exists) -> must still report device_binding_broken HIGH/8.
        RiskReport localTamper = new DataAggregator(sourceStore).aggregate(
                collectors, List.of(), CollectScene.STANDARD);
        DetectionResult localContinuity = findDetector(localTamper, "fingerprint_continuity");
        assertNotNull(localContinuity);
        assertEquals(RiskLevel.HIGH, localContinuity.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, localContinuity.getStatus());
        assertEquals(8, localContinuity.getScore());
        assertTrue(localContinuity.getDetails().contains("device_binding_broken"));
        assertTrue(localContinuity.getDetails().contains("device_binding_reason:salt_missing_tamper"));
        assertEquals(originalAnchorCipher, prefs.getString("anchor_hw", ""));
        assertFalse("Deleted salt must not be silently recreated", prefs.contains("salt"));

        // Case 2: Cloned XML (with salt deleted) onto a new device with empty Keystore ->
        // getOrCreateSalt() must NOT generate a replacement key on target device.
        InMemoryKeyProvider targetProvider = new InMemoryKeyProvider(false, false);
        FingerprintStore targetStore = new FingerprintStore(
                prefs, new KeystoreBackingStore(targetProvider));
        RiskReport clonedTamper = new DataAggregator(targetStore).aggregate(
                collectors, List.of(), CollectScene.STANDARD);
        DetectionResult clonedContinuity = findDetector(clonedTamper, "fingerprint_continuity");
        assertNotNull(clonedContinuity);
        assertEquals(RiskLevel.HIGH, clonedContinuity.getRiskLevel());
        assertEquals(8, clonedContinuity.getScore());
        assertTrue(clonedContinuity.getDetails().contains("device_binding_broken"));
        assertEquals("Target device must NOT generate a replacement key when salt was stripped",
                0, targetProvider.strongBoxAttempts.get() + targetProvider.teeAttempts.get());
        assertEquals(originalAnchorCipher, prefs.getString("anchor_hw", ""));
    }

    @Test
    public void keyInfoMeasuredSecurityLevelOverridesHeuristicSecurityPosture() {
        // Case 1: SecurityPostureCollector heuristically reports STRONGBOX, but Keystore falls back to TEE.
        InMemorySharedPreferences prefsTee = new InMemorySharedPreferences();
        InMemoryKeyProvider teeFallbackProvider = new InMemoryKeyProvider(true, false);
        FingerprintStore teeStore = new FingerprintStore(
                prefsTee, new KeystoreBackingStore(teeFallbackProvider));

        CollectorResult heuristicStrongBox = new CollectorResult("security_posture");
        heuristicStrongBox.addValue("keystore_level", "STRONGBOX");
        heuristicStrongBox.addValue("device_secure", "true");
        List<CollectorResult> withStrongBoxGuess = new java.util.ArrayList<>(
                buildSampleCollectors("Adreno 750", "build-1"));
        withStrongBoxGuess.add(heuristicStrongBox);

        RiskReport teeReport = new DataAggregator(teeStore).aggregate(
                withStrongBoxGuess, List.of(), CollectScene.STANDARD);
        assertEquals("Measured KeyInfo TEE must override heuristic STRONGBOX",
                DevicePosture.KeystoreSecurityLevel.TEE,
                teeReport.getDevicePosture().getKeystoreSecurityLevel());

        // Case 2: SecurityPostureCollector heuristically reports TEE, but KeyInfo measures SOFTWARE.
        InMemorySharedPreferences prefsSw = new InMemorySharedPreferences();
        InMemoryKeyProvider swProvider = new InMemoryKeyProvider(true, false);
        swProvider.overrideSecurityLevel = DevicePosture.KeystoreSecurityLevel.SOFTWARE;
        FingerprintStore swStore = new FingerprintStore(
                prefsSw, new KeystoreBackingStore(swProvider));

        CollectorResult heuristicTee = new CollectorResult("security_posture");
        heuristicTee.addValue("keystore_level", "TEE");
        heuristicTee.addValue("device_secure", "true");
        List<CollectorResult> withTeeGuess = new java.util.ArrayList<>(
                buildSampleCollectors("Adreno 750", "build-1"));
        withTeeGuess.add(heuristicTee);

        RiskReport swReport = new DataAggregator(swStore).aggregate(
                withTeeGuess, List.of(), CollectScene.STANDARD);
        assertEquals("Measured KeyInfo SOFTWARE must override heuristic TEE",
                DevicePosture.KeystoreSecurityLevel.SOFTWARE,
                swReport.getDevicePosture().getKeystoreSecurityLevel());
        assertFalse(swReport.getDevicePosture().isHardwareKeystoreBacked());
    }

    @Test
    public void directBootLockedThenUnlockedPerformsOneTimeMigrationAndRetriesOnFailure() {
        InMemorySharedPreferences cePrefs = new InMemorySharedPreferences();
        InMemorySharedPreferences dePrefs = new InMemorySharedPreferences();
        String legacySalt = "abcdef0123456789abcdef0123456789";
        cePrefs.edit().putString("salt", legacySalt).commit();

        AtomicBoolean unlocked = new AtomicBoolean(false);
        DirectBootTestContext ceContext = new DirectBootTestContext(cePrefs, dePrefs, unlocked);
        FingerprintStore store = new FingerprintStore(
                ceContext,
                new KeystoreBackingStore(new InMemoryKeyProvider(false, false)),
                ctx -> unlocked.get());

        // Phase 1: Locked (DirectBoot) -> read-only probe does NOT call moveSharedPreferencesFrom.
        FingerprintId sampleId = FingerprintIdBuilder.build(
                buildSampleFingerprint("Adreno 750", "build-1"), legacySalt);
        store.recordAndCompare(null);
        assertEquals(0, ceContext.movePrefsCallCount.get());
        assertFalse(dePrefs.getBoolean("de_migrated_v2", false));

        // Phase 2: User unlocks, but first migration attempt returns false -> marker NOT persisted.
        unlocked.set(true);
        ceContext.failNextMove.set(true);
        store.recordAndCompare(null);
        assertEquals(1, ceContext.movePrefsCallCount.get());
        assertFalse("Failed migration must not permanently set de_migrated_v2",
                dePrefs.getBoolean("de_migrated_v2", false));

        // Phase 3: Next cold-start instance retries migration once and succeeds.
        ceContext.failNextMove.set(false);
        FingerprintStore restarted = new FingerprintStore(
                ceContext,
                new KeystoreBackingStore(new InMemoryKeyProvider(false, false)),
                ctx -> unlocked.get());
        assertEquals(legacySalt, restarted.getOrCreateSalt());
        assertEquals(2, ceContext.movePrefsCallCount.get());
        assertTrue(dePrefs.getBoolean("de_migrated_v2", false));
        assertNotNull(restarted.recordAndCompare(sampleId));
        assertEquals("Migration must not repeat after de_migrated_v2 is persisted",
                2, ceContext.movePrefsCallCount.get());
    }

    private static String flipLastCiphertextByte(String envelope) {
        String body = envelope.substring(KeystoreBackingStore.ENVELOPE_PREFIX.length());
        int sep = body.indexOf(':');
        String ivPart = body.substring(0, sep);
        byte[] ct = Base64.getDecoder().decode(body.substring(sep + 1));
        ct[ct.length - 1] ^= 0x01;
        return KeystoreBackingStore.ENVELOPE_PREFIX
                + ivPart + ":"
                + Base64.getEncoder().withoutPadding().encodeToString(ct);
    }

    private static DetectionResult findDetector(RiskReport report, String name) {
        for (DetectionResult d : report.getDetections()) {
            if (name.equals(d.getDetectorName())) {
                return d;
            }
        }
        return null;
    }

    private static String encodeBuckets(Map<String, String> buckets) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : buckets.entrySet()) {
            if (sb.length() > 0) sb.append(';');
            sb.append(entry.getKey()).append('=').append(entry.getValue());
        }
        return sb.toString();
    }

    private static List<CollectorResult> buildSampleCollectors(String gpuRenderer,
                                                               String systemBuild) {
        CollectorResult gpu = new CollectorResult("gpu_info");
        gpu.addValue("vendor", "Qualcomm");
        gpu.addValue("renderer", gpuRenderer);
        gpu.addValue("extensions_hash", "ext-hash-1");
        gpu.addValue("max_texture_size", "16384");

        CollectorResult sensor = new CollectorResult("sensor_fingerprint");
        sensor.addValue("tuple_hash", "sensor-tuple-1");
        sensor.addValue("vendor_hash", "sensor-vendor-1");

        CollectorResult hw = new CollectorResult("hardware_profile");
        hw.addValue("camera_profile_hash", "cam-hash-1");
        hw.addValue("ram_total_mb_bucket", "12288");
        hw.addValue("battery_technology", "Li-ion");

        CollectorResult cpu = new CollectorResult("cpu_topology");
        cpu.addValue("core_distribution", "0x41|0xd80");
        cpu.addValue("freq_clusters", "300000-2000000,710000-3200000");
        cpu.addValue("soc_model", "SM8650");
        cpu.addValue("soc_manufacturer", "QTI");

        CollectorResult build = new CollectorResult("build_props");
        build.addValue("fingerprint",
                "google/husky/husky:15/" + systemBuild + "/1:user/release-keys");

        return List.of(gpu, sensor, hw, cpu, build);
    }

    private static DeviceFingerprint buildSampleFingerprint(String gpuRenderer, String systemBuild) {
        DeviceFingerprint fp = new DeviceFingerprint();
        for (CollectorResult cr : buildSampleCollectors(gpuRenderer, systemBuild)) {
            fp.addResult(cr);
        }
        return fp;
    }

    /** JVM stand-ins mirroring AndroidKeyStore exception names when android.jar stubs throw. */
    private static final class StrongBoxUnavailableException extends ProviderException {
        StrongBoxUnavailableException(String message) {
            super(message);
        }
    }

    private static final class KeyPermanentlyInvalidatedException extends InvalidKeyException {
        KeyPermanentlyInvalidatedException(String message) {
            super(message);
        }
    }

    private static final class InMemoryKeyProvider implements KeystoreBackingStore.KeyProvider {
        private final boolean failStrongBox;
        private final boolean invalidateSentinel;
        private final Map<String, SecretKey> keys = new HashMap<>();
        private final Map<String, DevicePosture.KeystoreSecurityLevel> levels = new HashMap<>();
        private final SecureRandom random = new SecureRandom();
        final AtomicInteger strongBoxAttempts = new AtomicInteger(0);
        final AtomicInteger teeAttempts = new AtomicInteger(0);
        final AtomicInteger loadCallCount = new AtomicInteger(0);
        final AtomicInteger failAfterLoadCalls = new AtomicInteger(-1);
        volatile DevicePosture.KeystoreSecurityLevel overrideSecurityLevel;

        InMemoryKeyProvider(boolean failStrongBox, boolean invalidateSentinel) {
            this.failStrongBox = failStrongBox;
            this.invalidateSentinel = invalidateSentinel;
        }

        private void checkTransientOutage() {
            int limit = failAfterLoadCalls.get();
            if (limit >= 0 && loadCallCount.get() >= limit) {
                throw new ProviderException("Simulated transient keystore2 outage");
            }
        }

        @Override
        public SecretKey loadKey(String alias) {
            int limit = failAfterLoadCalls.get();
            if (limit >= 0 && loadCallCount.getAndIncrement() >= limit) {
                throw new ProviderException("Simulated transient keystore2 outage");
            }
            return keys.get(alias);
        }

        @Override
        public SecretKey generateKey(String alias, boolean strongBoxBacked) {
            checkTransientOutage();
            if (strongBoxBacked) {
                strongBoxAttempts.incrementAndGet();
                if (failStrongBox) {
                    throw new StrongBoxUnavailableException("No StrongBox HAL");
                }
            } else {
                teeAttempts.incrementAndGet();
            }
            byte[] raw = new byte[32];
            random.nextBytes(raw);
            SecretKeySpec key = new SecretKeySpec(raw, "AES");
            keys.put(alias, key);
            levels.put(alias, overrideSecurityLevel != null
                    ? overrideSecurityLevel
                    : (strongBoxBacked
                            ? DevicePosture.KeystoreSecurityLevel.STRONGBOX
                            : DevicePosture.KeystoreSecurityLevel.TEE));
            return key;
        }

        @Override
        public DevicePosture.KeystoreSecurityLevel querySecurityLevel(
                SecretKey key, boolean createdWithStrongBox) {
            if (overrideSecurityLevel != null) {
                return overrideSecurityLevel;
            }
            for (Map.Entry<String, SecretKey> entry : keys.entrySet()) {
                if (entry.getValue() == key) {
                    return levels.getOrDefault(entry.getKey(),
                            DevicePosture.KeystoreSecurityLevel.UNKNOWN);
                }
            }
            return createdWithStrongBox
                    ? DevicePosture.KeystoreSecurityLevel.STRONGBOX
                    : DevicePosture.KeystoreSecurityLevel.TEE;
        }

        @Override
        public boolean callerProvidesIv() {
            return true;
        }

        @Override
        public KeystoreBackingStore.SentinelStatus probeSentinelKey(String alias) throws Exception {
            if (invalidateSentinel) {
                throw new KeyPermanentlyInvalidatedException("Biometric enrollment changed");
            }
            return KeystoreBackingStore.SentinelStatus.INTACT;
        }
    }

    private static final class DirectBootTestContext extends ContextWrapper {
        private final InMemorySharedPreferences cePrefs;
        private final InMemorySharedPreferences dePrefs;
        private final AtomicBoolean unlocked;
        private final DeviceProtectedTestContext deContext;
        final AtomicInteger movePrefsCallCount = new AtomicInteger(0);
        final AtomicInteger cePrefsAccessCount = new AtomicInteger(0);
        final AtomicBoolean failNextMove = new AtomicBoolean(false);

        DirectBootTestContext(InMemorySharedPreferences cePrefs,
                              InMemorySharedPreferences dePrefs,
                              AtomicBoolean unlocked) {
            super(null);
            this.cePrefs = cePrefs;
            this.dePrefs = dePrefs;
            this.unlocked = unlocked;
            this.deContext = new DeviceProtectedTestContext(this);
        }

        @Override public Context getApplicationContext() { return this; }
        @Override public String getPackageName() { return "com.wsttxm.riskenginesdk.test"; }
        @Override public boolean isDeviceProtectedStorage() { return false; }
        @Override public Context createDeviceProtectedStorageContext() { return deContext; }

        @Override
        public SharedPreferences getSharedPreferences(String name, int mode) {
            cePrefsAccessCount.incrementAndGet();
            if (!unlocked.get()) {
                throw new IllegalStateException(
                        "SharedPreferences in credential encrypted storage are not available "
                                + "until after user is unlocked");
            }
            return cePrefs;
        }
    }

    private static final class DeviceProtectedTestContext extends ContextWrapper {
        private final DirectBootTestContext parent;

        DeviceProtectedTestContext(DirectBootTestContext parent) {
            super(null);
            this.parent = parent;
        }

        @Override public Context getApplicationContext() { return this; }
        @Override public String getPackageName() { return parent.getPackageName(); }
        @Override public boolean isDeviceProtectedStorage() { return true; }
        @Override public Context createDeviceProtectedStorageContext() { return this; }

        @Override
        public SharedPreferences getSharedPreferences(String name, int mode) {
            return parent.dePrefs;
        }

        @Override
        public boolean moveSharedPreferencesFrom(Context sourceContext, String name) {
            parent.movePrefsCallCount.incrementAndGet();
            if (!parent.unlocked.get()) {
                throw new IllegalStateException(
                        "Cannot migrate CE SharedPreferences while user is locked");
            }
            if (parent.failNextMove.get()) {
                return false;
            }
            SharedPreferences.Editor deEditor = parent.dePrefs.edit();
            for (Map.Entry<String, ?> entry : parent.cePrefs.getAll().entrySet()) {
                Object val = entry.getValue();
                if (val instanceof String) deEditor.putString(entry.getKey(), (String) val);
                else if (val instanceof Integer) deEditor.putInt(entry.getKey(), (Integer) val);
                else if (val instanceof Long) deEditor.putLong(entry.getKey(), (Long) val);
                else if (val instanceof Boolean) deEditor.putBoolean(entry.getKey(), (Boolean) val);
            }
            deEditor.commit();
            parent.cePrefs.edit().clear().commit();
            return true;
        }
    }

    private static final class InMemorySharedPreferences implements SharedPreferences {
        private final Map<String, Object> data = new HashMap<>();

        @Override public Map<String, ?> getAll() { return new HashMap<>(data); }
        @Override public String getString(String key, String defValue) {
            Object v = data.get(key);
            return v instanceof String ? (String) v : defValue;
        }
        @Override @SuppressWarnings("unchecked")
        public Set<String> getStringSet(String key, Set<String> defValues) {
            Object v = data.get(key);
            return v instanceof Set ? new HashSet<>((Set<String>) v) : defValues;
        }
        @Override public int getInt(String key, int defValue) {
            Object v = data.get(key);
            return v instanceof Integer ? (Integer) v : defValue;
        }
        @Override public long getLong(String key, long defValue) {
            Object v = data.get(key);
            return v instanceof Long ? (Long) v : defValue;
        }
        @Override public float getFloat(String key, float defValue) {
            Object v = data.get(key);
            return v instanceof Float ? (Float) v : defValue;
        }
        @Override public boolean getBoolean(String key, boolean defValue) {
            Object v = data.get(key);
            return v instanceof Boolean ? (Boolean) v : defValue;
        }
        @Override public boolean contains(String key) { return data.containsKey(key); }
        @Override public Editor edit() { return new InMemoryEditor(); }
        @Override public void registerOnSharedPreferenceChangeListener(
                OnSharedPreferenceChangeListener listener) {}
        @Override public void unregisterOnSharedPreferenceChangeListener(
                OnSharedPreferenceChangeListener listener) {}

        private final class InMemoryEditor implements Editor {
            private final Map<String, Object> staged = new HashMap<>();
            private final Set<String> removals = new HashSet<>();
            private boolean clearAll;

            @Override public Editor putString(String key, String value) {
                staged.put(key, value);
                return this;
            }
            @Override public Editor putStringSet(String key, Set<String> values) {
                staged.put(key, values == null ? null : new HashSet<>(values));
                return this;
            }
            @Override public Editor putInt(String key, int value) {
                staged.put(key, value);
                return this;
            }
            @Override public Editor putLong(String key, long value) {
                staged.put(key, value);
                return this;
            }
            @Override public Editor putFloat(String key, float value) {
                staged.put(key, value);
                return this;
            }
            @Override public Editor putBoolean(String key, boolean value) {
                staged.put(key, value);
                return this;
            }
            @Override public Editor remove(String key) {
                removals.add(key);
                staged.remove(key);
                return this;
            }
            @Override public Editor clear() {
                clearAll = true;
                staged.clear();
                removals.clear();
                return this;
            }
            @Override public boolean commit() {
                apply();
                return true;
            }
            @Override public void apply() {
                if (clearAll) data.clear();
                for (String key : removals) data.remove(key);
                for (Map.Entry<String, Object> entry : staged.entrySet()) {
                    if (entry.getValue() == null) data.remove(entry.getKey());
                    else data.put(entry.getKey(), entry.getValue());
                }
            }
        }
    }
}
