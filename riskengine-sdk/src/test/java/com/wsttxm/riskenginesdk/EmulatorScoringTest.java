package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.EmulatorEvidenceClassifier;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class EmulatorScoringTest {
    @Test
    public void aospSensorAndMissingTelephonyAreNoise() {
        assertEquals(EmulatorEvidenceClassifier.Rank.WEAK,
                EmulatorEvidenceClassifier.rank("aosp_sensor_vendor:accel"));
        assertEquals(EmulatorEvidenceClassifier.Rank.WEAK,
                EmulatorEvidenceClassifier.rank("missing_feature:telephony"));
        assertTrue(EmulatorEvidenceClassifier.isHardwareNoise("aosp_sensor_vendor:accel"));
        assertTrue(EmulatorEvidenceClassifier.isHardwareNoise("missing_feature:telephony"));
    }

    @Test
    public void qemuAndHypervisorAreStrong() {
        assertEquals(EmulatorEvidenceClassifier.Rank.STRONG,
                EmulatorEvidenceClassifier.rank("qemu_prop:ro.kernel.qemu"));
        assertEquals(EmulatorEvidenceClassifier.Rank.STRONG,
                EmulatorEvidenceClassifier.rank("cpu:hypervisor"));
        assertEquals(EmulatorEvidenceClassifier.Rank.STRONG,
                EmulatorEvidenceClassifier.rank("emu_file:/dev/qemu_pipe"));
    }
}
