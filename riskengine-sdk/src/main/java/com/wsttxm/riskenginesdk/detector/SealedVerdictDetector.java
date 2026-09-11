package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import java.util.ArrayList;
import java.util.List;

/**
 * Consumes the native-sealed verdict and the JNI self-integrity result.
 *
 * This detector exists because every other detector reports through the same
 * Java bridge, and that bridge was previously unprotected: a single hook on
 * NativeCollectorBridge returning an empty string made the whole report read
 * SAFE. Here native computes its own ranked score, authenticates it with a key
 * that never crosses JNI, and verifies it on the way back. Java cannot mint a
 * passing blob, so a tampered bridge produces a verification failure instead of
 * a clean result.
 *
 * The limit is stated plainly: an attacker with native code execution in this
 * process can read the key and forge blobs. This raises the cost from a
 * one-line Java hook to native memory access, it does not eliminate the attack.
 */
public class SealedVerdictDetector extends BaseDetector {
    private final SignalSnapshot signals;

    public SealedVerdictDetector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
    }

    @Override
    public String getName() {
        return "sealed_verdict";
    }

    @Override
    protected DetectionResult detect() {
        CheckCoverage coverage = new CheckCoverage();
        List<String> evidence = new ArrayList<>();

        if (!NativeCollectorBridge.isNativeAvailable()) {
            return unavailable("native_library_unavailable");
        }

        checkJniSelfIntegrity(evidence, coverage);
        int nativeScore = checkSealedVerdict(evidence, coverage);

        if (evidence.isEmpty()) {
            return safe(coverage);
        }

        boolean tampered = false;
        for (String item : evidence) {
            if (item.startsWith("verdict_unverifiable")
                    || item.startsWith("jni_self_hook")) {
                tampered = true;
                break;
            }
        }

        if (tampered) {
            return result(RiskLevel.DEADLY, DetectionStatus.DANGER, 10, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        }
        // Map the native score onto the report's own scale.
        if (nativeScore >= 9) {
            return result(RiskLevel.DEADLY, DetectionStatus.DANGER, 10, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        }
        if (nativeScore >= 6) {
            return result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        }
        if (nativeScore >= 3) {
            return result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        }
        return result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, true,
                evidence, String.join("; ", evidence), coverage);
    }

    private void checkJniSelfIntegrity(List<String> evidence, CheckCoverage coverage) {
        SignalResult<String> self = signals.getJniSelfIntegrity();
        if (!self.isSuccess()) {
            coverage.failure("jni_self:" + self.getFailureReason());
            return;
        }
        coverage.success();
        String value = self.getValue() == null ? "" : self.getValue().trim();
        if (value.isEmpty()) return;
        for (String token : value.split(",")) {
            String item = token.trim();
            if (!item.isEmpty()) evidence.add(item);
        }
    }

    /**
     * Requests a sealed verdict and immediately asks native to verify it.
     * A blob that native will not vouch for means something between the two
     * calls altered it, which is itself the finding.
     */
    private int checkSealedVerdict(List<String> evidence, CheckCoverage coverage) {
        SignalResult<String> sealed = signals.getSealedVerdict();
        if (!sealed.isSuccess() || sealed.getValue() == null
                || sealed.getValue().isEmpty()) {
            coverage.failure("sealed_verdict:" + sealed.getFailureReason());
            return -1;
        }
        SignalResult<Integer> verified =
                NativeCollectorBridge.verifySealedVerdictResult(sealed.getValue());
        if (!verified.isSuccess() || verified.getValue() == null) {
            coverage.failure("verify:" + verified.getFailureReason());
            return -1;
        }
        coverage.success();
        int score = verified.getValue();
        if (score < 0) {
            evidence.add("verdict_unverifiable:mac_or_nonce_rejected");
            return -1;
        }
        if (score > 0) {
            evidence.add("native_score:" + score);
        }
        return score;
    }
}
