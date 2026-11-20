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
    private static final int FLAG_ROOT_STRONG = 1 << 0;
    private static final int FLAG_ROOT_HIDDEN = 1 << 1;
    private static final int FLAG_HOOK_INLINE = 1 << 2;
    private static final int FLAG_HOOK_FRAMEWORK = 1 << 3;
    private static final int FLAG_TEXT_MISMATCH = 1 << 4;
    private static final int FLAG_EMULATOR = 1 << 5;
    private static final int FLAG_DEBUGGER = 1 << 6;
    private static final int FLAG_KERNEL_ROOT = 1 << 7;
    private static final int FLAG_JNI_SELF_HOOK = 1 << 8;
    private static final int FLAG_COVERAGE_LOSS = 1 << 9;

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

        if (nativeScore <= 0 && evidence.size() == 1
                && "sealed:coverage_loss".equals(evidence.get(0))) {
            coverage.failure("sealed:coverage_loss");
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
        String value = self.getValue() == null ? "" : self.getValue().trim();
        boolean rangeUnavailable = false;
        for (String token : value.split(",")) {
            String item = token.trim();
            if (item.isEmpty()) continue;
            if (item.equals("jni_self:no_range")) {
                rangeUnavailable = true;
            } else {
                evidence.add(item);
            }
        }
        if (rangeUnavailable) coverage.failure("jni_self:no_range");
        else coverage.success();
    }

    /**
     * Requests a challenge-bound sealed verdict and immediately verifies it in
     * a single native HMAC-SHA256 + anti-replay call.
     */
    private int checkSealedVerdict(List<String> evidence, CheckCoverage coverage) {
        SignalResult<SignalSnapshot.SealedVerdictSample> sampleResult =
                signals.getSealedVerdictSample();
        if (!sampleResult.isSuccess() || sampleResult.getValue() == null
                || sampleResult.getValue().blob.isEmpty()) {
            coverage.failure("sealed_verdict:" + sampleResult.getFailureReason());
            return -1;
        }
        SignalSnapshot.SealedVerdictSample sample = sampleResult.getValue();
        SignalResult<Long> packed = NativeCollectorBridge.verifySealedVerdictPackedResult(
                sample.blob, sample.challenge);
        if (!packed.isSuccess() || packed.getValue() == null) {
            coverage.failure("verify:" + packed.getFailureReason());
            return -1;
        }
        coverage.success();
        long raw = packed.getValue();
        if (raw < 0L) {
            evidence.add("verdict_unverifiable:mac_or_nonce_rejected");
            return -1;
        }
        int score = (int) (raw & 0x7FFFFFFFL);
        int flags = (int) (raw >>> 32);
        appendFlagEvidence(evidence, flags);
        if (score > 0) {
            evidence.add("native_score:" + score);
        }
        return score;
    }

    private void appendFlagEvidence(List<String> evidence, int flags) {
        if ((flags & FLAG_ROOT_STRONG) != 0) evidence.add("sealed:root_strong");
        if ((flags & FLAG_ROOT_HIDDEN) != 0) evidence.add("sealed:root_hidden");
        if ((flags & FLAG_HOOK_INLINE) != 0) evidence.add("sealed:hook_inline");
        if ((flags & FLAG_HOOK_FRAMEWORK) != 0) evidence.add("sealed:hook_framework");
        if ((flags & FLAG_TEXT_MISMATCH) != 0) evidence.add("sealed:text_mismatch");
        if ((flags & FLAG_EMULATOR) != 0) evidence.add("sealed:emulator");
        if ((flags & FLAG_DEBUGGER) != 0) evidence.add("sealed:debugger");
        if ((flags & FLAG_KERNEL_ROOT) != 0) evidence.add("sealed:kernel_root");
        if ((flags & FLAG_JNI_SELF_HOOK) != 0) evidence.add("sealed:jni_self_hook");
        // Coverage is represented by the owning detector and never scores.
        // Keeping this token makes the sealed diagnostic explainable.
        if ((flags & FLAG_COVERAGE_LOSS) != 0) evidence.add("sealed:coverage_loss");
    }
}
