package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.CollectScene;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class CorrelationEngine {
    private CorrelationEngine() {}

    public static List<DetectionResult> applyScene(List<DetectionResult> detections,
                                                   CollectScene scene) {
        CollectScene effective = scene == null ? CollectScene.STANDARD : scene;
        List<DetectionResult> out = new ArrayList<>(detections.size());
        for (DetectionResult detection : detections) {
            out.add(applyScene(detection, effective));
        }
        return out;
    }

    public static DetectionResult applyScene(DetectionResult detection, CollectScene scene) {
        if (detection == null || scene == CollectScene.STANDARD) {
            return detection;
        }
        String name = detection.getDetectorName();
        boolean makeActionable = false;
        if (scene == CollectScene.DIAGNOSTIC) {
            makeActionable = !"debug".equals(name) || !isDebuggableOnly(detection);
        } else if ("emulator".equals(name) || "cloud_phone".equals(name)
                || "sandbox".equals(name)) {
            makeActionable = scene == CollectScene.LOGIN || scene == CollectScene.PAYMENT;
        } else if ("adb".equals(name)) {
            makeActionable = scene == CollectScene.PAYMENT;
        }
        if (makeActionable && detection.isInformational()) {
            return detection.withInformational(false);
        }
        return detection;
    }

    public static List<DetectionResult> dedupeFamilies(List<DetectionResult> detections) {
        Set<String> claimed = new LinkedHashSet<>();
        List<DetectionResult> out = new ArrayList<>(detections.size());
        for (DetectionResult detection : detections) {
            Set<String> families = EvidenceFamily.families(detection.getDetails());
            boolean conflict = false;
            for (String family : families) {
                if (claimed.contains(family)) {
                    conflict = true;
                    break;
                }
            }
            if (conflict && !detection.isInformational() && detection.getScore() > 0) {
                out.add(detection.withInformational(true));
            } else {
                out.add(detection);
                claimed.addAll(families);
            }
        }
        return out;
    }

    public static DetectionResult correlate(List<DetectionResult> detections, CollectScene scene) {
        CollectScene effective = scene == null ? CollectScene.STANDARD : scene;
        DetectionResult emulator = find(detections, "emulator");
        DetectionResult root = find(detections, "root");
        DetectionResult mount = find(detections, "mount_analysis");
        DetectionResult hook = find(detections, "hook_framework");
        DetectionResult cloud = find(detections, "cloud_phone");
        DetectionResult rom = find(detections, "custom_rom");

        List<String> details = new ArrayList<>();
        int score = 0;
        RiskLevel level = RiskLevel.SAFE;
        DetectionStatus status = DetectionStatus.NORMAL;
        boolean informational = false;

        if (emulator != null) {
            int strong = 0;
            boolean cpuOrQemu = false;
            boolean diskSmall = false;
            boolean x86 = false;
            for (String token : emulator.getDetails()) {
                EmulatorEvidenceClassifier.Rank rank = EmulatorEvidenceClassifier.rank(token);
                if (rank == EmulatorEvidenceClassifier.Rank.STRONG) strong++;
                String lower = token.toLowerCase(Locale.ROOT);
                if (lower.startsWith("cpu:hypervisor") || lower.startsWith("qemu_")) {
                    cpuOrQemu = true;
                }
                if (lower.startsWith("disk_small")) diskSmall = true;
                if (lower.startsWith("runtime_arch:x86") || lower.startsWith("runtime_arch:i386")) {
                    x86 = true;
                }
            }
            if (emulator.getRiskLevel().getValue() <= RiskLevel.LOW.getValue()
                    && (cpuOrQemu || (diskSmall && x86))) {
                details.add("C1:emulator_weak_with_hypervisor");
                score = Math.max(score, 4);
                level = RiskLevel.MEDIUM;
                status = DetectionStatus.WARNING;
            }
            if (strong == 1 && cpuOrQemu
                    && emulator.getRiskLevel() == RiskLevel.MEDIUM) {
                details.add("C2:emulator_strong_plus_hypervisor");
                score = Math.max(score, 4);
                level = max(level, RiskLevel.HIGH);
                status = DetectionStatus.DANGER;
            }
        }

        boolean inline = containsPrefix(hook, "inline_hook:") || containsPrefix(hook, "got_hook:");
        boolean frida = containsFamily(hook, "frida") || containsFamily(find(detections, "process_scan"), "frida");
        if (inline && frida) {
            details.add("C3:inline_hook_with_frida");
            score = Math.max(score, 10);
            level = RiskLevel.DEADLY;
            status = DetectionStatus.DANGER;
        }

        if ((containsPrefix(root, "syscall_mismatch") || containsPrefix(mount, "syscall_mismatch"))
                && (containsPrefix(root, "mount:module") || containsPrefix(mount, "module_mount")
                || containsPrefix(mount, "mountinfo:magisk") || containsPrefix(root, "mount:module"))) {
            details.add("C4:hidden_root");
            score = Math.max(score, 8);
            level = max(level, RiskLevel.HIGH);
            status = DetectionStatus.DANGER;
        }

        if (containsPrefix(rom, "prop_mismatch:fingerprint")
                && (rom == null || !containsPrefix(rom, "community_rom:"))
                && (emulator == null || emulator.getStatus() == DetectionStatus.NORMAL)) {
            details.add("C5:resetprop_fingerprint");
            if (score == 0) {
                informational = true;
                score = 1;
                level = RiskLevel.LOW;
                status = DetectionStatus.WARNING;
            }
        }

        int cloudWeak = cloud == null ? 0 : cloud.getDetails().size();
        boolean cloudPkg = containsPrefix(cloud, "cloud_pkg:");
        if ((effective == CollectScene.LOGIN || effective == CollectScene.PAYMENT)
                && cloud != null && !cloudPkg && cloudWeak >= 2) {
            details.add("C7:cloud_weak_cluster");
            if (score < 2) {
                score = 2;
                level = max(level, RiskLevel.LOW);
                status = DetectionStatus.WARNING;
            }
        }

        if (details.isEmpty()) {
            return null;
        }
        return new DetectionResult(
                "signal_correlation",
                level,
                status,
                score,
                10,
                informational,
                details,
                String.join("; ", details)
        );
    }

    private static boolean isDebuggableOnly(DetectionResult detection) {
        if (detection.getDetails().isEmpty()) return false;
        for (String detail : detection.getDetails()) {
            if (!"debuggable_flag".equals(detail)) return false;
        }
        return true;
    }

    private static DetectionResult find(List<DetectionResult> detections, String name) {
        for (DetectionResult detection : detections) {
            if (name.equals(detection.getDetectorName())) return detection;
        }
        return null;
    }

    private static boolean containsPrefix(DetectionResult detection, String prefix) {
        if (detection == null) return false;
        for (String detail : detection.getDetails()) {
            if (detail != null && detail.startsWith(prefix)) return true;
        }
        return false;
    }

    private static boolean containsFamily(DetectionResult detection, String family) {
        return detection != null && EvidenceFamily.families(detection.getDetails()).contains(family);
    }

    private static RiskLevel max(RiskLevel a, RiskLevel b) {
        return a.getValue() >= b.getValue() ? a : b;
    }
}
