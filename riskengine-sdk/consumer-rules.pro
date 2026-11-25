# Keep the complete source-level SDK contract, including nested builders.
# Public model accessors and constructors are consumed by host applications.
-keep public class com.wsttxm.riskenginesdk.RiskEngine { public *; protected *; }
-keep public class com.wsttxm.riskenginesdk.RiskEngineConfig { public *; protected *; }
-keep public class com.wsttxm.riskenginesdk.RiskEngineConfig$Builder { public *; protected *; }
-keep public class com.wsttxm.riskenginesdk.ThreatAppPolicy { public *; protected *; }
-keep public class com.wsttxm.riskenginesdk.ThreatAppPolicy$* { public *; protected *; }
-keep public class com.wsttxm.riskenginesdk.RiskPolicy { public *; protected *; }
-keep public class com.wsttxm.riskenginesdk.RiskPolicy$* { public *; protected *; }
-keep public interface com.wsttxm.riskenginesdk.RiskEngineCallback { *; }
-keep public class com.wsttxm.riskenginesdk.PrivacyProfile { public *; }
-keep public class com.wsttxm.riskenginesdk.CollectScene { public *; }
-keep public class com.wsttxm.riskenginesdk.ScanTier { public *; }
-keep public class com.wsttxm.riskenginesdk.EnvelopeMode { public *; }
-keep public class com.wsttxm.riskenginesdk.FingerprintVersion { public *; }
-keep public class com.wsttxm.riskenginesdk.FingerprintStability { public *; }
-keep public interface com.wsttxm.riskenginesdk.FingerprintHasher { *; }
-keep public interface com.wsttxm.riskenginesdk.ThreatListener { *; }
-keep public interface com.wsttxm.riskenginesdk.DeviceStateListener { *; }
-keep public interface com.wsttxm.riskenginesdk.ExecutionStateListener { *; }
-keep public class com.wsttxm.riskenginesdk.RiskWindowGuard { public *; }
-keep class com.wsttxm.riskenginesdk.model.** { public *; protected *; }
-keep public class com.wsttxm.riskenginesdk.model.EvidenceItem { public *; }
-keep public class com.wsttxm.riskenginesdk.model.EvidenceItem$* { public *; }
-keep public class com.wsttxm.riskenginesdk.model.SignedRiskEnvelope { public *; }
-keep public class com.wsttxm.riskenginesdk.model.SignedRiskEnvelope$* { public *; }
-keep public class com.wsttxm.riskenginesdk.attestation.AttestationRecord$SecurityLevel { public *; }
-keep public class com.wsttxm.riskenginesdk.model.ThreatEvent { public *; }
-keep public class com.wsttxm.riskenginesdk.model.DevicePosture { public *; }
-keep public class com.wsttxm.riskenginesdk.model.DevicePosture$* { public *; }
-keep public class com.wsttxm.riskenginesdk.model.TierReport { public *; }
-keep public class com.wsttxm.riskenginesdk.model.RiskDimension { public *; }
-keep public class com.wsttxm.riskenginesdk.model.RiskAction { public *; }
-keep public class com.wsttxm.riskenginesdk.model.ScoreBreakdown { public *; }
-keep public class com.wsttxm.riskenginesdk.model.ScoreBreakdown$* { public *; }
-keep public class com.wsttxm.riskenginesdk.process.RiskIsolatedProbeService { *; }
-keep public class com.wsttxm.riskenginesdk.process.IsolatedProbeClient { *; }
-keepattributes InnerClasses

# Native methods and JNI push-upcall anchors are resolved by exact class and method name in JNI_OnLoad.
-keep class com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge {
    public static boolean isNativeAvailable();
    public static boolean isNativeLoaded();
    public static boolean ensureNativeLoaded();
    native <methods>;
}
-keep class com.wsttxm.riskenginesdk.collector.native_layer.NativeMonitorDispatcher {
    public static void onNativeThreatDetected(java.lang.String, java.lang.String);
}
-keepclasseswithmembers,includedescriptorclasses class * {
    native <methods>;
}

# NOTE: com.wsttxm.riskenginesdk.detector.ObfuscationSentinel is intentionally NOT kept
# so AppIntegrityDetector can verify that R8/ProGuard obfuscation is active on release builds.
