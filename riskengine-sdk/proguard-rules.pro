# Keep public API and serialized models. Keep this in sync with consumer-rules.pro.
-keep public class com.wsttxm.riskenginesdk.RiskEngine { public *; protected *; }
-keep public class com.wsttxm.riskenginesdk.RiskEngineConfig { public *; protected *; }
-keep public class com.wsttxm.riskenginesdk.RiskEngineConfig$Builder { public *; protected *; }
-keep public class com.wsttxm.riskenginesdk.RiskPolicy { public *; protected *; }
-keep public class com.wsttxm.riskenginesdk.RiskPolicy$* { public *; protected *; }
-keep public interface com.wsttxm.riskenginesdk.RiskEngineCallback { *; }
-keep public class com.wsttxm.riskenginesdk.PrivacyProfile { public *; }
-keep public class com.wsttxm.riskenginesdk.CollectScene { public *; }
-keep class com.wsttxm.riskenginesdk.model.** { public *; protected *; }
-keep public class com.wsttxm.riskenginesdk.model.RiskDimension { public *; }
-keep public class com.wsttxm.riskenginesdk.model.RiskAction { public *; }
-keep public class com.wsttxm.riskenginesdk.model.ScoreBreakdown { public *; }
-keep public class com.wsttxm.riskenginesdk.model.ScoreBreakdown$* { public *; }
-keepattributes InnerClasses

-keep class com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge {
    public static boolean isNativeAvailable();
    native <methods>;
}
-keepclasseswithmembers,includedescriptorclasses class * {
    native <methods>;
}
