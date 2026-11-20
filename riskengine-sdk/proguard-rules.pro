# Keep public API and serialized models. Keep this in sync with consumer-rules.pro.
-keep public class com.wsttxm.riskenginesdk.RiskEngine { *; }
-keep public class com.wsttxm.riskenginesdk.RiskEngineConfig { *; }
-keep public class com.wsttxm.riskenginesdk.RiskEngineConfig$Builder { *; }
-keep public interface com.wsttxm.riskenginesdk.RiskEngineCallback { *; }
-keep public class com.wsttxm.riskenginesdk.PrivacyProfile { *; }
-keep public class com.wsttxm.riskenginesdk.CollectScene { *; }
-keep class com.wsttxm.riskenginesdk.model.** { *; }
-keepattributes InnerClasses

-keep class com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge {
    public static boolean isNativeAvailable();
    native <methods>;
}
-keepclasseswithmembers,includedescriptorclasses class * {
    native <methods>;
}
