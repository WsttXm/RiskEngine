# Keep the complete source-level SDK contract, including nested builders and
# Public model accessors and constructors are consumed by host applications.
-keep public class com.wsttxm.riskenginesdk.RiskEngine { *; }
-keep public class com.wsttxm.riskenginesdk.RiskEngineConfig { *; }
-keep public class com.wsttxm.riskenginesdk.RiskEngineConfig$Builder { *; }
-keep public interface com.wsttxm.riskenginesdk.RiskEngineCallback { *; }
-keep public class com.wsttxm.riskenginesdk.PrivacyProfile { *; }
-keep public class com.wsttxm.riskenginesdk.CollectScene { *; }
-keep class com.wsttxm.riskenginesdk.model.** { *; }

# Native methods are registered by exact class and method name in JNI_OnLoad.
-keep class com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge { *; }
-keepclasseswithmembers,includedescriptorclasses class * {
    native <methods>;
}
