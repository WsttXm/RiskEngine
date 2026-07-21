# Keep public API and serialized models. Keep this in sync with consumer-rules.pro.
-keep public class com.wsttxm.riskenginesdk.RiskEngine { *; }
-keep public class com.wsttxm.riskenginesdk.RiskEngineConfig { *; }
-keep public class com.wsttxm.riskenginesdk.RiskEngineConfig$Builder { *; }
-keep public interface com.wsttxm.riskenginesdk.RiskEngineCallback { *; }
-keep class com.wsttxm.riskenginesdk.model.** { *; }
-keep class com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge { *; }

# Keep JNI methods
-keepclasseswithmembers class * { native <methods>; }
