# Keep public API
-keep public class com.wsttxm.riskenginesdk.RiskEngine { *; }
-keep public class com.wsttxm.riskenginesdk.RiskEngineConfig { *; }
-keep public class com.wsttxm.riskenginesdk.RiskEngineCallback { *; }
-keep public class com.wsttxm.riskenginesdk.model.RiskReport { *; }
-keep public class com.wsttxm.riskenginesdk.model.RiskLevel { *; }

# Keep JNI methods
-keepclasseswithmembers class * { native <methods>; }

# Obfuscate everything else
-repackageclasses 'a'
-allowaccessmodification
