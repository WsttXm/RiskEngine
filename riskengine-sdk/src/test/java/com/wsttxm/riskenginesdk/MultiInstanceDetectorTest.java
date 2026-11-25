package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.CorrelationEngine;
import com.wsttxm.riskenginesdk.core.EvidenceFamily;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.MultiInstanceDetector;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.InstallTokenSanitizer;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;

public class MultiInstanceDetectorTest {

    private static final String PKG = "com.example.wallet";

    private static final class FakeEnv implements MultiInstanceDetector.MultiInstanceEnvironment {
        String packageName = PKG;
        int myUid = 10234;
        String filesDir = "/data/user/0/" + PKG + "/files";
        String dataDir = "/data/user/0/" + PKG;
        String sourceDir = "/data/app/~~RiruAbCdEfGhIjKlMnOpQr==/" + PKG
                + "-ksu1234567890abcdef123==/base.apk";
        int statUid = 10234;
        Map<String, String> dynamicProxies = Collections.emptyMap();

        @Override public String getPackageName() { return packageName; }
        @Override public int getMyUid() { return myUid; }
        @Override public String getFilesDirPath() { return filesDir; }
        @Override public String getDataDirPath() { return dataDir; }
        @Override public String getSourceDirPath() { return sourceDir; }
        @Override public int statUid(String path) { return statUid; }
        @Override public Map<String, String> inspectDynamicBinderProxies() { return dynamicProxies; }
    }

    @Test
    public void installTokenSanitizerStripsRandomTokensContainingSensitiveSubstrings() {
        String raw = "/data/app/~~RiruAbCdEfGhIjKlMnOpQr==/com.example.wallet-ksu1234567890abcdef123==/base.apk";
        String sanitized = InstallTokenSanitizer.stripInstallTokens(raw);
        assertEquals("/data/app/~~/com.example.wallet/base.apk", sanitized);
        assertFalse(sanitized.toLowerCase().contains("riru"));
        assertFalse(sanitized.toLowerCase().contains("ksu"));
        assertEquals("com.example.wallet", InstallTokenSanitizer.extractDataAppApkPackage(raw));
    }

    @Test
    public void cleanPrimaryUserWithSensitiveInstallTokensHasZeroFalsePositives() {
        FakeEnv env = new FakeEnv();
        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedSelfMapsForTest(SignalResult.success(Arrays.asList(
                "70000000-70001000 r--p 00000000 00:00 0 "
                        + "/data/app/~~RiruAbCdEfGhIjKlMnOpQr==/" + PKG
                        + "-ksu1234567890abcdef123==/base.apk",
                "70002000-70003000 r--p 00000000 00:00 0 "
                        + "/data/app/~~AbCdEfGhIjKlMnOpQrStUv==/com.google.android.webview-1234567890abcdefghijkl==/base.apk",
                "70004000-70005000 r--p 00000000 00:00 0 /system/framework/framework-res.apk"
        )));

        MultiInstanceDetector detector = MultiInstanceDetector.createForTest(null, signals, env);
        DetectionResult result = detector.call();

        assertEquals("multi_instance", result.getDetectorName());
        assertEquals(ScanTier.FAST, result.getScanTier());
        assertEquals(RiskLevel.SAFE, result.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, result.getStatus());
        assertEquals(0, result.getScore());
        assertTrue(result.getDetails().isEmpty());
        assertTrue(result.getEvidenceItems().isEmpty());
    }

    @Test
    public void normalAndroidWorkProfileUser10ProducesZeroFalsePositives() {
        FakeEnv env = new FakeEnv();
        env.myUid = 1_010_234; // userId = 10
        env.statUid = 1_010_234;
        env.filesDir = "/data/user/10/" + PKG + "/files";
        env.dataDir = "/data/user/10/" + PKG;

        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedSelfMapsForTest(SignalResult.success(Collections.singletonList(
                "70000000-70001000 r--p 00000000 00:00 0 /data/app/~~1234567890abcdefghijkl==/"
                        + PKG + "-1234567890abcdefghijkl==/base.apk"
        )));

        DetectionResult result = MultiInstanceDetector.createForTest(null, signals, env).call();
        assertEquals(RiskLevel.SAFE, result.getRiskLevel());
        assertEquals(0, result.getScore());
        assertTrue(result.getDetails().isEmpty());
    }

    @Test
    public void oemDualAppUser999IsInformationalInStandardAndActionableInLoginAndPayment() {
        FakeEnv env = new FakeEnv();
        env.myUid = 99_910_234; // userId = 999
        env.statUid = 99_910_234;
        env.filesDir = "/data/user/999/" + PKG + "/files";
        env.dataDir = "/data/user/999/" + PKG;

        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedSelfMapsForTest(SignalResult.success(Collections.emptyList()));

        DetectionResult raw = MultiInstanceDetector.createForTest(null, signals, env).call();
        assertEquals(RiskLevel.LOW, raw.getRiskLevel());
        assertEquals(2, raw.getScore());
        assertTrue(raw.isInformational());
        assertTrue(raw.getDetails().contains("oem_dual_app:user_999"));
        assertFalse(raw.getEvidenceItems().isEmpty());
        assertEquals("virtual_container", raw.getEvidenceItems().get(0).getEvidenceFamily());

        DetectionResult standard = CorrelationEngine.applyScene(raw, CollectScene.STANDARD);
        assertTrue(standard.isInformational());

        DetectionResult login = CorrelationEngine.applyScene(raw, CollectScene.LOGIN);
        assertFalse(login.isInformational());

        DetectionResult payment = CorrelationEngine.applyScene(raw, CollectScene.PAYMENT);
        assertFalse(payment.isInformational());
    }

    @Test
    public void nestedVirtualAppAndBlackBoxPathsAreActionableMedium5() {
        FakeEnv env = new FakeEnv();
        env.filesDir = "/data/user/0/io.va.exposed/virtual/data/user/0/" + PKG + "/files";
        env.dataDir = "/data/user/0/top.niunaijun.blackboxa/blackbox/data/user/0/" + PKG;
        env.sourceDir = "/data/user/0/io.va.exposed/virtual/data/app/" + PKG + "/base.apk";

        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedSelfMapsForTest(SignalResult.success(Collections.emptyList()));

        DetectionResult result = MultiInstanceDetector.createForTest(null, signals, env).call();
        assertEquals(RiskLevel.MEDIUM, result.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, result.getStatus());
        assertEquals(5, result.getScore());
        assertFalse(result.isInformational());
        assertTrue(result.getDetails().stream().anyMatch(d -> d.startsWith("nested_container_path:")));
        assertTrue(result.getDetails().stream().anyMatch(d -> d.startsWith("container_source_dir:")));

        Set<String> families = EvidenceFamily.families(result.getDetails(), result.getEvidenceItems());
        assertEquals(Collections.singleton("virtual_container"), families);
    }

    @Test
    public void statUidMismatchTriggersActionableMedium5() {
        FakeEnv env = new FakeEnv();
        env.myUid = 10234;
        env.statUid = 10999;

        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedSelfMapsForTest(SignalResult.success(Collections.emptyList()));

        DetectionResult result = MultiInstanceDetector.createForTest(null, signals, env).call();
        assertEquals(RiskLevel.MEDIUM, result.getRiskLevel());
        assertEquals(5, result.getScore());
        assertFalse(result.isInformational());
        assertTrue(result.getDetails().contains("dir_uid_mismatch:my=10234,stat=10999"));
        assertTrue(result.getEvidenceItems().stream()
                .anyMatch(e -> "dir_uid_mismatch".equals(e.getCode())
                        && "virtual_container".equals(e.getEvidenceFamily())
                        && e.getRank() == EvidenceItem.Rank.STRONG));
    }

    @Test
    public void multiApkMapsAndContainerLibraryTriggerActionableMedium5() {
        FakeEnv env = new FakeEnv();
        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedSelfMapsForTest(SignalResult.success(Arrays.asList(
                "70000000-70001000 r--p 00000000 00:00 0 /data/app/~~1234567890abcdefghijkl==/"
                        + PKG + "-1234567890abcdefghijkl==/base.apk",
                "70002000-70003000 r--p 00000000 00:00 0 /data/app/~~1234567890abcdefghijkl==/"
                        + "com.lbe.parallel.intl-1234567890abcdefghijkl==/base.apk",
                "70004000-70005000 r-xp 00000000 00:00 0 /data/app/com.lbe.parallel.intl/lib/arm64/libva++.so"
        )));

        DetectionResult result = MultiInstanceDetector.createForTest(null, signals, env).call();
        assertEquals(RiskLevel.MEDIUM, result.getRiskLevel());
        assertEquals(5, result.getScore());
        assertFalse(result.isInformational());
        assertTrue(result.getDetails().contains("multi_apk_maps:com.lbe.parallel.intl"));
        assertTrue(result.getDetails().contains("container_maps_artifact:libva++.so"));
    }

    @Test
    public void dynamicBinderProxyTriggersActionableMedium5WhileStubProxyIsIgnored() {
        FakeEnv env = new FakeEnv();
        Map<String, String> proxies = new LinkedHashMap<>();
        proxies.put("PackageManager", "com.sun.proxy.$Proxy3");
        env.dynamicProxies = proxies;

        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedSelfMapsForTest(SignalResult.success(Collections.emptyList()));

        DetectionResult result = MultiInstanceDetector.createForTest(null, signals, env).call();
        assertEquals(RiskLevel.MEDIUM, result.getRiskLevel());
        assertEquals(5, result.getScore());
        assertFalse(result.isInformational());
        assertTrue(result.getDetails().contains("binder_dynamic_proxy:PackageManager:com.sun.proxy.$Proxy3"));

        // Confirm legitimate Android Binder Stub$Proxy is never misclassified.
        assertFalse(isProxyNameHelper("android.content.pm.IPackageManager$Stub$Proxy"));
        assertTrue(isProxyNameHelper("com.sun.proxy.$Proxy0"));
        assertTrue(isProxyNameHelper("jdk.proxy2.$Proxy7"));
    }

    private static boolean isProxyNameHelper(String name) {
        try {
            java.lang.reflect.Method m = MultiInstanceDetector.class.getDeclaredMethod(
                    "isDynamicProxyClassName", String.class);
            m.setAccessible(true);
            return (Boolean) m.invoke(null, name);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }
}
