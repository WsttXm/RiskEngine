package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.CorrelationEngine;
import com.wsttxm.riskenginesdk.core.EvidenceFamily;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.NetworkRiskDetector;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;

public class NetworkRiskDetectorTest {

    private static final class FakeNetworkEnv implements NetworkRiskDetector.NetworkEnvironment {
        int keystoreUserCa = 0;
        int dirUserCa = 0;
        Boolean transportVpn = null; // simulates missing ACCESS_NETWORK_STATE
        List<String> ifaces = Arrays.asList("lo", "wlan0", "rmnet_data0");
        String proxySource = null;
        Map<String, Set<String>> installedCerts = new LinkedHashMap<>();
        Set<String> existingModules = Collections.emptySet();

        @Override public int countAndroidCaStoreUserCerts() { return keystoreUserCa; }
        @Override public int countCacertsAddedFiles() { return dirUserCa; }
        @Override public Boolean hasConnectivityTransportVpn() { return transportVpn; }
        @Override public List<String> getNetworkInterfaceNames() { return ifaces; }
        @Override public String detectActiveHttpProxySource() { return proxySource; }
        @Override public Set<String> getInstalledPackageCertSha256Hex(String pkg) {
            return installedCerts.getOrDefault(pkg, Collections.emptySet());
        }
        @Override public boolean probeModuleExistsReadOnly(String path) {
            return existingModules.contains(path);
        }
    }

    @Test
    public void cleanDeviceWithoutNetworkPermissionIsSafe() {
        FakeNetworkEnv env = new FakeNetworkEnv();
        DetectionResult result = NetworkRiskDetector.createForTest(
                null, new SignalSnapshot(null), env).call();

        assertEquals("network_risk", result.getDetectorName());
        assertEquals(ScanTier.FAST, result.getScanTier());
        assertEquals(RiskLevel.SAFE, result.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, result.getStatus());
        assertEquals(0, result.getScore());
        assertTrue(result.getDetails().isEmpty());
        assertTrue(result.getEvidenceItems().isEmpty());
    }

    @Test
    public void userCaMitmIsMedium5ActionableInAllScenes() {
        FakeNetworkEnv env = new FakeNetworkEnv();
        env.keystoreUserCa = 2;

        DetectionResult raw = NetworkRiskDetector.createForTest(
                null, new SignalSnapshot(null), env).call();
        assertEquals(RiskLevel.MEDIUM, raw.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, raw.getStatus());
        assertEquals(5, raw.getScore());
        assertFalse(raw.isInformational());
        assertTrue(raw.getDetails().contains("user_ca_cert:2"));
        assertTrue(raw.getEvidenceItems().stream()
                .anyMatch(e -> "user_ca_cert".equals(e.getCode())
                        && "network_mitm".equals(e.getEvidenceFamily())
                        && e.getRank() == EvidenceItem.Rank.STRONG));

        DetectionResult standard = CorrelationEngine.applyScene(raw, CollectScene.STANDARD);
        assertFalse(standard.isInformational());
        assertEquals(5, standard.getScore());
    }

    @Test
    public void sysfsVpnAndProxyFallbackAreLow2InfoInStandardAndMedium4ActionableInPayment() {
        FakeNetworkEnv env = new FakeNetworkEnv();
        env.transportVpn = null; // no ACCESS_NETWORK_STATE
        env.ifaces = Arrays.asList("lo", "wlan0", "tun0", "wg0");
        env.proxySource = "jvm_property";

        DetectionResult raw = NetworkRiskDetector.createForTest(
                null, new SignalSnapshot(null), env).call();
        assertEquals(RiskLevel.LOW, raw.getRiskLevel());
        assertEquals(2, raw.getScore());
        assertTrue(raw.isInformational());
        assertTrue(raw.getDetails().contains("vpn_active:tun0"));
        assertTrue(raw.getDetails().contains("http_proxy:jvm_property"));

        Set<String> families = EvidenceFamily.families(raw.getDetails(), raw.getEvidenceItems());
        assertEquals(Collections.singleton("network_mitm"), families);

        DetectionResult standard = CorrelationEngine.applyScene(raw, CollectScene.STANDARD);
        assertTrue(standard.isInformational());
        assertEquals(RiskLevel.LOW, standard.getRiskLevel());

        DetectionResult payment = CorrelationEngine.applyScene(raw, CollectScene.PAYMENT);
        assertFalse(payment.isInformational());
        assertEquals(RiskLevel.MEDIUM, payment.getRiskLevel());
        assertEquals(4, payment.getScore());
        assertFalse(payment.getEvidenceItems().isEmpty());
        assertEquals(ScanTier.FAST, payment.getScanTier());
    }

    @Test
    public void proxyToolOfficialCertMatchAndBox4ModuleFollowSoftPolicyAndIgnoreUnmatchedCerts() {
        String clashPkg = "com.github.metacubex.clash.meta";
        String officialCert = NetworkRiskDetector.KNOWN_PROXY_TOOL_CERT_SHA256
                .get(clashPkg).iterator().next();

        // Non-matching signature on same package must NOT trigger
        FakeNetworkEnv unmatchedEnv = new FakeNetworkEnv();
        unmatchedEnv.installedCerts.put(clashPkg,
                Collections.singleton("0000000000000000000000000000000000000000000000000000000000000000"));
        DetectionResult unmatched = NetworkRiskDetector.createForTest(
                null, new SignalSnapshot(null), unmatchedEnv).call();
        assertEquals(RiskLevel.SAFE, unmatched.getRiskLevel());

        // Matching official cert + /data/adb/modules/box4 present
        FakeNetworkEnv matchedEnv = new FakeNetworkEnv();
        matchedEnv.installedCerts.put(clashPkg, Collections.singleton(officialCert.toUpperCase()));
        matchedEnv.existingModules = Collections.singleton("/data/adb/modules/box4");
        DetectionResult matched = NetworkRiskDetector.createForTest(
                null, new SignalSnapshot(null), matchedEnv).call();
        assertEquals(RiskLevel.LOW, matched.getRiskLevel());
        assertEquals(2, matched.getScore());
        assertTrue(matched.isInformational());
        assertTrue(matched.getDetails().contains("proxy_tool_cert:" + clashPkg));
        assertTrue(matched.getDetails().contains("proxy_module:box4"));

        DetectionResult payment = CorrelationEngine.applyScene(matched, CollectScene.PAYMENT);
        assertFalse(payment.isInformational());
        assertEquals(RiskLevel.MEDIUM, payment.getRiskLevel());
        assertEquals(4, payment.getScore());
    }

    @Test
    public void cacertsAddedDirectoryAndDeniedProbesDoNotFalsePositive() {
        FakeNetworkEnv deniedEnv = new FakeNetworkEnv();
        deniedEnv.keystoreUserCa = -1; // unavailable
        deniedEnv.dirUserCa = -1;      // SELinux/permission denied -> never a threat
        deniedEnv.ifaces = null;
        DetectionResult denied = NetworkRiskDetector.createForTest(
                null, new SignalSnapshot(null), deniedEnv).call();
        assertEquals(RiskLevel.SAFE, denied.getRiskLevel());
        assertEquals(0, denied.getScore());

        FakeNetworkEnv dirHitEnv = new FakeNetworkEnv();
        dirHitEnv.keystoreUserCa = 0;
        dirHitEnv.dirUserCa = 1;
        DetectionResult dirHit = NetworkRiskDetector.createForTest(
                null, new SignalSnapshot(null), dirHitEnv).call();
        assertEquals(RiskLevel.MEDIUM, dirHit.getRiskLevel());
        assertEquals(5, dirHit.getScore());
        assertFalse(dirHit.isInformational());
        assertTrue(dirHit.getDetails().contains("user_ca_cert:1"));
    }

    @Test
    public void stockKernelTunlInterfaceDoesNotFalsePositiveAndClashPackageMatchesOfficialCert() {
        FakeNetworkEnv tunlOnly = new FakeNetworkEnv();
        tunlOnly.ifaces = Arrays.asList("lo", "wlan0", "tunl0", "tunl1", "rmnet0");
        DetectionResult clean = NetworkRiskDetector.createForTest(
                null, new SignalSnapshot(null), tunlOnly).call();
        assertEquals(RiskLevel.SAFE, clean.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, clean.getStatus());
        assertEquals(4, clean.getChecksSucceeded());
        assertTrue(clean.getDetails().isEmpty());

        String clashPkg = "com.github.kr328.clash";
        assertTrue("com.github.kr328.clash must be in official proxy tool cert table",
                NetworkRiskDetector.KNOWN_PROXY_TOOL_CERT_SHA256.containsKey(clashPkg));
        String officialCert = NetworkRiskDetector.KNOWN_PROXY_TOOL_CERT_SHA256
                .get(clashPkg).iterator().next();

        FakeNetworkEnv activeClash = new FakeNetworkEnv();
        activeClash.ifaces = Arrays.asList("lo", "wlan0", "tunl0", "tun0");
        activeClash.proxySource = "jvm_property";
        activeClash.installedCerts.put(clashPkg, Collections.singleton(officialCert));
        DetectionResult hit = NetworkRiskDetector.createForTest(
                null, new SignalSnapshot(null), activeClash).call();
        assertEquals(RiskLevel.LOW, hit.getRiskLevel());
        assertEquals(4, hit.getChecksSucceeded());
        assertTrue(hit.getDetails().contains("vpn_active:tun0"));
        assertFalse(hit.getDetails().contains("vpn_active:tunl0"));
        assertTrue(hit.getDetails().contains("http_proxy:jvm_property"));
        assertTrue(hit.getDetails().contains("proxy_tool_cert:" + clashPkg));
    }
}
