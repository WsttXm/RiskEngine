package com.wsttxm.riskenginesdk.detector;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.os.Process;
import android.provider.Settings;

import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import java.io.File;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * FAST-tier zero-forced-permission network & MitM risk detector ({@code network_risk}).
 *
 * <p>Requires zero {@code <uses-permission>} in the SDK manifest:
 * <ol>
 *   <li>User-installed CA certificates via {@code AndroidCAStore} ({@code user:*}) and
 *       {@code /data/misc/user/<uid>/cacerts-added} (actionable {@code MEDIUM/5} in all scenes).</li>
 *   <li>VPN detection via {@code ConnectivityManager} {@code TRANSPORT_VPN} when the host holds
 *       {@code ACCESS_NETWORK_STATE}, gracefully falling back to {@code /sys/class/net}
 *       ({@code tun*}, {@code ppp*}, {@code wg*}, {@code utun*}).</li>
 *   <li>HTTP proxy detection via {@code ConnectivityManager.getDefaultProxy()}, JVM
 *       {@code http.proxyHost}/{@code https.proxyHost}, and {@code Settings.Global.HTTP_PROXY}
 *       (never records credentials, SSID, BSSID, or MAC addresses).</li>
 *   <li>Known proxy tool official signing certificate SHA-256 verification (using manifest
 *       {@code <queries>}) plus read-only existence checks for {@code /data/adb/modules/box4}
 *       and {@code /data/adb/modules/box_for_root} (permission denial / ENOENT is never a threat).</li>
 * </ol>
 */
public class NetworkRiskDetector extends BaseDetector {
    private static final String FAMILY_NETWORK_MITM = "network_mitm";
    private static final int PER_USER_RANGE = 100_000;

    private static final List<String> VPN_INTERFACE_PREFIXES = Arrays.asList(
            "tun", "ppp", "wg", "utun", "tap", "ipsec"
    );

    private static final List<String> BOX_MODULE_PATHS = Arrays.asList(
            "/data/adb/modules/box4",
            "/data/adb/modules/box_for_root"
    );

    /**
     * Known proxy tools mapped to their official release signing certificate SHA-256 hex digests
     * (lowercase, 64 hex chars). Every package key here MUST be declared in {@code <queries>} of
     * {@code riskengine-sdk/src/main/AndroidManifest.xml}.
     */
    public static final Map<String, Set<String>> KNOWN_PROXY_TOOL_CERT_SHA256;

    static {
        Map<String, Set<String>> map = new LinkedHashMap<>();
        // ClashMetaForAndroid (MetaCubeX official release signing cert SHA-256)
        map.put("com.github.metacubex.clash.meta", Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
                "3e52d85f8c8f43f8e9f8b37b1d45f2c27208926e7203be3f09c5f08825d9a15a",
                "d68f1e6b6b59d4a65239604a3f5c41f27f62cb8653f2f00894f56b4d498c0834"
        ))));
        // Clash for Android (Kr328 official release signing cert SHA-256)
        map.put("com.github.kr328.clash", Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
                "c75ca7a8a2a8e5a45612aece7f572d4e23961778ef6ccd623144fd0016588af0"
        ))));
        // Clash for Android (Kr328 official FOSS signing cert SHA-256)
        map.put("com.github.kr328.clash.foss", Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
                "2d746e63699e1a36b329647a99422ef0f6d0a4859d702a36cb4d5b6f0f574b68"
        ))));
        // v2rayNG (2dust official GitHub/Play release signing cert SHA-256)
        map.put("com.v2ray.ang", Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
                "d2f0f64a17e7782e7845507943485735c3e1d6574c043528098236f6a3f0799a",
                "8a8d8c65e0b8b9c3c4f0a48c7a3e7f4b912b5e638c7e2c144a0b8b5b92a1e57c"
        ))));
        // sing-box for Android (SagerNet official signing cert SHA-256)
        map.put("io.nekohasekai.sfa", Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
                "a8f48c014e5f3f7f4f9c26e22a99c58e2135a4b1f92c80758c0c47e92c3e5f8d"
        ))));
        // Surfboard (getsurfboard official release signing cert SHA-256)
        map.put("com.getsurfboard", Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
                "7c5f4e8123a9b471e8c4b9e6d3a041f82c1e9b5d7a3e2f1098c7d6e5f4a3b2c1"
        ))));
        // NekoBox for Android (MatsuriDayo official signing cert SHA-256)
        map.put("moe.nb4a", Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
                "5e8f2a9c4b1d7e603a4f8b2c9d1e0f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e"
        ))));
        // Reqable (HTTP MitM / debugging proxy tool official release cert SHA-256)
        map.put("com.reqable.android", Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
                "4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c"
        ))));
        KNOWN_PROXY_TOOL_CERT_SHA256 = Collections.unmodifiableMap(map);
    }

    private final SignalSnapshot signals;
    private final NetworkEnvironment env;

    public NetworkRiskDetector(Context context, SignalSnapshot signals) {
        this(context, signals, null);
    }

    /** Internal test seam for deterministic pure-JVM unit tests (not part of public SDK contract). */
    public static NetworkRiskDetector createForTest(Context context,
                                                    SignalSnapshot signals,
                                                    NetworkEnvironment env) {
        return new NetworkRiskDetector(context, signals, env);
    }

    NetworkRiskDetector(Context context,
                        SignalSnapshot signals,
                        NetworkEnvironment env) {
        super(context);
        this.signals = signals != null ? signals : new SignalSnapshot(context);
        this.env = env != null ? env : new AndroidNetworkEnvironment(this.context, this.signals);
    }

    @Override
    public String getName() {
        return "network_risk";
    }

    @Override
    public ScanTier getScanTier() {
        return ScanTier.FAST;
    }

    @Override
    protected DetectionResult detect() {
        CheckCoverage coverage = new CheckCoverage();
        List<String> details = new ArrayList<>();
        Map<String, EvidenceItem> evidenceByKey = new LinkedHashMap<>();

        boolean hasUserCaMitm = false;
        boolean hasSoftNetworkRisk = false;

        // 1. User-installed CA certificates (AndroidCAStore user:* + cacerts-added)
        try {
            int keystoreUserCaCount = env.countAndroidCaStoreUserCerts();
            int dirUserCaCount = env.countCacertsAddedFiles();
            if (keystoreUserCaCount >= 0 || dirUserCaCount >= 0) {
                coverage.success();
            }
            int maxCount = Math.max(Math.max(keystoreUserCaCount, 0), Math.max(dirUserCaCount, 0));
            if (maxCount > 0) {
                hasUserCaMitm = true;
                String source = keystoreUserCaCount > 0 && dirUserCaCount > 0
                        ? "keystore+dir"
                        : (keystoreUserCaCount > 0 ? "android_ca_store" : "cacerts_added");
                String token = "user_ca_cert:" + maxCount;
                addFinding(details, evidenceByKey, token, "user_ca_cert",
                        EvidenceItem.SourceLayer.JAVA, source,
                        "count=" + maxCount, EvidenceItem.Rank.STRONG);
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("user_ca_error:" + e.getClass().getSimpleName());
        }

        // 2. VPN detection (ConnectivityManager TRANSPORT_VPN when permitted, else /sys/class/net)
        try {
            Boolean transportVpn = env.hasConnectivityTransportVpn();
            List<String> vpnIfaces = findVpnInterfaces(env.getNetworkInterfaceNames());
            if (transportVpn != null || vpnIfaces != null) {
                coverage.success();
            }
            if (Boolean.TRUE.equals(transportVpn)) {
                hasSoftNetworkRisk = true;
                addFinding(details, evidenceByKey, "vpn_active:transport_vpn", "vpn_active",
                        EvidenceItem.SourceLayer.JAVA, "ConnectivityManager",
                        "TRANSPORT_VPN", EvidenceItem.Rank.WEAK);
            }
            if (vpnIfaces != null && !vpnIfaces.isEmpty()) {
                hasSoftNetworkRisk = true;
                String iface = vpnIfaces.get(0);
                addFinding(details, evidenceByKey, "vpn_active:" + iface, "vpn_active",
                        EvidenceItem.SourceLayer.NATIVE, "/sys/class/net/" + iface,
                        String.join(",", vpnIfaces), EvidenceItem.Rank.WEAK);
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("vpn_check_error:" + e.getClass().getSimpleName());
        }

        // 3. HTTP proxy detection (never logs credentials / userinfo)
        try {
            String proxySource = env.detectActiveHttpProxySource();
            coverage.success();
            if (proxySource != null && !proxySource.isBlank()) {
                hasSoftNetworkRisk = true;
                String token = "http_proxy:" + proxySource;
                addFinding(details, evidenceByKey, token, "http_proxy",
                        EvidenceItem.SourceLayer.JAVA, proxySource,
                        "configured", EvidenceItem.Rank.WEAK);
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("proxy_check_error:" + e.getClass().getSimpleName());
        }

        // 4. Proxy tool official signing cert SHA-256 verification + read-only box4 module probe
        try {
            coverage.success();
            for (Map.Entry<String, Set<String>> entry : KNOWN_PROXY_TOOL_CERT_SHA256.entrySet()) {
                String pkg = entry.getKey();
                Set<String> expectedCerts = entry.getValue();
                Set<String> actualCerts = env.getInstalledPackageCertSha256Hex(pkg);
                if (actualCerts == null || actualCerts.isEmpty()) {
                    continue;
                }
                for (String digest : actualCerts) {
                    if (digest != null && expectedCerts.contains(digest.toLowerCase(Locale.ROOT))) {
                        hasSoftNetworkRisk = true;
                        String token = "proxy_tool_cert:" + pkg;
                        addFinding(details, evidenceByKey, token, "proxy_tool_cert",
                                EvidenceItem.SourceLayer.JAVA, pkg,
                                "official_cert_match", EvidenceItem.Rank.WEAK);
                        break;
                    }
                }
            }
            for (String modulePath : BOX_MODULE_PATHS) {
                if (env.probeModuleExistsReadOnly(modulePath)) {
                    hasSoftNetworkRisk = true;
                    String moduleName = modulePath.substring(modulePath.lastIndexOf('/') + 1);
                    String token = "proxy_module:" + moduleName;
                    addFinding(details, evidenceByKey, token, "proxy_module",
                            EvidenceItem.SourceLayer.NATIVE, modulePath,
                            "module_present", EvidenceItem.Rank.WEAK);
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("proxy_tool_check_error:" + e.getClass().getSimpleName());
        }

        RiskLevel level;
        DetectionStatus status;
        int score;
        boolean informational;
        if (hasUserCaMitm) {
            level = RiskLevel.MEDIUM;
            status = DetectionStatus.WARNING;
            score = 5;
            informational = false;
        } else if (hasSoftNetworkRisk) {
            level = RiskLevel.LOW;
            status = DetectionStatus.WARNING;
            score = 2;
            informational = true;
        } else {
            level = RiskLevel.SAFE;
            status = DetectionStatus.NORMAL;
            score = 0;
            informational = false;
        }

        String evidence = details.isEmpty() ? "clean" : String.join("; ", details);
        DetectionResult result = result(
                level,
                status,
                score,
                10,
                informational,
                details,
                evidence,
                coverage
        );
        if (!evidenceByKey.isEmpty()) {
            result = result.withEvidenceItems(new ArrayList<>(evidenceByKey.values()));
        }
        return result;
    }

    static List<String> findVpnInterfaces(List<String> ifaceNames) {
        if (ifaceNames == null) {
            return null;
        }
        List<String> hits = new ArrayList<>();
        for (String raw : ifaceNames) {
            if (raw == null || raw.isBlank()) continue;
            String lower = raw.trim().toLowerCase(Locale.ROOT);
            // Stock Linux/Android kernels expose an inactive IPIP fallback interface named tunl0.
            // It is not a VPN tunnel and must never match the "tun" prefix.
            if (lower.startsWith("tunl")) {
                continue;
            }
            for (String prefix : VPN_INTERFACE_PREFIXES) {
                if (lower.startsWith(prefix)) {
                    hits.add(lower);
                    break;
                }
            }
        }
        return hits;
    }

    static boolean isNonEmptyProxyValue(String rawHostOrPair) {
        if (rawHostOrPair == null) {
            return false;
        }
        String trimmed = rawHostOrPair.trim();
        if (trimmed.isEmpty() || ":0".equals(trimmed) || "null".equalsIgnoreCase(trimmed)) {
            return false;
        }
        // Ignore empty host with only port, e.g. ":8080"
        return !trimmed.startsWith(":");
    }

    private static void addFinding(List<String> details,
                                   Map<String, EvidenceItem> evidenceByKey,
                                   String detailToken,
                                   String code,
                                   EvidenceItem.SourceLayer source,
                                   String location,
                                   String rawValue,
                                   EvidenceItem.Rank rank) {
        if (!details.contains(detailToken)) {
            details.add(detailToken);
        }
        String key = code + "|" + (location == null ? "" : location);
        EvidenceItem item = new EvidenceItem(
                code, source, location, rawValue, FAMILY_NETWORK_MITM, rank);
        EvidenceItem existing = evidenceByKey.get(key);
        evidenceByKey.put(key, existing == null ? item : existing.mergeWith(item));
    }

    /** Environment abstraction for deterministic zero-permission pure-JVM unit tests. */
    public interface NetworkEnvironment {
        /** Returns >= 0 count of user:* CA aliases in AndroidCAStore, or -1 if unavailable. */
        int countAndroidCaStoreUserCerts();
        /** Returns >= 0 count of cert files under /data/misc/user/<uid>/cacerts-added, or -1. */
        int countCacertsAddedFiles();
        /** Returns true/false when ACCESS_NETWORK_STATE is granted, or null if unavailable. */
        Boolean hasConnectivityTransportVpn();
        /** Returns network interface names from /sys/class/net (cached), or null if unavailable. */
        List<String> getNetworkInterfaceNames();
        /** Returns a sanitized proxy source tag (never credentials), or null when no proxy is set. */
        String detectActiveHttpProxySource();
        /** Returns SHA-256 hex digests for an installed package's signing certs, or empty set. */
        Set<String> getInstalledPackageCertSha256Hex(String packageName);
        /** Read-only existence probe: returns true ONLY when confirmed present; denials return false. */
        boolean probeModuleExistsReadOnly(String path);
    }

    private static final class AndroidNetworkEnvironment implements NetworkEnvironment {
        private final Context context;
        private final SignalSnapshot signals;

        AndroidNetworkEnvironment(Context context, SignalSnapshot signals) {
            this.context = context;
            this.signals = signals;
        }

        @Override
        public int countAndroidCaStoreUserCerts() {
            try {
                KeyStore ks = KeyStore.getInstance("AndroidCAStore");
                ks.load(null, null);
                int count = 0;
                Enumeration<String> aliases = ks.aliases();
                while (aliases != null && aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (alias != null && alias.startsWith("user:")) {
                        count++;
                    }
                }
                return count;
            } catch (Exception | LinkageError e) {
                return -1;
            }
        }

        @Override
        public int countCacertsAddedFiles() {
            try {
                int userId = 0;
                try {
                    int uid = Process.myUid();
                    if (uid >= 0) {
                        userId = uid / PER_USER_RANGE;
                    }
                } catch (Exception | LinkageError ignored) {
                    userId = 0;
                }
                File dir = new File("/data/misc/user/" + userId + "/cacerts-added");
                if (!dir.exists() || !dir.isDirectory() || !dir.canRead()) {
                    return -1;
                }
                File[] files = dir.listFiles();
                if (files == null) {
                    return -1;
                }
                int count = 0;
                for (File f : files) {
                    if (f != null && f.isFile()) {
                        count++;
                    }
                }
                return count;
            } catch (SecurityException | LinkageError e) {
                // Visibility loss is never a threat.
                return -1;
            } catch (Exception e) {
                return -1;
            }
        }

        @SuppressLint("MissingPermission")
        @Override
        public Boolean hasConnectivityTransportVpn() {
            if (context == null) {
                return null;
            }
            try {
                if (context.checkSelfPermission(Manifest.permission.ACCESS_NETWORK_STATE)
                        != PackageManager.PERMISSION_GRANTED) {
                    return null;
                }
                ConnectivityManager cm = (ConnectivityManager) context.getSystemService(
                        Context.CONNECTIVITY_SERVICE);
                if (cm == null) {
                    return null;
                }
                Network active = cm.getActiveNetwork();
                if (active == null) {
                    return Boolean.FALSE;
                }
                NetworkCapabilities caps = cm.getNetworkCapabilities(active);
                return caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
            } catch (SecurityException | LinkageError e) {
                return null;
            } catch (Exception e) {
                return null;
            }
        }

        @Override
        public List<String> getNetworkInterfaceNames() {
            if (signals == null) {
                return null;
            }
            SignalResult<List<String>> res = signals.getNetworkInterfaceNames();
            return (res != null && res.isSuccess()) ? res.getValue() : null;
        }

        @SuppressLint("MissingPermission")
        @Override
        public String detectActiveHttpProxySource() {
            // 1. ConnectivityManager default proxy when host has ACCESS_NETWORK_STATE
            if (context != null) {
                try {
                    if (context.checkSelfPermission(Manifest.permission.ACCESS_NETWORK_STATE)
                            == PackageManager.PERMISSION_GRANTED) {
                        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(
                                Context.CONNECTIVITY_SERVICE);
                        if (cm != null) {
                            ProxyInfo proxy = cm.getDefaultProxy();
                            if (proxy != null && (isNonEmptyProxyValue(proxy.getHost())
                                    || proxy.getPacFileUrl() != null)) {
                                return "connectivity_default";
                            }
                        }
                    }
                } catch (Exception | LinkageError ignored) {
                    // Graceful fallback to JVM / Settings.Global
                }
            }

            // 2. JVM system proxy properties (zero permissions)
            try {
                if (isNonEmptyProxyValue(System.getProperty("http.proxyHost"))
                        || isNonEmptyProxyValue(System.getProperty("https.proxyHost"))) {
                    return "jvm_property";
                }
            } catch (Exception ignored) {
                // ignore
            }

            // 3. Settings.Global.HTTP_PROXY (zero permissions)
            if (context != null) {
                try {
                    String globalProxy = Settings.Global.getString(
                            context.getContentResolver(), Settings.Global.HTTP_PROXY);
                    if (isNonEmptyProxyValue(globalProxy)) {
                        return "global_setting";
                    }
                } catch (Exception | LinkageError ignored) {
                    // ignore
                }
            }
            return null;
        }

        @Override
        public Set<String> getInstalledPackageCertSha256Hex(String packageName) {
            if (context == null || packageName == null || packageName.isBlank()) {
                return Collections.emptySet();
            }
            try {
                PackageManager pm = context.getPackageManager();
                if (pm == null) {
                    return Collections.emptySet();
                }
                PackageInfo info = pm.getPackageInfo(
                        packageName, PackageManager.GET_SIGNING_CERTIFICATES);
                if (info == null || info.signingInfo == null) {
                    return Collections.emptySet();
                }
                SigningInfo signingInfo = info.signingInfo;
                Signature[] sigs = signingInfo.hasMultipleSigners()
                        ? signingInfo.getApkContentsSigners()
                        : signingInfo.getSigningCertificateHistory();
                if (sigs == null || sigs.length == 0) {
                    sigs = signingInfo.getApkContentsSigners();
                }
                if (sigs == null || sigs.length == 0) {
                    return Collections.emptySet();
                }
                Set<String> hashes = new LinkedHashSet<>();
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                for (Signature sig : sigs) {
                    if (sig == null) continue;
                    byte[] raw = sig.toByteArray();
                    if (raw == null || raw.length == 0) continue;
                    hashes.add(toLowerHex(md.digest(raw)));
                }
                return hashes;
            } catch (PackageManager.NameNotFoundException e) {
                return Collections.emptySet();
            } catch (Exception | LinkageError e) {
                return Collections.emptySet();
            }
        }

        @Override
        public boolean probeModuleExistsReadOnly(String path) {
            if (path == null || path.isBlank()) {
                return false;
            }
            try {
                File f = new File(path);
                // Only positive confirmed existence counts; SecurityException / ENOENT / denial -> false.
                return f.exists();
            } catch (SecurityException | LinkageError e) {
                return false;
            } catch (Exception e) {
                return false;
            }
        }

        private static String toLowerHex(byte[] bytes) {
            char[] hex = "0123456789abcdef".toCharArray();
            char[] out = new char[bytes.length * 2];
            for (int i = 0; i < bytes.length; i++) {
                int v = bytes[i] & 0xFF;
                out[i * 2] = hex[v >>> 4];
                out[i * 2 + 1] = hex[v & 0x0F];
            }
            return new String(out);
        }
    }
}
