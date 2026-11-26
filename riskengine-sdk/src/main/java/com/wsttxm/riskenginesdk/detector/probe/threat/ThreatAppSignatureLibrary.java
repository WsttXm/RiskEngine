package com.wsttxm.riskenginesdk.detector.probe.threat;

import com.wsttxm.riskenginesdk.ThreatAppPolicy;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Curated library of official release certificate SHA-256 digests, package identities,
 * extracted native daemon payloads, and Zygote preload markers for mainstream Root managers,
 * HMA app hiders, hook frameworks, memory/cheat tools, and privileged API bridges.
 *
 * <p>Root manager entries classify under {@link Category#ROOT_MANAGER} so {@code ThreatAppDetector}
 * maps them to the canonical {@code root_fw} evidence family (automatically deduplicating with
 * {@code root} and {@code mount_analysis} in {@code DataAggregator}). General cheat, hook, HMA,
 * and patch tools classify under {@link Category#THREAT_TOOL} or {@link Category#APP_HIDER}.
 */
public final class ThreatAppSignatureLibrary {

    public enum Category {
        /** Root manager apps (KernelSU, KSU-Next, SukiSU, Magisk, APatch, SKRoot, SuperSU). */
        ROOT_MANAGER,
        /** App-hiding frameworks (HideMyApplist, HMA-OSS, HMA). */
        APP_HIDER,
        /** Hook frameworks, memory editors, patchers, privileged bridges, and tamper tools. */
        THREAT_TOOL
    }

    public static final class ToolSignature {
        private final String toolId;
        private final String displayName;
        private final Category category;
        private final Set<String> packageNames;
        private final Set<String> officialCertSha256s;
        private final Set<String> nativePayloads;
        private final Set<String> zygotePreloadSuffixes;
        private final Set<String> zygoteNamespaces;

        ToolSignature(String toolId,
                      String displayName,
                      Category category,
                      List<String> packageNames,
                      List<String> officialCertSha256s,
                      List<String> nativePayloads,
                      List<String> zygotePreloadSuffixes,
                      List<String> zygoteNamespaces) {
            this.toolId = toolId;
            this.displayName = displayName;
            this.category = category;
            this.packageNames = Collections.unmodifiableSet(new LinkedHashSet<>(packageNames));
            Set<String> normalizedCerts = new LinkedHashSet<>();
            for (String sha : officialCertSha256s) {
                normalizedCerts.add(ThreatAppPolicy.normalizeSha256Hex(sha));
            }
            this.officialCertSha256s = Collections.unmodifiableSet(normalizedCerts);
            this.nativePayloads = Collections.unmodifiableSet(new LinkedHashSet<>(nativePayloads));
            this.zygotePreloadSuffixes =
                    Collections.unmodifiableSet(new LinkedHashSet<>(zygotePreloadSuffixes));
            this.zygoteNamespaces =
                    Collections.unmodifiableSet(new LinkedHashSet<>(zygoteNamespaces));
        }

        public String getToolId() {
            return toolId;
        }

        public String getDisplayName() {
            return displayName;
        }

        public Category getCategory() {
            return category;
        }

        public boolean isRootManager() {
            return category == Category.ROOT_MANAGER;
        }

        public Set<String> getPackageNames() {
            return packageNames;
        }

        public Set<String> getOfficialCertSha256s() {
            return officialCertSha256s;
        }

        public Set<String> getNativePayloads() {
            return nativePayloads;
        }

        public Set<String> getZygotePreloadSuffixes() {
            return zygotePreloadSuffixes;
        }

        public Set<String> getZygoteNamespaces() {
            return zygoteNamespaces;
        }
    }

    private static final String MAGICA_PRELOAD_SUFFIX = ".magica.AppZygotePreload";

    private static final List<ToolSignature> SIGNATURES;
    private static final Map<String, ToolSignature> BY_CERT_SHA256;
    private static final Map<String, ToolSignature> BY_PACKAGE;
    private static final Set<String> ALL_NATIVE_PAYLOADS;
    private static final Map<String, ToolSignature> BY_NATIVE_PAYLOAD;

    static {
        List<ToolSignature> list = Arrays.asList(
                // --- Root Managers (root_fw family) ---
                new ToolSignature(
                        "kernelsu",
                        "KernelSU",
                        Category.ROOT_MANAGER,
                        Arrays.asList("me.weishu.kernelsu", "io.github.a13e300.mksu"),
                        Arrays.asList(
                                // tiann/KernelSU & MKSU official kernel/Kbuild KSU_EXPECTED_HASH (827 B)
                                "c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6",
                                // KOWX712/KernelSU fork manager_sign.h EXPECTED_HASH (885 B)
                                "484fcba6e6c43b1fb09700633bf2fb4758f13cb0b2f4457b80d075084b26c588"
                        ),
                        Collections.singletonList("libksud.so"),
                        Collections.singletonList(MAGICA_PRELOAD_SUFFIX),
                        Collections.singletonList("me.weishu.kernelsu")
                ),
                new ToolSignature(
                        "ksu_next",
                        "KernelSU-Next",
                        Category.ROOT_MANAGER,
                        Collections.singletonList("com.rifsxd.ksunext"),
                        Collections.singletonList(
                                // KernelSU-Next official kernel/Kbuild KSU_NEXT_MANAGER_HASH (998 B)
                                "79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7"
                        ),
                        Collections.singletonList("libksud.so"),
                        Collections.emptyList(),
                        Collections.singletonList("com.rifsxd.ksunext")
                ),
                new ToolSignature(
                        "sukisu",
                        "SukiSU",
                        Category.ROOT_MANAGER,
                        Arrays.asList("com.sukisu.ultra", "com.resukisu.resukisu"),
                        Arrays.asList(
                                // SukiSU-Ultra official kernel/Kbuild KSU_EXPECTED_HASH (860 B)
                                "947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef",
                                // ReSukiSU / BakaSU manager_sign.h HASH_BAKASU (887 B)
                                "d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64"
                        ),
                        Collections.singletonList("libksud.so"),
                        Collections.singletonList(MAGICA_PRELOAD_SUFFIX),
                        Arrays.asList("com.sukisu.ultra", "com.resukisu.resukisu", "org.bakasu.bakasu")
                ),
                new ToolSignature(
                        "magisk",
                        "Magisk",
                        Category.ROOT_MANAGER,
                        Arrays.asList("com.topjohnwu.magisk", "io.github.vvb2060.magisk"),
                        Collections.singletonList(
                                // topjohnwu official Magisk release certificate SHA-256
                                "b4cb83b4dad99f997dbe872f013aa16c14eec41d167021f371f7e1330f273ee6"
                        ),
                        Arrays.asList("libmagisk.so", "libmagiskinit.so"),
                        Collections.emptyList(),
                        Collections.singletonList("com.topjohnwu.magisk")
                ),
                new ToolSignature(
                        "apatch",
                        "APatch",
                        Category.ROOT_MANAGER,
                        Collections.singletonList("me.bmax.apatch"),
                        Collections.singletonList(
                                // bmax121 official APatch release signing certificate DER SHA-256 (CN=APatch)
                                "d71dadc0ca07bdf594383bfb2a445134a07339f12a27044a1b326981acf5f319"
                        ),
                        Arrays.asList("libapd.so", "libkptools.so", "libkpatch.so"),
                        Collections.singletonList(MAGICA_PRELOAD_SUFFIX),
                        Collections.singletonList("me.bmax.apatch")
                ),
                new ToolSignature(
                        "skroot",
                        "SKRoot",
                        Category.ROOT_MANAGER,
                        Collections.singletonList("com.linux.permissionmanager"),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.singletonList("com.linux.permissionmanager")
                ),
                new ToolSignature(
                        "supersu",
                        "SuperSU",
                        Category.ROOT_MANAGER,
                        Collections.singletonList("eu.chainfire.supersu"),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList()
                ),

                // --- App Hiders (HMA family) ---
                new ToolSignature(
                        "hidemyapplist",
                        "HideMyApplist",
                        Category.APP_HIDER,
                        Arrays.asList(
                                "com.tsng.hidemyapplist",
                                "org.frknkrc44.hma_oss",
                                "com.tsng.pzyhrx.hma"
                        ),
                        Collections.singletonList(
                                // frknkrc44 HMA-OSS official release signing cert SHA-256
                                "dd5f995a223eac038b0b5147b5cfc69ae911ebcc04e2af5fb0e8a4eb68dbb9de"
                        ),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList()
                ),

                // --- Hook, Cheat, Patch & Privileged Tools ---
                // Matched via curated package catalog and/or behavioral probes; hosts may supply
                // verified extra signing certs via ThreatAppPolicy.Builder.additionalCertSha256s().
                new ToolSignature(
                        "lsposed",
                        "LSPosed",
                        Category.THREAT_TOOL,
                        Arrays.asList(
                                "org.lsposed.manager",
                                "org.lsposed.lspatch",
                                "de.robv.android.xposed.installer"
                        ),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList()
                ),
                new ToolSignature(
                        "gameguardian",
                        "GameGuardian",
                        Category.THREAT_TOOL,
                        Collections.singletonList("catch_.me_.if_.you_.can_"),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList()
                ),
                new ToolSignature(
                        "luckypatcher",
                        "LuckyPatcher",
                        Category.THREAT_TOOL,
                        Arrays.asList(
                                "com.chelpus.lackypatch",
                                "com.android.vending.billing.InAppBillingService.LUCK",
                                "com.forpda.lp"
                        ),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList()
                ),
                new ToolSignature(
                        "shizuku",
                        "Shizuku",
                        Category.THREAT_TOOL,
                        Collections.singletonList("moe.shizuku.privileged.api"),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList()
                ),
                new ToolSignature(
                        "thanox",
                        "Thanox",
                        Category.THREAT_TOOL,
                        Collections.singletonList("github.tornaco.android.thanos"),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList()
                ),
                new ToolSignature(
                        "fakelocation",
                        "FakeLocation",
                        Category.THREAT_TOOL,
                        Collections.singletonList("com.lerist.fakelocation"),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList()
                )
        );
        SIGNATURES = Collections.unmodifiableList(list);

        Map<String, ToolSignature> byCert = new LinkedHashMap<>();
        Map<String, ToolSignature> byPkg = new LinkedHashMap<>();
        Set<String> payloads = new LinkedHashSet<>();
        Map<String, ToolSignature> byPayload = new LinkedHashMap<>();
        for (ToolSignature sig : SIGNATURES) {
            for (String sha : sig.getOfficialCertSha256s()) {
                byCert.put(sha, sig);
            }
            for (String pkg : sig.getPackageNames()) {
                byPkg.put(pkg, sig);
            }
            for (String payload : sig.getNativePayloads()) {
                payloads.add(payload);
                byPayload.putIfAbsent(payload, sig);
            }
        }
        BY_CERT_SHA256 = Collections.unmodifiableMap(byCert);
        BY_PACKAGE = Collections.unmodifiableMap(byPkg);
        ALL_NATIVE_PAYLOADS = Collections.unmodifiableSet(payloads);
        BY_NATIVE_PAYLOAD = Collections.unmodifiableMap(byPayload);
    }

    private ThreatAppSignatureLibrary() {}

    public static List<ToolSignature> getSignatures() {
        return SIGNATURES;
    }

    public static ToolSignature matchByCertSha256(String sha256Hex) {
        if (sha256Hex == null || sha256Hex.isEmpty()) {
            return null;
        }
        return BY_CERT_SHA256.get(sha256Hex.toLowerCase(Locale.US));
    }

    public static ToolSignature matchByPackageName(String packageName) {
        if (packageName == null || packageName.isEmpty()) {
            return null;
        }
        return BY_PACKAGE.get(packageName);
    }

    public static ToolSignature matchByNativePayload(String payloadFileName) {
        if (payloadFileName == null || payloadFileName.isEmpty()) {
            return null;
        }
        return BY_NATIVE_PAYLOAD.get(payloadFileName);
    }

    public static Set<String> getAllNativePayloads() {
        return ALL_NATIVE_PAYLOADS;
    }

    /**
     * Matches an app's {@code android:zygotePreloadName} against known Root manager preload
     * suffixes (e.g. {@code .magica.AppZygotePreload}) or known Root manager code namespaces.
     */
    public static ToolSignature matchByZygotePreload(String preloadName) {
        if (preloadName == null || preloadName.isBlank()) {
            return null;
        }
        String trimmed = preloadName.trim();
        // Check namespace match first for more specific attribution (e.g. com.sukisu.ultra.*).
        for (ToolSignature sig : SIGNATURES) {
            for (String ns : sig.getZygoteNamespaces()) {
                if (trimmed.equals(ns) || trimmed.startsWith(ns + ".")) {
                    return sig;
                }
            }
        }
        for (ToolSignature sig : SIGNATURES) {
            for (String suffix : sig.getZygotePreloadSuffixes()) {
                if (trimmed.endsWith(suffix)) {
                    return sig;
                }
            }
        }
        return null;
    }
}
