package com.wsttxm.riskenginesdk.detector.probe.consistency;

import android.os.Build;

import com.wsttxm.riskenginesdk.attestation.AttestationCapability;
import com.wsttxm.riskenginesdk.attestation.AttestationRecord;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.ConsistencyDetector;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Authoritative Bootloader &amp; Verified Boot probe hosted inside {@link ConsistencyDetector}.
 *
 * <p>Combines:
 * <ol>
 *   <li>Fast pass: {@code /proc/bootconfig}, {@code /proc/cmdline}, 21 Boot/AVB/Samsung Knox
 *       system properties (strictly gating {@code ro.boot.warranty_bit} on Samsung OEMs), and
 *       the VBMeta empty-input SHA-256/SHA-512 digest trap (Specter {@code boot_hash.sh}).</li>
 *   <li>Postponed hardware pass: Hardware Key Attestation {@code RootOfTrust} (highest priority),
 *       runtime {@code ro.boot.vbmeta.digest} parity, and spoofed-green contradiction detection
 *       feeding correlation rule {@code C8:spoofed_verified_boot}.</li>
 * </ol>
 */
public final class BootloaderProbe {

    /** SHA-256("") — empty-input VBMeta digest spoofed by Specter boot_hash.sh. */
    public static final String EMPTY_SHA256_HEX =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /** SHA-512("") — empty-input SHA-512 VBMeta digest spoof. */
    public static final String EMPTY_SHA512_HEX =
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                    + "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

    /** Complete 21-property Boot / AVB / Samsung Knox catalog. */
    public static final String[] BOOTLOADER_PROPERTIES = {
        "ro.boot.flash.locked",
        "ro.boot.verifiedbootstate",
        "ro.boot.secureboot",
        "ro.debuggable",
        "ro.secure",
        "ro.boot.warranty_bit",
        "ro.warranty_bit",
        "ro.boot.knox.state",
        "ro.oem_unlock_supported",
        "ro.boot.vbmeta.device_state",
        "ro.boot.veritymode",
        "ro.boot.vbmeta.hash_alg",
        "ro.boot.vbmeta.size",
        "ro.boot.vbmeta.digest",
        "ro.boot.avb_version",
        "ro.boot.vbmeta.invalidate_on_error",
        "partition.system.verified",
        "partition.vendor.verified",
        "partition.product.verified",
        "partition.system_ext.verified",
        "partition.odm.verified"
    };

    private static final String[] PARTITION_VERITY_PROPS = {
        "partition.system.verified",
        "partition.vendor.verified",
        "partition.product.verified",
        "partition.system_ext.verified",
        "partition.odm.verified"
    };

    private static final Pattern BOOTCONFIG_ENTRY =
            Pattern.compile("^\\s*([a-zA-Z0-9_.-]+)\\s*=\\s*\"?([^\"]*?)\"?\\s*$");

    private BootloaderProbe() {
    }

    public static final class FastResult {
        private final boolean usable;
        private final Set<String> strongTokens;
        private final Set<String> mediumActionableTokens;
        private final Set<String> weakTokens;
        private final List<EvidenceItem> evidenceItems;

        FastResult(
                boolean usable,
                Set<String> strongTokens,
                Set<String> mediumActionableTokens,
                Set<String> weakTokens,
                List<EvidenceItem> evidenceItems) {
            this.usable = usable;
            this.strongTokens = Collections.unmodifiableSet(strongTokens);
            this.mediumActionableTokens = Collections.unmodifiableSet(mediumActionableTokens);
            this.weakTokens = Collections.unmodifiableSet(weakTokens);
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
        }

        public boolean isUsable() {
            return usable;
        }

        public Set<String> getStrongTokens() {
            return strongTokens;
        }

        public Set<String> getMediumActionableTokens() {
            return mediumActionableTokens;
        }

        public Set<String> getWeakTokens() {
            return weakTokens;
        }

        public List<EvidenceItem> getEvidenceItems() {
            return evidenceItems;
        }
    }

    public static final class HardwareResult {
        private final boolean evaluated;
        private final Set<String> strongTokens;
        private final Set<String> mediumActionableTokens;
        private final List<EvidenceItem> evidenceItems;

        HardwareResult(
                boolean evaluated,
                Set<String> strongTokens,
                Set<String> mediumActionableTokens,
                List<EvidenceItem> evidenceItems) {
            this.evaluated = evaluated;
            this.strongTokens = Collections.unmodifiableSet(strongTokens);
            this.mediumActionableTokens = Collections.unmodifiableSet(mediumActionableTokens);
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
        }

        public boolean isEvaluated() {
            return evaluated;
        }

        public Set<String> getStrongTokens() {
            return strongTokens;
        }

        public Set<String> getMediumActionableTokens() {
            return mediumActionableTokens;
        }

        public List<EvidenceItem> getEvidenceItems() {
            return evidenceItems;
        }

        public boolean hasFindings() {
            return !strongTokens.isEmpty() || !mediumActionableTokens.isEmpty() || !evidenceItems.isEmpty();
        }
    }

    /**
     * FAST-tier boot/AVB/Samsung Knox evaluation (no KeyMint IPC).
     */
    public static FastResult evaluateFast(SignalSnapshot signals) {
        Set<String> strong = new LinkedHashSet<>();
        Set<String> mediumActionable = new LinkedHashSet<>();
        Set<String> weak = new LinkedHashSet<>();
        List<EvidenceItem> items = new ArrayList<>();

        if (signals == null) {
            return new FastResult(false, strong, mediumActionable, weak, items);
        }

        boolean any = false;
        Map<String, String> props = new LinkedHashMap<>();
        SignalResult<String> stateRes = null;
        SignalResult<String> lockedRes = null;

        for (String name : BOOTLOADER_PROPERTIES) {
            SignalResult<String> res = signals.getSystemProperty(name);
            if ("ro.boot.verifiedbootstate".equals(name)) {
                stateRes = res;
            } else if ("ro.boot.flash.locked".equals(name)) {
                lockedRes = res;
            }
            String val = nonBlankLower(res);
            if (!val.isEmpty()) {
                any = true;
                props.put(name, val);
            }
        }

        String propState = props.getOrDefault("ro.boot.verifiedbootstate", "");
        String propLocked = props.getOrDefault("ro.boot.flash.locked", "");
        String propVbmetaDigest = normalizeHex(props.get("ro.boot.vbmeta.digest"));
        String propVbmetaDeviceState = props.getOrDefault("ro.boot.vbmeta.device_state", "");
        String propVerityMode = props.getOrDefault("ro.boot.veritymode", "");
        String propSecureBoot = props.getOrDefault("ro.boot.secureboot", "");

        if (!propState.isEmpty() && !"green".equals(propState)) {
            weak.add("verified_boot_state:" + propState);
            items.add(new EvidenceItem(
                    "verified_boot_state",
                    EvidenceItem.SourceLayer.JAVA,
                    "ro.boot.verifiedbootstate",
                    propState,
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.MEDIUM));
        }

        if ("0".equals(propLocked) || "unlocked".equals(propVbmetaDeviceState)) {
            weak.add("bootloader_unlocked");
            items.add(new EvidenceItem(
                    "bootloader_unlocked",
                    EvidenceItem.SourceLayer.JAVA,
                    "0".equals(propLocked) ? "ro.boot.flash.locked" : "ro.boot.vbmeta.device_state",
                    "0".equals(propLocked) ? "0" : "unlocked",
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.MEDIUM));
        }

        // VBMeta empty-input SHA-256 / SHA-512 trap (Specter boot_hash.sh)
        boolean propsClaimGreenLocked = "green".equals(propState) && "1".equals(propLocked);
        if (isEmptyInputHash(propVbmetaDigest)) {
            strong.add("vbmeta_empty_input_digest:ro.boot.vbmeta.digest");
            items.add(new EvidenceItem(
                    "vbmeta_empty_input_digest",
                    EvidenceItem.SourceLayer.JAVA,
                    "ro.boot.vbmeta.digest",
                    propVbmetaDigest,
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.STRONG));
            if (propsClaimGreenLocked) {
                strong.add("spoofed_verified_boot_props");
                items.add(new EvidenceItem(
                        "spoofed_verified_boot_props",
                        EvidenceItem.SourceLayer.JAVA,
                        "ro.boot.verifiedbootstate",
                        "empty_vbmeta_with_green_locked",
                        ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                        EvidenceItem.Rank.STRONG));
            }
        }

        // dm-verity mode disabled/eio/logging
        if ("disabled".equals(propVerityMode) || "eio".equals(propVerityMode) || "logging".equals(propVerityMode)) {
            weak.add("verity_mode_disabled:" + propVerityMode);
            items.add(new EvidenceItem(
                    "verity_mode_disabled",
                    EvidenceItem.SourceLayer.JAVA,
                    "ro.boot.veritymode",
                    propVerityMode,
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.MEDIUM));
        }

        // Per-partition dm-verity explicitly 0
        for (String partProp : PARTITION_VERITY_PROPS) {
            String val = props.getOrDefault(partProp, "");
            if ("0".equals(val) || "false".equals(val)) {
                weak.add("partition_verity_disabled:" + partProp);
                items.add(new EvidenceItem(
                        "partition_verity_disabled",
                        EvidenceItem.SourceLayer.JAVA,
                        partProp,
                        val,
                        ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                        EvidenceItem.Rank.MEDIUM));
            }
        }

        if ("0".equals(propSecureBoot)) {
            weak.add("secureboot_disabled");
            items.add(new EvidenceItem(
                    "secureboot_disabled",
                    EvidenceItem.SourceLayer.JAVA,
                    "ro.boot.secureboot",
                    "0",
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.WEAK));
        }

        // Samsung Knox warranty e-fuse — strictly gated on Samsung OEMs only!
        if (isSamsungDevice(signals)) {
            String wb = props.getOrDefault("ro.boot.warranty_bit", "");
            String wbAlt = props.getOrDefault("ro.warranty_bit", "");
            String knoxState = props.getOrDefault("ro.boot.knox.state", "");
            if ("1".equals(wb) || "1".equals(wbAlt)) {
                weak.add("knox_warranty_void");
                items.add(new EvidenceItem(
                        "knox_warranty_void",
                        EvidenceItem.SourceLayer.JAVA,
                        "1".equals(wb) ? "ro.boot.warranty_bit" : "ro.warranty_bit",
                        "1",
                        ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                        EvidenceItem.Rank.MEDIUM));
            } else if (!knoxState.isEmpty() && !"0".equals(knoxState) && !"0x0".equals(knoxState)
                    && !"normal".equals(knoxState)) {
                weak.add("knox_warranty_void:" + knoxState);
                items.add(new EvidenceItem(
                        "knox_warranty_void",
                        EvidenceItem.SourceLayer.JAVA,
                        "ro.boot.knox.state",
                        knoxState,
                        ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                        EvidenceItem.Rank.MEDIUM));
            }
        }

        // Cross-check /proc/cmdline boot params against ro.boot.* props
        SignalResult<Map<String, String>> cmdline = signals.getProcCmdlineBootProps();
        if (cmdline != null && cmdline.isSuccess() && cmdline.getValue() != null && !cmdline.getValue().isEmpty()) {
            any = true;
            crossCheckBootSource(
                    "cmdline",
                    EvidenceItem.SourceLayer.NATIVE,
                    cmdline.getValue(),
                    propState,
                    propLocked,
                    propVbmetaDigest,
                    propsClaimGreenLocked,
                    strong,
                    weak,
                    items);
        }

        // Cross-check /proc/bootconfig (Android 12+ GKI kernels)
        SignalResult<String> bootconfigRaw = signals.getTextFile("/proc/bootconfig");
        if (bootconfigRaw != null && bootconfigRaw.isSuccess()
                && bootconfigRaw.getValue() != null && !bootconfigRaw.getValue().isBlank()) {
            Map<String, String> bootconfig = parseBootconfig(bootconfigRaw.getValue());
            if (!bootconfig.isEmpty()) {
                any = true;
                crossCheckBootSource(
                        "bootconfig",
                        EvidenceItem.SourceLayer.JAVA,
                        bootconfig,
                        propState,
                        propLocked,
                        propVbmetaDigest,
                        propsClaimGreenLocked,
                        strong,
                        weak,
                        items);
            }
        }

        boolean propsQueriedCleanly = (stateRes != null && (stateRes.isSuccess() || stateRes.getStatus() == SignalResult.Status.EMPTY))
                || (lockedRes != null && (lockedRes.isSuccess() || lockedRes.getStatus() == SignalResult.Status.EMPTY));

        return new FastResult(any || propsQueriedCleanly, strong, mediumActionable, weak, items);
    }

    /**
     * POSTPONED-tier hardware RootOfTrust evaluation (highest authority).
     */
    public static HardwareResult evaluateHardwareRootOfTrust(
            SignalSnapshot signals, boolean enableTeeAttestation) {
        Set<String> strong = new LinkedHashSet<>();
        Set<String> mediumActionable = new LinkedHashSet<>();
        List<EvidenceItem> items = new ArrayList<>();

        if (signals == null || !enableTeeAttestation) {
            return new HardwareResult(false, strong, mediumActionable, items);
        }

        SignalResult<AttestationCapability.AttestationSnapshot> attRes =
                signals.getAttestationSnapshot(true);
        if (attRes == null || !attRes.isSuccess() || attRes.getValue() == null) {
            return new HardwareResult(false, strong, mediumActionable, items);
        }

        AttestationCapability.AttestationSnapshot snap = attRes.getValue();
        AttestationRecord rec = snap.getRecord();
        if (!snap.isAvailable() || rec == null || !rec.isValid() || rec.getRootOfTrust() == null) {
            return new HardwareResult(false, strong, mediumActionable, items);
        }

        AttestationRecord.RootOfTrust rot = rec.getRootOfTrust();
        if (!rot.isHardwareEnforced() && !rec.getAttestationSecurityLevel().isHardwareBacked()) {
            // Software-only RootOfTrust is not hardware authority.
            return new HardwareResult(false, strong, mediumActionable, items);
        }

        String propState = nonBlankLower(signals.getSystemProperty("ro.boot.verifiedbootstate"));
        String propLocked = nonBlankLower(signals.getSystemProperty("ro.boot.flash.locked"));
        String propVbmetaDigest = normalizeHex(nonBlankLower(signals.getSystemProperty("ro.boot.vbmeta.digest")));
        boolean propsClaimGreenLocked = "green".equals(propState) && "1".equals(propLocked);

        boolean hwUnlockedOrOrange = false;
        if (!rot.isDeviceLocked()) {
            hwUnlockedOrOrange = true;
            mediumActionable.add("key_attestation:bootloader_unlocked");
            items.add(new EvidenceItem(
                    "bootloader_unlocked",
                    EvidenceItem.SourceLayer.HARDWARE,
                    "RootOfTrust.deviceLocked",
                    "false",
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.MEDIUM));
        }

        AttestationRecord.VerifiedBootState bootState = rot.getVerifiedBootState();
        if (bootState == AttestationRecord.VerifiedBootState.UNVERIFIED) {
            hwUnlockedOrOrange = true;
            mediumActionable.add("key_attestation:verified_boot_orange");
            items.add(new EvidenceItem(
                    "verified_boot_state",
                    EvidenceItem.SourceLayer.HARDWARE,
                    "RootOfTrust.verifiedBootState",
                    "unverified",
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.MEDIUM));
        } else if (bootState == AttestationRecord.VerifiedBootState.FAILED) {
            hwUnlockedOrOrange = true;
            strong.add("key_attestation:verified_boot_red");
            items.add(new EvidenceItem(
                    "verified_boot_state",
                    EvidenceItem.SourceLayer.HARDWARE,
                    "RootOfTrust.verifiedBootState",
                    "failed",
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.STRONG));
        } else if (bootState == AttestationRecord.VerifiedBootState.SELF_SIGNED) {
            mediumActionable.add("key_attestation:verified_boot_yellow");
            items.add(new EvidenceItem(
                    "verified_boot_state",
                    EvidenceItem.SourceLayer.HARDWARE,
                    "RootOfTrust.verifiedBootState",
                    "self_signed",
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.MEDIUM));
        }

        // VBMeta empty-input digest trap in hardware RootOfTrust.verifiedBootHash
        String rotBootHash = normalizeHex(rot.getVerifiedBootHashHex());
        boolean emptyDigestTrap = false;
        if (isEmptyInputHash(rotBootHash)) {
            emptyDigestTrap = true;
            strong.add("vbmeta_empty_input_digest:root_of_trust");
            items.add(new EvidenceItem(
                    "vbmeta_empty_input_digest",
                    EvidenceItem.SourceLayer.HARDWARE,
                    "RootOfTrust.verifiedBootHash",
                    rotBootHash,
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.STRONG));
        }

        // Runtime VBMeta digest parity & all-zero checks when VERIFIED or SELF_SIGNED
        if (bootState == AttestationRecord.VerifiedBootState.VERIFIED
                || bootState == AttestationRecord.VerifiedBootState.SELF_SIGNED) {
            if (isAllZeroHex(rotBootHash)) {
                strong.add("attested_vbmeta_all_zero");
                items.add(new EvidenceItem(
                        "attested_vbmeta_all_zero",
                        EvidenceItem.SourceLayer.HARDWARE,
                        "RootOfTrust.verifiedBootHash",
                        "all_zero",
                        ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                        EvidenceItem.Rank.STRONG));
            } else if (!rotBootHash.isEmpty() && !propVbmetaDigest.isEmpty()
                    && !rotBootHash.equals(propVbmetaDigest)) {
                strong.add("attested_vbmeta_mismatch");
                items.add(new EvidenceItem(
                        "attested_vbmeta_mismatch",
                        EvidenceItem.SourceLayer.HARDWARE,
                        "ro.boot.vbmeta.digest",
                        "hw_vs_prop_mismatch",
                        ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                        EvidenceItem.Rank.STRONG));
            }
        }

        // Spoofed Verified Boot: hardware reports unlocked/orange/red or empty-VBMeta while props claim green + locked
        if (propsClaimGreenLocked && (hwUnlockedOrOrange || emptyDigestTrap)) {
            strong.add("spoofed_verified_boot_props");
            items.add(new EvidenceItem(
                    "spoofed_verified_boot_props",
                    EvidenceItem.SourceLayer.HARDWARE,
                    "RootOfTrust_vs_ro.boot",
                    "hw_unlocked_or_empty_vbmeta_while_props_green_locked",
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.STRONG));
        }

        return new HardwareResult(true, strong, mediumActionable, items);
    }

    private static void crossCheckBootSource(
            String sourceTag,
            EvidenceItem.SourceLayer layer,
            Map<String, String> bootMap,
            String propState,
            String propLocked,
            String propVbmetaDigest,
            boolean propsClaimGreenLocked,
            Set<String> strong,
            Set<String> weak,
            List<EvidenceItem> items) {
        String mismatchPrefix = sourceTag + "_prop_mismatch";

        String srcState = lowerOrEmpty(bootMap.get("androidboot.verifiedbootstate"));
        if (!srcState.isEmpty() && !propState.isEmpty() && !srcState.equals(propState)) {
            strong.add(mismatchPrefix + ":verifiedbootstate");
            items.add(new EvidenceItem(
                    mismatchPrefix,
                    layer,
                    "verifiedbootstate",
                    sourceTag + "=" + srcState + ",prop=" + propState,
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.STRONG));
        } else if (!srcState.isEmpty() && !"green".equals(srcState) && propState.isEmpty()) {
            weak.add("verified_boot_state:" + srcState);
            items.add(new EvidenceItem(
                    "verified_boot_state",
                    layer,
                    "androidboot.verifiedbootstate",
                    srcState,
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.MEDIUM));
        }

        String srcLocked = lowerOrEmpty(bootMap.get("androidboot.flash.locked"));
        if (!srcLocked.isEmpty() && !propLocked.isEmpty() && !srcLocked.equals(propLocked)) {
            strong.add(mismatchPrefix + ":flash_locked");
            items.add(new EvidenceItem(
                    mismatchPrefix,
                    layer,
                    "flash_locked",
                    sourceTag + "=" + srcLocked + ",prop=" + propLocked,
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.STRONG));
        } else if ("0".equals(srcLocked) && propLocked.isEmpty()) {
            weak.add("bootloader_unlocked");
            items.add(new EvidenceItem(
                    "bootloader_unlocked",
                    layer,
                    "androidboot.flash.locked",
                    "0",
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.MEDIUM));
        }

        String srcVbmeta = normalizeHex(lowerOrEmpty(bootMap.get("androidboot.vbmeta.digest")));
        if (!srcVbmeta.isEmpty() && !propVbmetaDigest.isEmpty() && !srcVbmeta.equals(propVbmetaDigest)) {
            strong.add(mismatchPrefix + ":vbmeta_digest");
            items.add(new EvidenceItem(
                    mismatchPrefix,
                    layer,
                    "vbmeta_digest",
                    sourceTag + "_vs_prop",
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.STRONG));
        }
        if (isEmptyInputHash(srcVbmeta)) {
            strong.add("vbmeta_empty_input_digest:" + sourceTag);
            items.add(new EvidenceItem(
                    "vbmeta_empty_input_digest",
                    layer,
                    "androidboot.vbmeta.digest",
                    srcVbmeta,
                    ConsistencyDetector.FAMILY_BOOT_INTEGRITY,
                    EvidenceItem.Rank.STRONG));
            if (propsClaimGreenLocked) {
                strong.add("spoofed_verified_boot_props");
            }
        }
    }

    public static Map<String, String> parseBootconfig(String content) {
        if (content == null || content.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, String> out = new LinkedHashMap<>();
        for (String line : content.split("\n")) {
            Matcher m = BOOTCONFIG_ENTRY.matcher(line);
            if (m.matches()) {
                String k = m.group(1).trim();
                String v = m.group(2).trim();
                if (!k.isEmpty() && !v.isEmpty()) {
                    out.put(k, v);
                }
            }
        }
        return out;
    }

    public static boolean isEmptyInputHash(String hex) {
        String norm = normalizeHex(hex);
        return EMPTY_SHA256_HEX.equals(norm) || EMPTY_SHA512_HEX.equals(norm);
    }

    static boolean isAllZeroHex(String hex) {
        String norm = normalizeHex(hex);
        if (norm.length() < 16) {
            return false;
        }
        for (int i = 0; i < norm.length(); i++) {
            if (norm.charAt(i) != '0') {
                return false;
            }
        }
        return true;
    }

    static boolean isSamsungDevice(SignalSnapshot signals) {
        String propMfr = nonBlankLower(signals.getSystemProperty("ro.product.manufacturer"));
        String propBrand = nonBlankLower(signals.getSystemProperty("ro.product.brand"));
        if (!propMfr.isEmpty() || !propBrand.isEmpty()) {
            return propMfr.contains("samsung") || propBrand.contains("samsung");
        }
        String mfr = Build.MANUFACTURER == null ? "" : Build.MANUFACTURER.toLowerCase(Locale.ROOT);
        String brand = Build.BRAND == null ? "" : Build.BRAND.toLowerCase(Locale.ROOT);
        return mfr.contains("samsung") || brand.contains("samsung");
    }

    static String normalizeHex(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == ':' || Character.isWhitespace(c)) {
                continue;
            }
            char lc = Character.toLowerCase(c);
            if ((lc >= '0' && lc <= '9') || (lc >= 'a' && lc <= 'f')) {
                sb.append(lc);
            } else {
                return "";
            }
        }
        return sb.toString();
    }

    private static String nonBlankLower(SignalResult<String> result) {
        if (result == null || !result.isSuccess() || result.getValue() == null) {
            return "";
        }
        return result.getValue().trim().toLowerCase(Locale.ROOT);
    }

    private static String lowerOrEmpty(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
