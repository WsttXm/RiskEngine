package com.wsttxm.riskenginesdk.attestation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Immutable parsed representation of Android Key Attestation extension OID
 * {@code 1.3.6.1.4.1.11129.2.1.17}.
 *
 * <p>Never stores raw PII tags (IMEI/MEID/serial number).</p>
 */
public final class AttestationRecord {

    public enum SecurityLevel {
        SOFTWARE(0),
        TRUSTED_ENVIRONMENT(1),
        STRONGBOX(2),
        UNKNOWN(-1);

        private final int code;

        SecurityLevel(int code) {
            this.code = code;
        }

        public int getCode() {
            return code;
        }

        public boolean isHardwareBacked() {
            return this == TRUSTED_ENVIRONMENT || this == STRONGBOX;
        }

        public static SecurityLevel fromCode(int code) {
            switch (code) {
                case 0:
                    return SOFTWARE;
                case 1:
                    return TRUSTED_ENVIRONMENT;
                case 2:
                    return STRONGBOX;
                default:
                    return UNKNOWN;
            }
        }
    }

    public enum VerifiedBootState {
        VERIFIED(0),
        SELF_SIGNED(1),
        UNVERIFIED(2),
        FAILED(3),
        UNKNOWN(-1);

        private final int code;

        VerifiedBootState(int code) {
            this.code = code;
        }

        public int getCode() {
            return code;
        }

        public static VerifiedBootState fromCode(int code) {
            switch (code) {
                case 0:
                    return VERIFIED;
                case 1:
                    return SELF_SIGNED;
                case 2:
                    return UNVERIFIED;
                case 3:
                    return FAILED;
                default:
                    return UNKNOWN;
            }
        }
    }

    public static final class RootOfTrust {
        private final byte[] verifiedBootKey;
        private final boolean deviceLocked;
        private final VerifiedBootState verifiedBootState;
        private final byte[] verifiedBootHash;
        private final boolean hardwareEnforced;

        public RootOfTrust(
                byte[] verifiedBootKey,
                boolean deviceLocked,
                VerifiedBootState verifiedBootState,
                byte[] verifiedBootHash,
                boolean hardwareEnforced) {
            this.verifiedBootKey = verifiedBootKey == null ? new byte[0] : Arrays.copyOf(verifiedBootKey, verifiedBootKey.length);
            this.deviceLocked = deviceLocked;
            this.verifiedBootState = verifiedBootState == null ? VerifiedBootState.UNKNOWN : verifiedBootState;
            this.verifiedBootHash = verifiedBootHash == null ? null : Arrays.copyOf(verifiedBootHash, verifiedBootHash.length);
            this.hardwareEnforced = hardwareEnforced;
        }

        public byte[] getVerifiedBootKey() {
            return Arrays.copyOf(verifiedBootKey, verifiedBootKey.length);
        }

        public String getVerifiedBootKeyHex() {
            return toLowerHex(verifiedBootKey);
        }

        public boolean isDeviceLocked() {
            return deviceLocked;
        }

        public VerifiedBootState getVerifiedBootState() {
            return verifiedBootState;
        }

        public byte[] getVerifiedBootHash() {
            return verifiedBootHash == null ? null : Arrays.copyOf(verifiedBootHash, verifiedBootHash.length);
        }

        public String getVerifiedBootHashHex() {
            return verifiedBootHash == null ? null : toLowerHex(verifiedBootHash);
        }

        public boolean isHardwareEnforced() {
            return hardwareEnforced;
        }
    }

    public static final class AttestationApplicationId {
        private final List<String> packageNames;
        private final Map<String, Long> packageVersions;
        private final List<String> signatureDigestsSha256;

        public AttestationApplicationId(
                List<String> packageNames,
                Map<String, Long> packageVersions,
                List<String> signatureDigestsSha256) {
            this.packageNames = Collections.unmodifiableList(new ArrayList<>(packageNames));
            this.packageVersions = Collections.unmodifiableMap(new LinkedHashMap<>(packageVersions));
            this.signatureDigestsSha256 = Collections.unmodifiableList(new ArrayList<>(signatureDigestsSha256));
        }

        public List<String> getPackageNames() {
            return packageNames;
        }

        public Map<String, Long> getPackageVersions() {
            return packageVersions;
        }

        public List<String> getSignatureDigestsSha256() {
            return signatureDigestsSha256;
        }
    }

    private final boolean valid;
    private final int attestationVersion;
    private final SecurityLevel attestationSecurityLevel;
    private final int keymasterVersion;
    private final SecurityLevel keymasterSecurityLevel;
    private final byte[] attestationChallenge;
    private final byte[] uniqueId;
    private final boolean challengeMatched;
    private final RootOfTrust rootOfTrust;
    private final Integer osVersion;
    private final String osVersionFormatted;
    private final Integer osPatchLevel;
    private final String osPatchLevelFormatted;
    private final Integer bootPatchLevel;
    private final String bootPatchLevelFormatted;
    private final Integer vendorPatchLevel;
    private final String vendorPatchLevelFormatted;
    private final AttestationApplicationId attestationApplicationId;
    private final String brand;
    private final String device;
    private final String product;
    private final String manufacturer;
    private final String model;
    private final Integer algorithm;
    private final Integer keySize;
    private final Integer ecCurve;
    private final Integer origin;
    private final List<Integer> purposes;
    private final boolean rollbackResistant;
    private final boolean deviceUniqueAttestation;
    private final String moduleHashHex;
    private final int trustedAttestationCertIndex;
    private final int attestationExtensionCount;
    private final boolean leafShadowAttempted;
    private final Set<Integer> swTagIds;
    private final Set<Integer> hwTagIds;
    private final DerReader.LeafDerInspection leafDerInspection;
    private final String parseError;

    private AttestationRecord(Builder b) {
        this.valid = b.valid;
        this.attestationVersion = b.attestationVersion;
        this.attestationSecurityLevel = b.attestationSecurityLevel;
        this.keymasterVersion = b.keymasterVersion;
        this.keymasterSecurityLevel = b.keymasterSecurityLevel;
        this.attestationChallenge = b.attestationChallenge == null
                ? new byte[0]
                : Arrays.copyOf(b.attestationChallenge, b.attestationChallenge.length);
        this.uniqueId = b.uniqueId == null
                ? new byte[0]
                : Arrays.copyOf(b.uniqueId, b.uniqueId.length);
        this.challengeMatched = b.challengeMatched;
        this.rootOfTrust = b.rootOfTrust;
        this.osVersion = b.osVersion;
        this.osVersionFormatted = b.osVersionFormatted;
        this.osPatchLevel = b.osPatchLevel;
        this.osPatchLevelFormatted = b.osPatchLevelFormatted;
        this.bootPatchLevel = b.bootPatchLevel;
        this.bootPatchLevelFormatted = b.bootPatchLevelFormatted;
        this.vendorPatchLevel = b.vendorPatchLevel;
        this.vendorPatchLevelFormatted = b.vendorPatchLevelFormatted;
        this.attestationApplicationId = b.attestationApplicationId;
        this.brand = b.brand;
        this.device = b.device;
        this.product = b.product;
        this.manufacturer = b.manufacturer;
        this.model = b.model;
        this.algorithm = b.algorithm;
        this.keySize = b.keySize;
        this.ecCurve = b.ecCurve;
        this.origin = b.origin;
        this.purposes = Collections.unmodifiableList(new ArrayList<>(b.purposes));
        this.rollbackResistant = b.rollbackResistant;
        this.deviceUniqueAttestation = b.deviceUniqueAttestation;
        this.moduleHashHex = b.moduleHashHex;
        this.trustedAttestationCertIndex = b.trustedAttestationCertIndex;
        this.attestationExtensionCount = b.attestationExtensionCount;
        this.leafShadowAttempted = b.leafShadowAttempted;
        this.swTagIds = Collections.unmodifiableSet(new LinkedHashSet<>(b.swTagIds));
        this.hwTagIds = Collections.unmodifiableSet(new LinkedHashSet<>(b.hwTagIds));
        this.leafDerInspection = b.leafDerInspection;
        this.parseError = b.parseError;
    }

    public boolean isValid() {
        return valid;
    }

    public int getAttestationVersion() {
        return attestationVersion;
    }

    public SecurityLevel getAttestationSecurityLevel() {
        return attestationSecurityLevel;
    }

    public int getKeymasterVersion() {
        return keymasterVersion;
    }

    public SecurityLevel getKeymasterSecurityLevel() {
        return keymasterSecurityLevel;
    }

    public byte[] getAttestationChallenge() {
        return Arrays.copyOf(attestationChallenge, attestationChallenge.length);
    }

    public byte[] getUniqueId() {
        return Arrays.copyOf(uniqueId, uniqueId.length);
    }

    public boolean isChallengeMatched() {
        return challengeMatched;
    }

    public RootOfTrust getRootOfTrust() {
        return rootOfTrust;
    }

    public Integer getOsVersion() {
        return osVersion;
    }

    public String getOsVersionFormatted() {
        return osVersionFormatted;
    }

    public Integer getOsPatchLevel() {
        return osPatchLevel;
    }

    public String getOsPatchLevelFormatted() {
        return osPatchLevelFormatted;
    }

    public Integer getBootPatchLevel() {
        return bootPatchLevel;
    }

    public String getBootPatchLevelFormatted() {
        return bootPatchLevelFormatted;
    }

    public Integer getVendorPatchLevel() {
        return vendorPatchLevel;
    }

    public String getVendorPatchLevelFormatted() {
        return vendorPatchLevelFormatted;
    }

    public AttestationApplicationId getAttestationApplicationId() {
        return attestationApplicationId;
    }

    public String getBrand() {
        return brand;
    }

    public String getDevice() {
        return device;
    }

    public String getProduct() {
        return product;
    }

    public String getManufacturer() {
        return manufacturer;
    }

    public String getModel() {
        return model;
    }

    public Integer getAlgorithm() {
        return algorithm;
    }

    public Integer getKeySize() {
        return keySize;
    }

    public Integer getEcCurve() {
        return ecCurve;
    }

    public Integer getOrigin() {
        return origin;
    }

    public List<Integer> getPurposes() {
        return purposes;
    }

    public boolean isRollbackResistant() {
        return rollbackResistant;
    }

    public boolean isDeviceUniqueAttestation() {
        return deviceUniqueAttestation;
    }

    public String getModuleHashHex() {
        return moduleHashHex;
    }

    public int getTrustedAttestationCertIndex() {
        return trustedAttestationCertIndex;
    }

    public int getAttestationExtensionCount() {
        return attestationExtensionCount;
    }

    public boolean isLeafShadowAttempted() {
        return leafShadowAttempted;
    }

    public Set<Integer> getSwTagIds() {
        return swTagIds;
    }

    public Set<Integer> getHwTagIds() {
        return hwTagIds;
    }

    public DerReader.LeafDerInspection getLeafDerInspection() {
        return leafDerInspection;
    }

    public String getParseError() {
        return parseError;
    }

    public static String toLowerHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        char[] out = new char[bytes.length * 2];
        final char[] hex = "0123456789abcdef".toCharArray();
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            out[i * 2] = hex[v >>> 4];
            out[i * 2 + 1] = hex[v & 0x0F];
        }
        return new String(out);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static AttestationRecord error(
            String parseError,
            int trustedAttestationCertIndex,
            int attestationExtensionCount,
            boolean leafShadowAttempted,
            DerReader.LeafDerInspection leafDerInspection) {
        return builder()
                .valid(false)
                .parseError(parseError)
                .trustedAttestationCertIndex(trustedAttestationCertIndex)
                .attestationExtensionCount(attestationExtensionCount)
                .leafShadowAttempted(leafShadowAttempted)
                .leafDerInspection(leafDerInspection)
                .build();
    }

    public static final class Builder {
        private boolean valid;
        private int attestationVersion = -1;
        private SecurityLevel attestationSecurityLevel = SecurityLevel.UNKNOWN;
        private int keymasterVersion = -1;
        private SecurityLevel keymasterSecurityLevel = SecurityLevel.UNKNOWN;
        private byte[] attestationChallenge;
        private byte[] uniqueId;
        private boolean challengeMatched;
        private RootOfTrust rootOfTrust;
        private Integer osVersion;
        private String osVersionFormatted;
        private Integer osPatchLevel;
        private String osPatchLevelFormatted;
        private Integer bootPatchLevel;
        private String bootPatchLevelFormatted;
        private Integer vendorPatchLevel;
        private String vendorPatchLevelFormatted;
        private AttestationApplicationId attestationApplicationId;
        private String brand;
        private String device;
        private String product;
        private String manufacturer;
        private String model;
        private Integer algorithm;
        private Integer keySize;
        private Integer ecCurve;
        private Integer origin;
        private List<Integer> purposes = Collections.emptyList();
        private boolean rollbackResistant;
        private boolean deviceUniqueAttestation;
        private String moduleHashHex;
        private int trustedAttestationCertIndex = -1;
        private int attestationExtensionCount;
        private boolean leafShadowAttempted;
        private Set<Integer> swTagIds = Collections.emptySet();
        private Set<Integer> hwTagIds = Collections.emptySet();
        private DerReader.LeafDerInspection leafDerInspection;
        private String parseError;

        public Builder valid(boolean v) {
            this.valid = v;
            return this;
        }

        public Builder attestationVersion(int v) {
            this.attestationVersion = v;
            return this;
        }

        public Builder attestationSecurityLevel(SecurityLevel v) {
            this.attestationSecurityLevel = v == null ? SecurityLevel.UNKNOWN : v;
            return this;
        }

        public Builder keymasterVersion(int v) {
            this.keymasterVersion = v;
            return this;
        }

        public Builder keymasterSecurityLevel(SecurityLevel v) {
            this.keymasterSecurityLevel = v == null ? SecurityLevel.UNKNOWN : v;
            return this;
        }

        public Builder attestationChallenge(byte[] v) {
            this.attestationChallenge = v;
            return this;
        }

        public Builder uniqueId(byte[] v) {
            this.uniqueId = v;
            return this;
        }

        public Builder challengeMatched(boolean v) {
            this.challengeMatched = v;
            return this;
        }

        public Builder rootOfTrust(RootOfTrust v) {
            this.rootOfTrust = v;
            return this;
        }

        public Builder osVersion(Integer raw, String formatted) {
            this.osVersion = raw;
            this.osVersionFormatted = formatted;
            return this;
        }

        public Builder osPatchLevel(Integer raw, String formatted) {
            this.osPatchLevel = raw;
            this.osPatchLevelFormatted = formatted;
            return this;
        }

        public Builder bootPatchLevel(Integer raw, String formatted) {
            this.bootPatchLevel = raw;
            this.bootPatchLevelFormatted = formatted;
            return this;
        }

        public Builder vendorPatchLevel(Integer raw, String formatted) {
            this.vendorPatchLevel = raw;
            this.vendorPatchLevelFormatted = formatted;
            return this;
        }

        public Builder attestationApplicationId(AttestationApplicationId v) {
            this.attestationApplicationId = v;
            return this;
        }

        public Builder brand(String v) {
            this.brand = v;
            return this;
        }

        public Builder device(String v) {
            this.device = v;
            return this;
        }

        public Builder product(String v) {
            this.product = v;
            return this;
        }

        public Builder manufacturer(String v) {
            this.manufacturer = v;
            return this;
        }

        public Builder model(String v) {
            this.model = v;
            return this;
        }

        public Builder algorithm(Integer v) {
            this.algorithm = v;
            return this;
        }

        public Builder keySize(Integer v) {
            this.keySize = v;
            return this;
        }

        public Builder ecCurve(Integer v) {
            this.ecCurve = v;
            return this;
        }

        public Builder origin(Integer v) {
            this.origin = v;
            return this;
        }

        public Builder purposes(List<Integer> v) {
            this.purposes = v == null ? Collections.emptyList() : v;
            return this;
        }

        public Builder rollbackResistant(boolean v) {
            this.rollbackResistant = v;
            return this;
        }

        public Builder deviceUniqueAttestation(boolean v) {
            this.deviceUniqueAttestation = v;
            return this;
        }

        public Builder moduleHashHex(String v) {
            this.moduleHashHex = v;
            return this;
        }

        public Builder trustedAttestationCertIndex(int v) {
            this.trustedAttestationCertIndex = v;
            return this;
        }

        public Builder attestationExtensionCount(int v) {
            this.attestationExtensionCount = v;
            return this;
        }

        public Builder leafShadowAttempted(boolean v) {
            this.leafShadowAttempted = v;
            return this;
        }

        public Builder swTagIds(Set<Integer> v) {
            this.swTagIds = v == null ? Collections.emptySet() : v;
            return this;
        }

        public Builder hwTagIds(Set<Integer> v) {
            this.hwTagIds = v == null ? Collections.emptySet() : v;
            return this;
        }

        public Builder leafDerInspection(DerReader.LeafDerInspection v) {
            this.leafDerInspection = v;
            return this;
        }

        public Builder parseError(String v) {
            this.parseError = v;
            return this;
        }

        public AttestationRecord build() {
            return new AttestationRecord(this);
        }
    }
}
