package com.wsttxm.riskenginesdk.attestation;

import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Root-first zero-dependency parser for Android Key Attestation extension OID
 * {@code 1.3.6.1.4.1.11129.2.1.17}.
 *
 * <p>Security invariants:
 * <ol>
 *   <li>Scans the certificate chain from root toward leaf (reverse order) so a spoofed leaf
 *       certificate carrying a fake OID {@code .17} extension cannot shadow an authoritative
 *       intermediate/root attestation certificate.</li>
 *   <li>Merges {@code softwareEnforced} + {@code teeEnforced} authorization lists with
 *       {@code hwTags} strictly overriding {@code swTags}.</li>
 *   <li>Enforces strict minimal DER decoding via {@link DerReader}.</li>
 *   <li>Never extracts raw PII device identifiers (serial/IMEI/MEID tags 713/714/715/723).</li>
 * </ol>
 */
public final class AttestationExtensionParser {

    public static final String KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

    private static final int TAG_PURPOSE = 1;
    private static final int TAG_ALGORITHM = 2;
    private static final int TAG_KEY_SIZE = 3;
    private static final int TAG_EC_CURVE = 10;
    private static final int TAG_ROLLBACK_RESISTANT = 303;
    private static final int TAG_ORIGIN = 702;
    private static final int TAG_ROOT_OF_TRUST = 704;
    private static final int TAG_OS_VERSION = 705;
    private static final int TAG_OS_PATCH_LEVEL = 706;
    private static final int TAG_ATTESTATION_APPLICATION_ID = 709;
    private static final int TAG_BRAND = 710;
    private static final int TAG_DEVICE = 711;
    private static final int TAG_PRODUCT = 712;
    private static final int TAG_MANUFACTURER = 716;
    private static final int TAG_MODEL = 717;
    private static final int TAG_VENDOR_PATCH_LEVEL = 718;
    private static final int TAG_BOOT_PATCH_LEVEL = 719;
    private static final int TAG_DEVICE_UNIQUE_ATTESTATION = 720;
    private static final int TAG_MODULE_HASH = 724;

    private static final int MAX_EXTENSION_BYTES = 64 * 1024;

    public AttestationRecord parse(X509Certificate[] chain, byte[] expectedChallenge) {
        if (chain == null) {
            return parse(Collections.<X509Certificate>emptyList(), expectedChallenge);
        }
        return parse(Arrays.asList(chain), expectedChallenge);
    }

    public AttestationRecord parse(List<X509Certificate> chain, byte[] expectedChallenge) {
        if (chain == null || chain.isEmpty()) {
            return AttestationRecord.error("Certificate chain is empty", -1, 0, false, null);
        }

        DerReader.LeafDerInspection leafInspection = inspectLeafCert(chain.get(0));

        int trustedIndex = -1;
        int extensionCount = 0;
        for (int i = chain.size() - 1; i >= 0; i--) {
            X509Certificate cert = chain.get(i);
            if (cert != null && cert.getExtensionValue(KEY_ATTESTATION_OID) != null) {
                extensionCount++;
                if (trustedIndex < 0) {
                    trustedIndex = i;
                }
            }
        }

        if (trustedIndex < 0) {
            return AttestationRecord.error(
                    "Attestation extension OID " + KEY_ATTESTATION_OID + " not found",
                    -1,
                    0,
                    false,
                    leafInspection);
        }

        boolean leafShadowAttempted = extensionCount > 1;
        byte[] extValue = chain.get(trustedIndex).getExtensionValue(KEY_ATTESTATION_OID);
        return parseExtensionValue(
                extValue,
                expectedChallenge,
                trustedIndex,
                extensionCount,
                leafShadowAttempted,
                leafInspection);
    }

    /**
     * Parses a raw DER-encoded X.509 extension value (outer OCTET STRING wrapping KeyDescription
     * SEQUENCE).
     */
    public AttestationRecord parseExtensionValue(
            byte[] derExtensionValue,
            byte[] expectedChallenge,
            int trustedCertIndex,
            int extensionCount,
            boolean leafShadowAttempted,
            DerReader.LeafDerInspection leafInspection) {
        if (derExtensionValue == null || derExtensionValue.length == 0) {
            return AttestationRecord.error(
                    "Empty attestation extension value",
                    trustedCertIndex,
                    extensionCount,
                    leafShadowAttempted,
                    leafInspection);
        }
        if (derExtensionValue.length > MAX_EXTENSION_BYTES) {
            return AttestationRecord.error(
                    "Attestation extension exceeds 64 KiB limit",
                    trustedCertIndex,
                    extensionCount,
                    leafShadowAttempted,
                    leafInspection);
        }

        try {
            byte[] inner = DerReader.unwrapOctetString(derExtensionValue);
            DerReader.DerElement seq = DerReader.parseSingle(inner);
            if (!seq.isUniversal(DerReader.TAG_SEQUENCE) || !seq.isConstructed()) {
                return AttestationRecord.error(
                        "KeyDescription is not a DER SEQUENCE",
                        trustedCertIndex,
                        extensionCount,
                        leafShadowAttempted,
                        leafInspection);
            }

            List<DerReader.DerElement> fields = seq.readChildren();
            if (fields.size() < 8) {
                return AttestationRecord.error(
                        "KeyDescription SEQUENCE has fewer than 8 fields: " + fields.size(),
                        trustedCertIndex,
                        extensionCount,
                        leafShadowAttempted,
                        leafInspection);
            }

            int attestationVersion = fields.get(0).asInt();
            AttestationRecord.SecurityLevel attestationLevel =
                    AttestationRecord.SecurityLevel.fromCode(fields.get(1).asInt());
            int keymasterVersion = fields.get(2).asInt();
            AttestationRecord.SecurityLevel keymasterLevel =
                    AttestationRecord.SecurityLevel.fromCode(fields.get(3).asInt());
            byte[] challenge = fields.get(4).asOctetString();
            byte[] uniqueId = fields.get(5).asOctetString();

            Map<Integer, DerReader.DerElement> swTags = parseAuthorizationList(fields.get(6));
            Map<Integer, DerReader.DerElement> hwTags = parseAuthorizationList(fields.get(7));

            // Strict merge: hwTags override swTags
            Map<Integer, DerReader.DerElement> merged = new LinkedHashMap<>(swTags);
            merged.putAll(hwTags);

            boolean challengeMatched = expectedChallenge != null
                    && expectedChallenge.length > 0
                    && MessageDigest.isEqual(challenge, expectedChallenge);

            AttestationRecord.RootOfTrust rot = null;
            DerReader.DerElement rotElem = merged.get(TAG_ROOT_OF_TRUST);
            if (rotElem != null) {
                rot = parseRootOfTrust(rotElem, hwTags.containsKey(TAG_ROOT_OF_TRUST));
            }

            Integer osVersion = readOptionalInt(merged, TAG_OS_VERSION);
            Integer osPatchLevel = readOptionalInt(merged, TAG_OS_PATCH_LEVEL);
            Integer vendorPatchLevel = readOptionalInt(merged, TAG_VENDOR_PATCH_LEVEL);
            Integer bootPatchLevel = readOptionalInt(merged, TAG_BOOT_PATCH_LEVEL);

            AttestationRecord.AttestationApplicationId appId = null;
            DerReader.DerElement appIdElem = merged.get(TAG_ATTESTATION_APPLICATION_ID);
            if (appIdElem != null) {
                appId = parseAttestationApplicationId(appIdElem);
            }

            String moduleHashHex = null;
            DerReader.DerElement moduleHashElem = merged.get(TAG_MODULE_HASH);
            if (moduleHashElem != null) {
                moduleHashHex = AttestationRecord.toLowerHex(moduleHashElem.asOctetString());
            }

            return AttestationRecord.builder()
                    .valid(true)
                    .attestationVersion(attestationVersion)
                    .attestationSecurityLevel(attestationLevel)
                    .keymasterVersion(keymasterVersion)
                    .keymasterSecurityLevel(keymasterLevel)
                    .attestationChallenge(challenge)
                    .uniqueId(uniqueId)
                    .challengeMatched(challengeMatched)
                    .rootOfTrust(rot)
                    .osVersion(osVersion, osVersion == null ? null : formatOsVersion(osVersion))
                    .osPatchLevel(osPatchLevel, osPatchLevel == null ? null : formatPatchLevel(osPatchLevel, false))
                    .vendorPatchLevel(
                            vendorPatchLevel,
                            vendorPatchLevel == null ? null : formatPatchLevel(vendorPatchLevel, true))
                    .bootPatchLevel(
                            bootPatchLevel,
                            bootPatchLevel == null ? null : formatPatchLevel(bootPatchLevel, true))
                    .attestationApplicationId(appId)
                    .brand(readOptionalOctetString(merged, TAG_BRAND))
                    .device(readOptionalOctetString(merged, TAG_DEVICE))
                    .product(readOptionalOctetString(merged, TAG_PRODUCT))
                    .manufacturer(readOptionalOctetString(merged, TAG_MANUFACTURER))
                    .model(readOptionalOctetString(merged, TAG_MODEL))
                    .algorithm(readOptionalInt(merged, TAG_ALGORITHM))
                    .keySize(readOptionalInt(merged, TAG_KEY_SIZE))
                    .ecCurve(readOptionalInt(merged, TAG_EC_CURVE))
                    .origin(readOptionalInt(merged, TAG_ORIGIN))
                    .purposes(readOptionalIntSet(merged, TAG_PURPOSE))
                    .rollbackResistant(merged.containsKey(TAG_ROLLBACK_RESISTANT))
                    .deviceUniqueAttestation(merged.containsKey(TAG_DEVICE_UNIQUE_ATTESTATION))
                    .moduleHashHex(moduleHashHex)
                    .trustedAttestationCertIndex(trustedCertIndex)
                    .attestationExtensionCount(extensionCount)
                    .leafShadowAttempted(leafShadowAttempted)
                    .swTagIds(swTags.keySet())
                    .hwTagIds(hwTags.keySet())
                    .leafDerInspection(leafInspection)
                    .build();
        } catch (DerReader.DerException e) {
            return AttestationRecord.error(
                    "DER parse error (" + e.getErrorCode() + "): " + e.getMessage(),
                    trustedCertIndex,
                    extensionCount,
                    leafShadowAttempted,
                    leafInspection);
        } catch (Exception e) {
            return AttestationRecord.error(
                    "Unexpected attestation parse error: " + e.getMessage(),
                    trustedCertIndex,
                    extensionCount,
                    leafShadowAttempted,
                    leafInspection);
        }
    }

    private static DerReader.LeafDerInspection inspectLeafCert(X509Certificate leaf) {
        if (leaf == null) {
            return null;
        }
        try {
            return DerReader.inspectLeafDer(leaf.getEncoded());
        } catch (CertificateEncodingException e) {
            return new DerReader.LeafDerInspection(
                    false, false, true, Collections.singletonList("CERT_ENCODING_ERROR"));
        }
    }

    private static Map<Integer, DerReader.DerElement> parseAuthorizationList(
            DerReader.DerElement authSeq) throws DerReader.DerException {
        if (!authSeq.isUniversal(DerReader.TAG_SEQUENCE) || !authSeq.isConstructed()) {
            throw new DerReader.DerException(
                    DerReader.ErrorCode.TYPE_MISMATCH, "AuthorizationList is not a SEQUENCE");
        }
        Map<Integer, DerReader.DerElement> tags = new LinkedHashMap<>();
        for (DerReader.DerElement item : authSeq.readChildren()) {
            if (!item.isContextSpecific() || !item.isConstructed()) {
                throw new DerReader.DerException(
                        DerReader.ErrorCode.TYPE_MISMATCH,
                        "AuthorizationList entry must be explicit context-specific constructed tag");
            }
            int tagNum = item.getTagNumber();
            if (tags.containsKey(tagNum)) {
                throw new DerReader.DerException(
                        DerReader.ErrorCode.INVALID_VALUE,
                        "Duplicate AuthorizationList tag: " + tagNum);
            }
            DerReader.DerElement inner = item.readSingleChild();
            tags.put(tagNum, inner);
        }
        return tags;
    }

    private static AttestationRecord.RootOfTrust parseRootOfTrust(
            DerReader.DerElement rotSeq, boolean hardwareEnforced) throws DerReader.DerException {
        if (!rotSeq.isUniversal(DerReader.TAG_SEQUENCE) || !rotSeq.isConstructed()) {
            throw new DerReader.DerException(
                    DerReader.ErrorCode.TYPE_MISMATCH, "RootOfTrust must be a SEQUENCE");
        }
        List<DerReader.DerElement> fields = rotSeq.readChildren();
        if (fields.size() < 3) {
            throw new DerReader.DerException(
                    DerReader.ErrorCode.INVALID_VALUE,
                    "RootOfTrust must have at least 3 fields, got " + fields.size());
        }
        byte[] verifiedBootKey = fields.get(0).asOctetString();
        boolean deviceLocked = fields.get(1).asBoolean();
        AttestationRecord.VerifiedBootState state =
                AttestationRecord.VerifiedBootState.fromCode(fields.get(2).asInt());
        byte[] verifiedBootHash = fields.size() > 3 ? fields.get(3).asOctetString() : null;
        return new AttestationRecord.RootOfTrust(
                verifiedBootKey, deviceLocked, state, verifiedBootHash, hardwareEnforced);
    }

    private static AttestationRecord.AttestationApplicationId parseAttestationApplicationId(
            DerReader.DerElement octetElem) throws DerReader.DerException {
        byte[] raw = octetElem.asOctetString();
        DerReader.DerElement seq = DerReader.parseSingle(raw);
        if (!seq.isUniversal(DerReader.TAG_SEQUENCE) || !seq.isConstructed()) {
            throw new DerReader.DerException(
                    DerReader.ErrorCode.TYPE_MISMATCH, "AttestationApplicationId must be SEQUENCE");
        }
        List<DerReader.DerElement> parts = seq.readChildren();
        if (parts.size() < 2) {
            throw new DerReader.DerException(
                    DerReader.ErrorCode.INVALID_VALUE, "AttestationApplicationId needs 2 SET fields");
        }

        DerReader.DerElement pkgSet = parts.get(0);
        DerReader.DerElement sigSet = parts.get(1);
        if (!pkgSet.isUniversal(DerReader.TAG_SET) || !sigSet.isUniversal(DerReader.TAG_SET)) {
            throw new DerReader.DerException(
                    DerReader.ErrorCode.TYPE_MISMATCH, "AttestationApplicationId fields must be SETs");
        }

        List<String> packages = new ArrayList<>();
        Map<String, Long> versions = new LinkedHashMap<>();
        for (DerReader.DerElement pkgInfo : pkgSet.readChildren()) {
            if (!pkgInfo.isUniversal(DerReader.TAG_SEQUENCE)) {
                throw new DerReader.DerException(
                        DerReader.ErrorCode.TYPE_MISMATCH, "AttestationPackageInfo must be SEQUENCE");
            }
            List<DerReader.DerElement> pkgFields = pkgInfo.readChildren();
            if (pkgFields.isEmpty()) {
                continue;
            }
            String pkgName = pkgFields.get(0).asOctetUtf8String();
            packages.add(pkgName);
            if (pkgFields.size() >= 2) {
                versions.put(pkgName, pkgFields.get(1).asLong());
            }
        }

        List<String> sigDigests = new ArrayList<>();
        for (DerReader.DerElement sigElem : sigSet.readChildren()) {
            sigDigests.add(AttestationRecord.toLowerHex(sigElem.asOctetString()));
        }

        return new AttestationRecord.AttestationApplicationId(packages, versions, sigDigests);
    }

    private static Integer readOptionalInt(Map<Integer, DerReader.DerElement> tags, int tag)
            throws DerReader.DerException {
        DerReader.DerElement elem = tags.get(tag);
        return elem == null ? null : elem.asInt();
    }

    private static String readOptionalOctetString(Map<Integer, DerReader.DerElement> tags, int tag)
            throws DerReader.DerException {
        DerReader.DerElement elem = tags.get(tag);
        return elem == null ? null : elem.asOctetUtf8String();
    }

    private static List<Integer> readOptionalIntSet(Map<Integer, DerReader.DerElement> tags, int tag)
            throws DerReader.DerException {
        DerReader.DerElement elem = tags.get(tag);
        if (elem == null) {
            return Collections.emptyList();
        }
        if (elem.isUniversal(DerReader.TAG_SET) || elem.isUniversal(DerReader.TAG_SEQUENCE)) {
            List<Integer> out = new ArrayList<>();
            for (DerReader.DerElement child : elem.readChildren()) {
                out.add(child.asInt());
            }
            return out;
        }
        return Collections.singletonList(elem.asInt());
    }

    static String formatOsVersion(int raw) {
        if (raw < 0) {
            return null;
        }
        int major = raw / 10000;
        int minor = (raw / 100) % 100;
        int patch = raw % 100;
        return major + "." + minor + "." + patch;
    }

    static String formatPatchLevel(int raw, boolean includeDay) {
        if (raw <= 0) {
            return null;
        }
        String s = Integer.toString(raw);
        if (includeDay && s.length() >= 8) {
            return s.substring(0, 4) + "-" + s.substring(4, 6) + "-" + s.substring(6, 8);
        }
        if (s.length() == 6) {
            return s.substring(0, 4) + "-" + s.substring(4, 6);
        }
        if (includeDay) {
            while (s.length() < 8) {
                s = "0" + s;
            }
            return s.substring(0, 4) + "-" + s.substring(4, 6) + "-" + s.substring(6, 8);
        }
        while (s.length() < 6) {
            s = "0" + s;
        }
        return s.substring(0, 4) + "-" + s.substring(4, 6);
    }
}
