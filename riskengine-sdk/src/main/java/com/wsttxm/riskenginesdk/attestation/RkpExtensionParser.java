package com.wsttxm.riskenginesdk.attestation;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Strict DER + canonical CBOR parser and cross-checker for Android Remote Key Provisioning (RKP)
 * ProvisioningInfo extension OID {@code 1.3.6.1.4.1.11129.2.1.30}.
 *
 * <p>Validates:
 * <ul>
 *   <li>Strict DER OCTET STRING outer wrapper (rejects non-minimal BER length)</li>
 *   <li>Strict canonical CBOR map (rejects duplicate keys, non-canonical ints, trailing bytes)</li>
 *   <li>Adjacency of the RKP certificate to the trusted attestation certificate</li>
 *   <li>Cross-check between server-signed RKP {@code map[3]} (manufacturer) and attestation tag 716</li>
 * </ul>
 */
public final class RkpExtensionParser {

    public static final String PROVISIONING_INFO_OID = "1.3.6.1.4.1.11129.2.1.30";

    private static final int MAX_EXTENSION_BYTES = 64 * 1024;
    private static final int MAX_METADATA_CHARS = 2048;

    public static final class RkpParseResult {
        private final boolean present;
        private final boolean valid;
        private final int provisioningCertIndex;
        private final boolean adjacentToAttestationCert;
        private final Integer certsIssued;
        private final String manufacturer;
        private final String validatedEntity;
        private final String buildMetadataDiagnostic;
        private final String leafManufacturer;
        private final boolean manufacturerMismatch;
        private final List<String> issues;

        private RkpParseResult(Builder b) {
            this.present = b.present;
            this.valid = b.valid;
            this.provisioningCertIndex = b.provisioningCertIndex;
            this.adjacentToAttestationCert = b.adjacentToAttestationCert;
            this.certsIssued = b.certsIssued;
            this.manufacturer = b.manufacturer;
            this.validatedEntity = b.validatedEntity;
            this.buildMetadataDiagnostic = b.buildMetadataDiagnostic;
            this.leafManufacturer = b.leafManufacturer;
            this.manufacturerMismatch = b.manufacturerMismatch;
            this.issues = Collections.unmodifiableList(new ArrayList<>(b.issues));
        }

        public boolean isPresent() {
            return present;
        }

        public boolean isValid() {
            return valid;
        }

        public int getProvisioningCertIndex() {
            return provisioningCertIndex;
        }

        public boolean isAdjacentToAttestationCert() {
            return adjacentToAttestationCert;
        }

        public Integer getCertsIssued() {
            return certsIssued;
        }

        public String getManufacturer() {
            return manufacturer;
        }

        public String getValidatedEntity() {
            return validatedEntity;
        }

        public String getBuildMetadataDiagnostic() {
            return buildMetadataDiagnostic;
        }

        public String getLeafManufacturer() {
            return leafManufacturer;
        }

        public boolean isManufacturerMismatch() {
            return manufacturerMismatch;
        }

        public List<String> getIssues() {
            return issues;
        }

        public static RkpParseResult absent() {
            return new Builder().present(false).valid(true).build();
        }

        static final class Builder {
            private boolean present;
            private boolean valid;
            private int provisioningCertIndex = -1;
            private boolean adjacentToAttestationCert = true;
            private Integer certsIssued;
            private String manufacturer;
            private String validatedEntity;
            private String buildMetadataDiagnostic;
            private String leafManufacturer;
            private boolean manufacturerMismatch;
            private final List<String> issues = new ArrayList<>();

            Builder present(boolean v) {
                this.present = v;
                return this;
            }

            Builder valid(boolean v) {
                this.valid = v;
                return this;
            }

            Builder provisioningCertIndex(int v) {
                this.provisioningCertIndex = v;
                return this;
            }

            Builder adjacentToAttestationCert(boolean v) {
                this.adjacentToAttestationCert = v;
                return this;
            }

            Builder certsIssued(Integer v) {
                this.certsIssued = v;
                return this;
            }

            Builder manufacturer(String v) {
                this.manufacturer = v;
                return this;
            }

            Builder validatedEntity(String v) {
                this.validatedEntity = v;
                return this;
            }

            Builder buildMetadataDiagnostic(String v) {
                this.buildMetadataDiagnostic = v;
                return this;
            }

            Builder leafManufacturer(String v) {
                this.leafManufacturer = v;
                return this;
            }

            Builder manufacturerMismatch(boolean v) {
                this.manufacturerMismatch = v;
                return this;
            }

            Builder addIssue(String issue) {
                if (issue != null && !issue.isEmpty()) {
                    this.issues.add(issue);
                }
                return this;
            }

            RkpParseResult build() {
                return new RkpParseResult(this);
            }
        }
    }

    /**
     * Scans {@code chain} root-first for OID {@code 1.3.6.1.4.1.11129.2.1.30}, checks adjacency
     * relative to {@code attestationRecord.getTrustedAttestationCertIndex()}, decodes the DER+CBOR
     * payload, and cross-checks {@code map[3]} against tag 716 ({@code manufacturer}).
     */
    public RkpParseResult parseChain(
            List<X509Certificate> chain, AttestationRecord attestationRecord) {
        if (chain == null || chain.isEmpty()) {
            return RkpParseResult.absent();
        }

        int provisioningIndex = -1;
        int count = 0;
        for (int i = chain.size() - 1; i >= 0; i--) {
            X509Certificate cert = chain.get(i);
            if (cert != null && cert.getExtensionValue(PROVISIONING_INFO_OID) != null) {
                count++;
                if (provisioningIndex < 0) {
                    provisioningIndex = i;
                }
            }
        }

        if (provisioningIndex < 0) {
            return RkpParseResult.absent();
        }

        int trustedAttestIdx = attestationRecord == null
                ? -1
                : attestationRecord.getTrustedAttestationCertIndex();
        boolean adjacent = trustedAttestIdx >= 0 && provisioningIndex == trustedAttestIdx + 1 && count == 1;
        String leafManufacturer = attestationRecord == null ? null : attestationRecord.getManufacturer();

        byte[] raw = chain.get(provisioningIndex).getExtensionValue(PROVISIONING_INFO_OID);
        return parseExtensionValueInternal(raw, leafManufacturer, provisioningIndex, adjacent, count > 1);
    }

    /**
     * Parses raw DER-wrapped CBOR RKP provisioning info extension bytes and cross-checks
     * {@code map[3]} against {@code leafManufacturerTag716}.
     */
    public RkpParseResult parseExtensionValue(
            byte[] derExtensionValue, String leafManufacturerTag716) {
        return parseExtensionValueInternal(derExtensionValue, leafManufacturerTag716, -1, true, false);
    }

    private RkpParseResult parseExtensionValueInternal(
            byte[] derExtensionValue,
            String leafManufacturerTag716,
            int provisioningIndex,
            boolean adjacent,
            boolean multipleExtensions) {
        RkpParseResult.Builder b = new RkpParseResult.Builder()
                .present(true)
                .provisioningCertIndex(provisioningIndex)
                .adjacentToAttestationCert(adjacent)
                .leafManufacturer(leafManufacturerTag716);

        if (multipleExtensions) {
            b.addIssue("rkp_multiple_provisioning_extensions");
        }
        if (!adjacent) {
            b.addIssue("rkp_extension_not_adjacent_to_attestation_cert");
        }
        if (derExtensionValue == null || derExtensionValue.length == 0) {
            b.addIssue("rkp_extension_empty");
            return b.valid(false).build();
        }
        if (derExtensionValue.length > MAX_EXTENSION_BYTES) {
            b.addIssue("rkp_extension_exceeds_64kib");
            return b.valid(false).build();
        }

        byte[] cborPayload;
        try {
            cborPayload = DerReader.unwrapOctetString(derExtensionValue);
        } catch (DerReader.DerException e) {
            b.addIssue("rkp_der_error:" + e.getErrorCode());
            return b.valid(false).build();
        }

        CanonicalCborReader.CborValue root;
        try {
            root = CanonicalCborReader.parse(cborPayload);
        } catch (CanonicalCborReader.CborException e) {
            b.addIssue("rkp_cbor_error:" + e.getErrorCode());
            return b.valid(false).build();
        }

        if (root.isTagged() || root.getType() != CanonicalCborReader.ValueType.MAP) {
            b.addIssue("rkp_cbor_root_not_untagged_map");
            return b.valid(false).build();
        }

        boolean hasStructuralError = false;

        // Key 1: certsIssued (required non-negative integer)
        CanonicalCborReader.CborValue countVal = root.getMapValue(1L);
        if (countVal == null) {
            b.addIssue("rkp_missing_key_1");
            hasStructuralError = true;
        } else if (countVal.isTagged()
                || countVal.getType() != CanonicalCborReader.ValueType.INTEGER
                || countVal.asLong() < 0L
                || countVal.asLong() > Integer.MAX_VALUE) {
            b.addIssue("rkp_invalid_key_1");
            hasStructuralError = true;
        } else {
            b.certsIssued((int) countVal.asLong());
        }

        // Key 3: manufacturer (optional text string, cross-checked against leaf tag 716)
        String manufacturer = null;
        CanonicalCborReader.CborValue mfrVal = root.getMapValue(3L);
        if (mfrVal != null) {
            if (mfrVal.isTagged() || mfrVal.getType() != CanonicalCborReader.ValueType.TEXT_STRING) {
                b.addIssue("rkp_invalid_key_3");
                hasStructuralError = true;
            } else {
                manufacturer = mfrVal.asText();
                b.manufacturer(manufacturer);
            }
        }

        // Key 4: validated entity (required text string)
        CanonicalCborReader.CborValue entityVal = root.getMapValue(4L);
        if (entityVal == null) {
            b.addIssue("rkp_missing_key_4");
            hasStructuralError = true;
        } else if (entityVal.isTagged() || entityVal.getType() != CanonicalCborReader.ValueType.TEXT_STRING) {
            b.addIssue("rkp_invalid_key_4");
            hasStructuralError = true;
        } else {
            b.validatedEntity(entityVal.asText());
        }

        // Key 5: optional diagnostic build metadata
        CanonicalCborReader.CborValue metaVal = root.getMapValue(5L);
        if (metaVal != null) {
            b.buildMetadataDiagnostic(metaVal.toDiagnosticString(MAX_METADATA_CHARS));
        }

        // Cross-check map[3] manufacturer against leaf attestation tag 716
        boolean mismatch = false;
        if (isNonBlank(manufacturer) && isNonBlank(leafManufacturerTag716)) {
            if (!normalizeManufacturer(manufacturer).equals(normalizeManufacturer(leafManufacturerTag716))) {
                mismatch = true;
                b.manufacturerMismatch(true);
                b.addIssue("rkp_manufacturer_mismatch");
            }
        }

        boolean valid = !hasStructuralError && adjacent && !multipleExtensions && !mismatch;
        return b.valid(valid).build();
    }

    private static boolean isNonBlank(String s) {
        return s != null && !s.trim().isEmpty();
    }

    private static String normalizeManufacturer(String s) {
        return s.trim().toLowerCase(Locale.US);
    }
}
