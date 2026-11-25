package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.attestation.AttestationExtensionParser;
import com.wsttxm.riskenginesdk.attestation.AttestationRecord;
import com.wsttxm.riskenginesdk.attestation.CanonicalCborReader;
import com.wsttxm.riskenginesdk.attestation.DerReader;
import com.wsttxm.riskenginesdk.attestation.RkpExtensionParser;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * Unit tests for P3-1: {@link DerReader}, {@link CanonicalCborReader},
 * {@link AttestationExtensionParser}, and {@link RkpExtensionParser}.
 */
public class AttestationExtensionParserTest {

    private static final byte[] SAMPLE_CHALLENGE =
            "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SAMPLE_VBKEY = new byte[] {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88
    };
    private static final byte[] SAMPLE_VBHASH = new byte[] {
        (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd,
        (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd,
        (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd,
        (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd,
        (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd,
        (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd,
        (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd,
        (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd
    };
    private static final byte[] SAMPLE_SIG_DIGEST = new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    // -------------------------------------------------------------------------
    // Keymaster v2/v3/v4 & KeyMint 100/200/300 vectors
    // -------------------------------------------------------------------------

    @Test
    public void parseValidKeymasterAndKeyMintVersions() {
        int[] versions = new int[] {2, 3, 4, 100, 200, 300};
        AttestationExtensionParser parser = new AttestationExtensionParser();

        for (int version : versions) {
            boolean hasBootHash = version >= 4;
            int secLevel = version >= 100 ? 2 : 1; // STRONGBOX vs TEE
            byte[] extValue = buildAttestationExtension(
                    version,
                    secLevel,
                    version,
                    secLevel,
                    SAMPLE_CHALLENGE,
                    buildSwAuthList("com.example.bank", 42L, SAMPLE_SIG_DIGEST, null),
                    buildHwAuthList(
                            true,
                            0, // VERIFIED
                            hasBootHash ? SAMPLE_VBHASH : null,
                            150000,
                            202604,
                            20260405,
                            20260401,
                            "Google",
                            "Pixel 8"));

            StubX509Cert leaf = new StubX509Cert(buildCleanDerCert(),
                    Collections.singletonMap(AttestationExtensionParser.KEY_ATTESTATION_OID, extValue));
            StubX509Cert root = new StubX509Cert(buildCleanDerCert(), Collections.<String, byte[]>emptyMap());

            AttestationRecord record = parser.parse(Arrays.<X509Certificate>asList(leaf, root), SAMPLE_CHALLENGE);
            assertTrue("version " + version + " should be valid: " + record.getParseError(), record.isValid());
            assertEquals(version, record.getAttestationVersion());
            assertEquals(version, record.getKeymasterVersion());
            assertEquals(
                    secLevel == 2
                            ? AttestationRecord.SecurityLevel.STRONGBOX
                            : AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                    record.getAttestationSecurityLevel());
            assertTrue(record.isChallengeMatched());
            assertEquals(0, record.getTrustedAttestationCertIndex());
            assertEquals(1, record.getAttestationExtensionCount());
            assertFalse(record.isLeafShadowAttempted());

            assertNotNull(record.getRootOfTrust());
            assertTrue(record.getRootOfTrust().isDeviceLocked());
            assertTrue(record.getRootOfTrust().isHardwareEnforced());
            assertEquals(AttestationRecord.VerifiedBootState.VERIFIED, record.getRootOfTrust().getVerifiedBootState());
            assertEquals(AttestationRecord.toLowerHex(SAMPLE_VBKEY), record.getRootOfTrust().getVerifiedBootKeyHex());
            if (hasBootHash) {
                assertEquals(
                        AttestationRecord.toLowerHex(SAMPLE_VBHASH),
                        record.getRootOfTrust().getVerifiedBootHashHex());
            } else {
                assertNull(record.getRootOfTrust().getVerifiedBootHashHex());
            }

            assertEquals("15.0.0", record.getOsVersionFormatted());
            assertEquals("2026-04", record.getOsPatchLevelFormatted());
            assertEquals("2026-04-05", record.getBootPatchLevelFormatted());
            assertEquals("2026-04-01", record.getVendorPatchLevelFormatted());
            assertEquals("Google", record.getManufacturer());
            assertEquals("Pixel 8", record.getModel());

            assertNotNull(record.getAttestationApplicationId());
            assertEquals(
                    Collections.singletonList("com.example.bank"),
                    record.getAttestationApplicationId().getPackageNames());
            assertEquals(
                    Long.valueOf(42L),
                    record.getAttestationApplicationId().getPackageVersions().get("com.example.bank"));
            assertEquals(
                    Collections.singletonList(AttestationRecord.toLowerHex(SAMPLE_SIG_DIGEST)),
                    record.getAttestationApplicationId().getSignatureDigestsSha256());

            assertNotNull(record.getLeafDerInspection());
            assertFalse(record.getLeafDerInspection().hasAnomaly());
        }
    }

    // -------------------------------------------------------------------------
    // Root-first defense & hwTags overriding swTags
    // -------------------------------------------------------------------------

    @Test
    public void rootFirstScanDefeatsLeafExtensionSpoofing() {
        byte[] fakeLeafExt = buildAttestationExtension(
                300,
                1,
                300,
                1,
                SAMPLE_CHALLENGE,
                buildSwAuthList("com.example.bank", 1L, SAMPLE_SIG_DIGEST, null),
                buildHwAuthList(true, 0, SAMPLE_VBHASH, 150000, 202604, 20260405, 20260405, "Google", "Pixel 8"));

        byte[] realIntermediateExt = buildAttestationExtension(
                300,
                1,
                300,
                1,
                SAMPLE_CHALLENGE,
                buildSwAuthList("com.example.bank", 1L, SAMPLE_SIG_DIGEST, null),
                buildHwAuthList(false, 2, SAMPLE_VBHASH, 140000, 202401, 20240105, 20240105, "Xiaomi", "2401"));

        StubX509Cert leaf = new StubX509Cert(
                buildCleanDerCert(),
                Collections.singletonMap(AttestationExtensionParser.KEY_ATTESTATION_OID, fakeLeafExt));
        StubX509Cert intermediate = new StubX509Cert(
                buildCleanDerCert(),
                Collections.singletonMap(AttestationExtensionParser.KEY_ATTESTATION_OID, realIntermediateExt));
        StubX509Cert root = new StubX509Cert(buildCleanDerCert(), Collections.<String, byte[]>emptyMap());

        AttestationRecord record = new AttestationExtensionParser()
                .parse(Arrays.<X509Certificate>asList(leaf, intermediate, root), SAMPLE_CHALLENGE);

        assertTrue(record.isValid());
        assertEquals(1, record.getTrustedAttestationCertIndex());
        assertEquals(2, record.getAttestationExtensionCount());
        assertTrue(record.isLeafShadowAttempted());
        assertNotNull(record.getRootOfTrust());
        assertFalse("Intermediate unlocked RoT must win over spoofed leaf locked RoT",
                record.getRootOfTrust().isDeviceLocked());
        assertEquals(AttestationRecord.VerifiedBootState.UNVERIFIED, record.getRootOfTrust().getVerifiedBootState());
        assertEquals("Xiaomi", record.getManufacturer());
    }

    @Test
    public void hwTagsStrictlyOverrideSwTags() {
        byte[] spoofedSwRot = derExplicitContextTag(704, derSequence(
                derOctetString(SAMPLE_VBKEY),
                derBoolean(true),
                derEnumerated(0),
                derOctetString(SAMPLE_VBHASH)));
        byte[] swList = derSequence(
                spoofedSwRot,
                derExplicitContextTag(706, derInteger(209912)),
                derExplicitContextTag(716, derOctetString("FakeOEM".getBytes(StandardCharsets.UTF_8))));

        byte[] hwList = buildHwAuthList(
                false, 2, SAMPLE_VBHASH, 140000, 202405, 20240505, 20240501, "RealOEM", "ModelX");

        byte[] extValue = buildAttestationExtension(
                200, 1, 200, 1, SAMPLE_CHALLENGE, swList, hwList);

        AttestationRecord record = new AttestationExtensionParser()
                .parseExtensionValue(extValue, SAMPLE_CHALLENGE, 0, 1, false, null);

        assertTrue(record.isValid());
        assertNotNull(record.getRootOfTrust());
        assertFalse(record.getRootOfTrust().isDeviceLocked());
        assertEquals(AttestationRecord.VerifiedBootState.UNVERIFIED, record.getRootOfTrust().getVerifiedBootState());
        assertTrue(record.getRootOfTrust().isHardwareEnforced());
        assertEquals(Integer.valueOf(202405), record.getOsPatchLevel());
        assertEquals("RealOEM", record.getManufacturer());
        assertTrue(record.getSwTagIds().contains(704));
        assertTrue(record.getHwTagIds().contains(704));
    }

    // -------------------------------------------------------------------------
    // Strict DER & Leaf DER inspection
    // -------------------------------------------------------------------------

    @Test
    public void derReaderRejectsNonMinimalBerAndTruncatedAndTrailing() {
        // Non-minimal short value encoded with 0x81 0x02
        byte[] nonMinimalShort = new byte[] {0x04, (byte) 0x81, 0x02, 0x01, 0x02};
        assertDerError(nonMinimalShort, DerReader.ErrorCode.NON_MINIMAL_LENGTH);

        // Non-minimal leading zero in multi-byte length: 0x82 0x00 0x80
        byte[] nonMinimalLeadingZero = new byte[4 + 128];
        nonMinimalLeadingZero[0] = 0x04;
        nonMinimalLeadingZero[1] = (byte) 0x82;
        nonMinimalLeadingZero[2] = 0x00;
        nonMinimalLeadingZero[3] = (byte) 0x80;
        assertDerError(nonMinimalLeadingZero, DerReader.ErrorCode.NON_MINIMAL_LENGTH);

        // Indefinite length 0x80
        byte[] indefinite = new byte[] {0x30, (byte) 0x80, 0x00, 0x00};
        assertDerError(indefinite, DerReader.ErrorCode.INDEFINITE_LENGTH);

        // Truncated TLV value
        byte[] truncated = new byte[] {0x04, 0x05, 0x01, 0x02};
        assertDerError(truncated, DerReader.ErrorCode.TRUNCATED);

        // Trailing bytes
        byte[] trailing = new byte[] {0x04, 0x01, 0x41, 0x00};
        assertDerError(trailing, DerReader.ErrorCode.TRAILING_BYTES);

        // Extension parser must also reject non-minimal outer OCTET STRING
        AttestationRecord rec = new AttestationExtensionParser()
                .parseExtensionValue(nonMinimalShort, SAMPLE_CHALLENGE, 0, 1, false, null);
        assertFalse(rec.isValid());
        assertTrue(rec.getParseError().contains("NON_MINIMAL_LENGTH"));
    }

    @Test
    public void leafDerInspectionDetectsHexTemplate32AndNonMinimalLength() {
        byte[] cleanCert = buildCleanDerCert();
        DerReader.LeafDerInspection clean = DerReader.inspectLeafDer(cleanCert);
        assertFalse(clean.hasAnomaly());
        assertTrue(clean.getFindings().isEmpty());

        // Embed a 32-char pure-hex placeholder template followed immediately by SEQUENCE (0x30) and SET (0x31),
        // matching real X.509 TBSCertificate layout (Subject RDN -> SubjectPublicKeyInfo / next RDN).
        byte[] hexUtf8 = derTlv(0x0C, "deadbeef0123456789abcdef01234567".getBytes(StandardCharsets.US_ASCII));
        byte[] placeholderBeforeSeq = derSequence(
                derSequence(derInteger(2)),
                hexUtf8,
                derSequence(derInteger(1)));
        DerReader.LeafDerInspection hexInspSeq = DerReader.inspectLeafDer(placeholderBeforeSeq);
        assertTrue("Must detect HEX_TEMPLATE_32 even when followed by 0x30 SEQUENCE",
                hexInspSeq.isHexTemplate32Detected());
        assertTrue(hexInspSeq.hasAnomaly());
        assertTrue(hexInspSeq.getFindings().contains("HEX_TEMPLATE_32"));

        byte[] placeholderBeforeSet = derSequence(
                hexUtf8,
                derSet(derInteger(1)));
        DerReader.LeafDerInspection hexInspSet = DerReader.inspectLeafDer(placeholderBeforeSet);
        assertTrue("Must detect HEX_TEMPLATE_32 even when followed by 0x31 SET",
                hexInspSet.isHexTemplate32Detected());

        // Embed a non-minimal length inner TLV inside top-level SEQUENCE
        byte[] badInner = new byte[] {0x04, (byte) 0x81, 0x02, 0x41, 0x42};
        byte[] nonMinCert = derSequence(derInteger(1), badInner);
        DerReader.LeafDerInspection berInsp = DerReader.inspectLeafDer(nonMinCert);
        assertTrue(berInsp.isNonMinimalLengthDetected());
        assertTrue(berInsp.hasAnomaly());
        assertTrue(berInsp.getFindings().contains("NON_MINIMAL_LENGTH"));
    }

    @Test
    public void duplicateAuthorizationListTagIsRejectedAndSixDigitPatchFormatsCleanly() {
        byte[] dupHwList = derSequence(
                derExplicitContextTag(706, derInteger(202604)),
                derExplicitContextTag(706, derInteger(202605)));
        byte[] extValue = buildAttestationExtension(
                200, 1, 200, 1, SAMPLE_CHALLENGE, derSequence(), dupHwList);
        AttestationRecord dupRec = new AttestationExtensionParser()
                .parseExtensionValue(extValue, SAMPLE_CHALLENGE, 0, 1, false, null);
        assertFalse(dupRec.isValid());
        assertTrue(dupRec.getParseError().contains("Duplicate AuthorizationList tag: 706"));

        byte[] sixDigitHw = buildHwAuthList(
                true, 0, SAMPLE_VBHASH, 150000, 202604, 202604, 202604, "Google", "Pixel");
        byte[] ext6 = buildAttestationExtension(
                200, 1, 200, 1, SAMPLE_CHALLENGE, derSequence(), sixDigitHw);
        AttestationRecord rec6 = new AttestationExtensionParser()
                .parseExtensionValue(ext6, SAMPLE_CHALLENGE, 0, 1, false, null);
        assertTrue(rec6.isValid());
        assertEquals("2026-04", rec6.getBootPatchLevelFormatted());
        assertEquals("2026-04", rec6.getVendorPatchLevelFormatted());
    }

    // -------------------------------------------------------------------------
    // Canonical CBOR & RKP OID .30
    // -------------------------------------------------------------------------

    @Test
    public void canonicalCborRejectsDuplicateKeysNonCanonicalIntsAndTrailingBytes() {
        // Duplicate key 1 in map: {1: 5, 1: 6} -> A2 01 05 01 06
        byte[] dupKeys = new byte[] {(byte) 0xA2, 0x01, 0x05, 0x01, 0x06};
        assertCborError(dupKeys, CanonicalCborReader.ErrorCode.DUPLICATE_MAP_KEY);

        // Non-canonical 1-byte int encoding for value 1: 0x18 0x01
        byte[] nonCanon1 = new byte[] {0x18, 0x01};
        assertCborError(nonCanon1, CanonicalCborReader.ErrorCode.NON_CANONICAL_INT);

        // Non-canonical 2-byte int encoding for value 32: 0x19 0x00 0x20
        byte[] nonCanon2 = new byte[] {0x19, 0x00, 0x20};
        assertCborError(nonCanon2, CanonicalCborReader.ErrorCode.NON_CANONICAL_INT);

        // Indefinite map: 0xBF 0xFF
        byte[] indefMap = new byte[] {(byte) 0xBF, (byte) 0xFF};
        assertCborError(indefMap, CanonicalCborReader.ErrorCode.INDEFINITE_LENGTH);

        // Trailing bytes after valid int 1: 0x01 0x00
        byte[] trailing = new byte[] {0x01, 0x00};
        assertCborError(trailing, CanonicalCborReader.ErrorCode.TRAILING_BYTES);
    }

    @Test
    public void rkpExtensionParserValidatesAndCrossChecksManufacturer() {
        byte[] cborPayload = buildRkpCborMap(12, "Google", "RKP-Prod-Entity", "approved");
        byte[] derExt = derOctetString(cborPayload);

        RkpExtensionParser rkpParser = new RkpExtensionParser();

        // Matching manufacturer (case-insensitive)
        RkpExtensionParser.RkpParseResult ok = rkpParser.parseExtensionValue(derExt, "  google ");
        assertTrue(ok.isPresent());
        assertTrue(ok.isValid());
        assertFalse(ok.isManufacturerMismatch());
        assertEquals(Integer.valueOf(12), ok.getCertsIssued());
        assertEquals("Google", ok.getManufacturer());
        assertEquals("RKP-Prod-Entity", ok.getValidatedEntity());
        assertNotNull(ok.getBuildMetadataDiagnostic());
        assertTrue(ok.getIssues().isEmpty());

        // Mismatched manufacturer vs leaf tag 716
        RkpExtensionParser.RkpParseResult mismatch = rkpParser.parseExtensionValue(derExt, "Xiaomi");
        assertTrue(mismatch.isPresent());
        assertFalse(mismatch.isValid());
        assertTrue(mismatch.isManufacturerMismatch());
        assertTrue(mismatch.getIssues().contains("rkp_manufacturer_mismatch"));

        // Non-canonical CBOR inside RKP extension rejected
        byte[] badCbor = new byte[] {(byte) 0xA2, 0x01, 0x05, 0x01, 0x06}; // duplicate key 1
        RkpExtensionParser.RkpParseResult dupResult = rkpParser.parseExtensionValue(derOctetString(badCbor), "Google");
        assertTrue(dupResult.isPresent());
        assertFalse(dupResult.isValid());
        assertTrue(dupResult.getIssues().contains("rkp_cbor_error:DUPLICATE_MAP_KEY"));

        // Trailing byte inside RKP CBOR rejected
        byte[] withTrailing = Arrays.copyOf(cborPayload, cborPayload.length + 1);
        RkpExtensionParser.RkpParseResult trailResult =
                rkpParser.parseExtensionValue(derOctetString(withTrailing), "Google");
        assertFalse(trailResult.isValid());
        assertTrue(trailResult.getIssues().contains("rkp_cbor_error:TRAILING_BYTES"));

        // Chain adjacency test: leaf(0) has .17, intermediate(1) has .30 -> adjacent == true
        byte[] attestExt = buildAttestationExtension(
                300, 1, 300, 1, SAMPLE_CHALLENGE,
                buildSwAuthList("com.example.app", 1L, SAMPLE_SIG_DIGEST, null),
                buildHwAuthList(true, 0, SAMPLE_VBHASH, 150000, 202604, 20260405, 20260405, "Google", "Pixel 9"));
        StubX509Cert leaf = new StubX509Cert(
                buildCleanDerCert(),
                Collections.singletonMap(AttestationExtensionParser.KEY_ATTESTATION_OID, attestExt));
        StubX509Cert rkpIntermediate = new StubX509Cert(
                buildCleanDerCert(),
                Collections.singletonMap(RkpExtensionParser.PROVISIONING_INFO_OID, derExt));
        StubX509Cert root = new StubX509Cert(buildCleanDerCert(), Collections.<String, byte[]>emptyMap());

        List<X509Certificate> chain = Arrays.<X509Certificate>asList(leaf, rkpIntermediate, root);
        AttestationRecord att = new AttestationExtensionParser().parse(chain, SAMPLE_CHALLENGE);
        RkpExtensionParser.RkpParseResult chainResult = rkpParser.parseChain(chain, att);
        assertTrue(chainResult.isPresent());
        assertTrue(chainResult.isValid());
        assertTrue(chainResult.isAdjacentToAttestationCert());
        assertEquals(1, chainResult.getProvisioningCertIndex());

        // Non-adjacent chain: leaf(0) has .17, mid(1) none, root(2) has .30 -> invalid adjacency
        List<X509Certificate> nonAdjacentChain = Arrays.<X509Certificate>asList(leaf, root, rkpIntermediate);
        RkpExtensionParser.RkpParseResult nonAdj = rkpParser.parseChain(nonAdjacentChain, att);
        assertTrue(nonAdj.isPresent());
        assertFalse(nonAdj.isAdjacentToAttestationCert());
        assertFalse(nonAdj.isValid());
    }

    @Test
    public void inspectLeafDer_excludesGoogleStrongBoxIssuerSerialNumber32Hex_butStillFlagsSubjectHex32() {
        // 1. Genuine Google Pixel 6 Titan M2 StrongBox leaf cert shape:
        //    Issuer: title=StrongBox, serialNumber=06842f84bcbadbd196405bfd6a6349eb (32-char hex PrintableString)
        //    Subject: CN=Android Keystore Key
        byte[] issuerDn = derSequence(
                derSet(derSequence(derOidBytes(new byte[] {0x55, 0x04, 0x0C}),
                        derTlv(0x13, "StrongBox".getBytes(StandardCharsets.US_ASCII)))),
                derSet(derSequence(derOidBytes(new byte[] {0x55, 0x04, 0x05}),
                        derTlv(0x13, "06842f84bcbadbd196405bfd6a6349eb".getBytes(StandardCharsets.US_ASCII)))));
        byte[] cleanSubjectDn = derSequence(
                derSet(derSequence(derOidBytes(new byte[] {0x55, 0x04, 0x03}),
                        derTlv(0x13, "Android Keystore Key".getBytes(StandardCharsets.US_ASCII)))));
        byte[] genuinePixelCert = buildMinimalX509Cert(issuerDn, cleanSubjectDn);

        DerReader.LeafDerInspection genuineInsp = DerReader.inspectLeafDer(genuinePixelCert);
        assertFalse("Genuine Google StrongBox Issuer serialNumber=32hex must NOT trigger HEX_TEMPLATE_32",
                genuineInsp.isHexTemplate32Detected());
        assertFalse(genuineInsp.isNonMinimalLengthDetected());
        assertFalse(genuineInsp.isStructureInvalid());

        // 2. Spoofed leaf cert with 32-hex template in Subject CN MUST still be caught
        byte[] spoofedSubjectDn = derSequence(
                derSet(derSequence(derOidBytes(new byte[] {0x55, 0x04, 0x03}),
                        derTlv(0x13, "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII)))));
        byte[] spoofedCert = buildMinimalX509Cert(issuerDn, spoofedSubjectDn);

        DerReader.LeafDerInspection spoofedInsp = DerReader.inspectLeafDer(spoofedCert);
        assertTrue("32-hex placeholder in Subject DN must still trigger HEX_TEMPLATE_32",
                spoofedInsp.isHexTemplate32Detected());

        // 3. Non-minimal BER length INSIDE Issuer DN must STILL be detected (Issuer is only excluded from HEX_TEMPLATE_32)
        byte[] nonMinSerial = new byte[] {0x13, (byte) 0x81, 0x04, 'a', 'b', 'c', 'd'};
        byte[] nonMinIssuerDn = derSequence(
                derSet(derSequence(derOidBytes(new byte[] {0x55, 0x04, 0x05}), nonMinSerial)));
        byte[] nonMinCert = buildMinimalX509Cert(nonMinIssuerDn, cleanSubjectDn);

        DerReader.LeafDerInspection nonMinInsp = DerReader.inspectLeafDer(nonMinCert);
        assertTrue("Non-minimal BER length inside Issuer DN must still be flagged",
                nonMinInsp.isNonMinimalLengthDetected());
        assertFalse(nonMinInsp.isHexTemplate32Detected());

        // 4. Valid X.509 v1 certificate (no [0] version) excludes Issuer 32-hex, while extension 32-hex is still caught
        byte[] sigAlg = derSequence(derOidBytes(new byte[] {0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x04, 0x03, 0x02}));
        byte[] validity = derSequence(
                derTlv(0x17, "260101000000Z".getBytes(StandardCharsets.US_ASCII)),
                derTlv(0x17, "360101000000Z".getBytes(StandardCharsets.US_ASCII)));
        byte[] spki = derSequence(sigAlg, derTlv(0x03, new byte[] {0x00, 0x04, 0x01, 0x02}));
        byte[] sigVal = derTlv(0x03, new byte[] {0x00, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02});
        byte[] v1Tbs = derSequence(derInteger(1), sigAlg, issuerDn, validity, cleanSubjectDn, spki);
        DerReader.LeafDerInspection v1Insp = DerReader.inspectLeafDer(derSequence(v1Tbs, sigAlg, sigVal));
        assertFalse("Valid X.509 v1 Issuer serialNumber=32hex must NOT trigger HEX_TEMPLATE_32",
                v1Insp.isHexTemplate32Detected());
        assertFalse(v1Insp.isStructureInvalid());

        // 5. 32-hex placeholder inside v3 [3] extensions MUST still be caught
        byte[] spoofedExt = derExplicitContextTag(3, derSequence(derSequence(
                derOidBytes(new byte[] {0x55, 0x1D, 0x11}),
                derTlv(0x04, "fedcba9876543210fedcba9876543210".getBytes(StandardCharsets.US_ASCII)))));
        byte[] extTbs = derSequence(
                derExplicitContextTag(0, derInteger(2)),
                derInteger(1), sigAlg, issuerDn, validity, cleanSubjectDn, spki, spoofedExt);
        DerReader.LeafDerInspection extInsp = DerReader.inspectLeafDer(derSequence(extTbs, sigAlg, sigVal));
        assertTrue("32-hex placeholder in X.509 extensions must still trigger HEX_TEMPLATE_32",
                extInsp.isHexTemplate32Detected());

        // 6. Anti-bypass: malformed TBSCertificate omitting serialNumber/signature to shift Subject onto idx 2/3
        //    MUST NOT fool findX509IssuerRange into excluding Subject 32-hex (use a clean issuer with NO 32-hex
        //    so spoofedSubjectDn is the sole 32-hex source in the certificate)
        byte[] cleanIssuerDn = derSequence(
                derSet(derSequence(derOidBytes(new byte[] {0x55, 0x04, 0x03}),
                        derTlv(0x13, "Test CA".getBytes(StandardCharsets.US_ASCII)))));
        byte[] shiftedV3Tbs = derSequence(
                derExplicitContextTag(0, derInteger(2)),
                cleanIssuerDn, validity, spoofedSubjectDn);
        DerReader.LeafDerInspection shiftedV3Insp = DerReader.inspectLeafDer(
                derSequence(shiftedV3Tbs, sigAlg, sigVal));
        assertTrue("Malformed v3 TBS shifting Subject to idx 3 must still trigger HEX_TEMPLATE_32",
                shiftedV3Insp.isHexTemplate32Detected());

        byte[] shiftedV1Tbs = derSequence(cleanIssuerDn, validity, spoofedSubjectDn);
        DerReader.LeafDerInspection shiftedV1Insp = DerReader.inspectLeafDer(
                derSequence(shiftedV1Tbs, sigAlg, sigVal));
        assertTrue("Malformed v1 TBS shifting Subject to idx 2 must still trigger HEX_TEMPLATE_32",
                shiftedV1Insp.isHexTemplate32Detected());
    }

    private static byte[] buildMinimalX509Cert(byte[] issuerDn, byte[] subjectDn) {
        byte[] version = derExplicitContextTag(0, derInteger(2));
        byte[] serial = derInteger(1);
        byte[] sigAlg = derSequence(derOidBytes(new byte[] {0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x04, 0x03, 0x02}));
        byte[] validity = derSequence(
                derTlv(0x17, "260101000000Z".getBytes(StandardCharsets.US_ASCII)),
                derTlv(0x17, "360101000000Z".getBytes(StandardCharsets.US_ASCII)));
        byte[] spki = derSequence(sigAlg, derTlv(0x03, new byte[] {0x00, 0x04, 0x01, 0x02}));
        byte[] tbs = derSequence(version, serial, sigAlg, issuerDn, validity, subjectDn, spki);
        byte[] sigVal = derTlv(0x03, new byte[] {0x00, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02});
        return derSequence(tbs, sigAlg, sigVal);
    }

    private static byte[] derOidBytes(byte[] body) {
        return derTlv(0x06, body);
    }

    // -------------------------------------------------------------------------
    // Helpers: minimal DER / CBOR builders & Stub X509Certificate
    // -------------------------------------------------------------------------

    private static void assertDerError(byte[] input, DerReader.ErrorCode expected) {
        try {
            DerReader.parseSingle(input);
            fail("Expected DerException(" + expected + ")");
        } catch (DerReader.DerException e) {
            assertEquals(expected, e.getErrorCode());
        }
    }

    private static void assertCborError(byte[] input, CanonicalCborReader.ErrorCode expected) {
        try {
            CanonicalCborReader.parse(input);
            fail("Expected CborException(" + expected + ")");
        } catch (CanonicalCborReader.CborException e) {
            assertEquals(expected, e.getErrorCode());
        }
    }

    private static byte[] buildCleanDerCert() {
        return derSequence(
                derSequence(derInteger(2), derOctetString("RiskEngineTestCert".getBytes(StandardCharsets.US_ASCII))),
                derSequence(derInteger(1)));
    }

    private static byte[] buildSwAuthList(
            String pkg, long version, byte[] sigDigest, byte[] extraTag) {
        byte[] pkgInfo = derSequence(
                derOctetString(pkg.getBytes(StandardCharsets.UTF_8)),
                derInteger(version));
        byte[] appId = derSequence(
                derSet(pkgInfo),
                derSet(derOctetString(sigDigest)));
        byte[] tag709 = derExplicitContextTag(709, derOctetString(appId));
        if (extraTag != null) {
            return derSequence(tag709, extraTag);
        }
        return derSequence(tag709);
    }

    private static byte[] buildHwAuthList(
            boolean locked,
            int bootState,
            byte[] bootHash,
            int osVersion,
            int osPatch,
            int bootPatch,
            int vendorPatch,
            String manufacturer,
            String model) {
        ByteArrayOutputStream rot = new ByteArrayOutputStream();
        write(rot, derOctetString(SAMPLE_VBKEY));
        write(rot, derBoolean(locked));
        write(rot, derEnumerated(bootState));
        if (bootHash != null) {
            write(rot, derOctetString(bootHash));
        }
        byte[] rotSeq = derTlv(0x30, rot.toByteArray());

        return derSequence(
                derExplicitContextTag(1, derSet(derInteger(2))), // PURPOSE_SIGN
                derExplicitContextTag(2, derInteger(3)), // EC
                derExplicitContextTag(3, derInteger(256)),
                derExplicitContextTag(10, derInteger(1)), // P-256
                derExplicitContextTag(702, derInteger(0)), // KM_ORIGIN_GENERATED
                derExplicitContextTag(704, rotSeq),
                derExplicitContextTag(705, derInteger(osVersion)),
                derExplicitContextTag(706, derInteger(osPatch)),
                derExplicitContextTag(716, derOctetString(manufacturer.getBytes(StandardCharsets.UTF_8))),
                derExplicitContextTag(717, derOctetString(model.getBytes(StandardCharsets.UTF_8))),
                derExplicitContextTag(718, derInteger(vendorPatch)),
                derExplicitContextTag(719, derInteger(bootPatch)));
    }

    private static byte[] buildAttestationExtension(
            int attestationVersion,
            int attestationSecLevel,
            int keymasterVersion,
            int keymasterSecLevel,
            byte[] challenge,
            byte[] swAuthList,
            byte[] hwAuthList) {
        byte[] keyDescription = derSequence(
                derInteger(attestationVersion),
                derEnumerated(attestationSecLevel),
                derInteger(keymasterVersion),
                derEnumerated(keymasterSecLevel),
                derOctetString(challenge),
                derOctetString(new byte[0]),
                swAuthList,
                hwAuthList);
        return derOctetString(keyDescription);
    }

    private static byte[] buildRkpCborMap(
            int certsIssued, String manufacturer, String validatedEntity, String metadata) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xA4); // map(4)
        writeCborUint(out, 0, 1);
        writeCborUint(out, 0, certsIssued);
        writeCborUint(out, 0, 3);
        writeCborText(out, manufacturer);
        writeCborUint(out, 0, 4);
        writeCborText(out, validatedEntity);
        writeCborUint(out, 0, 5);
        writeCborText(out, metadata);
        return out.toByteArray();
    }

    private static void writeCborUint(ByteArrayOutputStream out, int major, long value) {
        int prefix = major << 5;
        if (value < 24) {
            out.write(prefix | (int) value);
        } else if (value <= 0xFF) {
            out.write(prefix | 24);
            out.write((int) value);
        } else if (value <= 0xFFFF) {
            out.write(prefix | 25);
            out.write((int) (value >>> 8));
            out.write((int) value);
        } else {
            out.write(prefix | 26);
            out.write((int) (value >>> 24));
            out.write((int) (value >>> 16));
            out.write((int) (value >>> 8));
            out.write((int) value);
        }
    }

    private static void writeCborText(ByteArrayOutputStream out, String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        writeCborUint(out, 3, bytes.length);
        write(out, bytes);
    }

    private static byte[] derSequence(byte[]... items) {
        return derTlv(0x30, concat(items));
    }

    private static byte[] derSet(byte[]... items) {
        return derTlv(0x31, concat(items));
    }

    private static byte[] derOctetString(byte[] content) {
        return derTlv(0x04, content);
    }

    private static byte[] derBoolean(boolean val) {
        return derTlv(0x01, new byte[] {val ? (byte) 0xFF : 0x00});
    }

    private static byte[] derInteger(long val) {
        return derTlv(0x02, BigInteger.valueOf(val).toByteArray());
    }

    private static byte[] derEnumerated(int val) {
        return derTlv(0x0A, BigInteger.valueOf(val).toByteArray());
    }

    private static byte[] derExplicitContextTag(int tagNumber, byte[] inner) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (tagNumber < 31) {
            out.write(0xA0 | tagNumber);
        } else {
            out.write(0xBF);
            // base-128 big endian
            byte[] buf = new byte[5];
            int idx = 0;
            int n = tagNumber;
            buf[idx++] = (byte) (n & 0x7F);
            n >>>= 7;
            while (n > 0) {
                buf[idx++] = (byte) ((n & 0x7F) | 0x80);
                n >>>= 7;
            }
            for (int i = idx - 1; i >= 0; i--) {
                out.write(buf[i]);
            }
        }
        writeDerLength(out, inner.length);
        write(out, inner);
        return out.toByteArray();
    }

    private static byte[] derTlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeDerLength(out, content.length);
        write(out, content);
        return out.toByteArray();
    }

    private static void writeDerLength(ByteArrayOutputStream out, int len) {
        if (len < 0x80) {
            out.write(len);
        } else if (len <= 0xFF) {
            out.write(0x81);
            out.write(len);
        } else if (len <= 0xFFFF) {
            out.write(0x82);
            out.write((len >>> 8) & 0xFF);
            out.write(len & 0xFF);
        } else {
            out.write(0x83);
            out.write((len >>> 16) & 0xFF);
            out.write((len >>> 8) & 0xFF);
            out.write(len & 0xFF);
        }
    }

    private static byte[] concat(byte[]... arrays) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] a : arrays) {
            write(out, a);
        }
        return out.toByteArray();
    }

    private static void write(ByteArrayOutputStream out, byte[] data) {
        out.write(data, 0, data.length);
    }

    private static final class StubX509Cert extends X509Certificate {
        private final byte[] encoded;
        private final Map<String, byte[]> extensions;

        StubX509Cert(byte[] encoded, Map<String, byte[]> extensions) {
            this.encoded = encoded;
            this.extensions = new HashMap<>(extensions);
        }

        @Override
        public byte[] getEncoded() {
            return Arrays.copyOf(encoded, encoded.length);
        }

        @Override
        public byte[] getExtensionValue(String oid) {
            byte[] v = extensions.get(oid);
            return v == null ? null : Arrays.copyOf(v, v.length);
        }

        @Override
        public Set<String> getCriticalExtensionOIDs() {
            return Collections.emptySet();
        }

        @Override
        public Set<String> getNonCriticalExtensionOIDs() {
            return new HashSet<>(extensions.keySet());
        }

        @Override
        public boolean hasUnsupportedCriticalExtension() {
            return false;
        }

        @Override
        public void checkValidity() {
        }

        @Override
        public void checkValidity(Date date) {
        }

        @Override
        public int getVersion() {
            return 3;
        }

        @Override
        public BigInteger getSerialNumber() {
            return BigInteger.ONE;
        }

        @Override
        public Principal getIssuerDN() {
            return () -> "CN=TestIssuer";
        }

        @Override
        public Principal getSubjectDN() {
            return () -> "CN=TestSubject";
        }

        @Override
        public Date getNotBefore() {
            return new Date(0);
        }

        @Override
        public Date getNotAfter() {
            return new Date(Long.MAX_VALUE);
        }

        @Override
        public byte[] getTBSCertificate() {
            return new byte[0];
        }

        @Override
        public byte[] getSignature() {
            return new byte[0];
        }

        @Override
        public String getSigAlgName() {
            return "SHA256withECDSA";
        }

        @Override
        public String getSigAlgOID() {
            return "1.2.840.10045.4.3.2";
        }

        @Override
        public byte[] getSigAlgParams() {
            return null;
        }

        @Override
        public boolean[] getIssuerUniqueID() {
            return null;
        }

        @Override
        public boolean[] getSubjectUniqueID() {
            return null;
        }

        @Override
        public boolean[] getKeyUsage() {
            return null;
        }

        @Override
        public int getBasicConstraints() {
            return -1;
        }

        @Override
        public void verify(PublicKey key) {
        }

        @Override
        public void verify(PublicKey key, String sigProvider) {
        }

        @Override
        public String toString() {
            return "StubX509Cert";
        }

        @Override
        public PublicKey getPublicKey() {
            return null;
        }
    }
}
